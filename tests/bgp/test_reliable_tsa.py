import logging
import threading

import pytest

from tests.common import reboot, config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.reboot import wait_for_startup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes, _all_critical_processes_healthy
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.bgp.bgp_helpers import get_tsa_chassisdb_config, get_sup_cfggen_tsa_value, verify_dut_configdb_tsa_value
from tests.bgp.traffic_checker import get_traffic_shift_state
from tests.bgp.route_checker import parse_routes_on_neighbors, check_and_log_routes_diff, \
    verify_current_routes_announced_to_neighs, assert_only_loopback_routes_announced_to_neighs
from tests.bgp.constants import TS_NORMAL, TS_MAINTENANCE
from tests.bgp.test_startup_tsa_tsb_service import get_tsa_tsb_service_uptime, get_tsa_tsb_service_status, \
    get_startup_tsb_timer, enable_disable_startup_tsa_tsb_service     # noqa: F401

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

CONTAINER_CHECK_INTERVAL_SECS = 2
CONTAINER_STOP_THRESHOLD_SECS = 60
CONTAINER_RESTART_THRESHOLD_SECS = 300
BGP_CRIT_PROCESS = "bgpcfgd"
supported_tsa_configs = ['false', 'true']
lock = threading.Lock()


def nbrhosts_to_dut(duthost, nbrhosts, dut_nbrhosts):
    """
    @summary: Fetch the neighbor hosts' details for duthost and update the dut_nbrhosts dict
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    all_nbrhosts = {}
    for host in nbrhosts.keys():
        if host in mg_facts['minigraph_devices']:
            new_nbrhost = {host: nbrhosts[host]}
            all_nbrhosts.update(new_nbrhost)

    with lock:
        dut_nbrhosts[duthost] = all_nbrhosts


def toggle_bgp_autorestart_state(duthost, current_state, target_state):
    feature_list, _ = duthost.get_feature_status()
    bgp_autorestart_state = duthost.get_container_autorestart_states()['bgp']
    for feature, status in list(feature_list.items()):
        if feature == 'bgp' and status == 'enabled' and bgp_autorestart_state == current_state:
            duthost.shell("sudo config feature autorestart {} {}".format(feature, target_state))
            break


@pytest.fixture
def enable_disable_bgp_autorestart_state(duthosts):
    """
    @summary: enable/disable bgp feature autorestart state during OC run.
              After test_pretest, autorestart status of bgp feature is disabled. This fixture
              enables autorestart state of bgp before test start and disables once the test is done.
    Args:
        duthosts: Fixture returns a list of Ansible object DuT.
    Returns:
        None.
    """
    # Enable autorestart status for bgp feature to overcome pretest changes
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in duthosts.frontend_nodes:
            executor.submit(toggle_bgp_autorestart_state, duthost, "disabled", "enabled")

    yield

    # Disable autorestart status for bgp feature as in pretest
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in duthosts.frontend_nodes:
            executor.submit(toggle_bgp_autorestart_state, duthost, "enabled", "disabled")


def run_tsb_on_linecard(linecard):
    if verify_dut_configdb_tsa_value(linecard) is not False or get_tsa_chassisdb_config(linecard) != 'false' or \
            get_traffic_shift_state(linecard, cmd='TSC no-stats') != TS_NORMAL:
        linecard.shell('TSB')
        linecard.shell('sudo config save -y')
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                      "DUT is not in normal state")


def set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Common method to make sure the supervisor and line cards are in normal state before and after the test
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    if get_tsa_chassisdb_config(suphost) != 'false' or get_sup_cfggen_tsa_value(suphost) != 'false':
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

    # Issue TSB on line card before proceeding further
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(run_tsb_on_linecard, linecard)


def verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes):
    """
    @summary: Verify all routes are announced to neighbors in TSB
    """
    for linecard in duthosts.frontend_nodes:
        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard, dut_nbrhosts[linecard],
                          orig_v4_routes[linecard], cur_v4_routes, 4):
            if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                             orig_v4_routes[linecard], cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard, dut_nbrhosts[linecard],
                          orig_v6_routes[linecard], cur_v6_routes, 6):
            if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                             orig_v6_routes[linecard], cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


def kill_process_by_pid(duthost, container_name, program_name, program_pid):
    """
    @summary: Kill a process in the specified container by its pid
    """
    kill_cmd_result = duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid))

    # Get the exit code of 'kill' command
    exit_code = kill_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to stop program '{}' before test".format(program_name))

    logger.info("Program '{}' in container '{}' was stopped successfully"
                .format(program_name, container_name))


def get_program_info(duthost, container_name, program_name):
    """
    @summary: Get program running status and its pid by analyzing the command
              output of "docker exec <container_name> supervisorctl status"
    @return:  Program running status and its pid
    """
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl status".
                                 format(container_name), module_ignore_errors=True)
    for program_info in program_list["stdout_lines"]:
        if program_info.find(program_name) != -1:
            program_status = program_info.split()[1].strip()
            if program_status == "RUNNING":
                program_pid = int(program_info.split()[3].strip(','))
            break

    if program_pid != -1:
        logger.info("Found program '{}' in the '{}' state with pid {}"
                    .format(program_name, program_status, program_pid))

    return program_status, program_pid


def is_process_running(duthost, container_name, program_name):
    """
    @summary: Determine whether a process under container is in the expected state (running/not running)
    @returns: True if its running and false if its not
    """
    program_status, _ = get_program_info(duthost, container_name, program_name)
    logger.info(
        "Program '{}' in container '{}' is in '{}' state".format(program_name, container_name, program_status)
    )

    if program_status == "RUNNING":
        return True
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        return False
    else:
        pytest.fail("Failed to find program '{}' in container '{}'"
                    .format(program_name, container_name))


def restart_bgp(duthost, container_name, service_name, program_name, program_pid):
    """
    @summary: Kill a critical process in a container to verify whether the container
              is stopped and restarted correctly
    """
    pytest_assert(wait_until(40, 3, 0, is_process_running, duthost, container_name, program_name),
                  "Program '{}' in container '{}' is not 'RUNNING' state after given time"
                  .format(program_name, container_name))

    kill_process_by_pid(duthost, container_name, program_name, program_pid)
    logger.info("Waiting until container '{}' is stopped...".format(container_name))
    stopped = wait_until(CONTAINER_STOP_THRESHOLD_SECS,
                         CONTAINER_CHECK_INTERVAL_SECS,
                         0,
                         check_container_state, duthost, container_name, False)
    pytest_assert(stopped, "Failed to stop container '{}'".format(container_name))
    logger.info("Container '{}' was stopped".format(container_name))

    logger.info("Waiting until container '{}' is restarted...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           0,
                           check_container_state, duthost, container_name, True)
    if not restarted:
        if is_hiting_start_limit(duthost, service_name):
            clear_failed_flag_and_restart(duthost, service_name, container_name)
        else:
            pytest.fail("Failed to restart container '{}'".format(container_name))

    logger.info("Container '{}' was restarted".format(container_name))


def is_container_running(duthost, container_name):
    """
    @summary: Decide whether the container is running or not
    @return:  Boolean value. True represents the container is running
    """
    result = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))  # noqa: W605
    return result["stdout_lines"][0].strip() == "true"


def check_container_state(duthost, container_name, should_be_running):
    """
    @summary: Determine whether a container is in the expected state (running/not running)
    """
    is_running = is_container_running(duthost, container_name)
    return is_running == should_be_running


def is_hiting_start_limit(duthost, service_name):
    """
    @summary: Determine whether the service can not be restarted is due to
              start-limit-hit or not
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(service_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def clear_failed_flag_and_restart(duthost, service_name, container_name):
    """
    @summary: If a container hits the restart limitation, then we clear the failed flag and
              restart it.
    """
    logger.info("{} hits start limit and clear reset-failed flag".format(service_name))
    duthost.shell("sudo systemctl reset-failed {}.service".format(service_name))
    duthost.shell("sudo systemctl start {}.service".format(service_name))
    restarted = wait_until(300, 1, 0, check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart container '{}' after reset-failed was cleared".format(container_name))


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_sup_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                    enable_disable_startup_tsa_tsb_service, nbrhosts,     # noqa: F811
                                                    traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor and line cards are in TSB initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from supervisor and verify line cards' BGP operational state changes to TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Verify DUT is in maintenance state
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_sup_on_tsb_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor is on TSB and line cards are in TSA initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state maintains TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Ensure that the DUT is in maintenance state
            pytest_assert(
                TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                "DUT is not in maintenance state",
            )

        # Convert line cards to BGP operational TSA state for the current test as initial config
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state with supervisor TSA action")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Verify DUT continues to be in maintenance state even with supervisor TSA action
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_act_when_sup_on_tsa_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor is on TSA and line cards are in TSB configuration initially but with
    BGP operational TSA states
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state changes to TSB from TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Confirm all the line cards are in BGP operational TSA state due to supervisor TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Verify line cards change the state to TSB from TSA after supervisor TSB
        def verify_linecard_after_sup_tsb(lc):
            # Verify DUT changes to normal state with supervisor TSB action
            pytest_assert(TS_NORMAL == get_traffic_shift_state(lc),
                          "DUT is not in normal state with supervisor TSB action")
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsb, linecard)
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_act_when_sup_and_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                        enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                        nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor and line cards are in TSA configuration initially
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state is maintained
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Similarly keep line cards in TSA mode to start with as part of the test
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsb(lc):
            # Verify DUT continues to be in maintenance state even with supervisor TSB action
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Verify line cards maintains the BGP operational TSA state but with chassisdb tsa-enabled config as 'false'
        # in sync with supervisor
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsb, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_when_sup_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                    enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                    nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state changes to TSA from TSB
    Verify supervisor card continues to be in TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'false' config
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_when_sup_on_tsa_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor is on TSA and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state maintains its TSA state
    Verify supervisor card continues to be in TSA config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Verify line card config TSA enabled is still false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))

        # Confirm all the line cards are in BGP operational TSA state due to supervisor TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state continues to be in TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'true' config
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_act_when_sup_on_tsb_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor is on TSB and line cards are in TSA initially
    Verify line card config state changes to TSB and BGP TSA operational state changes to TSB from TSA
    Verify supervisor card continues to be in TSB config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Keep supervisor in TSB mode to start with as part of the test
        # And keep the line cards in TSA and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        def run_tsb_on_linecard_and_verify(lc):
            lc.shell('TSB')
            lc.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in normal state
            pytest_assert(TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in normal state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSB from line card and verify line cards' BGP operational state changes to TSB
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsb_on_linecard_and_verify, linecard)

        # Make sure all routes are advertised back to neighbors after TSB on line cards
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the normal state at the end of test
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_act_when_sup_and_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                        enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                        nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor and line cards are in TSA configuration initially
    Verify line card config state changes to TSB but the line card BGP TSA operational state is maintained
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Similarly keep line cards in TSA mode to start with as part of the test
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        def run_tsb_on_linecard_and_verify(lc):
            lc.shell('TSB')
            lc.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Issue TSB from line card and verify line cards' BGP operational state maintained at TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsb_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'true' config
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_with_sup_reboot(duthosts, localhost, enum_supervisor_dut_hostname,
                                     enable_disable_startup_tsa_tsb_service,                # noqa: F811
                                     nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor and line cards are in TSB initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do 'config save' and reboot supervisor.
    After reboot, make sure the BGP TSA operational states are same as before reboot.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    tsa_tsb_timer = dict()
    int_status_result, crit_process_check = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    orig_v4_routes, orig_v6_routes = dict(), dict()
    up_bgp_neighbors = dict()
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from supervisor and verify line cards' BGP operational state changes to TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))
            # Not verifying loopback routes here check since its been checked multiple times with previous test cases

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        # Get a dut uptime before reboot
        sup_uptime_before = suphost.get_up_time()
        # Reboot supervisor and wait for startup_tsa_tsb service to start on line cards
        logger.info("Cold reboot on supervisor node: %s", suphost.hostname)
        reboot(suphost, localhost, wait=240)
        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(suphost)

        sup_uptime = suphost.get_up_time()
        logger.info('DUT {} up since {}'.format(suphost.hostname, sup_uptime))
        rebooted = float(sup_uptime_before.strftime("%s")) != float(sup_uptime.strftime("%s"))
        assert rebooted, "Device {} did not reboot".format(suphost.hostname)
        # verify chassisdb config is same as before reboot
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_reboot(lc):
            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 160,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in the same maintenance state like before supervisor reboot
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

            logging.info("Wait until all critical processes are fully started")

            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    300, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_reboot, linecard)

        def verify_linecard_tsa_tsb(lc):
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify dut continues to be in TSA even after startup_tsa_tsb service is stopped
                pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")
                pytest_assert('true' == get_tsa_chassisdb_config(lc),
                              "{} tsa_enabled config is not enabled".format(lc.hostname))
                # Verify line card config changed to TSB after startup-tsa-tsb service expiry
                pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                              "DUT {} tsa_enabled config is enabled".format(lc.hostname))

        # Once all line cards are in maintenance state, proceed further
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_tsa_tsb, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and
                    TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats')):
                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        # Make sure linecards are in Normal state, if not do config-reload on the dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_duts_on_tsa_with_sup_config_reload(duthosts, localhost, enum_supervisor_dut_hostname,
                                                             enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                             nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor is on TSB and line cards are in TSA initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state maintained at TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do config_reload on the supervisor.
    After config_relaod, make sure the BGP TSA operational states are same as before.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    up_bgp_neighbors = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Convert line cards to BGP operational TSA state for the current test as initial config
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_tsa_after_sup_tsa(lc):
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state with supervisor TSA action")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

            up_bgp_neighbors_of_linecard = lc.get_bgp_neighbors_per_asic("established")
            with lock:
                up_bgp_neighbors[lc] = up_bgp_neighbors_of_linecard

        # Verify DUT continues to be in maintenance state even with supervisor TSA action
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_tsa_after_sup_tsa, linecard)

        # Do config_reload on the supervisor and verify configs are same as before
        config_reload(suphost, wait=300, safe_reload=True)
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_line_card_after_sup_config_reload(lc):
            # Verify DUT is in the same maintenance state like before supervisor config reload
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state after supervisor config reload")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled chassisdb config is not enabled".format(lc.hostname))
            # Before verifying loopback address, make sure IBGP neighbors are in established state
            pytest_assert(wait_until(300, 20, 0, lc.check_bgp_session_state_all_asics,
                                     up_bgp_neighbors[lc], "established"))

        # Verify line cards traffic shift states are same as before config_reload
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_line_card_after_sup_config_reload, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_with_reboot_when_sup_dut_on_tsb_init(duthosts, localhost, enum_supervisor_dut_hostname,
                                                          enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                          nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state changes to TSA from TSB
    Verify supervisor card continues to be in TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do 'config save' and reboot the line cards.
    After reboot, make sure the BGP TSA operational states are same as before reboot on line cards.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    tsa_tsb_timer = dict()
    int_status_result, crit_process_check = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    up_bgp_neighbors = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        def reboot_linecard_and_verify(lc):
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)

            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 160,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")
            # Verify startup_tsa_tsb service is not started and in exited due to manual TSA
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is in running state after dut reboot which is not expected")
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))
            # Verify line card config changed is still TSA enabled true after reboot
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))

            # Make sure the ports, interfaces are UP and running after reboot
            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_result = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_result

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    300, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        # Verify dut reboot scenario for one of the line card to make sure tsa config is in sync
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(reboot_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced to neighbors when the linecards are in TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'false' config
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and
                    TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats')):
                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        # Make sure linecards are in Normal state, if not do config-reload on the dut to recover
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_with_conf_reload_when_sup_on_tsa_dut_on_tsb_init(duthosts, localhost, enum_supervisor_dut_hostname,
                                                                  enable_disable_startup_tsa_tsb_service,     # noqa: F811, E501
                                                                  nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor is on TSA and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state maintains its TSA state
    Verify supervisor card continues to be in TSA config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do 'config save' and config_reload the line card
    After config_reload, make sure the BGP TSA operational states are same as before config reload on line card.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        # Verify line cards' BGP operational state changes to TSA
        def verify_line_card_after_sup_tsa(lc):
            # Verify line card BGP operational state changes to TSA
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled chassisdb config is not enabled".format(lc.hostname))

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_line_card_after_sup_tsa, linecard)

        # Verify dut config_reload scenario for one of the line card to make sure tsa config is in sync
        first_linecard = duthosts.frontend_nodes[0]
        first_linecard.shell('sudo config save -y')
        config_reload(first_linecard, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(first_linecard, cmd='TSC no-stats'),
                      "DUT is not in maintenance state after config reload")
        assert_only_loopback_routes_announced_to_neighs(duthosts, first_linecard,
                                                        dut_nbrhosts[first_linecard],
                                                        traffic_shift_community,
                                                        "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'true' config
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_user_init_tsa_on_dut_followed_by_sup_tsa(duthosts, localhost, enum_supervisor_dut_hostname,
                                                  enable_disable_startup_tsa_tsb_service,      # noqa: F811
                                                  nbrhosts, traffic_shift_community, tbinfo):
    """
    Test user initiated line card TSA action when supervisor and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state changes to TSA from TSB
    Verify supervisor card continues to be in TSB
    Then, issue TSA on supervisor card.
    Verify supervisor and line card chassisdb config state changes to TSA and line card continues to be in
    BGP operational TSA state.
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Issue TSA from supervisor and verify line cards' BGP operational state continues to be in TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Verify line cards' BGP operational state continues in maintenance state
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced with TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_user_init_tsa_on_dut_followed_by_sup_tsb(duthosts, localhost, enum_supervisor_dut_hostname,
                                                  enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                  nbrhosts, traffic_shift_community, tbinfo):
    """
    Test user initiated line card TSA action when supervisor and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state changes to TSA from TSB
    Verify supervisor card continues to be in TSB
    Then, issue TSB on supervisor card.
    Verify supervisor and line card chassisdb config state changes to TSB and line card continues to be in
    BGP operational TSA state.
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Issue TSB from supervisor and verify line cards' BGP operational state continues to be in TSA
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsb(lc):
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Verify line cards' BGP operational state continues in maintenance state
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsb, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced with TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_when_startup_tsa_tsb_service_running(duthosts, localhost, enum_supervisor_dut_hostname,
                                                      enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when startup-tsa-tsb service is running on line cards after reboot
    Verify line card BGP operational state continues to be in TSA after the supervisor TSA action
    Verify supervisor card changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    tsa_tsb_timer = dict()
    int_status_result, crit_process_check = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    up_bgp_neighbors = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def reboot_linecard_and_verify(lc):
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)
            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 160,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")
            # Verify startup_tsa_tsb service is started and running
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'running'),
                          "startup_tsa_tsb service is not in running state after dut reboot")

        # Verify dut reboot scenario for line card to make sure tsa config is in sync
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(reboot_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Now Issue TSA from supervisor and make sure it changes from TSB->TSA while the service is running
            if get_tsa_tsb_service_status(linecard, 'running'):
                # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
                suphost.shell('TSA')
                suphost.shell('sudo config save -y')
                pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                              "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Verify line card config changed to tsa_enabled true during service run
            pytest_assert(verify_dut_configdb_tsa_value(linecard) is True,
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))

        def verify_linecard_after_sup_tsa(lc):
            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)

            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    300, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut is still in TSA even after startup-tsa-tsb timer expiry
            if get_tsa_tsb_service_status(lc, 'exited'):
                pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                              "DUT is in normal state after startup_tsa_tsb service is stopped")
                # Ensure line card chassisdb config is in sync with supervisor
                pytest_assert('true' == get_tsa_chassisdb_config(lc),
                              "{} tsa_enabled config is not enabled".format(lc.hostname))
                # Verify line card config changed to tsa_enabled false after timer expiry
                pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                              "DUT {} tsa_enabled config is enabled".format(lc.hostname))

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        # Verify only loopback routes are announced to neighbors at this state
        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and
                    TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats')):
                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        # Make sure linecards are in Normal state, if not do config-reload on the dut to recover
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_when_startup_tsa_tsb_service_running(duthosts, localhost, enum_supervisor_dut_hostname,
                                                      enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when startup-tsa-tsb service is running on line cards after reboot
    Verify line card BGP operational state changes to normal from maintenance after supervisor TSB with timer expiry
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and make sure all routes
    are advertised back once the line cards are in normal state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    tsa_tsb_timer = dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    int_status_result, crit_process_check = True, True
    up_bgp_neighbors = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Verify dut reboot scenario for one of the line card to make sure tsa config is in sync
        first_linecard = duthosts.frontend_nodes[0]
        logger.info("Cold reboot on node: %s", first_linecard.hostname)
        reboot(first_linecard, localhost, wait=240)
        wait_for_startup(first_linecard, localhost, delay=10, timeout=300)

        # Ensure startup_tsa_tsb service started on expected time since dut rebooted
        dut_uptime = first_linecard.get_up_time()
        logging.info('DUT {} up since {}'.format(first_linecard.hostname, dut_uptime))
        service_uptime = get_tsa_tsb_service_uptime(first_linecard)
        time_diff = (service_uptime - dut_uptime).total_seconds()
        pytest_assert(int(time_diff) < 160,
                      "startup_tsa_tsb service started much later than the expected time after dut reboot")
        # Verify startup_tsa_tsb service is started and running
        pytest_assert(wait_until(tsa_tsb_timer[first_linecard], 20, 0,
                                 get_tsa_tsb_service_status, first_linecard, 'running'),
                      "startup_tsa_tsb service is not in running state after dut reboot")
        # Now Issue TSB from supervisor and make sure it changes from TSA->TSB
        if get_tsa_tsb_service_status(first_linecard, 'running'):
            # Now Issue TSB from supervisor
            suphost.shell('TSB')
            suphost.shell('sudo config save -y')
            pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                          "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(first_linecard, cmd='TSC no-stats'),
                      "DUT is not in maintenance state when startup_tsa_tsb service is running")

        logging.info("Wait until all critical processes are fully started")
        crit_process_check = wait_until(600, 20, 0, _all_critical_processes_healthy, first_linecard)
        int_status_result = wait_until(1200, 20, 0, check_interface_status_of_up_ports, first_linecard)

        # verify bgp sessions are established
        pytest_assert(
            wait_until(
                300, 10, 0,
                first_linecard.check_bgp_session_state_all_asics, up_bgp_neighbors[first_linecard], "established"),
            "All BGP sessions are not up, no point in continuing the test")

        # Verify startup_tsa_tsb service stopped after expected time
        pytest_assert(wait_until(tsa_tsb_timer[first_linecard], 20, 0,
                                 get_tsa_tsb_service_status, first_linecard, 'exited'),
                      "startup_tsa_tsb service is not stopped even after configured timer expiry")

        # Ensure dut gets back to normal state after startup-tsa-tsb timer expiry
        if get_tsa_tsb_service_status(first_linecard, 'exited'):
            pytest_assert(TS_NORMAL == get_traffic_shift_state(first_linecard, cmd='TSC no-stats'),
                          "DUT is not in normal state after startup_tsa_tsb service is stopped")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(first_linecard),
                          "{} tsa_enabled config is enabled".format(first_linecard.hostname))
            # Verify line card config changed to tsa_enabled false after timer expiry
            pytest_assert(verify_dut_configdb_tsa_value(first_linecard) is False,
                          "DUT {} tsa_enabled config is enabled".format(first_linecard.hostname))
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result and crit_process_check and
                    TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats')):
                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_followed_by_dut_bgp_restart_when_sup_on_tsa_duts_on_tsb(
        duthosts, localhost, enum_supervisor_dut_hostname, enable_disable_startup_tsa_tsb_service,     # noqa: F811
        enable_disable_bgp_autorestart_state, nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor is on TSA and line cards are in TSB configuration initially but with
    BGP operational TSA states
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state changes to TSB from TSA
    Restart bgp on the line cards and make sure BGP TSA operational state is maintained after docker restart
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        # Confirm all the line cards are in BGP operational TSA state due to supervisor TSA
        for linecard in duthosts.frontend_nodes:
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        def restart_bgp_on_linecard_and_verify(lc):
            # Restart bgp on the line cards and check the status
            for asic in lc.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, lc.hostname))
                process_status, program_pid = get_program_info(lc, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(lc, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

            # Verify line cards continues to be in TSB state even after bgp restart
            # Verify DUT changes to normal state with supervisor TSB action
            pytest_assert(TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in normal state with supervisor TSB action")
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(restart_bgp_on_linecard_and_verify, linecard)
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_followed_by_dut_bgp_restart_when_sup_and_duts_on_tsa(duthosts, localhost, enum_supervisor_dut_hostname,
                                                                      enable_disable_startup_tsa_tsb_service,    # noqa: F811, E501
                                                                      enable_disable_bgp_autorestart_state,
                                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor and line cards are in TSA configuration initially
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state is maintained
    Restart bgp on the line cards and make sure BGP TSA operational state is maintained after docker restart
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Similarly keep line cards in TSA mode to start with as part of the test
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        def restart_bgp_and_verify(lc):
            for asic in lc.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, lc.hostname))
                process_status, program_pid = get_program_info(lc, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(lc, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

            # Verify line cards maintains the BGP operational TSA state but with chassisdb tsa-enabled config as 'false'
            # in sync with supervisor
            # Verify DUT continues to be in maintenance state even with supervisor TSB action
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Restart bgp on the line cards and check the status
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(restart_bgp_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_followed_by_dut_bgp_restart_when_sup_on_tsb_duts_on_tsa(duthosts, localhost,
                                                                         enum_supervisor_dut_hostname,
                                                                         enable_disable_startup_tsa_tsb_service,     # noqa: F811, E501
                                                                         enable_disable_bgp_autorestart_state,
                                                                         nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor is on TSB and line cards are in TSA initially
    Verify line card config state changes to TSB and BGP TSA operational state changes to TSB from TSA
    Restart bgp on the line cards and make sure BGP TSA operational state is maintained after docker restart
    Verify supervisor card continues to be in TSB config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Keep supervisor in the current TSB mode to start with as part of the test
        # And keep the line cards in TSA and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        def run_tsb_on_linecard_and_verify(lc):
            lc.shell('TSB')
            lc.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in normal state
            pytest_assert(TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in normal state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSB from line card and verify line cards' BGP operational state changes to TSB
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsb_on_linecard_and_verify, linecard)

        def restart_bgp_and_verify(lc):
            for asic in lc.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, lc.hostname))
                process_status, program_pid = get_program_info(lc, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(lc, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

            # Verify line cards are in the same state as before docker restart
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in normal state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Restart bgp on the line cards and check the status
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(restart_bgp_and_verify, linecard)

        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the normal state at the end of test
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_followed_by_dut_bgp_restart_when_sup_and_duts_on_tsa(duthosts, localhost,
                                                                      enum_supervisor_dut_hostname,
                                                                      enable_disable_startup_tsa_tsb_service,     # noqa: F811, E501
                                                                      enable_disable_bgp_autorestart_state,
                                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor and line cards are in TSA configuration initially
    Verify line card config state changes to TSB but the line card BGP TSA operational state is maintained
    Restart bgp on the line cards and make sure BGP TSA operational state is continued after docker restart
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Similarly keep line cards in TSA mode to start with as part of the test
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        def run_tsb_on_linecard_and_verify(lc):
            lc.shell('TSB')
            lc.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Issue TSB from line card and verify line cards' BGP operational state maintained at TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsb_on_linecard_and_verify, linecard)

        def restart_bgp_and_verify(lc):
            for asic in lc.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, lc.hostname))
                process_status, program_pid = get_program_info(lc, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(lc, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

            # Verify line cards are in the same state as before bgp restart
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Restart bgp on the line cards and check the status
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(restart_bgp_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
