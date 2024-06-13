import logging
import pytest

from tests.common import reboot, config_reload
from tests.common.reboot import wait_for_startup
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.bgp.test_traffic_shift import get_traffic_shift_state, parse_routes_on_neighbors,\
    check_tsa_persistence_support, verify_current_routes_announced_to_neighs, check_and_log_routes_diff, \
    verify_only_loopback_routes_are_announced_to_neighs
from tests.bgp.test_startup_tsa_tsb_service import get_tsa_tsb_service_uptime, get_tsa_tsb_service_status, \
    get_startup_tsb_timer

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

TS_NORMAL = "System Mode: Normal"
TS_MAINTENANCE = "System Mode: Maintenance"
TS_INCONSISTENT = "System Mode: Not consistent"
TS_NO_NEIGHBORS = "System Mode: No external neighbors"
CONTAINER_CHECK_INTERVAL_SECS = 2
CONTAINER_STOP_THRESHOLD_SECS = 60
CONTAINER_RESTART_THRESHOLD_SECS = 300
PROGRAM_STATUS = "RUNNING"
BGP_CRIT_PROCESS = "bgpcfgd"


@pytest.fixture(scope="module", autouse=True)
def enable_disable_startup_tsa_tsb_service(duthosts):
    """
    @summary: enable/disable startup-tsa-tsb.service during OC run.
    Args:
        duthosts: Fixture returns a list of Ansible object DuT.
    Returns:
        None.
    """
    for duthost in duthosts.frontend_nodes:
        platform = duthost.facts['platform']
        startup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/startup-tsa-tsb.conf".format(platform)
        backup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/backup-startup-tsa-tsb.bck".format(platform)
        out = duthost.shell("cat {}".format(backup_tsa_tsb_file_path), module_ignore_errors=True)['rc']
        if not out:
            duthost.shell("sudo mv {} {}".format(backup_tsa_tsb_file_path, startup_tsa_tsb_file_path),
                          module_ignore_errors=True)
    yield
    for duthost in duthosts.frontend_nodes:
        platform = duthost.facts['platform']
        startup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/startup-tsa-tsb.conf".format(platform)
        backup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/backup-startup-tsa-tsb.bck".format(platform)
        out = duthost.shell("cat {}".format(startup_tsa_tsb_file_path), module_ignore_errors=True)['rc']
        if not out:
            duthost.shell("sudo mv {} {}".format(startup_tsa_tsb_file_path, backup_tsa_tsb_file_path),
                          module_ignore_errors=True)
            output = duthost.shell("TSB", module_ignore_errors=True)
            pytest_assert(not output['rc'], "Failed TSB")


@pytest.fixture
def traffic_shift_community(duthost):
    """
    @summary: Fetch device's traffic_shift_community string
    """
    community = duthost.shell('sonic-cfggen -y /etc/sonic/constants.yml -v constants.bgp.traffic_shift_community')[
        'stdout']
    return community


def nbrhosts_to_dut(duthost, nbrhosts):
    """
    @summary: Fetch the neighbor hosts' details for duthost
    @returns: dut_nbrhosts dict
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    dut_nbrhosts = {}
    for host in nbrhosts.keys():
        if host in mg_facts['minigraph_devices']:
            new_nbrhost = {host: nbrhosts[host]}
            dut_nbrhosts.update(new_nbrhost)
    return dut_nbrhosts


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

    for linecard in duthosts.frontend_nodes:
        # Issue TSB on line card before proceeding further
        if verify_dut_configdb_tsa_value(linecard) != 'false' or get_tsa_chassisdb_config(linecard) != 'false' or \
                get_traffic_shift_state(linecard, cmd='TSC no-stats') != TS_NORMAL:
            linecard.shell('TSB')
            linecard.shell('sudo config save -y')
            # Ensure that the DUT is not in maintenance already before start of the test
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in normal state")


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


def get_tsa_chassisdb_config(duthost):
    """
    @summary: Returns the dut's CHASSIS_APP_DB value for BGP_DEVICE_GLOBAL.STATE.tsa_enabled flag
    """
    tsa_conf = duthost.shell('sonic-db-cli CHASSIS_APP_DB HGET \'BGP_DEVICE_GLOBAL|STATE\' tsa_enabled')['stdout']
    return tsa_conf


def get_sup_cfggen_tsa_value(suphost):
    """
    @summary: Returns the supervisor sonic-cfggen value for BGP_DEVICE_GLOBAL.STATE.tsa_enabled flag
    """
    tsa_conf = suphost.shell('sonic-cfggen -d -v BGP_DEVICE_GLOBAL.STATE.tsa_enabled')['stdout']
    return tsa_conf


def verify_dut_configdb_tsa_value(duthost):
    """
    @summary: Returns the line cards' asic CONFIG_DB value for BGP_DEVICE_GLOBAL.STATE.tsa_enabled flag
    """
    tsa_config = list()
    tsa_enabled = 'false'
    for asic_index in duthost.get_frontend_asic_ids():
        prefix = "-n asic{}".format(asic_index) if asic_index != DEFAULT_ASIC_ID else ''
        output = duthost.shell('sonic-db-cli {} CONFIG_DB HGET \'BGP_DEVICE_GLOBAL|STATE\' \'tsa_enabled\''.
                               format(prefix))['stdout']
        tsa_config.append(output)
    if 'true' in tsa_config:
        tsa_enabled = 'true'

    return tsa_enabled


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
    global PROGRAM_STATUS
    program_status, _ = get_program_info(duthost, container_name, program_name)
    PROGRAM_STATUS = program_status
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
    global PROGRAM_STATUS
    pytest_assert(wait_until(40, 3, 0, is_process_running, duthost, container_name, program_name),
                  "Program '{}' in container '{}' is in the '{}' state, expected 'RUNNING'"
                  .format(program_name, container_name, PROGRAM_STATUS))

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
                                                    nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor and line cards are in TSB initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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

        for linecard in duthosts.frontend_nodes:
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_sup_on_tsb_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor is on TSB and line cards are in TSA initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state maintains TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Convert line cards to BGP operational TSA state for the current test as initial config
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        for linecard in duthosts.frontend_nodes:
            # Verify DUT continues to be in maintenance state even with supervisor TSA action
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state with supervisor TSA action")
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_act_when_sup_on_tsa_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor is on TSA and line cards are in TSB configuration initially but with
    BGP operational TSA states
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state changes to TSB from TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Verify line cards change the state to TSB from TSA after supervisor TSB
        for linecard in duthosts.frontend_nodes:
            # Verify DUT changes to normal state with supervisor TSB action
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                          "DUT is not in normal state with supervisor TSB action")
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_act_when_sup_and_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                        nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor and line cards are in TSA configuration initially
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state is maintained
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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
        # Similarly keep line cards in TSA mode to start with as part of the test
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Verify line cards maintains the BGP operational TSA state but with chassisdb tsa-enabled config as 'false'
        # in sync with supervisor
        for linecard in duthosts.frontend_nodes:
            # Verify DUT continues to be in maintenance state even with supervisor TSB action
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_when_sup_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                    nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state changes to TSA from TSB
    Verify supervisor card continues to be in TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
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
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor is on TSA and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state maintains its TSA state
    Verify supervisor card continues to be in TSA config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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
            # Verify line card config TSA enabled is still false
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state continues to be in TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
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
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor is on TSB and line cards are in TSA initially
    Verify line card config state changes to TSB and BGP TSA operational state changes to TSB from TSA
    Verify supervisor card continues to be in TSB config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSB mode to start with as part of the test
        # And keep the line cards in TSA and verify line cards' BGP operational state changes to TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

        # Issue TSB from line card and verify line cards' BGP operational state changes to TSB
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSB')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            # Ensure that the DUT is in normal state
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in normal state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))

        # Make sure all routes are advertised back to neighbors after TSB on line cards
        for linecard in duthosts.frontend_nodes:
            # Wait until all routes are announced to neighbors
            cur_v4_routes = {}
            cur_v6_routes = {}
            # Verify that all routes advertised to neighbor at the start of the test
            if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard,
                              dut_nbrhosts[linecard],
                              orig_v4_routes[linecard], cur_v4_routes, 4):
                if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                                 orig_v4_routes[linecard], cur_v4_routes, 4):
                    pytest.fail("Not all ipv4 routes are announced to neighbors")

            if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard,
                              dut_nbrhosts[linecard],
                              orig_v6_routes[linecard], cur_v6_routes, 6):
                if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                                 orig_v6_routes[linecard], cur_v6_routes, 6):
                    pytest.fail("Not all ipv6 routes are announced to neighbors")

    finally:
        # Bring back the supervisor and line cards to the normal state at the end of test
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_act_when_sup_and_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                        nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor and line cards are in TSA configuration initially
    Verify line card config state changes to TSB but the line card BGP TSA operational state is maintained
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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

        # Similarly keep line cards in TSA mode to start with as part of the test
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Issue TSB from line card and verify line cards' BGP operational state maintained at TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSB')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
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
                                     nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor and line cards are in TSB initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do 'config save' and reboot supervisor.
    After reboot, make sure the BGP TSA operational states are same as before reboot.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    tsa_tsb_timer = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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

        for linecard in duthosts.frontend_nodes:
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Not verifying loopback routes here check since its been checked multiple times with previous test cases

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

        for linecard in duthosts.frontend_nodes:
            wait_for_startup(linecard, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = linecard.get_up_time()
            logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(linecard)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 120,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in the same maintenance state like before supervisor reboot
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))

            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(linecard)
            pytest_assert(wait_until(1200, 20, 0, check_interface_status_of_up_ports, linecard),
                          "Not all ports that are admin up on are operationally up")

        # Once all line cards are in maintenance state, proceed further
        for linecard in duthosts.frontend_nodes:
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(linecard, 'running'):
                # Verify dut continues to be in TSA even after startup_tsa_tsb service is stopped
                pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")
                pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                              "{} tsa_enabled config is not enabled".format(linecard.hostname))
                # Verify line card config changed to TSB after startup-tsa-tsb service expiry
                pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                              "DUT {} tsa_enabled config is enabled".format(linecard.hostname))

            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_duts_on_tsa_with_sup_config_reload(duthosts, localhost, enum_supervisor_dut_hostname,
                                                             nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor is on TSB and line cards are in TSA initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state maintained at TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do config_reload on the supervisor.
    After config_relaod, make sure the BGP TSA operational states are same as before.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Convert line cards to BGP operational TSA state for the current test as initial config
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        for linecard in duthosts.frontend_nodes:
            # Verify DUT continues to be in maintenance state even with supervisor TSA action
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state with supervisor TSA action")
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))

        # Do config_reload on the supervisor and verify configs are same as before
        config_reload(suphost, wait=300, safe_reload=True)
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        # Verify line cards traffic shift states are same as before config_reload
        for linecard in duthosts.frontend_nodes:
            # Verify DUT is in the same maintenance state like before supervisor config reload
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state after supervisor config reload")
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled chassisdb config is not enabled".format(linecard.hostname))

            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_with_reboot_when_sup_dut_on_tsb_init(duthosts, localhost, enum_supervisor_dut_hostname,
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
    orig_v4_routes, orig_v6_routes = dict(), dict()
    tsa_tsb_timer = dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))

        # Verify dut reboot scenario for one of the line card to make sure tsa config is in sync
        for linecard in duthosts.frontend_nodes:
            logger.info("Cold reboot on node: %s", linecard.hostname)
            reboot(linecard, localhost, wait=240)

        for linecard in duthosts.frontend_nodes:
            wait_for_startup(linecard, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = linecard.get_up_time()
            logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(linecard)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 120,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")
            # Verify startup_tsa_tsb service is not started and in exited due to manual TSA
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'exited'),
                          "startup_tsa_tsb service is in running state after dut reboot which is not expected")
            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            # Verify line card config changed is still TSA enabled true after reboot
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))

        # Make sure the ports, interfaces are UP and running after reboot
        for linecard in duthosts.frontend_nodes:
            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(linecard)
            pytest_assert(wait_until(1200, 20, 0, check_interface_status_of_up_ports, linecard),
                          "Not all ports that are admin up on are operationally up")

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced to neighbors when the linecards are in TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
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
def test_dut_tsa_with_conf_reload_when_sup_on_tsa_dut_on_tsb_init(duthosts, localhost, enum_supervisor_dut_hostname,
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
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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
        for linecard in duthosts.frontend_nodes:
            # Verify line card BGP operational state changes to TSA
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled chassisdb config is not enabled".format(linecard.hostname))

        # Verify dut config_reload scenario for one of the line card to make sure tsa config is in sync
        for linecard in duthosts.frontend_nodes:
            linecard.shell('sudo config save -y')
            config_reload(linecard, safe_reload=True, check_intf_up_ports=True)

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state after config reload")

            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")
            break

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
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))

        # Issue TSA from supervisor and verify line cards' BGP operational state continues to be in TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        # Verify line cards' BGP operational state continues in mainternance state
        for linecard in duthosts.frontend_nodes:
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Verify only loopback routes are announced with TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_user_init_tsa_on_dut_followed_by_sup_tsb(duthosts, localhost, enum_supervisor_dut_hostname,
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
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))

        # Issue TSB from supervisor and verify line cards' BGP operational state continues to be in TSA
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Verify line cards' BGP operational state continues in mainternance state
        for linecard in duthosts.frontend_nodes:
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            # Verify only loopback routes are announced with TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_when_startup_tsa_tsb_service_running(duthosts, localhost, enum_supervisor_dut_hostname,
                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when startup-tsa-tsb service is running on line cards after reboot
    Verify line card BGP operational state continues to be in TSA after the supervisor TSA action
    Verify supervisor card changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    tsa_tsb_timer = dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Verify dut reboot scenario for line card to make sure tsa config is in sync
        for linecard in duthosts.frontend_nodes:
            logger.info("Cold reboot on node: %s", linecard.hostname)
            reboot(linecard, localhost, wait=240)
            wait_for_startup(linecard, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = linecard.get_up_time()
            logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(linecard)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 120,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")
            # Verify startup_tsa_tsb service is started and running
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'running'),
                          "startup_tsa_tsb service is not in running state after dut reboot")
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
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))

        for linecard in duthosts.frontend_nodes:
            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(linecard)
            pytest_assert(wait_until(1200, 20, 0, check_interface_status_of_up_ports, linecard),
                          "Not all ports that are admin up on are operationally up")

            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut is still in TSA even after startup-tsa-tsb timer expiry
            if get_tsa_tsb_service_status(linecard, 'exited'):
                pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                              "DUT is in normal state after startup_tsa_tsb service is stopped")
                # Ensure line card chassisdb config is in sync with supervisor
                pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                              "{} tsa_enabled config is not enabled".format(linecard.hostname))
                # Verify line card config changed to tsa_enabled false after timer expiry
                pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                              "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
        # Verify only loopback routes are announced to neighbors at this state
        for linecard in duthosts.frontend_nodes:
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_when_startup_tsa_tsb_service_running(duthosts, localhost, enum_supervisor_dut_hostname,
                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when startup-tsa-tsb service is running on line cards after reboot
    Verify line card BGP operational state changes to normal from maintenance after supervisor TSB with timer expiry
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and make sure all routes
    are advertised back once the line cards are in normal state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    tsa_tsb_timer = dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Verify dut reboot scenario for one of the line card to make sure tsa config is in sync
        for linecard in duthosts.frontend_nodes:
            logger.info("Cold reboot on node: %s", linecard.hostname)
            reboot(linecard, localhost, wait=240)
            wait_for_startup(linecard, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = linecard.get_up_time()
            logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(linecard)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 120,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")
            # Verify startup_tsa_tsb service is started and running
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'running'),
                          "startup_tsa_tsb service is not in running state after dut reboot")
            # Now Issue TSB from supervisor and make sure it changes from TSA->TSB
            if get_tsa_tsb_service_status(linecard, 'running'):
                # Now Issue TSB from supervisor
                suphost.shell('TSB')
                suphost.shell('sudo config save -y')
                pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                              "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(linecard)
            pytest_assert(wait_until(1200, 20, 0, check_interface_status_of_up_ports, linecard),
                          "Not all ports that are admin up on are operationally up")

            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut gets back to normal state after startup-tsa-tsb timer expiry
            if get_tsa_tsb_service_status(linecard, 'exited'):
                pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")
                # Ensure line card chassisdb config is in sync with supervisor
                pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                              "{} tsa_enabled config is enabled".format(linecard.hostname))
                # Verify line card config changed to tsa_enabled false after timer expiry
                pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                              "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            break

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_followed_by_dut_bgp_restart_when_sup_on_tsa_duts_on_tsb(
        duthosts, localhost, enum_supervisor_dut_hostname, nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor is on TSA and line cards are in TSB configuration initially but with
    BGP operational TSA states
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state changes to TSB from TSA
    Restart bgp on the line cards and make sure BGP TSA operational state is maintained after docker restart
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Restart bgp on the line cards and check the status
        for linecard in duthosts.frontend_nodes:
            for asic in linecard.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, linecard.hostname))
                process_status, program_pid = get_program_info(linecard, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(linecard, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

        # Verify line cards continues to be in TSB state even after bgp restart
        for linecard in duthosts.frontend_nodes:
            # Verify DUT changes to normal state with supervisor TSB action
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in normal state with supervisor TSB action")
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_followed_by_dut_bgp_restart_when_sup_and_duts_on_tsa(duthosts, localhost, enum_supervisor_dut_hostname,
                                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor and line cards are in TSA configuration initially
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state is maintained
    Restart bgp on the line cards and make sure BGP TSA operational state is maintained after docker restart
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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
        # Similarly keep line cards in TSA mode to start with as part of the test
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Restart bgp on the line cards and check the status
        for linecard in duthosts.frontend_nodes:
            for asic in linecard.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, linecard.hostname))
                process_status, program_pid = get_program_info(linecard, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(linecard, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

        # Verify line cards maintains the BGP operational TSA state but with chassisdb tsa-enabled config as 'false'
        # in sync with supervisor
        for linecard in duthosts.frontend_nodes:
            # Verify DUT continues to be in maintenance state even with supervisor TSB action
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_followed_by_dut_bgp_restart_when_sup_on_tsb_duts_on_tsa(duthosts, localhost,
                                                                         enum_supervisor_dut_hostname,
                                                                         nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor is on TSB and line cards are in TSA initially
    Verify line card config state changes to TSB and BGP TSA operational state changes to TSB from TSA
    Restart bgp on the line cards and make sure BGP TSA operational state is maintained after docker restart
    Verify supervisor card continues to be in TSB config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    orig_v4_routes, orig_v6_routes = dict(), dict()
    dut_nbrhosts = dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in the current TSB mode to start with as part of the test
        # And keep the line cards in TSA and verify line cards' BGP operational state changes to TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

        # Issue TSB from line card and verify line cards' BGP operational state changes to TSB
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSB')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            # Ensure that the DUT is in normal state
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in normal state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))

        # Restart bgp on the line cards and check the status
        for linecard in duthosts.frontend_nodes:
            for asic in linecard.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, linecard.hostname))
                process_status, program_pid = get_program_info(linecard, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(linecard, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

        # Verify line cards are in the same state as before docker restart
        for linecard in duthosts.frontend_nodes:
            # Verify line card config changed to tsa_enabled false
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in normal state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is enabled".format(linecard.hostname))

        for linecard in duthosts.frontend_nodes:
            # Wait until all routes are announced to neighbors
            cur_v4_routes = {}
            cur_v6_routes = {}
            # Verify that all routes advertised to neighbor at the start of the test
            if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard,
                              dut_nbrhosts[linecard],
                              orig_v4_routes[linecard], cur_v4_routes, 4):
                if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                                 orig_v4_routes[linecard], cur_v4_routes, 4):
                    pytest.fail("Not all ipv4 routes are announced to neighbors")

            if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard,
                              dut_nbrhosts[linecard],
                              orig_v6_routes[linecard], cur_v6_routes, 6):
                if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                                 orig_v6_routes[linecard], cur_v6_routes, 6):
                    pytest.fail("Not all ipv6 routes are announced to neighbors")

    finally:
        # Bring back the supervisor and line cards to the normal state at the end of test
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_followed_by_dut_bgp_restart_when_sup_and_duts_on_tsa(duthosts, localhost,
                                                                      enum_supervisor_dut_hostname,
                                                                      nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor and line cards are in TSA configuration initially
    Verify line card config state changes to TSB but the line card BGP TSA operational state is maintained
    Restart bgp on the line cards and make sure BGP TSA operational state is continued after docker restart
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")
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

        # Similarly keep line cards in TSA mode to start with as part of the test
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSA')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert('true' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is not enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")

        # Issue TSB from line card and verify line cards' BGP operational state maintained at TSA
        for linecard in duthosts.frontend_nodes:
            linecard.shell('TSB')
            linecard.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))

        # Restart bgp on the line cards and check the status
        for linecard in duthosts.frontend_nodes:
            for asic in linecard.asics:
                service_name = asic.get_service_name("bgp")
                container_name = asic.get_docker_name("bgp")
                logger.info("Restarting {} container on dut {}".format(container_name, linecard.hostname))
                process_status, program_pid = get_program_info(linecard, container_name, BGP_CRIT_PROCESS)
                if process_status == "RUNNING":
                    restart_bgp(linecard, container_name, service_name, BGP_CRIT_PROCESS, program_pid)

        # Verify line cards are in the same state as before bgp restart
        for linecard in duthosts.frontend_nodes:
            # Verify line card config changed to tsa_enabled false
            pytest_assert('false' == verify_dut_configdb_tsa_value(linecard),
                          "DUT {} tsa_enabled config is enabled".format(linecard.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard, cmd='TSC no-stats'),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(linecard),
                          "{} tsa_enabled config is not enabled".format(linecard.hostname))
            # Verify only loopback routes are announced after TSA
            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
