import logging
import datetime
import threading

import pytest
from tests.common import reboot, config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.reboot import get_reboot_cause, SONIC_SSH_PORT, SONIC_SSH_REGEX, wait_for_startup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes, _all_critical_processes_healthy
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.bgp.bgp_helpers import initial_tsa_check_before_and_after_test
from tests.bgp.traffic_checker import get_traffic_shift_state, check_tsa_persistence_support
from tests.bgp.route_checker import parse_routes_on_neighbors, check_and_log_routes_diff, \
    verify_current_routes_announced_to_neighs, assert_only_loopback_routes_announced_to_neighs
from tests.bgp.constants import TS_NORMAL, TS_MAINTENANCE
from tests.conftest import get_hosts_per_hwsku

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

KERNEL_PANIC_REBOOT_CAUSE = "Kernel Panic"
COLD_REBOOT_CAUSE = 'cold'
UNKNOWN_REBOOT_CAUSE = "Unknown"
SUP_REBOOT_CAUSE = 'Reboot from Supervisor'
SUP_HEARTBEAT_LOSS_CAUSE = 'Heartbeat with the Supervisor card lost'
SSH_SHUTDOWN_TIMEOUT = 480
SSH_STARTUP_TIMEOUT = 600

SSH_STATE_ABSENT = "absent"
SSH_STATE_STARTED = "started"

lock = threading.Lock()
_cached_frontend_nodes = None


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


def get_startup_tsb_timer(duthost):
    """
    @summary: Fetch startup-tsa-tsb service timer value configured on 'startup-tsa-tsb.conf' file
    @returns: Returns the timer value in integer format
    """
    timer = None
    # Check whether startup-tsa-tsb.conf file exists for this specific platform. If yes get timer value.
    platform = duthost.facts['platform']
    startup_tsa_tsb_file_path = "/usr/share/sonic/device/{}/startup-tsa-tsb.conf".format(platform)
    # Check if the conf file exists in the specific path. Return 0 if it DOES exist.
    file_check = duthost.shell("[ -f {} ]".format(startup_tsa_tsb_file_path), module_ignore_errors=True)
    if file_check.get('rc') == 0:
        output = duthost.shell("cat {} | grep STARTUP_TSB_TIMER".format(startup_tsa_tsb_file_path),
                               module_ignore_errors=True)['stdout']
        timer = int(output.split('=', 2)[1].strip().encode('utf-8'))
    else:
        logger.warning("{} file does not exist in the specified path on dut {}".
                       format(startup_tsa_tsb_file_path, duthost.hostname))

    return timer


def get_tsa_tsb_service_uptime(duthost):
    """
    @summary: Fetch startup-tsa-tsb service running time when its active
    """
    service_uptime = ""
    service_status = duthost.shell("sudo systemctl status startup_tsa_tsb.service | grep 'Active'")
    for line in service_status["stdout_lines"]:
        if 'active' in line:
            tmp_time = line.split('since')[1].strip()
            act_time = tmp_time.split('UTC')[0].strip()
            service_uptime = datetime.datetime.strptime(act_time[4:], '%Y-%m-%d %H:%M:%S')
            return service_uptime
    return service_uptime


def get_tsa_tsb_service_status(duthost, pattern):
    """
    @summary: Determine whether the startup-tsa-tsb service is Active but in exited state
    """
    service_status = duthost.shell("sudo systemctl status startup_tsa_tsb.service | grep 'Active'")
    for line in service_status["stdout_lines"]:
        if pattern in line:
            return True

    return False


def check_tsc_command_error(duthost):
    """
    @summary: Determine whether the TSC command execution on dut has any errors
    """
    outputs = duthost.shell("TSC")['stderr_lines']
    if len(outputs) == 0:
        return True
    return False


def check_tsa_tsb_service_run_time_diff(service_uptime, configured_service_timer):
    """
    @summary: Determine time difference between service runtime and configured value
    """
    current_time = datetime.datetime.now()
    actual_service_timer = (current_time - service_uptime).total_seconds()
    return int(actual_service_timer) < configured_service_timer


def nbrhosts_to_dut(duthost, nbrhosts, dut_nbrhosts):
    """
    @summary: Fetch the neighbor hosts' details for duthost
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    all_nbhhosts = {}
    for host in nbrhosts.keys():
        if host in mg_facts['minigraph_devices']:
            new_nbrhost = {host: nbrhosts[host]}
            all_nbhhosts.update(new_nbrhost)

    with lock:
        dut_nbrhosts[duthost] = all_nbhhosts


def check_ssh_state(localhost, dut_ip, expected_state, timeout=60):
    """
    Check the SSH state of DUT.

    :param localhost: A `tests.common.devices.local.Localhost` Object.
    :param dut_ip: A string, the IP address of DUT.
    :param expected_state: A string, the expected SSH state.
    :param timeout: An integer, the maximum number of seconds to wait for.
    :return: A boolean, True if SSH state is the same as expected
                      , False otherwise.
    """
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state=expected_state,
                             search_regex=SONIC_SSH_REGEX,
                             delay=10,
                             timeout=timeout,
                             module_ignore_errors=True)
    return not res.is_failed and 'Timeout' not in res.get('msg', '')


def verify_route_on_neighbors(linecards, dut_nbrhosts, orig_v4_routes, orig_v6_routes):
    for linecard in linecards:
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


def get_frontend_nodes_per_hwsku(duthosts, request):
    global _cached_frontend_nodes
    if _cached_frontend_nodes is None:
        _cached_frontend_nodes = [
            duthosts[hostname] for hostname in get_hosts_per_hwsku(
                request,
                [host.hostname for host in duthosts.frontend_nodes],
            )
        ]

    return _cached_frontend_nodes


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_dut_cold_reboot(request, duthosts, localhost, nbrhosts, traffic_shift_community):
    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    for linecard in frontend_nodes_per_hwsku:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in frontend_nodes_per_hwsku:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(linecard.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in frontend_nodes_per_hwsku:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in frontend_nodes_per_hwsku:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def reboot_and_verify(lc):
            # Reboot dut and wait for startup_tsa_tsb service to start
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)

            logger.info('Cold reboot finished on {}'.format(lc.hostname))
            dut_uptime = lc.get_up_time()
            logger.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))

            # Ensure startup_tsa_tsb service is running after dut reboot
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, lc, 'running'),
                          "startup_tsa_tsb service is not started after reboot")

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(reboot_and_verify, linecard)

        for linecard in frontend_nodes_per_hwsku:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        def further_verify_linecard(lc):
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_NORMAL == get_traffic_shift_state(lc),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(further_verify_linecard, linecard)

        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        def config_reload_linecard_if_unhealthy(lc):
            # Verify DUT is in normal state after cold reboot scenario.
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        for linecard in frontend_nodes_per_hwsku:
            # Make sure the dut's reboot cause is as expected
            logger.info("Check reboot cause of the dut")
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_dut_abnormal_reboot(request, duthosts, localhost, nbrhosts, traffic_shift_community):
    """
    Test startup TSA_TSB service after DUT abnormal reboot/crash
    Verify startup_tsa_tsb.service started automatically when dut comes up after crash
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    for linecard in frontend_nodes_per_hwsku:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in frontend_nodes_per_hwsku:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(linecard.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in frontend_nodes_per_hwsku:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in frontend_nodes_per_hwsku:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def abnormal_reboot_linecard_and_verify(lc):
            # Our shell command is designed as 'nohup bash -c "sleep 5 && tail /dev/zero" &' because of:
            #  * `tail /dev/zero` is used to run out of memory completely.
            #  * Since `tail /dev/zero` will cause the DUT reboot, we need to run it in the background
            #    (using &) to avoid pytest getting stuck. `nohup` is also necessary to protect the
            #    background process.
            #  * Some DUTs with few free memory may reboot before ansible receive the result of shell
            #    command, so we add `sleep 5` to ensure ansible receive the result first.
            cmd = 'nohup bash -c "sleep 5 && tail /dev/zero" &'
            res = lc.shell(cmd)
            if not res.is_successful:
                pytest.fail('DUT {} run command {} failed'.format(lc.hostname, cmd))

            # Waiting for SSH connection shutdown
            dut_ip = lc.mgmt_ip
            pytest_assert(check_ssh_state(localhost, dut_ip, SSH_STATE_ABSENT, SSH_SHUTDOWN_TIMEOUT),
                          'DUT {} did not shutdown'.format(lc.hostname))
            # Waiting for SSH connection startup
            pytest_assert(check_ssh_state(localhost, dut_ip, SSH_STATE_STARTED, SSH_STARTUP_TIMEOUT),
                          'DUT {} did not startup'.format(lc.hostname))

            # Ensure startup_tsa_tsb service is running after dut reboot
            pytest_assert(wait_until(90, 5, 0, get_tsa_tsb_service_status, lc, 'running'),
                          "startup_tsa_tsb service is not started after reboot")

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            logger.info("Time difference between dut up-time & tsa_tsb_service up-time is {}".format(int(time_diff)))
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Make sure BGP containers are running properly before verifying
            pytest_assert(wait_until(90, 5, 0, check_tsc_command_error, lc),
                          "TSC command still returns error even after startup_tsa_tsb service started")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(abnormal_reboot_linecard_and_verify, linecard)

        for linecard in frontend_nodes_per_hwsku:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        def further_verify_linecard(lc):
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_NORMAL == get_traffic_shift_state(lc),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(further_verify_linecard, linecard)

        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        def config_reload_linecard_if_unhealthy(lc):
            # Verify DUT is in normal state after abnormal reboot scenario.
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after abnormal reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        for linecard in frontend_nodes_per_hwsku:
            # Make sure the dut's reboot cause is as expected
            logger.info("Check reboot cause of the dut")
            reboot_cause = get_reboot_cause(linecard)
            out = linecard.command('show kdump config')
            if "Enabled" not in out["stdout"]:
                pytest_assert(
                    reboot_cause == UNKNOWN_REBOOT_CAUSE,
                    "Reboot cause {} did not match the trigger {}".format(reboot_cause, UNKNOWN_REBOOT_CAUSE)
                )
            else:
                pytest_assert(
                    reboot_cause == KERNEL_PANIC_REBOOT_CAUSE,
                    "Reboot cause {} did not match the trigger {}".format(reboot_cause, KERNEL_PANIC_REBOOT_CAUSE)
                )


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_supervisor_cold_reboot(duthosts, localhost, enum_supervisor_dut_hostname, nbrhosts,
                                                     traffic_shift_community):
    """
    Test startup TSA_TSB service after supervisor cold reboot
    Verify startup_tsa_tsb.service started automatically on all linecards when they come up
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired on linecards
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in duthosts.frontend_nodes:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(suphost.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in duthosts.frontend_nodes:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in duthosts.frontend_nodes:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Get a dut uptime before reboot
        sup_uptime_before = suphost.get_up_time()
        # Reboot dut and wait for startup_tsa_tsb service to start on linecards
        logger.info("Cold reboot on supervisor node: %s", suphost.hostname)
        reboot(suphost, localhost, wait=240)
        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(suphost)

        sup_uptime = suphost.get_up_time()
        logger.info('DUT {} up since {}'.format(suphost.hostname, sup_uptime))
        rebooted = float(sup_uptime_before.strftime("%s")) != float(sup_uptime.strftime("%s"))
        assert rebooted, "Device {} did not reboot".format(suphost.hostname)

        def verify_linecard_after_sup_reboot(lc):
            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_reboot, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Once all line cards are in maintenance state, proceed further
        def further_verify_linecard(lc):
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_NORMAL == get_traffic_shift_state(lc),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(further_verify_linecard, linecard)

        verify_route_on_neighbors(duthosts.frontend_nodes, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        # Make sure DUT is in normal state after supervisor cold reboot
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        for linecard in duthosts.frontend_nodes:
            # Make sure the dut's reboot cause is as expected
            logger.info("Check reboot cause of the dut {}".format(linecard))
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == SUP_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, SUP_REBOOT_CAUSE))

        # Make sure the Supervisor's reboot cause is as expected
        logger.info("Check reboot cause of the supervisor")
        reboot_cause = get_reboot_cause(suphost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_supervisor_abnormal_reboot(duthosts, localhost, enum_supervisor_dut_hostname, nbrhosts,
                                                         traffic_shift_community):
    """
    Test startup TSA_TSB service after supervisor abnormal reboot
    Verify startup_tsa_tsb.service started automatically on all linecards when they come up
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired on linecards
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    sup_ip = suphost.mgmt_ip
    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in duthosts.frontend_nodes:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(suphost.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in duthosts.frontend_nodes:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in duthosts.frontend_nodes:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Get a dut uptime before reboot
        sup_uptime_before = suphost.get_up_time()

        # Our shell command is designed as 'nohup bash -c "sleep 5 && tail /dev/zero" &' because of:
        #  * `tail /dev/zero` is used to run out of memory completely.
        #  * Since `tail /dev/zero` will cause the DUT reboot, we need to run it in the background
        #    (using &) to avoid pytest getting stuck. `nohup` is also necessary to protect the
        #    background process.
        #  * Some DUTs with few free memory may reboot before ansible receive the result of shell
        #    command, so we add `sleep 5` to ensure ansible receive the result first.
        cmd = 'nohup bash -c "sleep 5 && tail /dev/zero" &'
        res = suphost.shell(cmd)
        if not res.is_successful:
            pytest.fail('DUT {} run command {} failed'.format(suphost.hostname, cmd))

        # Waiting for SSH connection shutdown
        pytest_assert(check_ssh_state(localhost, sup_ip, SSH_STATE_ABSENT, SSH_SHUTDOWN_TIMEOUT),
                      'DUT {} did not shutdown'.format(suphost.hostname))
        # Waiting for SSH connection startup
        pytest_assert(check_ssh_state(localhost, sup_ip, SSH_STATE_STARTED, SSH_STARTUP_TIMEOUT),
                      'DUT {} did not startup'.format(suphost.hostname))

        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(suphost)

        sup_uptime = suphost.get_up_time()
        logger.info('DUT {} up since {}'.format(suphost.hostname, sup_uptime))
        rebooted = float(sup_uptime_before.strftime("%s")) != float(sup_uptime.strftime("%s"))
        assert rebooted, "Device {} did not reboot".format(suphost.hostname)

        def verify_linecard_after_sup_reboot(lc):
            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Make sure BGP containers are running properly before verifying
            pytest_assert(wait_until(90, 5, 0, check_tsc_command_error, lc),
                          "TSC command still returns error even after startup_tsa_tsb service started")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_reboot, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Once all line cards are in maintenance state, proceed further
        def further_verify_linecard(lc):
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_NORMAL == get_traffic_shift_state(lc),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(further_verify_linecard, linecard)

        verify_route_on_neighbors(duthosts.frontend_nodes, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after SUP abnormal reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        # Make sure DUT is in normal state after supervisor abnormal reboot
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        for linecard in duthosts.frontend_nodes:
            # Make sure the dut's reboot cause is as expected
            logger.info("Check reboot cause of the dut {}".format(linecard))
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == SUP_HEARTBEAT_LOSS_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, SUP_HEARTBEAT_LOSS_CAUSE))

        # Make sure the Supervisor's reboot cause is as expected
        logger.info("Check reboot cause of the supervisor")
        reboot_cause = get_reboot_cause(suphost)
        out = suphost.command('show kdump config')
        if "Enabled" not in out["stdout"]:
            pytest_assert(
                reboot_cause == UNKNOWN_REBOOT_CAUSE,
                "Reboot cause {} did not match the trigger {}".format(reboot_cause, UNKNOWN_REBOOT_CAUSE)
            )
        else:
            pytest_assert(
                reboot_cause == KERNEL_PANIC_REBOOT_CAUSE,
                "Reboot cause {} did not match the trigger {}".format(reboot_cause, KERNEL_PANIC_REBOOT_CAUSE)
            )


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_user_init_tsa(request, duthosts, localhost, nbrhosts, traffic_shift_community):
    """
    Initially, User initiates TSA on the DUT and saves the config on DUT.
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service starts automatically when dut comes up
    Verify this service doesn't configure another TSA and retains the existing TSA config on DUT
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    for linecard in frontend_nodes_per_hwsku:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, up_bgp_neighbors = dict(), dict()
    for linecard in frontend_nodes_per_hwsku:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(linecard.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in frontend_nodes_per_hwsku:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in frontend_nodes_per_hwsku:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_and_reboot_and_verify(lc):
            # Issue TSA on DUT
            lc.shell("TSA")
            lc.shell('sudo config save -y')

            # Reboot dut and wait for startup_tsa_tsb service to start
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)

            logger.info('Cold reboot finished on {}'.format(lc.hostname))
            dut_uptime = lc.get_up_time()
            logger.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Ensure startup_tsa_tsb service is in exited state after dut reboot
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not in exited state after reboot")

            # Verify DUT continues to be in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state with saved TSA config after reboot")

            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(lc)
            pytest_assert(wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc),
                          "Not all ports that are admin up on are operationally up")

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(run_tsa_and_reboot_and_verify, linecard)

        for linecard in frontend_nodes_per_hwsku:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

    finally:
        """
        Test TSB after config save and config reload
        Verify all routes are announced back to neighbors
        """
        def run_tsb_and_config_reload(lc):
            # Recover to Normal state
            lc.shell("TSB")
            lc.shell('sudo config save -y')
            config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(run_tsb_and_config_reload, linecard)

        # Verify DUT comes back to  normal state after TSB.
        for linecard in frontend_nodes_per_hwsku:
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard), "DUT is not in normal state")

        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)

        # Make sure the dut's reboot cause is as expected
        for linecard in frontend_nodes_per_hwsku:
            logger.info("Check reboot cause of the dut")
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))

        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)


@pytest.mark.disable_loganalyzer
def test_user_init_tsa_while_service_run_on_dut(request, duthosts, localhost, nbrhosts, traffic_shift_community):

    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer
    Issue TSA while the service is running on dut, and make sure the TSA is configured
    Make sure TSA_TSB service is stopped and dut continues to be in maintenance mode
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    for linecard in frontend_nodes_per_hwsku:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in frontend_nodes_per_hwsku:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(linecard.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in frontend_nodes_per_hwsku:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in frontend_nodes_per_hwsku:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def reboot_and_verify(lc):
            # Reboot dut and wait for startup_tsa_tsb service to start
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)

            logger.info('Cold reboot finished on {}'.format(lc.hostname))
            dut_uptime = lc.get_up_time()
            logger.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))

            # Ensure startup_tsa_tsb service is running after dut reboot
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, lc, 'running'),
                          "startup_tsa_tsb service is not started after reboot")

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(reboot_and_verify, linecard)

        def run_tsa_and_verify(lc):
            # Issue TSA on DUT
            lc.shell("TSA")
            lc.shell('sudo config save -y')

            # Ensure startup_tsa_tsb service is in inactive state after user-initiated TSA
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, lc, 'inactive'),
                          "startup_tsa_tsb service is not in inactive state after user init TSA")

            # Verify DUT continues to be in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state with saved TSA config after reboot")

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(run_tsa_and_verify, linecard)

        for linecard in frontend_nodes_per_hwsku:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

    finally:
        """
        Test TSB after config save and config reload
        Verify all routes are announced back to neighbors
        """
        # Recover to Normal state
        for linecard in frontend_nodes_per_hwsku:
            linecard.shell("TSB")
            linecard.shell('sudo config save -y')

        def config_reload_linecard_if_unhealthy(lc):
            # Verify DUT is in normal state after cold reboot scenario.
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Wait until all routes are announced to neighbors
        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)

        # Make sure the dut's reboot cause is as expected
        for linecard in frontend_nodes_per_hwsku:
            logger.info("Check reboot cause of the dut")
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))

        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)


@pytest.mark.disable_loganalyzer
def test_user_init_tsb_while_service_run_on_dut(request, duthosts, localhost, nbrhosts, traffic_shift_community):

    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer
    Issue TSB while the service is running on dut, and make sure the TSB is configured
    Make sure TSA_TSB service is stopped and dut continues to be in normal mode
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    for linecard in frontend_nodes_per_hwsku:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in frontend_nodes_per_hwsku:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(linecard.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in frontend_nodes_per_hwsku:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in duthosts.frontend_nodes:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def reboot_and_verify(lc):
            # Reboot dut and wait for startup_tsa_tsb service to start
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)

            logger.info('Cold reboot finished on {}'.format(lc.hostname))
            dut_uptime = lc.get_up_time()
            logger.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))

            # Ensure startup_tsa_tsb service is running after dut reboot
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, lc, 'running'),
                          "startup_tsa_tsb service is not started after reboot")

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(reboot_and_verify, linecard)

        def run_tsb_and_verify(lc):
            # Issue TSB on DUT
            lc.shell("TSB")
            lc.shell('sudo config save -y')

            # Verify DUT comes back to normal state after TSB.
            pytest_assert(TS_NORMAL == get_traffic_shift_state(lc), "DUT is not in normal state")

            # Ensure startup_tsa_tsb service is in inactive state after user-initiated TSB
            pytest_assert(wait_until(60, 5, 10, get_tsa_tsb_service_status, lc, 'inactive'),
                          "startup_tsa_tsb service is not in inactive state after user init TSB")

            # Make sure DUT continues to be in good state after TSB
            assert wait_until(300, 20, 2, lc.critical_services_fully_started), \
                "Not all critical services are fully started on {}".format(lc.hostname)
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(run_tsb_and_verify, linecard)

        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        def config_reload_linecard_if_unhealthy(lc):
            # Verify DUT is in normal state after cold reboot scenario.
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Make sure the dut's reboot cause is as expected
        for linecard in frontend_nodes_per_hwsku:
            logger.info("Check reboot cause of the dut")
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_user_init_tsb_on_sup_while_service_run_on_dut(duthosts, localhost, enum_supervisor_dut_hostname, nbrhosts,
                                                       traffic_shift_community):
    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer
    Issue TSB from supervisor, while the service is running on dut, and make sure the TSB is configured on linecards
    Make sure TSA_TSB service is stopped and dut changes from maintenance mode to normal mode
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    for linecard in duthosts.frontend_nodes:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(suphost.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in duthosts.frontend_nodes:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    service_up_times = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors before doing reboot
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Get a dut uptime before reboot
        sup_uptime_before = suphost.get_up_time()
        # Reboot dut and wait for startup_tsa_tsb service to start on linecards
        logger.info("Cold reboot on supervisor node: %s", suphost.hostname)
        reboot(suphost, localhost, wait=240)
        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(suphost)

        sup_uptime = suphost.get_up_time()
        logger.info('DUT {} up since {}'.format(suphost.hostname, sup_uptime))
        rebooted = float(sup_uptime_before.strftime("%s")) != float(sup_uptime.strftime("%s"))
        assert rebooted, "Device {} did not reboot".format(suphost.hostname)

        def verify_linecard_after_sup_reboot(lc):
            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 10, check_interface_status_of_up_ports, lc)
            with lock:
                service_up_times[lc] = service_uptime
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_reboot, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Issue user initiated TSB on the supervisor
        suphost.shell('TSB')

        def verify_linecard_after_sup_tsb(lc):
            if get_tsa_tsb_service_status(lc, 'running') and \
                    check_tsa_tsb_service_run_time_diff(service_up_times[lc], tsa_tsb_timer[lc]):
                # Verify DUT continues to be in maintenance state if the timer is running.
                pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                              "DUT is not in maintenance state when startup_tsa_tsb service is running")
            else:
                # Verify DUT continues came back to normal state after timer expiry.
                pytest_assert(TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats'),
                              "DUT is not in normal state when startup_tsa_tsb service is running")

            # Ensure startup_tsa_tsb service is in exited state after timer expiry
            pytest_assert(wait_until(tsa_tsb_timer[lc], 5, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not in exited state after user init TSB from supervisor")

            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                int_status_result[lc] = int_status_check_res

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsb, linecard)

        verify_route_on_neighbors(duthosts.frontend_nodes, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        # Make sure linecards are in Normal state and save the config to proceed further
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        for linecard in duthosts.frontend_nodes:
            # Make sure the dut's reboot cause is as expected
            logger.info("Check reboot cause of the dut {}".format(linecard))
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == SUP_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, SUP_REBOOT_CAUSE))

        # Make sure the Supervisor's reboot cause is as expected
        logger.info("Check reboot cause of the supervisor")
        reboot_cause = get_reboot_cause(suphost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_timer_efficiency(request, duthosts, localhost, nbrhosts, traffic_shift_community):
    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify the configured tsa_tsb_timer is sufficient for system to be stable
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired
    """
    frontend_nodes_per_hwsku = get_frontend_nodes_per_hwsku(duthosts, request)
    for linecard in frontend_nodes_per_hwsku:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in frontend_nodes_per_hwsku:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(linecard.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in frontend_nodes_per_hwsku:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in frontend_nodes_per_hwsku:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    orig_v4_routes, orig_v6_routes = dict(), dict()
    try:
        # Get all routes on neighbors before doing reboot
        for linecard in frontend_nodes_per_hwsku:
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def reboot_and_verify(lc):
            # Reboot dut and wait for startup_tsa_tsb service to start
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)

            logger.info('Cold reboot finished on {}'.format(lc.hostname))
            dut_uptime = lc.get_up_time()
            logger.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))

            # Ensure startup_tsa_tsb service is running after dut reboot
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, lc, 'running'),
                          "startup_tsa_tsb service is not started after reboot")

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            logging.info("Wait until all critical services are fully started")
            pytest_assert(wait_until(300, 20, 2, lc.critical_services_fully_started)), \
                "Not all critical services are fully started on {}".format(lc.hostname)

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"))

            stability_check_time = datetime.datetime.now()
            time_to_stabilize = (stability_check_time - service_uptime).total_seconds()
            logging.info("Time taken for system stability : {}".format(time_to_stabilize))

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Verify tsa_tsb_timer configured is sufficient
            pytest_assert(time_to_stabilize < tsa_tsb_timer[lc],
                          "Configured tsa_tsb_timer is not sufficient for the system to be stable")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_NORMAL == get_traffic_shift_state(lc),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(reboot_and_verify, linecard)

        verify_route_on_neighbors(frontend_nodes_per_hwsku, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        def config_reload_linecard_if_unhealthy(lc):
            # Verify DUT is in normal state after cold reboot scenario.
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in frontend_nodes_per_hwsku:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Make sure the dut's reboot cause is as expected
        for linecard in frontend_nodes_per_hwsku:
            logger.info("Check reboot cause of the dut")
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_tsa_on_sup(duthosts, localhost, enum_supervisor_dut_hostname, nbrhosts,
                                         traffic_shift_community):
    """
    Test startup TSA_TSB service after supervisor cold reboot with TSA enabled on supervisor
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer and maintains TSA once the timer is expired on linecards
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    for linecard in duthosts.frontend_nodes:
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    tsa_tsb_timer, int_status_result, crit_process_check, up_bgp_neighbors = dict(), dict(), dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(suphost.hostname))

        int_status_result[linecard] = True
        crit_process_check[linecard] = True

        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                      "DUT is not in normal state")

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    initial_tsa_check_before_and_after_test(duthosts)
    for linecard in duthosts.frontend_nodes:
        up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")

    try:
        # Execute user initiated TSA from supervisor card
        suphost.shell("TSA")
        suphost.shell('sudo config save -y')

        # Get a dut uptime before reboot
        sup_uptime_before = suphost.get_up_time()
        # Reboot dut and wait for startup_tsa_tsb service to start on linecards
        logger.info("Cold reboot on supervisor node: %s", suphost.hostname)
        reboot(suphost, localhost, wait=240)
        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(suphost)

        sup_uptime = suphost.get_up_time()
        logger.info('DUT {} up since {}'.format(suphost.hostname, sup_uptime))
        rebooted = float(sup_uptime_before.strftime("%s")) != float(sup_uptime.strftime("%s"))
        assert rebooted, "Device {} did not reboot".format(suphost.hostname)

        def verify_linecard_after_sup_reboot(lc):
            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service is running after dut reboot
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, lc, 'running'),
                          "startup_tsa_tsb service is not started after reboot")

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # Verify BGP sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up. No point in continuing the test")
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_reboot, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        def further_verify_linecard(lc):
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to maintenance state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify TSA is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(lc),
                              "DUT is not in maintenance state after startup_tsa_tsb service is stopped")
                assert_only_loopback_routes_announced_to_neighs(duthosts, lc, dut_nbrhosts[lc],
                                                                traffic_shift_community,
                                                                "Failed to verify routes on nbr in TSA")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(further_verify_linecard, linecard)

    finally:
        # Bring back the supervisor and line cards to the BGP operational normal state
        initial_tsa_check_before_and_after_test(duthosts)

        # Make sure linecards are in Normal state and save the config to proceed further
        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and TS_NORMAL == get_traffic_shift_state(lc)):
                logger.info(
                    "DUT's current interface status is {}, critical process check is {} "
                    "or traffic shift state is not {}".format(
                        int_status_result[lc],
                        crit_process_check[lc],
                        TS_NORMAL,
                    )
                )

                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True)

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        for linecard in duthosts.frontend_nodes:
            # Make sure the dut's reboot cause is as expected
            logger.info("Check reboot cause of the dut {}".format(linecard))
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == SUP_REBOOT_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, SUP_REBOOT_CAUSE))

        # Make sure the Supervisor's reboot cause is as expected
        logger.info("Check reboot cause of the supervisor")
        reboot_cause = get_reboot_cause(suphost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))
