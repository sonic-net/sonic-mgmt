import logging
import datetime
import pexpect

import pytest

from tests.common import reboot, config_reload
from tests.common.reboot import get_reboot_cause, SONIC_SSH_PORT, SONIC_SSH_REGEX, wait_for_startup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.bgp.test_traffic_shift import get_traffic_shift_state, parse_routes_on_neighbors,\
    check_tsa_persistence_support, verify_current_routes_announced_to_neighs, check_and_log_routes_diff, \
    verify_only_loopback_routes_are_announced_to_neighs

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

TS_NORMAL = "System Mode: Normal"
TS_MAINTENANCE = "System Mode: Maintenance"
TS_INCONSISTENT = "System Mode: Not consistent"
TS_NO_NEIGHBORS = "System Mode: No external neighbors"
COLD_REBOOT_CAUSE = 'cold'
UNKNOWN_REBOOT_CAUSE = "Unknown"
SUP_REBOOT_CAUSE = 'Reboot from Supervisor'
SUP_HEARTBEAT_LOSS_CAUSE = 'Heartbeat with the Supervisor card lost'
SSH_SHUTDOWN_TIMEOUT = 480
SSH_STARTUP_TIMEOUT = 600

SSH_STATE_ABSENT = "absent"
SSH_STATE_STARTED = "started"


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
        logger.warn("{} file does not exist in the specified path on dut {}".
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
            tmp_time = line.split('since')[1].strip().encode('utf-8')
            act_time = tmp_time.split('UTC')[0].strip().encode('utf-8')
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


def exec_tsa_tsb_cmd_on_supervisor(duthosts, enum_supervisor_dut_hostname, creds, tsa_tsb_cmd):
    """
    @summary: Issue TSA/TSB command on supervisor card using user credentials
    Verify command is executed on supervisor card
    @returns: None
    """
    try:
        suphost = duthosts[enum_supervisor_dut_hostname]
        sup_ip = suphost.mgmt_ip
        sonic_username = creds['sonicadmin_user']
        sonic_password = creds['sonicadmin_password']
        logger.info('sonic-username: {}, sonic_password: {}'.format(sonic_username, sonic_password))
        ssh_cmd = "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no {}@{}".format(sonic_username, sup_ip)
        connect = pexpect.spawn(ssh_cmd)
        connect.expect('.*[Pp]assword:')
        connect.sendline(sonic_password)
        i = connect.expect('{}@{}:'.format(sonic_username, suphost.hostname), timeout=10)
        pytest_assert(i == 0, "Failed to connect")
        connect.sendline(tsa_tsb_cmd)
        connect.expect('.*[Pp]assword for username \'{}\':'.format(sonic_username))
        connect.sendline(sonic_password)
        j = connect.expect('{}@{}:'.format(sonic_username, suphost.hostname), timeout=10)
        pytest_assert(j == 0, "Failed to connect")
    except pexpect.exceptions.EOF:
        pytest.fail("EOF reached")
    except pexpect.exceptions.TIMEOUT:
        pytest.fail("Timeout reached")
    except Exception as e:
        pytest.fail("Cannot connect to DUT {} host via SSH: {}".format(suphost.hostname, e))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_dut_cold_reboot(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                                              nbrhosts, traffic_shift_community, tbinfo):
    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    tsa_tsb_timer = get_startup_tsb_timer(duthost)
    if not tsa_tsb_timer:
        pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(duthost.hostname))
    dut_nbrhosts = nbrhosts_to_dut(duthost, nbrhosts)
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing reboot
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

        # Reboot dut and wait for startup_tsa_tsb service to start
        logger.info("Cold reboot on node: %s", duthost.hostname)
        reboot(duthost, localhost, wait=240)

        logger.info('Cold reboot finished on {}'.format(duthost.hostname))
        dut_uptime = duthost.get_up_time()
        logger.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))

        # Ensure startup_tsa_tsb service is running after dut reboot
        pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, duthost, 'running'),
                      "startup_tsa_tsb service is not started after reboot")

        # Ensure startup_tsa_tsb service started on expected time since dut rebooted
        dut_uptime = duthost.get_up_time()
        logging.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))
        service_uptime = get_tsa_tsb_service_uptime(duthost)
        time_diff = (service_uptime - dut_uptime).total_seconds()
        pytest_assert(int(time_diff) < 120,
                      "startup_tsa_tsb service started much later than the expected time after dut reboot")

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state when startup_tsa_tsb service is running")

        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(duthost)
        pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
            duthosts, duthost, dut_nbrhosts, traffic_shift_community), "Failed to verify routes on nbr in TSA")

        # Verify startup_tsa_tsb service stopped after expected time
        pytest_assert(wait_until(tsa_tsb_timer, 20, 0, get_tsa_tsb_service_status, duthost, 'exited'),
                      "startup_tsa_tsb service is not stopped even after configured timer expiry")

        # Ensure dut comes back to normal state after timer expiry
        if not get_tsa_tsb_service_status(duthost, 'running'):
            # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
            pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                          "DUT is not in normal state after startup_tsa_tsb service is stopped")

        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")

    finally:

        # Verify DUT is in normal state.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                      "DUT is not in normal state")
        # Make sure the dut's reboot cause is as expected
        logger.info("Check reboot cause of the dut")
        reboot_cause = get_reboot_cause(duthost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_dut_abnormal_reboot(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname,
                                                  ptfhost, nbrhosts, traffic_shift_community, tbinfo):
    """
    Test startup TSA_TSB service after DUT abnormal reboot/crash
    Verify startup_tsa_tsb.service started automatically when dut comes up after crash
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    tsa_tsb_timer = get_startup_tsb_timer(duthost)
    if not tsa_tsb_timer:
        pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(duthost.hostname))
    dut_nbrhosts = nbrhosts_to_dut(duthost, nbrhosts)
    dut_ip = duthost.mgmt_ip
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing reboot
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

        # Our shell command is designed as 'nohup bash -c "sleep 5 && tail /dev/zero" &' because of:
        #  * `tail /dev/zero` is used to run out of memory completely.
        #  * Since `tail /dev/zero` will cause the DUT reboot, we need to run it in the background
        #    (using &) to avoid pytest getting stuck. `nohup` is also necessary to protect the
        #    background process.
        #  * Some DUTs with few free memory may reboot before ansible receive the result of shell
        #    command, so we add `sleep 5` to ensure ansible receive the result first.
        cmd = 'nohup bash -c "sleep 5 && tail /dev/zero" &'
        res = duthost.shell(cmd)
        if not res.is_successful:
            pytest.fail('DUT {} run command {} failed'.format(duthost.hostname, cmd))

        # Waiting for SSH connection shutdown
        pytest_assert(check_ssh_state(localhost, dut_ip, SSH_STATE_ABSENT, SSH_SHUTDOWN_TIMEOUT),
                      'DUT {} did not shutdown'.format(duthost.hostname))
        # Waiting for SSH connection startup
        pytest_assert(check_ssh_state(localhost, dut_ip, SSH_STATE_STARTED, SSH_STARTUP_TIMEOUT),
                      'DUT {} did not startup'.format(duthost.hostname))

        # Ensure startup_tsa_tsb service is running after dut reboot
        pytest_assert(wait_until(90, 5, 0, get_tsa_tsb_service_status, duthost, 'running'),
                      "startup_tsa_tsb service is not started after reboot")

        # Ensure startup_tsa_tsb service started on expected time since dut rebooted
        dut_uptime = duthost.get_up_time()
        logging.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))
        service_uptime = get_tsa_tsb_service_uptime(duthost)
        time_diff = (service_uptime - dut_uptime).total_seconds()
        logger.info("Time difference between dut up-time & tsa_tsb_service up-time is {}".format(int(time_diff)))
        pytest_assert(int(time_diff) < 120,
                      "startup_tsa_tsb service started much later than the expected time after dut reboot")

        # Make sure BGP containers are running properly before verifying
        pytest_assert(wait_until(90, 5, 0, check_tsc_command_error, duthost),
                      "TSC command still returns error even after startup_tsa_tsb service started")

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state when startup_tsa_tsb service is running")

        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(duthost)
        pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
            duthosts, duthost, dut_nbrhosts, traffic_shift_community), "Failed to verify routes on nbr in TSA")

        # Verify startup_tsa_tsb service stopped after expected time
        pytest_assert(wait_until(tsa_tsb_timer, 20, 0, get_tsa_tsb_service_status, duthost, 'exited'),
                      "startup_tsa_tsb service is not stopped even after configured timer expiry")

        # Ensure dut comes back to normal state after timer expiry
        if not get_tsa_tsb_service_status(duthost, 'running'):
            # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
            pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                          "DUT is not in normal state after startup_tsa_tsb service is stopped")

        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")

    finally:

        # Verify DUT is in normal state.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                      "DUT is not in normal state")
        # Make sure the dut's reboot cause is as expected
        logger.info("Check reboot cause of the dut")
        reboot_cause = get_reboot_cause(duthost)
        pytest_assert(reboot_cause == UNKNOWN_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, UNKNOWN_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_supervisor_cold_reboot(duthosts, localhost, enum_supervisor_dut_hostname, ptfhost,
                                                     nbrhosts, traffic_shift_community, tbinfo):
    """
    Test startup TSA_TSB service after supervisor cold reboot
    Verify startup_tsa_tsb.service started automatically on all linecards when they comes up
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired on linecards
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    tsa_tsb_timer = dict()
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(suphost.hostname))
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                      "DUT is not in normal state")
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

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

        for linecard in duthosts.frontend_nodes:
            wait_for_startup(linecard, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = linecard.get_up_time()
            logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(linecard)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 120,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(linecard)
            pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, linecard),
                          "Not all ports that are admin up on are operationally up")

            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

        # Once all line cards are in maintenance state, proceed further
        for linecard in duthosts.frontend_nodes:
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(linecard, 'running'):
                # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")

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

    finally:
        for linecard in duthosts.frontend_nodes:
            # Verify DUT is in normal state.
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                          "DUT {} is not in normal state".format(linecard))
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
def test_tsa_tsb_service_with_supervisor_abnormal_reboot(duthosts, localhost, enum_supervisor_dut_hostname, ptfhost,
                                                         nbrhosts, traffic_shift_community, tbinfo):
    """
    Test startup TSA_TSB service after supervisor abnormal reboot
    Verify startup_tsa_tsb.service started automatically on all linecards when they come up
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired on linecards
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    sup_ip = suphost.mgmt_ip
    tsa_tsb_timer = dict()
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(suphost.hostname))
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                      "DUT is not in normal state")
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

    try:
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors before doing reboot
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

        for linecard in duthosts.frontend_nodes:
            wait_for_startup(linecard, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = linecard.get_up_time()
            logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(linecard)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 120,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(linecard)
            pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, linecard),
                          "Not all ports that are admin up on are operationally up")

            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

        # Once all line cards are in maintenance state, proceed further
        for linecard in duthosts.frontend_nodes:
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[linecard], 20, 0, get_tsa_tsb_service_status, linecard, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(linecard, 'running'):
                # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
                pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")

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

    finally:
        for linecard in duthosts.frontend_nodes:
            # Verify DUT is in normal state.
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                          "DUT {} is not in normal state".format(linecard))
            # Make sure the dut's reboot cause is as expected
            logger.info("Check reboot cause of the dut {}".format(linecard))
            reboot_cause = get_reboot_cause(linecard)
            pytest_assert(reboot_cause == SUP_HEARTBEAT_LOSS_CAUSE,
                          "Reboot cause {} did not match the trigger {}".format(reboot_cause, SUP_HEARTBEAT_LOSS_CAUSE))

        # Make sure the Supervisor's reboot cause is as expected
        logger.info("Check reboot cause of the supervisor")
        reboot_cause = get_reboot_cause(suphost)
        pytest_assert(reboot_cause == UNKNOWN_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, UNKNOWN_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_tsa_tsb_service_with_user_init_tsa(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                                            nbrhosts, traffic_shift_community, tbinfo):
    """
    Initially, User initiates TSA on the DUT and saves the config on DUT.
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service starts automatically when dut comes up
    Verify this service doesn't configure another TSA and retains the existing TSA config on DUT
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    tsa_tsb_timer = get_startup_tsb_timer(duthost)
    if not tsa_tsb_timer:
        pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(duthost.hostname))
    dut_nbrhosts = nbrhosts_to_dut(duthost, nbrhosts)
    orig_v4_routes, orig_v6_routes = {}, {}
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing reboot
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

        # Issue TSA on DUT
        duthost.shell("TSA")
        duthost.shell('sudo config save -y')

        # Reboot dut and wait for startup_tsa_tsb service to start
        logger.info("Cold reboot on node: %s", duthost.hostname)
        reboot(duthost, localhost, wait=240)

        logger.info('Cold reboot finished on {}'.format(duthost.hostname))
        dut_uptime = duthost.get_up_time()
        logger.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))

        # Ensure startup_tsa_tsb service started on expected time since dut rebooted
        dut_uptime = duthost.get_up_time()
        logging.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))
        service_uptime = get_tsa_tsb_service_uptime(duthost)
        time_diff = (service_uptime - dut_uptime).total_seconds()
        pytest_assert(int(time_diff) < 120,
                      "startup_tsa_tsb service started much later than the expected time after dut reboot")

        # Ensure startup_tsa_tsb service is in exited state after dut reboot
        pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, duthost, 'exited'),
                      "startup_tsa_tsb service is not in exited state after reboot")

        # Verify DUT continues to be in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state with saved TSA config after reboot")

        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(duthost)
        pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
            duthosts, duthost, dut_nbrhosts, traffic_shift_community),
            "Failed to verify routes on nbr in TSA")

    finally:
        """
        Test TSB after config save and config reload
        Verify all routes are announced back to neighbors
        """
        # Recover to Normal state
        duthost.shell("TSB")
        duthost.shell('sudo config save -y')
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

        # Verify DUT comes back to  normal state after TSB.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")
        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")

        # Make sure the dut's reboot cause is as expected
        logger.info("Check reboot cause of the dut")
        reboot_cause = get_reboot_cause(duthost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_user_init_tsa_while_service_run_on_dut(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                                                nbrhosts, traffic_shift_community, tbinfo):

    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer
    Issue TSA while the service is running on dut, and make sure the TSA is configured
    Make sure TSA_TSB service is stopped and dut continues to be in maintenance mode
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    tsa_tsb_timer = get_startup_tsb_timer(duthost)
    if not tsa_tsb_timer:
        pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(duthost.hostname))
    dut_nbrhosts = nbrhosts_to_dut(duthost, nbrhosts)
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing reboot
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

        # Reboot dut and wait for startup_tsa_tsb service to start
        logger.info("Cold reboot on node: %s", duthost.hostname)
        reboot(duthost, localhost, wait=240)

        logger.info('Cold reboot finished on {}'.format(duthost.hostname))
        dut_uptime = duthost.get_up_time()
        logger.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))

        # Ensure startup_tsa_tsb service is running after dut reboot
        pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, duthost, 'running'),
                      "startup_tsa_tsb service is not started after reboot")

        # Ensure startup_tsa_tsb service started on expected time since dut rebooted
        dut_uptime = duthost.get_up_time()
        logging.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))
        service_uptime = get_tsa_tsb_service_uptime(duthost)
        time_diff = (service_uptime - dut_uptime).total_seconds()
        pytest_assert(int(time_diff) < 120,
                      "startup_tsa_tsb service started much later than the expected time after dut reboot")

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state when startup_tsa_tsb service is running")

        # Issue TSA on DUT
        duthost.shell("TSA")
        duthost.shell('sudo config save -y')

        # Ensure startup_tsa_tsb service is in inactive state after user-initiated TSA
        pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, duthost, 'inactive'),
                      "startup_tsa_tsb service is not in inactive state after user init TSA")

        # Verify DUT continues to be in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state with saved TSA config after reboot")

        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(duthost)
        pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

        pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
            duthosts, duthost, dut_nbrhosts, traffic_shift_community),
            "Failed to verify routes on nbr in TSA")

    finally:
        """
        Test TSB after config save and config reload
        Verify all routes are announced back to neighbors
        """
        # Recover to Normal state
        duthost.shell("TSB")
        duthost.shell('sudo config save -y')

        # Verify DUT comes back to  normal state after TSB.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")
        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")

        # Make sure the dut's reboot cause is as expected
        logger.info("Check reboot cause of the dut")
        reboot_cause = get_reboot_cause(duthost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_user_init_tsb_while_service_run_on_dut(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                                                nbrhosts, traffic_shift_community, tbinfo):

    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer
    Issue TSB while the service is running on dut, and make sure the TSB is configured
    Make sure TSA_TSB service is stopped and dut continues to be in normal mode
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    tsa_tsb_timer = get_startup_tsb_timer(duthost)
    if not tsa_tsb_timer:
        pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(duthost.hostname))
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing reboot
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

        # Reboot dut and wait for startup_tsa_tsb service to start
        logger.info("Cold reboot on node: %s", duthost.hostname)
        reboot(duthost, localhost, wait=240)

        logger.info('Cold reboot finished on {}'.format(duthost.hostname))
        dut_uptime = duthost.get_up_time()
        logger.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))

        # Ensure startup_tsa_tsb service is running after dut reboot
        pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, duthost, 'running'),
                      "startup_tsa_tsb service is not started after reboot")

        # Ensure startup_tsa_tsb service started on expected time since dut rebooted
        dut_uptime = duthost.get_up_time()
        logging.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))
        service_uptime = get_tsa_tsb_service_uptime(duthost)
        time_diff = (service_uptime - dut_uptime).total_seconds()
        pytest_assert(int(time_diff) < 120,
                      "startup_tsa_tsb service started much later than the expected time after dut reboot")

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state when startup_tsa_tsb service is running")

        # Issue TSB on DUT
        duthost.shell("TSB")
        duthost.shell('sudo config save -y')

        # Verify DUT comes back to normal state after TSB.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost), "DUT is not in normal state")

        # Ensure startup_tsa_tsb service is in inactive state after user-initiated TSB
        pytest_assert(wait_until(60, 5, 10, get_tsa_tsb_service_status, duthost, 'inactive'),
                      "startup_tsa_tsb service is not in inactive state after user init TSB")

        # Make sure DUT continues to be in good state after TSB
        assert wait_until(300, 20, 2, duthost.critical_services_fully_started), \
            "Not all critical services are fully started on {}".format(duthost.hostname)

        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")

    finally:

        # Verify DUT is in normal state.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                      "DUT is not in normal state")

        # Make sure the dut's reboot cause is as expected
        logger.info("Check reboot cause of the dut")
        reboot_cause = get_reboot_cause(duthost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))


@pytest.mark.disable_loganalyzer
def test_user_init_tsb_on_sup_while_service_run_on_dut(duthosts, localhost,
                                                       enum_supervisor_dut_hostname, ptfhost, nbrhosts,
                                                       traffic_shift_community, creds, tbinfo):
    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify startup_tsa_tsb.service started automatically when dut comes up
    Verify this service configures TSA and starts a timer
    Issue TSB from supervisor, while the service is running on dut, and make sure the TSB is configured on linecards
    Make sure TSA_TSB service is stopped and dut changes from maintenance mode to normal mode
    """
    tsa_tsb_cmd = 'sudo TSB'
    suphost = duthosts[enum_supervisor_dut_hostname]
    tsa_tsb_timer = dict()
    dut_nbrhosts = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        if not tsa_tsb_timer[linecard]:
            pytest.skip("startup_tsa_tsb.service is not supported on the duts under {}".format(suphost.hostname))
        dut_nbrhosts[linecard] = nbrhosts_to_dut(linecard, nbrhosts)
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                      "DUT is not in normal state")
        if not check_tsa_persistence_support(linecard):
            pytest.skip("TSA persistence not supported in the image")

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

        for linecard in duthosts.frontend_nodes:
            wait_for_startup(linecard, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = linecard.get_up_time()
            logging.info('DUT {} up since {}'.format(linecard.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(linecard)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 120,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in maintenance state.
            pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(linecard),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")

            logging.info("Wait until all critical processes are fully started")
            wait_critical_processes(linecard)

            pytest_assert(verify_only_loopback_routes_are_announced_to_neighs(
                duthosts, linecard, dut_nbrhosts[linecard], traffic_shift_community),
                "Failed to verify routes on nbr in TSA")

        # Execute user initiated TSB from supervisor card
        exec_tsa_tsb_cmd_on_supervisor(duthosts, enum_supervisor_dut_hostname, creds, tsa_tsb_cmd)

        for linecard in duthosts.frontend_nodes:
            # Ensure dut comes back to normal state
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                          "DUT is not in normal state after TSB command from supervisor")

            # Ensure startup_tsa_tsb service is in inactive state after user-initiated TSB on supervisor
            pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, linecard, 'inactive'),
                          "startup_tsa_tsb service is not in inactive state after user init TSB from supervisor")

            pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, linecard),
                          "Not all ports that are admin up on are operationally up")

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

    finally:
        for linecard in duthosts.frontend_nodes:
            # Make sure linecards are in Normal state and save the config to proceed further
            linecard.shell("TSB")
            linecard.shell('sudo config save -y')
            # Verify DUT is in normal state.
            pytest_assert(TS_NORMAL == get_traffic_shift_state(linecard),
                          "DUT {} is not in normal state".format(linecard))
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
def test_tsa_tsb_timer_efficiency(duthosts, localhost, enum_rand_one_per_hwsku_frontend_hostname, ptfhost,
                                  nbrhosts, traffic_shift_community, tbinfo):
    """
    Test startup TSA_TSB service after DUT cold reboot
    Verify the configured tsa_tsb_timer is sufficient for system to be stable
    Verify this service configures TSA and starts a timer and configures TSB once the timer is expired
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    tsa_tsb_timer = get_startup_tsb_timer(duthost)
    if not tsa_tsb_timer:
        pytest.skip("startup_tsa_tsb.service is not supported on the {}".format(duthost.hostname))
    # Ensure that the DUT is not in maintenance already before start of the test
    pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                  "DUT is not in normal state")
    if not check_tsa_persistence_support(duthost):
        pytest.skip("TSA persistence not supported in the image")

    try:
        # Get all routes on neighbors before doing reboot
        orig_v4_routes = parse_routes_on_neighbors(duthost, nbrhosts, 4)
        orig_v6_routes = parse_routes_on_neighbors(duthost, nbrhosts, 6)

        up_bgp_neighbors = duthost.get_bgp_neighbors_per_asic("established")

        # Reboot dut and wait for startup_tsa_tsb service to start
        logger.info("Cold reboot on node: %s", duthost.hostname)
        reboot(duthost, localhost, wait=240)

        logger.info('Cold reboot finished on {}'.format(duthost.hostname))
        dut_uptime = duthost.get_up_time()
        logger.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))

        # Ensure startup_tsa_tsb service is running after dut reboot
        pytest_assert(wait_until(60, 5, 0, get_tsa_tsb_service_status, duthost, 'running'),
                      "startup_tsa_tsb service is not started after reboot")

        # Ensure startup_tsa_tsb service started on expected time since dut rebooted
        dut_uptime = duthost.get_up_time()
        logging.info('DUT {} up since {}'.format(duthost.hostname, dut_uptime))
        service_uptime = get_tsa_tsb_service_uptime(duthost)
        time_diff = (service_uptime - dut_uptime).total_seconds()
        pytest_assert(int(time_diff) < 120,
                      "startup_tsa_tsb service started much later than the expected time after dut reboot")

        logging.info("Wait until all critical services are fully started")
        pytest_assert(wait_until(300, 20, 2, duthost.critical_services_fully_started)), \
            "Not all critical services are fully started on {}".format(duthost.hostname)

        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(duthost)
        pytest_assert(wait_until(600, 20, 0, check_interface_status_of_up_ports, duthost),
                      "Not all ports that are admin up on are operationally up")

        pytest_assert(wait_until(300, 10, 0,
                                 duthost.check_bgp_session_state_all_asics, up_bgp_neighbors, "established"))

        stability_check_time = datetime.datetime.now()
        time_to_stabilize = (stability_check_time - service_uptime).total_seconds()
        logging.info("Time taken for system stability : {}".format(time_to_stabilize))

        # Verify DUT is in maintenance state.
        pytest_assert(TS_MAINTENANCE == get_traffic_shift_state(duthost),
                      "DUT is not in maintenance state when startup_tsa_tsb service is running")

        # Verify startup_tsa_tsb service stopped after expected time
        pytest_assert(wait_until(tsa_tsb_timer, 20, 0, get_tsa_tsb_service_status, duthost, 'exited'),
                      "startup_tsa_tsb service is not stopped even after configured timer expiry")

        # Verify tsa_tsb_timer configured is sufficient
        pytest_assert(time_to_stabilize < tsa_tsb_timer,
                      "Configured tsa_tsb_timer is not sufficient for the system to be stable")

        # Ensure dut comes back to normal state after timer expiry
        if not get_tsa_tsb_service_status(duthost, 'running'):
            # Verify TSB is configured on the dut after startup_tsa_tsb service is stopped
            pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                          "DUT is not in normal state after startup_tsa_tsb service is stopped")

        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v4_routes, cur_v4_routes, 4):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v4_routes, cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, duthost, nbrhosts,
                          orig_v6_routes, cur_v6_routes, 6):
            if not check_and_log_routes_diff(duthost, nbrhosts, orig_v6_routes, cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")

    finally:

        # Verify DUT is in normal state.
        pytest_assert(TS_NORMAL == get_traffic_shift_state(duthost),
                      "DUT is not in normal state")
        # Make sure the dut's reboot cause is as expected
        logger.info("Check reboot cause of the dut")
        reboot_cause = get_reboot_cause(duthost)
        pytest_assert(reboot_cause == COLD_REBOOT_CAUSE,
                      "Reboot cause {} did not match the trigger {}".format(reboot_cause, COLD_REBOOT_CAUSE))
