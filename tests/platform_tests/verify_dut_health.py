import copy
import pytest
import logging
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.transceiver_utils import parse_transceiver_info
from tests.common.reboot import reboot, REBOOT_TYPE_COLD

test_report = dict()


def handle_test_error(health_check):
    def _wrapper(*args, **kwargs):
        try:
            health_check(*args, **kwargs)
        except RebootHealthError as err:
            # set result to fail
            logging.error("Health check {} failed with {}".format(health_check.__name__, err.message))
            test_report[health_check.__name__] = err.message
            return
        except Exception as err:
            traceback.print_exc()
            logging.error("Health check {} failed with unknown error: {}".format(health_check.__name__, str(err)))
            test_report[health_check.__name__] = "Unkown error"
            return
        # set result to pass
        test_report[health_check.__name__] = True
    return _wrapper


@handle_test_error
def check_services(duthost):
    """
    Perform a health check of services
    """
    logging.info("Wait until all critical services are fully started")
    # Wait until 300 seconds after boot up since a part of the services has delayed start (e.g., snmp)
    wait_until_uptime(duthost, 300)

    logging.info("Check critical service status")
    if not duthost.critical_services_fully_started():
        raise RebootHealthError("dut.critical_services_fully_started is False")

    for service in duthost.critical_services:
        status = duthost.get_service_props(service)
        if status["ActiveState"] != "active":
            raise RebootHealthError("ActiveState of {} is {}, expected: active".format(service, status["ActiveState"]))
        if status["SubState"] != "running":
            raise RebootHealthError("SubState of {} is {}, expected: running".format(service, status["SubState"]))


@handle_test_error
def check_interfaces_and_transceivers(duthost, request):
    """
    Perform a check of transceivers, LAGs and interfaces status
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    """
    logging.info("Check if all the interfaces are operational")
    check_interfaces = request.getfixturevalue("check_interfaces")
    conn_graph_facts = request.getfixturevalue("conn_graph_facts")
    results = check_interfaces()
    failed = [result for result in results if "failed" in result and result["failed"]]
    if failed:
        raise RebootHealthError("Interface check failed, not all interfaces are up. Failed: {}".format(failed))

    # Skip this step for virtual testbed - KVM testbed has transeivers marked as "Not present"
    # and the DB returns an "empty array" for "keys TRANSCEIVER_INFO*"
    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        return

    logging.info("Check whether transceiver information of all ports are in redis")
    xcvr_info = duthost.command("redis-cli -n 6 keys TRANSCEIVER_INFO*")
    parsed_xcvr_info = parse_transceiver_info(xcvr_info["stdout_lines"])
    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    for intf in interfaces:
        if intf not in parsed_xcvr_info:
            raise RebootHealthError("TRANSCEIVER INFO of {} is not found in DB".format(intf))


@handle_test_error
def check_neighbors(duthost, tbinfo):
    """
    Perform a BGP neighborship check.
    """
    logging.info("Check BGP neighbors status. Expected state - established")
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    mg_facts  = duthost.get_extended_minigraph_facts(tbinfo)

    for value in bgp_facts['bgp_neighbors'].values():
        # Verify bgp sessions are established
        if value['state'] != 'established':
            raise RebootHealthError("BGP session not established")
        # Verify locat ASNs in bgp sessions
        if(value['local AS'] != mg_facts['minigraph_bgp_asn']):
            raise RebootHealthError("Local ASNs not found in BGP session.\
                Minigraph: {}. Found {}".format(value['local AS'], mg_facts['minigraph_bgp_asn']))
    for v in mg_facts['minigraph_bgp']:
        # Compare the bgp neighbors name with minigraph bgp neigbhors name
        if(v['name'] != bgp_facts['bgp_neighbors'][v['addr'].lower()]['description']):
            raise RebootHealthError("BGP neighbor's name does not match minigraph.\
                Minigraph: {}. Found {}".format(v['name'], bgp_facts['bgp_neighbors'][v['addr'].lower()]['description']))
        # Compare the bgp neighbors ASN with minigraph
        if(v['asn'] != bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS']):
            raise RebootHealthError("BGP neighbor's ASN does not match minigraph.\
                Minigraph: {}. Found {}".format(v['asn'], bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS']))


@handle_test_error
def verify_no_coredumps(duthost, pre_existing_cores):
    if "20191130" in duthost.os_version:
        coredumps_count = duthost.shell('ls /var/core/ | grep -v python | wc -l')['stdout']
    else:
        coredumps_count = duthost.shell('ls /var/core/ | wc -l')['stdout']
    if int(coredumps_count) > int(pre_existing_cores):
        raise RebootHealthError("Core dumps found. Expected: {} Found: {}".format(pre_existing_cores,\
            coredumps_count))


def wait_until_uptime(duthost, post_reboot_delay):
    logging.info("Wait until DUT uptime reaches {}s".format(post_reboot_delay))
    while duthost.get_uptime().total_seconds() < post_reboot_delay:
        time.sleep(1)


def get_test_report():
    global test_report
    result = copy.deepcopy(test_report)
    test_report = dict()
    return result


@pytest.fixture
def verify_dut_health(request, duthosts, rand_one_dut_hostname, tbinfo):
    global test_report
    test_report = {}
    duthost = duthosts[rand_one_dut_hostname]
    check_services(duthost)
    check_interfaces_and_transceivers(duthost, request)
    check_neighbors(duthost, tbinfo)
    if "20191130" in duthost.os_version:
        pre_existing_cores = duthost.shell('ls /var/core/ | grep -v python | wc -l')['stdout']
    else:
        pre_existing_cores = duthost.shell('ls /var/core/ | wc -l')['stdout']
    pytest_assert(all(list(test_report.values())), "DUT not ready for test. Health check failed before reboot: {}"
        .format(test_report))

    yield

    test_report = {}
    check_services(duthost)
    check_interfaces_and_transceivers(duthost, request)
    check_neighbors(duthost, tbinfo)
    verify_no_coredumps(duthost, pre_existing_cores)
    check_all = all([check == True for check in list(test_report.values())])
    pytest_assert(check_all, "Health check failed after reboot: {}"
        .format(test_report))


@pytest.fixture
def add_fail_step_to_reboot(localhost, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    def add_exit_to_script(reboot_type):
        add_exit_to_script.params = tuple()
        if "warm" in reboot_type:
            reboot_script = "warm-reboot"
        elif "fast" in reboot_type:
            reboot_script = "fast-reboot"

        cmd_format = "sed -i -u 's/{}/{}/' {}"
        reboot_script_path = duthost.shell('which {}'.format(reboot_script))['stdout']
        original_line = '^setup_control_plane_assistant$'
        replaced_line = 'exit -1; setup_control_plane_assistant'
        replace_cmd = cmd_format.format(original_line, replaced_line, reboot_script_path)
        logging.info("Modify {} to exit before set +e".format(reboot_script_path))
        duthost.shell(replace_cmd)
        add_exit_to_script.params = (cmd_format, replaced_line, original_line, reboot_script_path, reboot_script_path)

    yield add_exit_to_script

    if add_exit_to_script.params:
        cmd_format, replaced_line, original_line, reboot_script_path, reboot_script_path = add_exit_to_script.params
        replace_cmd = cmd_format.format(replaced_line, "setup_control_plane_assistant", reboot_script_path)
        logging.info("Revert {} script to original".format(reboot_script_path))
        duthost.shell(replace_cmd)
    # cold reboot DUT to restore any bad state caused by negative test
    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD)


class RebootHealthError(Exception):
    def __init__(self, message):
        self.message = message
        super(RebootHealthError, self).__init__(message)
