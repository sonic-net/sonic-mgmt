import re
import time
import logging
import pytest
import traceback
import os
import json
import glob
import http.client
from datetime import datetime
from collections import OrderedDict
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_ports import encode_dut_port_name
from tests.common.platform.transceiver_utils import parse_transceiver_info
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.broadcom_data import is_broadcom_device
from tests.common.mellanox_data import is_mellanox_device
from tests.common.platform.reboot_timing_constants import SERVICE_PATTERNS, OTHER_PATTERNS, SAIREDIS_PATTERNS, \
    OFFSET_ITEMS, TIME_SPAN_ITEMS, REQUIRED_PATTERNS
from tests.common.devices.duthosts import DutHosts
from tests.common.plugins.ansible_fixtures import ansible_adhoc  # noqa: F401

"""
Helper script for fanout switch operations
"""

logger = logging.getLogger(__name__)


LOGS_ON_TMPFS_PLATFORMS = [
    "x86_64-arista_7050_qx32",
    "x86_64-arista_7050_qx32s",
    "x86_64-arista_7060_cx32s",
    "x86_64-arista_7260cx3_64",
    "x86_64-arista_7050cx3_32s",
    "x86_64-mlnx_msn2700-r0",
    "x86_64-dell_s6100_c2538-r0",
    "armhf-nokia_ixs7215_52x-r0"
]

MGFX_HWSKU = ["Arista-720DT-G48S4", "Nokia-7215", "Nokia-M0-7215", "Celestica-E1031-T48S4"]
MGFX_XCVR_INTF = ['Ethernet48', 'Ethernet49', 'Ethernet50', 'Ethernet51']

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")

FMT = "%b %d %H:%M:%S.%f"
FMT_YEAR = "%Y %b %d %H:%M:%S.%f"
FMT_SHORT = "%b %d %H:%M:%S"
FMT_ALT = "%Y-%m-%dT%H:%M:%S.%f%z"

SERVER_FILE = 'platform_api_server.py'
SERVER_PORT = 8000
IPTABLES_PREPEND_RULE_CMD = 'iptables -I INPUT 1 -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)
IP6TABLES_PREPEND_RULE_CMD = 'ip6tables -I INPUT 1 -p tcp -m tcp --dport {} -j ACCEPT'.format(SERVER_PORT)
test_report = dict()


def fanout_switch_port_lookup(fanout_switches, dut_name, dut_port):
    """
        look up the fanout switch instance and the fanout switch port
        connecting to the dut_port

        Args:
            fanout_switches (list FanoutHost): list of fanout switch
                                               instances.
            dut_name (str): the host name of the DUT
            dut_port (str): port name on the DUT

        Returns:
            None, None if fanout switch instance and port is not found
            FanoutHost, Portname(str) if found
    """
    dut_host_port = encode_dut_port_name(dut_name, dut_port)
    for _, fanout in list(fanout_switches.items()):
        if dut_host_port in fanout.host_to_fanout_port_map:
            return fanout, fanout.host_to_fanout_port_map[dut_host_port]

    return None, None


def get_dut_psu_line_pattern(dut):
    if "201811" in dut.os_version or "201911" in dut.os_version:
        psu_line_pattern = re.compile(r"PSU\s+(\d)+\s+(OK|NOT OK|NOT PRESENT)")
    elif dut.facts['platform'] == "x86_64-dellemc_z9332f_d1508-r0":
        psu_line_pattern = re.compile(r"PSU\s+(\d+).*?(OK|NOT OK|NOT PRESENT|WARNING)\s+(N/A)")
    elif dut.facts["asic_type"] in ["mellanox"]:
        psu_line_pattern = re.compile(r"PSU\s+(\d+).*?(OK|NOT OK|NOT PRESENT|WARNING)\s+(green|amber|red|off|N/A)")
    else:
        # Changed the pattern to match different PSU name formats and status patterns.
        # Supports various PSU naming conventions:
        #
        # example 1:
        #     psu1   PWR-500AC-R  L8180S01HTAVP  N/A            N/A            N/A          OK        green
        #     psu2   PWR-500AC-R  L8180S01HFAVP  N/A            N/A            N/A          OK        green
        # example 2:
        #     psutray0.psu0  N/A      N/A               12.05           3.38        40.62  OK        green
        #     psutray0.psu1  N/A      N/A               12.01           4.12        49.50  OK        green
        # example 3:
        #     PSU 9  PSU6.3KW-20A-HV  DTM273501QU      1.00  55.052         11.359         626.386      OK        green
        #
        psu_line_pattern = re.compile(
            r"^(PSU\s+\d+|\S+)\s+.*?(OK|NOT OK|NOT PRESENT|WARNING)\s+(green|amber|red|off|N/A)")
    return psu_line_pattern


def list_dut_fanout_connections(dut, fanouthosts):
    """
    Lists connected dut-fanout ports

    Args:
        dut: DUT host object
        fanouthosts: List of fanout switch instances.

    Returns:
        A list of tuple with DUT's port, fanout port
        and fanout
    """
    candidates = []

    status = dut.show_interface(command='status')['ansible_facts']['int_status']

    for dut_port in list(status.keys()):
        fanout, fanout_port = fanout_switch_port_lookup(fanouthosts, dut.hostname, dut_port)

        if fanout and fanout_port and status[dut_port]['admin_state'] != 'down':
            candidates.append((dut_port, fanout, fanout_port))

    return candidates


def eos_to_linux_intf(eos_intf_name, hwsku=None):
    """
    @Summary: Map EOS's interface name to Linux's interface name
    @param eos_intf_name: Interface name in EOS
    @return: Return the interface name in Linux
    """
    if hwsku == "MLNX-OS":
        linux_intf_name = eos_intf_name.replace(
            "ernet 1/", "sl1p").replace("/", "sp")
    elif hwsku and "Nokia" in hwsku:
        linux_intf_name = eos_intf_name
    else:
        linux_intf_name = eos_intf_name.replace(
            'Ethernet', 'et').replace('/', '_')
    return linux_intf_name


def nxos_to_linux_intf(nxos_intf_name):
    """
        @Summary: Map NxOS's interface name to Linux's interface name
        @param nxos_intf_name: Interface name in NXOS
        @return: Return the interface name in Linux
    """
    return nxos_intf_name.replace('Ethernet', 'Eth').replace('/', '-')


def sonic_to_linux_intf(sonic_intf_name):
    """
    @Summary: Map SONiC's interface name to Linux's interface name
    @param sonic_intf_name: Interface name in SONiC
    @return: Return the interface name in Linux
    """
    return sonic_intf_name


def watch_system_status(dut):
    """
    Watch DUT's system status

    Args:
        dut: DUT host object
    """
    # Watch memory status
    memory_output = dut.shell("show system-memory")["stdout"]
    logger.info("Memory Status: %s", memory_output)

    # Watch orchagent CPU utilization
    orch_cpu = dut.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"]
    logger.info("Orchagent CPU Util: %s", orch_cpu)

    # Watch Redis Memory
    redis_memory = dut.shell("redis-cli info memory | grep used_memory_human")["stdout"]
    logger.info("Redis Memory: %s", redis_memory)


def __get_dut_if_status(dut, ifname=None):
    """
    Get interface status on the DUT.

    Args:
        dut: DUT host object
        ifname: Interface of DUT
        exp_state: State of DUT's port ('up' or 'down')
        verbose: Logging port state.

    Returns:
        Interface state
    """
    if not ifname:
        status = dut.show_interface(command='status')['ansible_facts']['int_status']
    else:
        status = dut.show_interface(command='status', interfaces=[ifname])['ansible_facts']['int_status']
    return status


def __check_if_status(dut, dut_port, exp_state, verbose=False):
    """
    Check interface status on the DUT.

    Args:
        dut: DUT host object
        dut_port: Port of DUT
        exp_state: State of DUT's port ('up' or 'down')
        verbose: Logging port state.

    Returns:
        Bool value which confirm port state
    """
    status = __get_dut_if_status(dut, dut_port)[dut_port]
    if verbose:
        logger.debug("Interface status : %s", status)
    return status['oper_state'] == exp_state


def toggle_one_link(dut, dut_port, fanout, fanout_port, watch=False, check_status=True):
    """
    Toggle one link on the fanout.

    Args:
        dut: DUT host object
        dut_port: Port of DUT
        fanout: Fanout host object
        fanout_port: Port of fanout
        watch: Logging system state
    """

    sleep_time = 90
    logger.info("Testing link flap on %s", dut_port)
    if check_status:
        pytest_assert(__check_if_status(dut, dut_port, 'up', verbose=True),
                      "Fail: dut port {}: link operational down".format(dut_port))

    logger.info("Shutting down fanout switch %s port %s connecting to %s", fanout.hostname, fanout_port, dut_port)

    need_recovery = True
    try:
        fanout.shutdown(fanout_port)
        if check_status:
            pytest_assert(wait_until(sleep_time, 1, 0, __check_if_status, dut, dut_port, 'down', True),
                          "dut port {} didn't go down as expected".format(dut_port))

        if watch:
            time.sleep(1)
            watch_system_status(dut)

        logger.info("Bring up fanout switch %s port %s connecting to %s", fanout.hostname, fanout_port, dut_port)
        fanout.no_shutdown(fanout_port)
        need_recovery = False

        if check_status:
            pytest_assert(wait_until(sleep_time, 1, 0, __check_if_status, dut, dut_port, 'up', True),
                          "dut port {} didn't go up as expected".format(dut_port))
    finally:
        if need_recovery:
            fanout.no_shutdown(fanout_port)
            if check_status:
                wait_until(sleep_time, 1, 0, __check_if_status, dut, dut_port, 'up', True)


class RebootHealthError(Exception):
    def __init__(self, message):
        self.message = message
        super(RebootHealthError, self).__init__(message)


def handle_test_error(health_check):
    def _wrapper(*args, **kwargs):
        try:
            health_check(*args, **kwargs)
        except RebootHealthError as err:
            # set result to fail
            logging.error("Health check {} failed with {}".format(
                health_check.__name__, err.message))
            test_report[health_check.__name__] = err.message
            return
        except Exception as err:
            traceback.print_exc()
            logging.error("Health check {} failed with unknown error: {}".format(
                health_check.__name__, str(err)))
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
    if not wait_until(330, 30, 0, duthost.critical_services_fully_started):
        raise RebootHealthError("dut.critical_services_fully_started is False")

    critical_services = [re.sub(r'(\d+)$', r'@\1', service) for service in duthost.critical_services]
    logging.info("Check critical service status")
    for service in critical_services:
        status = duthost.get_service_props(service)
        if status["ActiveState"] != "active":
            raise RebootHealthError("ActiveState of {} is {}, expected: active".format(
                service, status["ActiveState"]))
        if status["SubState"] != "running":
            raise RebootHealthError(
                "SubState of {} is {}, expected: running".format(service, status["SubState"]))


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
    failed = [
        result for result in results if "failed" in result and result["failed"]]
    if failed:
        raise RebootHealthError(
            "Interface check failed, not all interfaces are up. Failed: {}".format(failed))

    # Skip this step for virtual testbed - KVM testbed has transeivers marked as "Not present"
    # and the DB returns an "empty array" for "keys TRANSCEIVER_INFO*"
    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        return

    logging.info(
        "Check whether transceiver information of all ports are in redis")
    parsed_xcvr_info = []

    for asichost in duthost.asics:
        docker_cmd = asichost.get_docker_cmd("redis-cli -n 6 keys TRANSCEIVER_INFO*", "database")
        xcvr_info = duthost.command(docker_cmd)
        parsed_xcvr_info.extend(parse_transceiver_info(xcvr_info["stdout_lines"]))

    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    if duthost.facts['hwsku'] in MGFX_HWSKU:
        interfaces = MGFX_XCVR_INTF
    for intf in interfaces:
        if intf not in parsed_xcvr_info:
            raise RebootHealthError(
                "TRANSCEIVER INFO of {} is not found in DB".format(intf))


@handle_test_error
def check_neighbors(duthost, tbinfo):
    """
    Perform a BGP neighborship check.
    """
    logging.info("Check BGP neighbors status. Expected state - established")

    # Verify bgp sessions are established
    bgp_neighbors = duthost.get_bgp_neighbors_per_asic(state="all")
    if not wait_until(600, 10, 0, duthost.check_bgp_session_state_all_asics, bgp_neighbors):
        raise RebootHealthError("BGP session not established")

    # Only produces bgp_neighbors attribute of bgp_facts (only one used at the moment)
    bgp_facts = {'bgp_neighbors': {}}
    for asichost in duthost.asics:
        asic_ansible_facts = asichost.bgp_facts()['ansible_facts']
        bgp_facts['bgp_neighbors'].update(asic_ansible_facts['bgp_neighbors'])

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for value in list(bgp_facts['bgp_neighbors'].values()):
        # Verify locat ASNs in bgp sessions
        if (value['local AS'] != mg_facts['minigraph_bgp_asn']):
            raise RebootHealthError("Local ASNs not found in BGP session.\
                Minigraph: {}. Found {}".format(value['local AS'], mg_facts['minigraph_bgp_asn']))
    for v in mg_facts['minigraph_bgp']:
        # Compare the bgp neighbors name with minigraph bgp neigbhors name
        if (v['name'] != bgp_facts['bgp_neighbors'][v['addr'].lower()]['description']):
            raise RebootHealthError("BGP neighbor's name does not match minigraph.\
                Minigraph: {}. Found {}".format(v['name'],
                                                bgp_facts['bgp_neighbors'][v['addr'].lower()]['description']))
        # Compare the bgp neighbors ASN with minigraph
        if (v['asn'] != bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS']):
            raise RebootHealthError("BGP neighbor's ASN does not match minigraph.\
                Minigraph: {}. Found {}".format(v['asn'], bgp_facts['bgp_neighbors'][v['addr'].lower()]['remote AS']))


@handle_test_error
def verify_no_coredumps(duthost, pre_existing_cores):
    if "20191130" in duthost.os_version:
        coredumps_count = duthost.shell(
            'ls /var/core/ | grep -v python | wc -l')['stdout']
    else:
        coredumps_count = duthost.shell('ls /var/core/ | wc -l')['stdout']
        coredumps = duthost.shell('ls -l /var/core/')['stdout']
        logging.info(f"Found core dumps: {coredumps}")
    if int(coredumps_count) > int(pre_existing_cores):
        raise RebootHealthError("Core dumps found. Expected: {} Found: {}".format(pre_existing_cores,
                                                                                  coredumps_count))


@handle_test_error
def verify_yang(duthost):
    """
    Verify yang over running config
    """
    logging.info("Verify yang over running config")

    # return release number of current sonic version such as '20191130'
    def get_current_sonic_version(duthost):
        os_version = duthost.shell('sonic_installer list 2>/dev/null | grep Current | cut -f2 -d " "')['stdout']
        # os_version format:
        # "SONiC-OS-20191130.89"
        # "SONiC-OS-master.825947-534613c6d"
        # "SONiC-OS-internal.121161804-317e9bb571"
        version = os_version.split('-')[2].split('.')[0]
        match = re.search(r"SONiC-OS-(\d{8})\.", version)
        if match:
            release = match.group(1)
        else:
            release = None
        return release

    release = get_current_sonic_version(duthost)
    # Skip yang validation when no release number found or old version
    if not release or release < '20220500':
        return True

    strict_yang_validation = False
    # Strict yang validation is supported from 202505
    if release > '20250500':
        strict_yang_validation = True

    if not wait_until(60, 15, 0, duthost.yang_validate, strict_yang_validation):
        raise RebootHealthError("Yang validation failed")


@pytest.fixture
def verify_dut_health(request, duthosts, rand_one_dut_hostname, tbinfo):
    """
    Performs health check on single DUT defined by rand_one_dut_hostname before and after a test
    """
    global test_report
    test_report = {}
    duthost = duthosts[rand_one_dut_hostname]
    check_services(duthost)
    check_interfaces_and_transceivers(duthost, request)
    check_neighbors(duthost, tbinfo)
    if "20191130" in duthost.os_version:
        pre_existing_cores = duthost.shell(
            'ls /var/core/ | grep -v python | wc -l')['stdout']
    else:
        pre_existing_cores = duthost.shell('ls /var/core/ | wc -l')['stdout']
    check_all = all([check is True for check in list(test_report.values())])
    pytest_assert(check_all, "DUT not ready for test. Health check failed before reboot: {}".format(test_report))

    yield

    test_report = {}
    check_services(duthost)
    check_interfaces_and_transceivers(duthost, request)
    check_neighbors(duthost, tbinfo)
    verify_no_coredumps(duthost, pre_existing_cores)
    verify_yang(duthost)
    check_all = all([check is True for check in list(test_report.values())])
    pytest_assert(check_all, "Health check failed after reboot: {}"
                  .format(test_report))


@pytest.fixture
def verify_testbed_health(request, duthosts, tbinfo):
    """
    Performs health check on all DUTs in a testbed before and after a test
    """
    global test_report
    for duthost in duthosts:
        test_report = {}
        check_services(duthost)
        check_interfaces_and_transceivers(duthost, request)
        check_neighbors(duthost, tbinfo)
        check_all = all([check is True for check in list(test_report.values())])
        pytest_assert(check_all, "DUT {} not ready for test. Health check failed before reboot: {}"
                      .format(duthost.hostname, test_report))

    if "20191130" in duthost.os_version:
        pre_existing_cores = duthost.shell(
            'ls /var/core/ | grep -v python | wc -l')['stdout']
    else:
        pre_existing_cores = duthost.shell('ls /var/core/ | wc -l')['stdout']

    yield

    for duthost in duthosts:
        test_report = {}
        check_services(duthost)
        check_interfaces_and_transceivers(duthost, request)
        check_neighbors(duthost, tbinfo)
        verify_no_coredumps(duthost, pre_existing_cores)
        check_all = all([check is True for check in list(test_report.values())])
        pytest_assert(check_all, "Health check failed for {} after reboot: {}"
                      .format(duthost.hostname, test_report))


def get_current_sonic_version(duthost):
    return duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']


def overwrite_script_to_backup_logs(duthost, reboot_type, bgpd_log):
    # find the fast/warm-reboot script path
    reboot_script_path = duthost.shell('which {}'.format(
        "{}-reboot".format(reboot_type)))['stdout']
    # backup original script
    duthost.shell("cp {} {}".format(
        reboot_script_path, reboot_script_path + ".orig"))
    # find the anchor string inside fast/warm-reboot script
    rebooting_log_line = "debug.*Rebooting with.*to.*"
    # Create a backup log command to be inserted right after the anchor string defined above
    backup_log_cmds = "cat /var/log/syslog.1 /var/log/syslog > /host/syslog.99 || true;" +\
        "cat /var/log/swss/sairedis.rec.1 /var/log/swss/sairedis.rec > /host/sairedis.rec.99 || true;" +\
        "cat /var/log/swss/swss.rec.1 /var/log/swss/swss.rec > /host/swss.rec.99 || true;" +\
        "cat {}.1 {} > /host/bgpd.log.99 || true".format(bgpd_log, bgpd_log)
    # Do find-and-replace on fast/warm-reboot script to insert the backup_log_cmds string
    insert_backup_command = "sed -i '/{}/a {}' {}".format(
        rebooting_log_line, backup_log_cmds, reboot_script_path)
    duthost.shell(insert_backup_command)


def _parse_timestamp(timestamp):
    for format in [FMT, FMT_YEAR, FMT_SHORT, FMT_ALT]:
        try:
            time = datetime.strptime(timestamp, format)
            return time
        except ValueError:
            continue
    # Handling leap year FEB29 case, where year not provided causing exception
    # if strptime fails for all format, check if its leap year
    # ValueError exception will be raised for invalid cases for strptime
    time = datetime.strptime(str(datetime.now().year) + " " + timestamp, FMT_YEAR)
    return time


def get_kexec_time(duthost, messages, result):
    reboot_pattern = re.compile(
        r'.* NOTICE (?:admin|root): Rebooting with /sbin/kexec -e to.*...')
    reboot_time = "N/A"
    logging.info("FINDING REBOOT PATTERN")
    for message in messages:
        # Get timestamp of reboot - Rebooting string
        if re.search(reboot_pattern, message):
            logging.info(
                "FOUND REBOOT PATTERN for {}".format(duthost.hostname))
            delim = "{}|{}".format(duthost.hostname, "sonic")
            reboot_time = _parse_timestamp(re.split(delim, message)[
                                           0].strip()).strftime(FMT)
            continue
    result["reboot_time"] = {
        "timestamp": {"Start": reboot_time},
    }


def get_state_times(timestamp, state, state_times, first_after_offset=None):
    time = timestamp.strftime(FMT)
    state_name = state.split("|")[0].strip()
    state_status = state.split("|")[1].strip()
    state_dict = state_times.get(state_name, {"timestamp": {}})
    timestamps = state_dict.get("timestamp")
    if state_status in timestamps:
        state_dict[state_status +
                   " count"] = state_dict.get(state_status+" count") + 1
        # capture last occcurence - useful in calculating events end time
        state_dict["last_occurence"] = time
    elif first_after_offset:
        state_dict[state_status+" count"] = 1
        # capture the first occurence as the one after offset timestamp and ignore the ones before
        # this is useful to find time after a specific instance, for eg. - kexec time or FDB disable time.
        if _parse_timestamp(first_after_offset) < _parse_timestamp(time):
            timestamps[state_status] = time
    else:
        # only capture timestamp of first occurence of the entity. Otherwise, just increment the count above.
        # this is useful in capturing start point. Eg., first neighbor entry, LAG ready, etc.
        state_dict[state_status+" count"] = 1
        timestamps[state_status] = time
    return {state_name: state_dict}


def analyze_log_file(duthost, messages, result, offset_from_kexec):
    service_restart_times = dict()
    derived_patterns = OTHER_PATTERNS.get("COMMON")
    service_patterns = dict()
    # get platform specific regexes
    if is_broadcom_device(duthost):
        derived_patterns.update(OTHER_PATTERNS.get("BRCM"))
    elif is_mellanox_device(duthost):
        derived_patterns.update(OTHER_PATTERNS.get("MLNX"))
    # get image specific regexes
    if "20191130" in get_current_sonic_version(duthost):
        derived_patterns.update(OTHER_PATTERNS.get("201911"))
        service_patterns.update(SERVICE_PATTERNS.get("201911"))
    else:
        derived_patterns.update(OTHER_PATTERNS.get("LATEST"))
        service_patterns.update(SERVICE_PATTERNS.get("LATEST"))

    if not messages:
        logging.error("Expected messages not found in syslog")
        return None

    def service_time_check(message, status):
        delim = "{}|{}".format(duthost.hostname, "sonic")
        time = _parse_timestamp(re.split(delim, message)[0].strip())
        time = time.strftime(FMT)
        service_name = message.split(status + " ")[1].split()[0]
        service_name = service_name.upper()
        if service_name == "ROUTER":
            service_name = "RADV"
        service_dict = service_restart_times.get(
            service_name, {"timestamp": {}})
        timestamps = service_dict.get("timestamp")
        if status in timestamps:
            service_dict[status +
                         " count"] = service_dict.get(status+" count") + 1
        else:
            service_dict[status+" count"] = 1
        timestamps[status] = time
        service_restart_times.update({service_name: service_dict})

    for message in messages:
        # Get stopping to started timestamps for services (swss, bgp, etc)
        for status, pattern in list(service_patterns.items()):
            if re.search(pattern, message):
                service_time_check(message, status)
                break
        # Get timestamps of all other entities
        for state, pattern in list(derived_patterns.items()):
            if re.search(pattern, message):
                delim = "{}|{}".format(duthost.hostname, "sonic")
                timestamp = _parse_timestamp(
                    re.split(delim, message)[0].strip())
                state_name = state.split("|")[0].strip()
                if state_name + "|End" not in list(derived_patterns.keys()):
                    if "FDB_EVENT_OTHER_MAC_EXPIRY" in state_name or "FDB_EVENT_SCAPY_MAC_EXPIRY" in state_name:
                        fdb_aging_disable_start = service_restart_times.get("FDB_AGING_DISABLE", {})\
                            .get("timestamp", {}).get("Start")
                        if not fdb_aging_disable_start:
                            break
                        first_after_offset = fdb_aging_disable_start
                    else:
                        first_after_offset = result.get("reboot_time", {}).get(
                            "timestamp", {}).get("Start")
                    state_times = get_state_times(timestamp, state, offset_from_kexec,
                                                  first_after_offset=first_after_offset)
                    offset_from_kexec.update(state_times)
                else:
                    state_times = get_state_times(
                        timestamp, state, service_restart_times)
                    service_restart_times.update(state_times)
                if "PORT_READY" not in state_name:
                    # If PORT_READY, don't break out of the for-loop here, because we want to
                    # try to match the other regex as well
                    break
    # Calculate time that services took to stop/start
    for _, timings in list(service_restart_times.items()):
        timestamps = timings["timestamp"]
        timings["stop_time"] = (_parse_timestamp(timestamps["Stopped"]) -
                                _parse_timestamp(timestamps["Stopping"])).total_seconds() \
            if "Stopped" in timestamps and "Stopping" in timestamps else None

        timings["start_time"] = (_parse_timestamp(timestamps["Started"]) -
                                 _parse_timestamp(timestamps["Starting"])).total_seconds() \
            if "Started" in timestamps and "Starting" in timestamps else None

        if "Started" in timestamps and "Stopped" in timestamps:
            timings["time_span"] = (_parse_timestamp(timestamps["Started"]) -
                                    _parse_timestamp(timestamps["Stopped"])).total_seconds()
        elif "Start" in timestamps and "End" in timestamps:
            if "last_occurence" in timings:
                timings["time_span"] = (_parse_timestamp(timings["last_occurence"]) -
                                        _parse_timestamp(timestamps["Start"])).total_seconds()
            else:
                timings["time_span"] = (_parse_timestamp(timestamps["End"]) -
                                        _parse_timestamp(timestamps["Start"])).total_seconds()

    result["time_span"].update(service_restart_times)
    result["offset_from_kexec"] = offset_from_kexec
    return result


def analyze_sairedis_rec(messages, result, offset_from_kexec):
    sai_redis_state_times = dict()
    for message in messages:
        for state, pattern in list(SAIREDIS_PATTERNS.items()):
            if re.search(pattern, message):
                timestamp = datetime.strptime(message.split(
                    "|")[0].strip(), "%Y-%m-%d.%H:%M:%S.%f")
                state_name = state.split("|")[0].strip()
                reboot_time = result.get("reboot_time", {}).get(
                    "timestamp", {}).get("Start")
                if state_name + "|End" not in list(SAIREDIS_PATTERNS.keys()):
                    if "FDB_EVENT_OTHER_MAC_EXPIRY" in state_name or "FDB_EVENT_SCAPY_MAC_EXPIRY" in state_name:
                        fdb_aging_disable_start = result.get("time_span", {}).get("FDB_AGING_DISABLE", {})\
                            .get("timestamp", {}).get("Start")
                        if not fdb_aging_disable_start:
                            break
                        # Ignore MAC learning events before FDB aging disable, as MAC learning is still allowed
                        log_time = timestamp.strftime(FMT)
                        if _parse_timestamp(log_time) < _parse_timestamp(fdb_aging_disable_start):
                            break
                        first_after_offset = fdb_aging_disable_start
                    else:
                        first_after_offset = result.get("reboot_time", {}).get(
                            "timestamp", {}).get("Start")
                    state_times = get_state_times(timestamp, state, offset_from_kexec,
                                                  first_after_offset=first_after_offset)
                    offset_from_kexec.update(state_times)
                else:
                    state_times = get_state_times(timestamp, state, sai_redis_state_times,
                                                  first_after_offset=reboot_time)
                    sai_redis_state_times.update(state_times)

    for _, timings in list(sai_redis_state_times.items()):
        timestamps = timings["timestamp"]
        if "Start" in timestamps and "End" in timestamps:
            timings["time_span"] = (_parse_timestamp(timestamps["End"]) -
                                    _parse_timestamp(timestamps["Start"])).total_seconds()

    result["time_span"].update(sai_redis_state_times)
    result["offset_from_kexec"] = offset_from_kexec


def get_report_summary(duthost, analyze_result, reboot_type, reboot_oper, base_os_version):
    time_spans = analyze_result.get("time_span", {})
    time_spans_summary = OrderedDict()
    kexec_offsets = analyze_result.get("offset_from_kexec", {})
    reboot_start_time = analyze_result.get(
        "reboot_time", {}).get("timestamp", {}).get("Start")
    kexec_offsets_summary = OrderedDict()
    for entity in OFFSET_ITEMS:
        time_taken = ""
        if entity in kexec_offsets:
            time_taken = kexec_offsets.get(entity).get("time_taken", "")
        elif entity in time_spans:
            timestamp = time_spans.get(entity).get("timestamp", {})
            marker_start_time = timestamp.get(
                "Start") if "Start" in timestamp else timestamp.get("Started")
            if reboot_start_time and reboot_start_time != "N/A" and marker_start_time:
                time_taken = (_parse_timestamp(marker_start_time) -
                              _parse_timestamp(reboot_start_time)).total_seconds()
        kexec_offsets_summary.update({entity.lower(): str(time_taken)})

    for entity in TIME_SPAN_ITEMS:
        time_taken = ""
        if entity in time_spans:
            time_taken = time_spans.get(entity, {}).get("time_span", "")
        elif entity in kexec_offsets:
            marker_first_time = kexec_offsets.get(
                entity).get("timestamp", {}).get("Start")
            marker_last_time = kexec_offsets.get(entity).get("last_occurence")
            if marker_first_time and marker_last_time:
                time_taken = (_parse_timestamp(marker_last_time) -
                              _parse_timestamp(marker_first_time)).total_seconds()
        time_spans_summary.update({entity.lower(): str(time_taken)})

    lacp_sessions_dict = analyze_result.get("controlplane")
    lacp_sessions_waittime = lacp_sessions_dict.pop("lacp_sessions")\
        if lacp_sessions_dict and "lacp_sessions" in lacp_sessions_dict else None
    controlplane_summary = {"downtime": "",
                            "arp_ping": "", "lacp_session_max_wait": ""}
    if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
        if lacp_sessions_waittime and len(lacp_sessions_waittime) > 0:
            # Filter out None values and then fine the maximum
            filtered_lacp_sessions_waittime = [value for value in lacp_sessions_waittime.values() if value is not None]
            if filtered_lacp_sessions_waittime:
                max_lacp_session_wait = max(filtered_lacp_sessions_waittime)
            else:
                max_lacp_session_wait = None
            analyze_result.get(
                "controlplane", controlplane_summary).update(
                    {"lacp_session_max_wait": max_lacp_session_wait})

    result_summary = {
        "reboot_type": "{}-{}".format(reboot_type, reboot_oper) if reboot_oper else reboot_type,
        "hwsku": duthost.facts["hwsku"],
        "hostname": duthost.hostname,
        "base_ver": base_os_version[0] if base_os_version and len(base_os_version) else "",
        "target_ver": get_current_sonic_version(duthost),
        "dataplane": analyze_result.get("dataplane", {"downtime": "", "lost_packets": ""}),
        "controlplane": analyze_result.get("controlplane", controlplane_summary),
        "time_span": time_spans_summary,
        "offset_from_kexec": kexec_offsets_summary
    }
    return result_summary


def get_data_plane_report(analyze_result, reboot_type, log_dir, reboot_oper):
    report = {"controlplane": {"arp_ping": "", "downtime": ""},
              "dataplane": {"lost_packets": "", "downtime": ""}}
    files = glob.glob1(log_dir, '*reboot*-report.json')
    if files:
        filepath = "{}/{}".format(log_dir, files[0])
        with open(filepath) as json_file:
            report = json.load(json_file)
    analyze_result.update(report)


def verify_mac_jumping(test_name, timing_data, verification_errors):
    mac_jumping_other_addr = timing_data.get("offset_from_kexec", {})\
        .get("FDB_EVENT_OTHER_MAC_EXPIRY", {}).get("Start count", 0)
    mac_jumping_scapy_addr = timing_data.get("offset_from_kexec", {})\
        .get("FDB_EVENT_SCAPY_MAC_EXPIRY", {}).get("Start count", 0)
    mac_expiry_start = timing_data.get("offset_from_kexec", {}).get("FDB_EVENT_OTHER_MAC_EXPIRY", {})\
        .get("timestamp", {}).get("Start")
    fdb_aging_disable_start = timing_data.get("time_span", {}).get("FDB_AGING_DISABLE", {})\
        .get("timestamp", {}).get("Start")
    fdb_aging_disable_end = timing_data.get("time_span", {}).get("FDB_AGING_DISABLE", {})\
        .get("timestamp", {}).get("End")

    if "mac_jump" in test_name:
        # MAC jumping allowed - allow Scapy default MAC to jump
        logging.info("MAC jumping is allowed. Jump count for expected mac: {}, unexpected MAC: {}"
                     .format(mac_jumping_scapy_addr, mac_jumping_other_addr))
        if not mac_jumping_scapy_addr:
            verification_errors.append(
                "MAC jumping not detected when expected for address: 00-06-07-08-09-0A")
    else:
        # MAC jumping not allowed - do not allow the SCAPY default MAC to jump
        if mac_jumping_scapy_addr:
            verification_errors.append("MAC jumping is not allowed. Jump count for scapy mac: {}, other MAC: {}"
                                       .format(mac_jumping_scapy_addr, mac_jumping_other_addr))
    if mac_jumping_other_addr:
        # In both mac jump allowed and denied cases unexpected MAC addresses should NOT jump between
        # the window that starts when SAI is instructed to disable MAC learning (warmboot shutdown path)
        # and ends when SAI is instructed to enable MAC learning (warmboot recovery path)
        logging.info("Mac expiry for unexpected addresses started at {}".format(mac_expiry_start) +
                     " and FDB learning enabled at {}".format(fdb_aging_disable_end))
        if _parse_timestamp(mac_expiry_start) > _parse_timestamp(fdb_aging_disable_start) and\
           _parse_timestamp(mac_expiry_start) < _parse_timestamp(fdb_aging_disable_end):
            verification_errors.append(
                "Mac expiry detected during the window when FDB ageing was disabled")


def verify_required_events(duthost, event_counters, timing_data, verification_errors):
    for key in ["time_span", "offset_from_kexec"]:
        for pattern in REQUIRED_PATTERNS.get(key):
            if pattern == 'PORT_READY':
                observed_start_count = timing_data.get(
                    key, {}).get(pattern, {}).get("Start-changes-only count", 0)
            else:
                observed_start_count = timing_data.get(
                    key, {}).get(pattern, {}).get("Start count", 0)
            observed_end_count = timing_data.get(
                key, {}).get(pattern, {}).get("End count", 0)
            expected_count = event_counters.get(pattern)
            # If we're checking PORT_READY, allow any number of PORT_READY messages between 0 and the number of ports.
            # Some platforms appear to have a random number of these messages, other platforms have however many ports
            # are up.
            if observed_start_count != expected_count and (
                    pattern != 'PORT_READY' or observed_start_count > expected_count):
                verification_errors.append("FAIL: Event {} was found {} times, when expected exactly {} times".
                                           format(pattern, observed_start_count, expected_count))
            if key == "time_span" and observed_start_count != observed_end_count:
                verification_errors.append("FAIL: Event {} counters did not match. ".format(pattern) +
                                           "Started {} times, and ended {} times".
                                           format(observed_start_count, observed_end_count))


def advanceboot_loganalyzer_factory(duthost, request, marker_postfix=None):
    """Create pre-reboot and post-reboot analysis functions via `LogAnalyzer` with optional marker postfix"""
    test_name = request.node.name
    if "upgrade_path" in test_name:
        reboot_type_source = request.config.getoption("--upgrade_type")
    else:
        reboot_type_source = test_name
    if "warm" in reboot_type_source:
        reboot_type = "warm"
    elif "fast" in reboot_type_source:
        reboot_type = "fast"
    else:
        reboot_type = "unknown"
    platform = duthost.facts["platform"]
    logs_in_tmpfs = list()

    marker_prefix = "test_advanced_reboot_{}".format(test_name) if not marker_postfix else\
        "test_advanced_reboot_{}_{}".format(test_name, marker_postfix)
    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix=marker_prefix)
    base_os_version = list()

    def bgpd_log_handler(preboot=False):
        # check current OS version post-reboot. This can be different than preboot OS version in case of upgrade
        current_os_version = get_current_sonic_version(duthost)
        if preboot:
            if 'SONiC-OS-201811' in current_os_version:
                bgpd_log = "/var/log/quagga/bgpd.log"
            else:
                bgpd_log = "/var/log/frr/bgpd.log"
            additional_files = {'/var/log/swss/sairedis.rec': '', bgpd_log: ''}
            loganalyzer.additional_files = list(additional_files.keys())
            loganalyzer.additional_start_str = list(additional_files.values())
            return bgpd_log
        else:
            # log_analyzer may start with quagga and end with frr, and frr.log might still have old logs.
            # To avoid missing preboot log, or analyzing old logs, combine quagga and frr log into new file
            duthost.shell("cat {} {} | sort -n > {}".format(
                "/var/log/quagga/bgpd.log", "/var/log/frr/bgpd.log", "/var/log/bgpd.log"), module_ignore_errors=True)
            loganalyzer.additional_files = [
                '/var/log/swss/sairedis.rec', '/var/log/bgpd.log']

    def pre_reboot_analysis():
        log_filesystem = duthost.shell(
            "df --output=fstype -h /var/log")['stdout']
        logs_in_tmpfs.append(
            True if (log_filesystem and "tmpfs" in log_filesystem) else False)
        base_os_version.append(get_current_sonic_version(duthost))
        bgpd_log = bgpd_log_handler(preboot=True)
        if platform in LOGS_ON_TMPFS_PLATFORMS or (len(logs_in_tmpfs) > 0 and logs_in_tmpfs[0] is True):
            logger.info("Inserting step to back up logs to /host/ before reboot")
            # For small disk devices, /var/log in mounted in tmpfs.
            # Hence, after reboot the preboot logs are lost.
            # For log_analyzer to work, it needs logs from the shutdown path
            # Below method inserts a step in reboot script to back up logs to /host/
            overwrite_script_to_backup_logs(duthost, reboot_type, bgpd_log)
        marker = loganalyzer.init()
        loganalyzer.load_common_config()

        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_boot_messages")
        expect_file = os.path.join(TEMPLATES_DIR, "expect_boot_messages")
        ignore_reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
        expect_reg_exp = loganalyzer.parse_regexp_file(src=expect_file)

        loganalyzer.ignore_regex.extend(ignore_reg_exp)
        loganalyzer.expect_regex = []
        loganalyzer.expect_regex.extend(expect_reg_exp)
        loganalyzer.match_regex = []
        return marker

    def post_reboot_analysis(marker, event_counters=None, reboot_oper=None, log_dir=None):
        bgpd_log_handler()
        if platform in LOGS_ON_TMPFS_PLATFORMS or (len(logs_in_tmpfs) > 0 and logs_in_tmpfs[0] is True):
            logger.info("Restoring log backup from /host/ after reboot")
            restore_backup = "mv /host/syslog.99 /var/log/; " +\
                "mv /host/sairedis.rec.99 /var/log/swss/; " +\
                "mv /host/swss.rec.99 /var/log/swss/; " +\
                "mv /host/bgpd.log.99 /var/log/"
            duthost.shell(restore_backup, module_ignore_errors=True)
            # find the fast/warm-reboot script path
            reboot_script_path = duthost.shell('which {}'.format(
                "{}-reboot".format(reboot_type)))['stdout']
            # restore original script. If the ".orig" file does not exist (upgrade path case), ignore the error.
            duthost.shell("mv {} {}".format(reboot_script_path + ".orig", reboot_script_path),
                          module_ignore_errors=True)
        # For mac jump test, the log message we care about is uaually combined with other messages in one line,
        # which makes the length of the line longer than 1000 and get dropped by Logananlyzer. So we need to increase
        # the max allowed length.
        # The regex library in Python 2 takes very long time (over 10 minutes) to process long lines. In our test,
        # most of the combined log message for mac jump test is around 5000 characters. So we set the max allowed
        # length to 6000.
        result = loganalyzer.analyze(marker, fail=False, maximum_log_length=6000)
        analyze_result = {"time_span": dict(), "offset_from_kexec": dict()}
        offset_from_kexec = dict()

        # Parsing sairedis shall happen after parsing syslog because FDB_AGING_DISABLE is required
        # when analysing sairedis.rec log, so we need to sort the keys
        key_list = ["syslog", "bgpd.log", "sairedis.rec"]
        for i in range(0, len(key_list)):
            for message_key in list(result["expect_messages"].keys()):
                if key_list[i] in message_key:
                    key_list[i] = message_key
                    break

        for key in key_list:
            messages = result["expect_messages"][key]
            if "syslog" in key:
                get_kexec_time(duthost, messages, analyze_result)
                reboot_start_time = analyze_result.get(
                    "reboot_time", {}).get("timestamp", {}).get("Start")
                if not reboot_start_time or reboot_start_time == "N/A":
                    logging.error("kexec regex \"Rebooting with /sbin/kexec\" not found in syslog. " +
                                  "Skipping log_analyzer checks..")
                    return
                syslog_messages = messages
            elif "bgpd.log" in key:
                bgpd_log_messages = messages
            elif "sairedis.rec" in key:
                sairedis_rec_messages = messages

        # analyze_sairedis_rec() use information from syslog and must be called after analyzing syslog
        analyze_log_file(duthost, syslog_messages,
                         analyze_result, offset_from_kexec)
        analyze_log_file(duthost, bgpd_log_messages,
                         analyze_result, offset_from_kexec)
        analyze_sairedis_rec(sairedis_rec_messages,
                             analyze_result, offset_from_kexec)

        for marker, time_data in list(analyze_result["offset_from_kexec"].items()):
            marker_start_time = time_data.get("timestamp", {}).get("Start")
            reboot_start_time = analyze_result.get(
                "reboot_time", {}).get("timestamp", {}).get("Start")
            if reboot_start_time and reboot_start_time != "N/A" and marker_start_time:
                time_data["time_taken"] = (_parse_timestamp(marker_start_time) -
                                           _parse_timestamp(reboot_start_time)).total_seconds()
            else:
                time_data["time_taken"] = "N/A"

        if reboot_oper and not isinstance(reboot_oper, str):
            reboot_oper = type(reboot_oper).__name__
        get_data_plane_report(analyze_result, reboot_type,
                              log_dir, reboot_oper)
        result_summary = get_report_summary(
            duthost, analyze_result, reboot_type, reboot_oper, base_os_version)
        logging.info(json.dumps(analyze_result, indent=4))
        logging.info(json.dumps(result_summary, indent=4))
        if reboot_oper:
            report_file_name = request.node.name + "_" + reboot_oper + "_report.json"
            summary_file_name = request.node.name + "_" + reboot_oper + "_summary.json"
        else:
            report_file_name = request.node.name + "_report.json"
            summary_file_name = request.node.name + "_summary.json"

        report_file_dir = os.path.realpath((os.path.join(os.path.dirname(__file__),
                                           "../../logs/platform_tests/")))
        report_file_path = report_file_dir + "/" + report_file_name
        summary_file_path = report_file_dir + "/" + summary_file_name
        if not os.path.exists(report_file_dir):
            os.makedirs(report_file_dir)
        with open(report_file_path, 'w') as fp:
            json.dump(analyze_result, fp, indent=4)
        with open(summary_file_path, 'w') as fp:
            json.dump(result_summary, fp, indent=4)

        # After generating timing data report, do some checks on the timing data
        verification_errors = list()
        verify_mac_jumping(test_name, analyze_result, verification_errors)
        if duthost.facts['platform'] != 'x86_64-kvm_x86_64-r0':
            # TBD: expand this verification to KVM - extra port events in KVM which need to be filtered
            verify_required_events(
                duthost, event_counters, analyze_result, verification_errors)
        return verification_errors

    return pre_reboot_analysis, post_reboot_analysis


@pytest.fixture()
def advanceboot_loganalyzer(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
    """
    Advance reboot log analysis.
    This fixture starts log analysis at the beginning of the test. At the end,
    the collected expect messages are verified and timing of start/stop is calculated.

    Args:
        duthosts : List of DUT hosts
        enum_rand_one_per_hwsku_frontend_hostname: hostname of a randomly selected DUT
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Currently, advanced reboot test would skip for kvm platform if the test has no device_type marker for vs.
    # Doing the same skip logic in this fixture to avoid running loganalyzer without the test executed
    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        device_marks = [arg for mark in request.node.iter_markers(
            name='device_type') for arg in mark.args]
        if 'vs' not in device_marks:
            pytest.skip('Testcase not supported for kvm')

    pre_reboot_analysis, post_reboot_analysis = advanceboot_loganalyzer_factory(duthost, request)
    yield pre_reboot_analysis, post_reboot_analysis


@pytest.fixture()
def multihop_advanceboot_loganalyzer_factory(duthosts, enum_rand_one_per_hwsku_frontend_hostname, request):
    """
    Advance reboot log analysis involving multiple hops.
    This fixture returns a factory function requiring the hop_index to be supplied.
    Then, it starts log analysis at the beginning of the test. At the end,
    the collected expect messages are verified and timing of start/stop is calculated.

    Args:
        duthosts : List of DUT hosts
        enum_rand_one_per_hwsku_frontend_hostname: hostname of a randomly selected DUT
        request: pytests request fixture
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Currently, advanced reboot test would skip for kvm platform if the test has no device_type marker for vs.
    # Doing the same skip logic in this fixture to avoid running loganalyzer without the test executed
    if duthost.facts['platform'] == 'x86_64-kvm_x86_64-r0':
        device_marks = [arg for mark in request.node.iter_markers(
            name='device_type') for arg in mark.args]
        if 'vs' not in device_marks:
            pytest.skip('Testcase not supported for kvm')

    def _multihop_advanceboot_loganalyzer_factory(hop_index):
        pre_reboot_analysis, post_reboot_analysis = advanceboot_loganalyzer_factory(
            duthost, request, marker_postfix="hop-{}".format(hop_index))
        return pre_reboot_analysis, post_reboot_analysis

    yield _multihop_advanceboot_loganalyzer_factory


@pytest.fixture()
def advanceboot_neighbor_restore(duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts, tbinfo):
    """
    This fixture is invoked at the test teardown for advanced-reboot SAD cases.
    If a SAD case fails or crashes for some reason, the neighbor VMs can be left in
    a bad state. This fixture will restore state of neighbor interfaces, portchannels
    and BGP sessions that were shutdown during the test.
    """
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    from tests.common.plugins.sanity_check.recover import neighbor_vm_restore
    neighbor_vm_restore(duthost, nbrhosts, tbinfo)


@pytest.fixture(scope='function')
def start_platform_api_service(duthosts, enum_rand_one_per_hwsku_hostname,
                               localhost, request):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost_mgmt_info = duthost.get_mgmt_ip()
    dut_ip = duthost_mgmt_info['mgmt_ip']
    dut_mgmt_ver = duthost_mgmt_info['version']

    res = localhost.wait_for(host=dut_ip,
                             port=SERVER_PORT,
                             state='started',
                             delay=1,
                             timeout=10,
                             module_ignore_errors=True)
    if res['failed'] is True:

        res = duthost.command('docker exec -i pmon python3 -c "import sonic_platform"', module_ignore_errors=True)
        py3_platform_api_available = not res['failed']

        supervisor_conf = [
            '[program:platform_api_server]',
            'command=/usr/bin/python{} /opt/platform_api_server.py --port {} {}'.format(
                '3' if py3_platform_api_available else '2',
                SERVER_PORT,
                '--ipv6' if dut_mgmt_ver == 'v6' else ''),
            'autostart=True',
            'autorestart=True',
            'stdout_logfile=syslog',
            'stderr_logfile=syslog',
            'startsec=0',
        ]
        dest_path = os.path.join(os.sep, 'tmp', 'platform_api_server.conf')
        pmon_path = os.path.join(os.sep, 'etc', 'supervisor', 'conf.d', 'platform_api_server.conf')
        duthost.copy(content='\n'.join(supervisor_conf), dest=dest_path)
        duthost.command('docker cp {} pmon:{}'.format(dest_path, pmon_path))

        src_path = os.path.join('common', 'helpers', 'platform_api', 'scripts', SERVER_FILE)
        dest_path = os.path.join(os.sep, 'tmp', SERVER_FILE)
        pmon_path = os.path.join(os.sep, 'opt', SERVER_FILE)
        duthost.copy(src=src_path, dest=dest_path)
        duthost.command('docker cp {} pmon:{}'.format(dest_path, pmon_path))

        # Prepend an iptables rule to allow incoming traffic to the HTTP server
        if dut_mgmt_ver == 'v6':
            duthost.command(IP6TABLES_PREPEND_RULE_CMD)
        else:
            duthost.command(IPTABLES_PREPEND_RULE_CMD)

        # Reload the supervisor config and Start the HTTP server
        duthost.command('docker exec -i pmon supervisorctl reread')
        duthost.command('docker exec -i pmon supervisorctl update')

        res = localhost.wait_for(host=dut_ip, port=SERVER_PORT, state='started', delay=1, timeout=10)
        assert res['failed'] is False


@pytest.fixture(scope='function')
def platform_api_conn(duthosts, enum_rand_one_per_hwsku_hostname, start_platform_api_service):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_ip = duthost.get_mgmt_ip()["mgmt_ip"]

    conn = http.client.HTTPConnection(dut_ip, 8000)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture(scope='module')
def add_platform_api_server_port_nat_for_dpu(
        ansible_adhoc, tbinfo, request, duthosts, enum_rand_one_per_hwsku_hostname):  # noqa: F811
    '''
    This fixture is used to add a NAT rule to the DPU's eth0-midplane interface
    to forward traffic from NPU to the platform API server on DPU.
    It is used to test the platform API test on DPU of the Smartswitch.
    The NAT rule is added before the test and removed after the test.
    '''
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_dpu"):
        ip_interface_status = duthost.show_and_parse('show ip interface')
        for item in ip_interface_status:
            if item['interface'] == "eth0-midplane":
                dpu_ip = item['ipv4 address/mask'].split('/')[0]
                logger.info(f'Found DPU IP {dpu_ip} for {duthost.hostname}')
                break
        npu_host = create_npu_host_based_on_dpu_info(ansible_adhoc, tbinfo, request, duthost)
        npu_host.command(
            f'sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport \
            {SERVER_PORT} -j DNAT --to-destination {dpu_ip}:{SERVER_PORT}')

    yield

    if duthost.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_dpu"):
        npu_host.command(
            f'sudo iptables -t nat -D PREROUTING -i eth0 -p tcp --dport \
                {SERVER_PORT} -j DNAT --to-destination {dpu_ip}:{SERVER_PORT}')


def get_ansible_ssh_port(duthost, ansible_adhoc):  # noqa: F811
    host = ansible_adhoc(become=True, args=[], kwargs={})[duthost.hostname]
    vm = host.options["inventory_manager"].get_host(duthost.hostname).vars
    ansible_ssh_port = vm.get("ansible_ssh_port", None)
    logger.info(f'ansible_ssh_port for {duthost.hostname} is {ansible_ssh_port}')
    return ansible_ssh_port


def create_npu_host_based_on_dpu_info(ansible_adhoc, tbinfo, request, duthost):  # noqa: F811
    '''
    Create a NPU host object based on DPU info
    E.g
    when one smartswitch setup has following devices:
    smartswitch-01
    smartswitch-01-dpu-0
    smartswitch-01-dpu-1
    smartswitch-01-dpu-2
    smartswitch-01-dpu-3
    when we want run the platform api test on dpu, we pass smartswitch-01-dpu-0 to host-pattern,
    then we can find the NPU host smartswitch-01 from the setup info,
    and then create a NPU host object based on the info
    '''
    for dut in tbinfo['duts']:
        npu_host_name = None
        if 'dpu' not in dut and dut in duthost.hostname:
            npu_host_name = dut
            logger.info(f'Found NPU hostname {npu_host_name} for {duthost.hostname}')
            break
    if npu_host_name is None:
        pytest.fail('No NPU host found in testbed')
    npu_host = DutHosts(ansible_adhoc, tbinfo, request, npu_host_name)[0]
    return npu_host


def get_dpu_ip(duthost, dpu_index):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    if not config_facts:
        logging.error("Failed to retrieve config_facts from DUT")
        return None

    dhcp_server_ipv4_port = config_facts.get('DHCP_SERVER_IPV4_PORT', {})
    if not dhcp_server_ipv4_port:
        logging.error("DHCP_SERVER_IPV4_PORT not found in config_facts")
        return None

    # Navigate through the nested structure: bridge-midplane -> dpu{index} -> ips
    bridge_midplane = dhcp_server_ipv4_port.get('bridge-midplane', {})
    if not bridge_midplane:
        logging.error("bridge-midplane not found in DHCP_SERVER_IPV4_PORT")
        return None

    dpu_config = bridge_midplane.get('dpu{}'.format(dpu_index), {})
    if not dpu_config:
        logging.error("dpu{} not found in bridge-midplane".format(dpu_index))
        return None

    ips = dpu_config.get('ips', [])
    if not ips:
        logging.error("IP address not found in config_facts for dpu_index {}".format(dpu_index))
        return None

    # Take the first IP and remove any CIDR notation
    ip = ips[0]
    return ip.split('/')[0]


def get_dpu_port(duthost, dpu_index):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    if not config_facts:
        logger.error("Failed to retrieve config_facts from DUT")
        return None

    dpu_section = config_facts.get('DPU', {})
    if not dpu_section:
        logger.error("DPU section not found in config_facts")
        return None

    dpu_key = 'dpu{}'.format(dpu_index)
    # Check if the DPU exists in the configuration
    if dpu_key not in dpu_section:
        logger.error("DPU '{}' not found in config_facts. Available DPUs: {}".format(
            dpu_key, list(dpu_section.keys())))
        return None

    dpu_config = dpu_section[dpu_key]
    port = dpu_config.get('gnmi_port', None)
    if port is None:
        logger.error("gnmi_port not found in config_facts for dpu_index {}".format(dpu_index))
        return None
    return port


def check_dpu_reachable_from_npu(duthost, dpuhost_name, dpu_index):
    # Check DPU ping status
    logging.info("Checking DPU ping status")
    dpu_ip = get_dpu_ip(duthost, dpu_index)
    if not dpu_ip:
        logging.error(f"Failed to retrieve IP address for DPU {dpuhost_name}")
        return False

    ping_status = duthost.command(f"ping -c 3 {dpu_ip}", module_ignore_errors=True)
    if ping_status['rc'] != 0:
        logging.error(f"Failed to ping DPU {dpuhost_name} at IP {dpu_ip}")
        return False
    return True


def reboot_dpu_and_wait_for_start_up(duthost, dpuhost_name, dpu_index):
    logging.info(f"Rebooting DPU {dpuhost_name} (DPU index: {dpu_index})")
    reboot_status = duthost.command(f"sudo reboot -d dpu{dpu_index}")
    if reboot_status['rc'] != 0:
        logging.error(f"Failed to initiate reboot for DPU {dpuhost_name} (DPU index: {dpu_index}). "
                      f"Command output: {reboot_status}")
        return False

    logging.info(f"DPU {dpuhost_name} (DPU index: {dpu_index}) reboot initiated successfully")

    # Wait until the system is back up
    wait_until(180, 15, 0, check_dpu_reachable_from_npu, duthost, dpuhost_name, dpu_index)
    is_dpu_reachable = check_dpu_reachable_from_npu(duthost, dpuhost_name, dpu_index)
    if not is_dpu_reachable:
        logging.error(f"DPU {dpuhost_name} (DPU index: {dpu_index}) is not reachable from NPU after reboot")
        return False

    return True
