import pytest
import random
import time
import logging
import re
import json

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.common.gcu_utils import generate_tmpfile, create_checkpoint, \
    apply_patch, expect_op_success, delete_tmpfile, \
    rollback_or_reload, delete_checkpoint
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import check_link_status
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.dhcp_relay.dhcp_relay_utils import check_routes_to_dhcp_server, restart_dhcp_service

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(rand_one_dut_hostname, loganalyzer):
    """Ignore expected failures logs during test execution."""
    if loganalyzer:
        ignoreRegex = [
            r".*ERR snmp#snmp-subagent.*",
            r".*ERR rsyslogd: omfwd: socket (\d+): error (\d+) sending via udp: Network is (unreachable|down).*",
            r".*ERR rsyslogd: omfwd/udp: socket (\d+): sendto\(\) error: Network is (unreachable|down).*"
        ]
        loganalyzer[rand_one_dut_hostname].ignore_regex.extend(ignoreRegex)

    yield


def check_interface_status(duthost):
    if ":67" in duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcrelay",
                              module_ignore_errors=True)["stdout"]:
        return True

    return False


def query_dhcpcom_relay_counter_result(duthost, query_key):
    '''
    Query the DHCPv4 counters from the COUNTERS_DB by the given key.
    The returned value is a dictionary and the counter values are converted to integers.

    Example return value:
    {"TX": {"Unknown": 0, "Discover": 48, "Offer": 0, "Request": 96, "Decline": 0, "Ack": 0, "Nak": 0, "Release": 0,
    "Inform": 0, "Bootp": 48}, "RX": {"Unknown": 0, "Discover": 0, "Offer": 1, "Request": 0, "Decline": 0, "Ack": 1,
    "Nak": 0, "Release": 0, "Inform": 0, "Bootp": 0}}
    '''
    counters_query_string = 'sonic-db-cli COUNTERS_DB hgetall "DHCPV4_COUNTER_TABLE:{key}"'
    shell_result = json.loads(
        duthost.shell(counters_query_string.format(key=query_key))['stdout'].replace("\"", "").replace("'", "\"")
    )
    return {
        rx_or_tx: {
            dhcp_type: int(counter_value) for dhcp_type, counter_value in counters.items()
        } for rx_or_tx, counters in shell_result.items()}


def query_and_sum_dhcpcom_relay_counters(duthost, vlan_name, interface_name_list):
    """Format the counters output for the given VLAN and interface names."""
    if interface_name_list is None or len(interface_name_list) == 0:
        # If no interface names are provided, return the counters for the VLAN interface only.
        return query_dhcpcom_relay_counter_result(duthost, vlan_name)
    total_counters = {}
    # If interface names are provided, sum all of the provided interface names' counters
    for interface_name in interface_name_list:
        internal_shell_result = query_dhcpcom_relay_counter_result(duthost, vlan_name + ":" + interface_name)
        for rx_or_tx, counters in internal_shell_result.items():
            total_value = total_counters.setdefault(rx_or_tx, {})
            for dhcp_type, counter_value in counters.items():
                total_value[dhcp_type] = total_value.get(dhcp_type, 0) + counter_value
    return total_counters


def compare_dhcpcom_relay_counter_values(dhcp_relay_counter, send_ack=0, send_bootp=0, send_decline=0,
                                         send_discover=0, send_inform=0, send_nak=0, send_offer=0,
                                         send_release=0, send_request=0, send_unknown=0, receive_ack=0,
                                         receive_bootp=0, receive_decline=0, receive_discover=0,
                                         receive_inform=0, receive_nak=0, receive_offer=0,
                                         receive_release=0, receive_request=0, receive_unknown=0):
    """Compare the DHCP relay counter value with the expected values."""
    pytest_assert(
        dhcp_relay_counter['TX']['Ack'] == send_ack,
        "DHCP relay TX Ack counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Ack'], send_ack
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Bootp'] == send_bootp,
        "DHCP relay TX Bootp counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Bootp'], send_bootp
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Decline'] == send_decline,
        "DHCP relay TX Decline counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Decline'], send_decline
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Discover'] == send_discover,
        "DHCP relay TX Discover counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Discover'], send_discover
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Inform'] == send_inform,
        "DHCP relay TX Inform counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Inform'], send_inform
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Nak'] == send_nak,
        "DHCP relay TX Nak counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Nak'], send_nak
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Offer'] == send_offer,
        "DHCP relay TX Offer counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Offer'], send_offer
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Release'] == send_release,
        "DHCP relay TX Release counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Release'], send_release
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Request'] == send_request,
        "DHCP relay TX Request counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Request'], send_request
        )
    )
    pytest_assert(
        dhcp_relay_counter['TX']['Unknown'] == send_unknown,
        "DHCP relay TX Unknown counter value is {}, expected {}".format(
            dhcp_relay_counter['TX']['Unknown'], send_unknown
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Ack'] == receive_ack,
        "DHCP relay RX Ack counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Ack'], receive_ack
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Bootp'] == receive_bootp,
        "DHCP relay RX Bootp counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Bootp'], receive_bootp
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Decline'] == receive_decline,
        "DHCP relay RX Decline counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Decline'], receive_decline
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Discover'] == receive_discover,
        "DHCP relay RX Discover counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Discover'], receive_discover
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Inform'] == receive_inform,
        "DHCP relay RX Inform counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Inform'], receive_inform
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Nak'] == receive_nak,
        "DHCP relay RX Nak counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Nak'], receive_nak
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Offer'] == receive_offer,
        "DHCP relay RX Offer counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Offer'], receive_offer
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Release'] == receive_release,
        "DHCP relay RX Release counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Release'], receive_release
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Request'] == receive_request,
        "DHCP relay RX Request counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Request'], receive_request
        )
    )
    pytest_assert(
        dhcp_relay_counter['RX']['Unknown'] == receive_unknown,
        "DHCP relay RX Unknown counter value is {}, expected {}".format(
            dhcp_relay_counter['RX']['Unknown'], receive_unknown
        )
    )


def validate_dhcpcom_relay_counters(dhcp_relay, duthost):
    """Validate the dhcpcom relay counters"""
    downlink_vlan_iface = dhcp_relay['downlink_vlan_iface']['name']
    # it can be portchannel or interface, it depends on the topology
    uplink_portchannels_or_interfaces = dhcp_relay['uplink_interfaces']
    client_iface = dhcp_relay['client_iface']['name']
    dhcp_server_sum = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
    portchannels = dhcp_relay['portchannels']

    '''
    If the uplink_portchannels_or_interfaces are portchannels,
        uplink_interfaces will contains the members of the portchannels
    If the uplink_portchannels_or_interfaces are not portchannels,
        uplink_interfaces will equal to uplink_portchannels_or_interfaces
    '''
    uplink_interfaces = []
    for portchannel_name in uplink_portchannels_or_interfaces:
        if portchannel_name in portchannels.keys():
            uplink_interfaces.extend(portchannels[portchannel_name]['members'])
        else:
            uplink_interfaces.append(portchannel_name)

    vlan_interface_counter = query_and_sum_dhcpcom_relay_counters(duthost, downlink_vlan_iface, [])
    client_interface_counter = query_and_sum_dhcpcom_relay_counters(duthost, downlink_vlan_iface, [client_iface])
    uplink_portchannels_interfaces_counter = query_and_sum_dhcpcom_relay_counters(
        duthost, downlink_vlan_iface, uplink_portchannels_or_interfaces
    )
    uplink_interface_counter = query_and_sum_dhcpcom_relay_counters(duthost, downlink_vlan_iface, uplink_interfaces)

    assert vlan_interface_counter == client_interface_counter
    assert uplink_interface_counter == uplink_portchannels_interfaces_counter
    compare_dhcpcom_relay_counter_values(vlan_interface_counter,
                                         send_ack=1, send_offer=1, receive_bootp=1,
                                         receive_discover=1, receive_request=2)
    compare_dhcpcom_relay_counter_values(uplink_interface_counter,
                                         send_bootp=dhcp_server_sum, send_discover=dhcp_server_sum,
                                         send_request=dhcp_server_sum * 2, receive_ack=1, receive_offer=1)


def init_dhcpcom_relay_counters(duthost):
    command_output = duthost.shell("sudo sonic-clear dhcp_relay ipv4 counters")
    pytest_assert("Clear DHCPv4 relay counter done" == command_output["stdout"],
                  "dhcp_relay counters are not cleared successfully, output: {}".format(command_output["stdout"]))


@pytest.fixture(scope="function")
def enable_source_port_ip_in_relay(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    """
    Enable source port ip in relay function
    -si parameter(Enable source port ip in relay function) will be added if deployment_id is '8', ref:
    https://github.com/sonic-net/sonic-buildimage/blob/e0e0c0c1b3c58635bc25fde6a77ca3b0849dfde1/dockers/docker-dhcp-relay/dhcpv4-relay.agents.j2#L16
    """

    json_patch = [
        {
            "op": "replace",
            "path": "/DEVICE_METADATA/localhost/deployment_id",
            "value": "8"
        }
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))
    check_point = "dhcp_relay"
    try:
        create_checkpoint(duthost, check_point)
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)
        restart_dhcp_service(duthost)

        def dhcp_ready(enable_source_port_ip_in_relay):
            dhcp_relay_running = duthost.is_service_fully_started("dhcp_relay")
            dhcp_relay_process = duthost.shell("ps -ef |grep dhcrelay|grep -v grep",
                                               module_ignore_errors=True)["stdout"]
            dhcp_mon_process = duthost.shell("ps -ef |grep dhcpmon|grep -v grep",
                                             module_ignore_errors=True)["stdout"]
            dhcp_mon_process_running = "dhcpmon" in dhcp_mon_process
            if enable_source_port_ip_in_relay:
                dhcp_relay_process_ready = "-si" in dhcp_relay_process and "dhcrelay" in dhcp_relay_process
            else:
                dhcp_relay_process_ready = "-si" not in dhcp_relay_process and "dhcrelay" in dhcp_relay_process
            return dhcp_relay_running and dhcp_relay_process_ready and dhcp_mon_process_running
        pytest_assert(wait_until(60, 2, 0, dhcp_ready, True), "Source port ip in relay is not enabled!")
        yield
    finally:
        delete_tmpfile(duthost, tmpfile)
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost, check_point)
        delete_checkpoint(duthost, check_point)
        restart_dhcp_service(duthost)
        pytest_assert(wait_until(60, 2, 0, dhcp_ready, False), "Source port ip in relay is not disabled!")


def test_interface_binding(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data):
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, ["201811", "201911", "202106"])
    if not check_interface_status(duthost):
        config_reload(duthost)
        wait_critical_processes(duthost)
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost))
    output = duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcrelay", module_ignore_errors=True)["stdout"]
    logger.info(output)
    for dhcp_relay in dut_dhcp_relay_data:
        assert "{}:67".format(dhcp_relay['downlink_vlan_iface']['name']) in output, \
            "{} is not found in {}".format("{}:67".format(dhcp_relay['downlink_vlan_iface']['name']), output)
        for iface in dhcp_relay['uplink_interfaces']:
            assert "{}:67".format(iface) in output, "{} is not found in {}".format("{}:67".format(iface), output)


def start_dhcp_monitor_debug_counter(duthost):
    program_name = "dhcpmon"
    program_pid_list = []
    program_list = duthost.shell("ps aux | grep {}".format(program_name))
    matches = re.findall(r'/usr/sbin/dhcpmon.*', program_list["stdout"])

    for program_info in program_list["stdout_lines"]:
        if program_name in program_info:
            program_pid = int(program_info.split()[1])
            program_pid_list.append(program_pid)

    for program_pid in program_pid_list:
        kill_cmd_result = duthost.shell("sudo kill {} || true".format(program_pid), module_ignore_errors=True)
        # Get the exit code of 'kill' command
        exit_code = kill_cmd_result["rc"]
        if exit_code != 0:
            stderr = kill_cmd_result.get("stderr", "")
            if "No such process" not in stderr:
                pytest.fail("Failed to stop program '{}' before test. Error: {}".format(program_name, stderr))

    if matches:
        for dhcpmon_cmd in matches:
            if "-D" not in dhcpmon_cmd:
                dhcpmon_cmd += " -D"
            duthost.shell("docker exec -d dhcp_relay %s" % dhcpmon_cmd)
    else:
        assert False, "Failed to start dhcpmon in debug counter mode\n"


def get_acl_count_by_mark(rand_unselected_dut, mark):
    output = rand_unselected_dut.shell("iptables -nvL DHCP | grep 'DROP' | grep '{}' | awk '{{print $1}}'"
                                       .format(mark))
    pytest_assert(output["rc"] == 0 and len(output["stdout_lines"]) == 1,
                  "Failed get DHCP acl count for {}, err: {}".format(mark, output["stderr"]))
    return int(output["stdout"].strip())


@pytest.fixture(scope="function")
def verify_acl_drop_on_standby_tor(rand_unselected_dut, dut_dhcp_relay_data, testing_config, tbinfo):
    testing_mode, _ = testing_config
    if testing_mode == DUAL_TOR_MODE and "dualtor-aa" not in tbinfo["topo"]["name"]:
        pre_client_dhcp_acl_counts = {}
        for dhcp_relay in dut_dhcp_relay_data:
            client_interface_name = dhcp_relay["client_iface"]["name"]
            # Get acl mark per interface
            output = (rand_unselected_dut
                      .shell(r"ebtables -L INPUT | grep '\-i {} \-j mark \-\-mark\-set' | awk '{{print $6}}'"
                             .format(client_interface_name)))
            pytest_assert(output["rc"] == 0 and len(output["stdout_lines"]) == 1,
                          "Failed get DHCP acl mark for {}, err: {}".format(client_interface_name, output["stderr"]))
            mark = output["stdout"].strip()
            pre_client_dhcp_acl_counts[client_interface_name] = {"mark": mark}
            # Get acl count by acl mark
            pre_client_dhcp_acl_counts[client_interface_name]["count"] = get_acl_count_by_mark(rand_unselected_dut,
                                                                                               mark)

    yield

    if testing_mode == DUAL_TOR_MODE and "dualtor-aa" not in tbinfo["topo"]["name"]:
        for client_interface_name, item in pre_client_dhcp_acl_counts.items():
            after_count = get_acl_count_by_mark(rand_unselected_dut, item["mark"])
            pytest_assert(after_count == item["count"] + 3, "Drop count of {} {} is unexpected, pre: {}, after: {}"
                          .format(client_interface_name, item["mark"], item["count"], after_count))


def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,												# noqa F811
                            rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m,    # noqa F811
                            verify_acl_drop_on_standby_tor):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """

    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    skip_dhcpmon = any(vers in duthost.os_version for vers in ["201811", "201911", "202111"])

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            if not skip_dhcpmon:
                dhcp_server_num = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                if testing_mode == DUAL_TOR_MODE:
                    standby_duthost = rand_unselected_dut
                    start_dhcp_monitor_debug_counter(standby_duthost)
                    init_dhcpcom_relay_counters(standby_duthost)
                    expected_standby_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +0/ +0, Offer: +0/ +0, Request: +0/ +0, ACK: +0/ +0+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'])
                    loganalyzer_standby = LogAnalyzer(ansible_host=standby_duthost, marker_prefix="dhcpmon counter")
                    marker_standby = loganalyzer_standby.init()
                    loganalyzer_standby.expect_regex = [expected_standby_agg_counter_message]
                start_dhcp_monitor_debug_counter(duthost)
                init_dhcpcom_relay_counters(duthost)
                if testing_mode == DUAL_TOR_MODE:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +1/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num)
                else:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +2/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num * 2)
                loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcpmon counter")
                marker = loganalyzer.init()
                loganalyzer.expect_regex = [expected_agg_counter_message]

            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
                               # This port is introduced to test DHCP relay packet received
                               # on other client port
                               "other_client_port": repr(dhcp_relay['other_client_ports']),
                               "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                               "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                               "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                               "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                               "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                               "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                               "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                               "dest_mac_address": BROADCAST_MAC,
                               "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                               "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                               "uplink_mac": str(dhcp_relay['uplink_mac']),
                               "testing_mode": testing_mode,
                               "kvm_support": True},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.default.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)
            if not skip_dhcpmon:
                time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)
                validate_dhcpcom_relay_counters(dhcp_relay, duthost)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    if not skip_dhcpmon:
        # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
        restart_dhcp_service(duthost)
        if testing_mode == DUAL_TOR_MODE:
            restart_dhcp_service(standby_duthost)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost))
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost))


def test_dhcp_relay_with_source_port_ip_in_relay_enabled(ptfhost, dut_dhcp_relay_data,
                                                         validate_dut_routes_exist, testing_config,
                                                         setup_standby_ports_on_rand_unselected_tor,												# noqa F811
                                                         rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
                                                         enable_source_port_ip_in_relay, verify_acl_drop_on_standby_tor):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    skip_dhcpmon = any(vers in duthost.os_version for vers in ["201811", "201911", "202111"])

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            if not skip_dhcpmon:
                dhcp_server_num = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                if testing_mode == DUAL_TOR_MODE:
                    standby_duthost = rand_unselected_dut
                    start_dhcp_monitor_debug_counter(standby_duthost)
                    expected_standby_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +0/ +0, Offer: +0/ +0, Request: +0/ +0, ACK: +0/ +0+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'])
                    loganalyzer_standby = LogAnalyzer(ansible_host=standby_duthost, marker_prefix="dhcpmon counter")
                    marker_standby = loganalyzer_standby.init()
                    loganalyzer_standby.expect_regex = [expected_standby_agg_counter_message]
                start_dhcp_monitor_debug_counter(duthost)
                if testing_mode == DUAL_TOR_MODE:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +1/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num)
                else:
                    expected_agg_counter_message = (
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                        r"Discover: +1/ +%d, Offer: +1/ +1, Request: +2/ +%d, ACK: +1/ +1+"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num * 2)
                loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcpmon counter")
                marker = loganalyzer.init()
                loganalyzer.expect_regex = [expected_agg_counter_message]

            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
                               # This port is introduced to test DHCP relay packet received
                               # on other client port
                               "other_client_port": repr(dhcp_relay['other_client_ports']),
                               "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                               "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                               "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                               "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                               "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                               "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                               "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                               "dest_mac_address": BROADCAST_MAC,
                               "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                               "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                               "uplink_mac": str(dhcp_relay['uplink_mac']),
                               "testing_mode": testing_mode,
                               "enable_source_port_ip_in_relay": True,
                               "kvm_support": True},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.src_ip.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)
            if not skip_dhcpmon:
                time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    if not skip_dhcpmon:
        # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
        restart_dhcp_service(duthost)
        if testing_mode == DUAL_TOR_MODE:
            restart_dhcp_service(standby_duthost)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost))
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost))


def test_dhcp_relay_after_link_flap(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config):
    """Test DHCP relay functionality on T0 topology after uplinks flap
       For each DHCP relay agent running on the DuT, with relay agent running, flap the uplinks,
       then test whether the DHCP relay agent relays packets properly.
    """
    testing_mode, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface shutdown {}'.format(iface))

        pytest_assert(wait_until(50, 5, 0, check_link_status, duthost, dhcp_relay['uplink_interfaces'], "down"),
                      "Not all uplinks go down")

        # Bring all uplink interfaces back up
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface startup {}'.format(iface))

        # Wait until uplinks are up and routes are recovered
        pytest_assert(wait_until(50, 5, 0, check_routes_to_dhcp_server, duthost, dut_dhcp_relay_data),
                      "Not all DHCP servers are routed")

        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.link_flap.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def test_dhcp_relay_start_with_uplinks_down(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config):
    """Test DHCP relay functionality on T0 topology when relay agent starts with uplinks down
       For each DHCP relay agent running on the DuT, bring the uplinks down, then restart the
       relay agent while the uplinks are still down. Then test whether the DHCP relay agent
       relays packets properly.
    """
    testing_mode, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface shutdown {}'.format(iface))

        pytest_assert(wait_until(50, 5, 0, check_link_status, duthost, dhcp_relay['uplink_interfaces'], "down"),
                      "Not all uplinks go down")

        # Restart DHCP relay service on DUT
        # dhcp_relay service has 3 times restart limit in 20 mins, for 4 vlans config it will hit the maximum limit
        # reset-failed before restart service
        cmds = ['systemctl reset-failed dhcp_relay', 'systemctl restart dhcp_relay']
        duthost.shell_cmds(cmds=cmds)

        # Sleep to give the DHCP relay container time to start up and
        # allow the relay agent to begin listening on the down interfaces
        time.sleep(40)

        # Bring all uplink interfaces back up
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('config interface startup {}'.format(iface))

        # Wait until uplinks are up and routes are recovered
        pytest_assert(wait_until(50, 5, 0, check_routes_to_dhcp_server, duthost, dut_dhcp_relay_data),
                      "Not all DHCP servers are routed")

        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.uplinks_down.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def test_dhcp_relay_unicast_mac(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                setup_standby_ports_on_rand_unselected_tor,				 # noqa F811
                                toggle_all_simulator_ports_to_rand_selected_tor_m):     # noqa F811
    """Test DHCP relay functionality on T0 topology with unicast mac
       Instead of using broadcast MAC, use unicast MAC of DUT and verify that DHCP relay functionality is entact.
    """
    testing_mode, duthost = testing_config

    if len(dut_dhcp_relay_data) > 1:
        pytest.skip("skip the unicast mac testcase in the multi-Vlan setting")

    for dhcp_relay in dut_dhcp_relay_data:
        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": duthost.facts["router_mac"] if testing_mode != DUAL_TOR_MODE
                                else str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.unicast_mac.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def test_dhcp_relay_random_sport(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                 setup_standby_ports_on_rand_unselected_tor,				 # noqa F811
                                 toggle_all_simulator_ports_to_rand_selected_tor_m,     # noqa F811
                                 verify_acl_drop_on_standby_tor):    # noqa F811
    """Test DHCP relay functionality on T0 topology with random source port (sport)
       If the client is SNAT'd, the source port could be changed to a non-standard port (i.e., not 68).
       Verify that DHCP relay works with random high sport.
    """
    testing_mode, duthost = testing_config

    RANDOM_CLIENT_PORT = random.choice(list(range(1000, 65535)))
    for dhcp_relay in dut_dhcp_relay_data:
        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": RANDOM_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.random_sport.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


def get_dhcp_relay_counter(duthost, ifname, type, dir):
    # counter table
    # sonic-db-cli STATE_DB hgetall 'DHCP_COUNTER_TABLE|Vlan1000'
    # {'RX': "{'Unknown':'0','Discover':'0','Offer':'0','Request':'0','Decline':'0','Ack':'0',
    #  'Nak':'0','Release':'0','Inform':'0'}",'TX': "{'Unknown':'0','Discover':'0','Offer':'0',
    #  'Request':'0','Decline':'0','Ack':'0','Nak':'0','Release':'0','Inform':'0'}"}
    cmd = 'sonic-db-cli STATE_DB hget "DHCP_COUNTER_TABLE|{}" {}'.format(ifname, dir)
    output = duthost.shell(cmd)['stdout']
    if len(output) != 0:
        counters = eval(output)
        if type in counters:
            return int(counters[type])
        return 0
    else:
        return 0


def init_counter(duthost, ifname):
    cmd = 'sonic-db-cli STATE_DB hget "DHCP_COUNTER_TABLE|{}" RX'.format(ifname)
    output = duthost.shell(cmd)['stdout']
    if len(output) != 0:
        counters_str = ("{'Unknown':'0','Discover':'0','Offer':'0','Request':'0','Decline':'0',"
                        "'Ack':'0','Nack':'0','Release':'0','Inform':'0'}")
        cmd = 'sonic-db-cli STATE_DB hmset "DHCP_COUNTER_TABLE|{}" "RX" "{}"'.format(ifname, str(counters_str))
        duthost.shell(cmd)
        cmd = 'sonic-db-cli STATE_DB hmset "DHCP_COUNTER_TABLE|{}" "TX" "{}"'.format(ifname, str(counters_str))
        duthost.shell(cmd)
    else:
        # image does not support STATE_DB counter, ignore
        pytest.skip("skip the dhcpv4 counter testing")


def test_dhcp_relay_counter(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,
                            toggle_all_simulator_ports_to_rand_selected_tor_m):     # noqa F811
    testing_mode, duthost = testing_config

    skip_release(duthost, ["201811", "201911", "202012"])

    # based on message types we currently support in ptftest/py3/dhcp_relay_test.py
    dhcp_message_types = ["Discover", "Offer", "Request", "Ack"]
    for dhcp_relay in dut_dhcp_relay_data:
        init_counter(duthost, dhcp_relay['client_iface']['name'])
        init_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'])
        for iface in dhcp_relay['uplink_interfaces']:
            init_counter(duthost, iface)
        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcp_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                           "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                           "dest_mac_address": BROADCAST_MAC,
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testing_mode": testing_mode,
                           "kvm_support": True},
                   log_file="/tmp/dhcp_relay_test_counter.DHCPTest.log", is_python3=True)
        for type in dhcp_message_types:
            if type in ["Discover", "Request"]:
                cnt = get_dhcp_relay_counter(duthost, dhcp_relay['client_iface']['name'], type, "RX")
                assert cnt >= 1, "{}({}) {} count mismatch, expect >= 1, actual {}".format(
                    dhcp_relay['client_iface']['name'], "RX", type, cnt
                )
                cnt = get_dhcp_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "RX")
                assert cnt >= 1, "{}({}) {} count mismatch, expect >= 1, actual {}".format(
                    dhcp_relay['downlink_vlan_iface']['name'], "RX", type, cnt
                )
                cnt = 0
                for iface in dhcp_relay['uplink_interfaces']:
                    cnt += get_dhcp_relay_counter(duthost, iface, type, "TX")
                assert cnt >= len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']), (
                    "uplink interfaces {} ({}) {} count mismatch, expect >= {}, actual {}").format(
                    dhcp_relay['uplink_interfaces'], "TX", type,
                    len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']), cnt
                )
            if type in ["Offer", "Ack"]:
                cnt = get_dhcp_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "TX")
                assert cnt >= 1, "{}({}) {} count mismatch, expect >= 1, actual {}".format(
                    dhcp_relay['downlink_vlan_iface']['name'], "RX", type, cnt
                )
                cnt = get_dhcp_relay_counter(duthost, dhcp_relay['client_iface']['name'], type, "TX")
                assert cnt >= 1, "{}({}) {} count mismatch, expect >= 1, actual {}".format(
                    dhcp_relay['client_iface']['name'], "TX", type, cnt
                )
