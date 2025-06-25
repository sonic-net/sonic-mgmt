import pytest
import random
import time
import logging
import re

from tests.common.dhcp_relay_utils import init_dhcpcom_relay_counters, validate_dhcpcom_relay_counters
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
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.dhcp_relay.dhcp_relay_utils import check_routes_to_dhcp_server, restart_dhcp_service
from tests.common.fixtures.dhcp_utils import enable_sonic_dhcpv4_relay_agent, check_process_and_socket_status

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

SUPPORTED_DHCPV4_TYPE = [
    "Unknown", "Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform", "Bootp"
]
SUPPORTED_DIR = ["TX", "RX"]


BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'
CLIENT_SENT_PACKET_COUNT = 7
DHCP_SERVER_PORT = 67  # Global macro for DHCP server port

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

def check_interface_status(duthost, relay_agent="isc-relay-agent"):
    if relay_agent == "sonic-relay-agent":
        cmd = "docker exec -t dhcp_relay ss -nlp | grep dhcp4relay"
    else:
        cmd = "docker exec -t dhcp_relay ss -nlp | grep dhcrelay"

    if ":67" in duthost.shell(cmd,
                              module_ignore_errors=True)["stdout"]:
        return True

    return False


@pytest.fixture(scope="function")
def enable_source_port_ip_in_relay(duthosts, rand_one_dut_hostname, tbinfo, request):
    duthost = duthosts[rand_one_dut_hostname]
    
    relay_agent = request.getfixturevalue("relay_agent")

    if relay_agent == "sonic-relay-agent":
        try:
            # Read and cache the original deployment_id
            default_deployment_id = duthost.shell('sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" "deployment_id"'                                    , module_ignore_errors=True)["stdout"].strip()
            duthost.shell('sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "deployment_id" "8"', module_ignore_errors=True)
            yield
        finally:
            duthost.shell('sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "deployment_id" "{default_deployment_id}"', module_ignore_errors=True)
    else:
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

@pytest.mark.parametrize("relay_agent", ["isc-relay-agent"])
def test_interface_binding(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data, relay_agent):
    duthost = duthosts[rand_one_dut_hostname]
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

@pytest.fixture(autouse=True)
def config_dhcp_relay_agent(duthost, dut_dhcp_relay_data, request, enable_sonic_dhcpv4_relay_agent):

   if request.getfixturevalue("relay_agent") == "sonic-relay-agent":
       sonic_dhcp_relay_config(duthost, dut_dhcp_relay_data)
   yield
   if request.getfixturevalue("relay_agent") == "sonic-relay-agent":
       sonic_dhcp_relay_unconfig(duthost, dut_dhcp_relay_data)

def sonic_dhcp_relay_config(duthost, dut_dhcp_relay_data):

    for dhcp_relay in dut_dhcp_relay_data:
        vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
        dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
        duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} {vlan}')

    pytest_assert(wait_until(40, 5, 0, check_process_and_socket_status, duthost, dut_dhcp_relay_data, None))

def sonic_dhcp_relay_unconfig(duthost, dut_dhcp_relay_data):

    for dhcp_relay in dut_dhcp_relay_data:
        vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
        duthost.shell(f'config dhcpv4_relay del {vlan}')

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
        kill_cmd_result = duthost.shell("sudo kill -9 {} || true".format(program_pid), module_ignore_errors=True)
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
            pytest_assert(after_count == item["count"] + CLIENT_SENT_PACKET_COUNT,
                          "Drop count of {} {} is unexpected, pre: {}, after: {}"
                          .format(client_interface_name, item["mark"], item["count"], after_count))

@pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,												# noqa F811
                            rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m,    # noqa F811
                            verify_acl_drop_on_standby_tor, relay_agent):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """

    testing_mode, duthost = testing_config

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
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]:\s+"
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\]\s+"
                        r"Discover:\s+2/\s+%d,\s+Offer:\s+1/\s+1,\s+Request:\s+2/\s+%d,\s+ACK:\s+1/\s+1"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num * 2, dhcp_server_num * 2)
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
                               "kvm_support": True,
                               "relay_agent" : relay_agent,
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.default.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)
            if not skip_dhcpmon:
                time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                dhcp_server_sum = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                dhcp_relay_request_times = 2
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)
                    dhcp_relay_request_times = 1
                    # If the testing mode is DUAL_TOR_MODE, standby tor's dhcpcom relay counters should all be 0
                    validate_dhcpcom_relay_counters(dhcp_relay, standby_duthost, {}, {})
                expected_downlink_counter = {
                    "RX": {"Unknown": 1, "Discover": 1, "Request": dhcp_relay_request_times, "Bootp": 1,
                           "Decline": 1, "Release": 1, "Inform": 1},
                    "TX": {"Unknown": 1, "Ack": 1, "Offer": 1, "Nak": 1}
                }
                expected_uplink_counter = {
                    "RX": {"Unknown": 1, "Nak": 1, "Ack": 1, "Offer": 1},
                    "TX": {"Unknown": dhcp_server_sum, "Bootp": dhcp_server_sum, "Discover": dhcp_server_sum,
                           "Request": dhcp_server_sum * dhcp_relay_request_times, "Inform": dhcp_server_sum,
                           "Decline": dhcp_server_sum, "Release": dhcp_server_sum}
                }
                validate_dhcpcom_relay_counters(dhcp_relay, duthost,
                                                expected_uplink_counter,
                                                expected_downlink_counter)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    if not skip_dhcpmon:
        # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
        restart_dhcp_service(duthost)
        if testing_mode == DUAL_TOR_MODE:
            restart_dhcp_service(standby_duthost)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost, relay_agent))
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost, relay_agent))

@pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
def test_dhcp_relay_with_source_port_ip_in_relay_enabled(ptfhost, dut_dhcp_relay_data,
                                                         validate_dut_routes_exist, testing_config,
                                                         setup_standby_ports_on_rand_unselected_tor,												# noqa F811
                                                         rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
                                                         enable_source_port_ip_in_relay, verify_acl_drop_on_standby_tor, relay_agent):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """
    testing_mode, duthost = testing_config

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
                        r".*dhcp_relay#dhcpmon\[[0-9]+\]:\s+"
                        r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\]\s+"
                        r"Discover:\s+2/\s+%d,\s+Offer:\s+1/\s+1,\s+Request:\s+2/\s+%d,\s+ACK:\s+1/\s+1"
                    ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num * 2, dhcp_server_num * 2)
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
                               "kvm_support": True,
                               "relay_agent" : relay_agent,
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.src_ip.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)

            if not skip_dhcpmon:
                time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                dhcp_server_sum = len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
                dhcp_relay_request_times = 2
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)
                    dhcp_relay_request_times = 1
                    # If the testing mode is DUAL_TOR_MODE, standby tor's dhcpcom relay counters should all be 0
                    validate_dhcpcom_relay_counters(dhcp_relay, standby_duthost, {}, {})
                expected_downlink_counter = {
                    "RX": {"Unknown": 1, "Discover": 1, "Request": dhcp_relay_request_times, "Bootp": 1,
                           "Decline": 1, "Release": 1, "Inform": 1},
                    "TX": {"Unknown": 1, "Ack": 1, "Offer": 1, "Nak": 1}
                }
                expected_uplink_counter = {
                    "RX": {"Unknown": 1, "Nak": 1, "Ack": 1, "Offer": 1},
                    "TX": {"Unknown": dhcp_server_sum, "Bootp": dhcp_server_sum, "Discover": dhcp_server_sum,
                           "Request": dhcp_server_sum * dhcp_relay_request_times, "Inform": dhcp_server_sum,
                           "Decline": dhcp_server_sum, "Release": dhcp_server_sum}
                }
                validate_dhcpcom_relay_counters(dhcp_relay, duthost,
                                                expected_uplink_counter,
                                                expected_downlink_counter)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    if not skip_dhcpmon:
        # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
        restart_dhcp_service(duthost)
        if testing_mode == DUAL_TOR_MODE:
            restart_dhcp_service(standby_duthost)
            pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost, relay_agent))
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost, relay_agent))

@pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
def test_dhcp_relay_after_link_flap(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config, relay_agent):
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
                           "kvm_support": True,
                           "relay_agent" : relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.link_flap.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


@pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
def test_dhcp_relay_start_with_uplinks_down(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config, relay_agent):
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
                           "kvm_support": True,
                           "relay_agent" : relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.uplinks_down.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


@pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
def test_dhcp_relay_unicast_mac(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                setup_standby_ports_on_rand_unselected_tor,				 # noqa F811
                                toggle_all_simulator_ports_to_rand_selected_tor_m, relay_agent):     # noqa F811
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
                           "kvm_support": True,
                           "relay_agent" : relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                   log_file=("/tmp/dhcp_relay_test.DHCPTest.unicast_mac.{}.log"
                             .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                   is_python3=True)


@pytest.mark.parametrize("relay_agent", ["isc-relay-agent"])
def test_dhcp_relay_random_sport(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                 setup_standby_ports_on_rand_unselected_tor,				 # noqa F811
                                 toggle_all_simulator_ports_to_rand_selected_tor_m,     # noqa F811
                                 verify_acl_drop_on_standby_tor, relay_agent):    # noqa F811
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
                           "kvm_support": True,
                           "relay_agent" : relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
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


@pytest.mark.parametrize("relay_agent", ["isc-relay-agent"])
def test_dhcp_relay_counter(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,
                            toggle_all_simulator_ports_to_rand_selected_tor_m, relay_agent):     # noqa F811
    testing_mode, duthost = testing_config
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
                           "kvm_support": True,
                           "relay_agent" : relay_agent,
                           "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
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

@pytest.mark.parametrize("relay_agent", ["sonic-relay-agent"])
@pytest.mark.parametrize("testcase", ["source_intf", "server_id_override"])
def test_dhcp_relay_option82_suboptions(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,                                                  
                            rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m, testcase, relay_agent):

    """
    Test Case: DHCP relay option82

    Purpose:
        Validate DHCP relay functionality when using the default VRF.
        The test runs in multiple modes (source interface injection, server ID override) to verify behavior.

    Key Steps:
        - Configure DHCP relay with appropriate server IPs and test-mode specific parameters.
        - Remove existing relay configurations and reconfigure for this test case.
        - Run PTF test to verify relayed DHCP packet behavior (using Option 82 variations).
        - Validate correct transmission of DHCP Discover/Offer/Request/ACK messages through syslog regex patterns.
        - Clean up relay service to restore original DHCP monitor settings.

    Test Modes:
        - source_intf: Inserts 'source_interface' and 'link_selection' flags in relay config.
        - server_id_override: Enables 'server_id_override' flag to override DHCP server IP in Option 82.

    """

    testing_mode, duthost = testing_config
    link_selection = source_intf = server_id_override = None

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay del {vlan}')
            loopback_iface = dhcp_relay["loopback_iface"]

            # Add test-case specific options
            if testcase == "source_intf":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} --link-selection enable --source-interface {loopback_iface} {vlan}')
                link_selection = True
                source_intf = True
            elif testcase == "server_id_override":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} --server-id-override enable {vlan}')
                server_id_override = True

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
                               "kvm_support": True,
                               "link_selection": link_selection,
                               "source_interface": source_intf,
                               "server_id_override": server_id_override,
                               "relay_agent" : relay_agent,
                               "link_selection_ip":str(dhcp_relay['downlink_vlan_iface']['link_selection_ip']),
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])
                               },
                       log_file="/tmp/test_dhcp_relay_option82_suboptions.DHCPTest.log", is_python3=True)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

@pytest.mark.parametrize("relay_agent", ["sonic-relay-agent"])
@pytest.mark.parametrize("test_mode", [
                                    "discard",
                                    "forward_untouched",
                                    "forward_and_replace",
                                    "forward_and_append"
                                ])
def test_dhcp_relay_agent_mode(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,
                            rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m, relay_agent,
                            test_mode):

    """
    Test Case: DHCP Relay Agent Mode Functionality on T0 Topology

    Purpose:
        Validate the DHCP relay agent's behavior based on different `agent_relay_mode` settings in CONFIG_DB.
        These modes influence how Option 82 (Relay Agent Information Option) is handled when relaying DHCP packets.

    Relay Modes Tested:
        - "discard": Drops packets containing Option 82.
        - "forward_untouched": Forwards packets with Option 82 unmodified.
        - "forward_and_replace": Replaces existing Option 82 with new data before forwarding.
        - "forward_and_append": Appends a new Option 82 to packets that already have it.

    Key Actions:
        - Configures the device under test (DUT) with the selected relay mode.
        - Executes a PTF test to simulate DHCP traffic and validate relay behavior.
        - Cleans up after test by restoring DHCP relay state.

    """

    agent_relay_mode = True
    agent_relay_discard_mode = agent_relay_forward_and_append_mode = None
    agent_relay_forward_and_replace_mode = agent_relay_forward_untouched_mode = None
    testing_mode, duthost = testing_config

    try:
        for dhcp_relay in dut_dhcp_relay_data:

            vlan = str(dhcp_relay['downlink_vlan_iface']['name'])
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay del {vlan}')

            # Update CONFIG_DB
            duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} --agent-relay-mode {test_mode} {vlan}')

            if test_mode == "discard":
                agent_relay_discard_mode = True
            elif test_mode == "forward_untouched":
                agent_relay_forward_untouched_mode = True
            elif test_mode == "forward_and_replace":
                agent_relay_forward_and_replace_mode = True
            elif test_mode == "forward_and_append":
                agent_relay_forward_and_append_mode = True

            # Run PTF test with current mode
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_test.DHCPTest",
                platform_dir="ptftests",
                params={
                    "hostname": duthost.hostname,
                    "client_port_index": dhcp_relay['client_iface']['port_idx'],
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
                    "kvm_support": True,
                    "relay_agent" : relay_agent,
                    "agent_relay_discard_mode": agent_relay_discard_mode,
                    "agent_relay_forward_untouched_mode": agent_relay_forward_untouched_mode,
                    "agent_relay_forward_and_replace_mode": agent_relay_forward_and_replace_mode,
                    "agent_relay_forward_and_append_mode": agent_relay_forward_and_append_mode,
                    "agent_relay_mode": agent_relay_mode,
                    "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name']),
                },
                log_file=f"/tmp/test_dhcp_relay_agent_mode.log",
                is_python3=True
            )

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err


@pytest.mark.parametrize("relay_agent", ["sonic-relay-agent"])
@pytest.mark.parametrize("testcase", ["vrf_selection", "source_intf", "server_id_override"])
def test_dhcp_relay_with_non_default_vrf(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor, rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m, testcase, relay_agent):

    """
    Test Case: DHCP Relay with Non-Default VRF on T0 Topology

    Purpose:
        Validate the DHCP relay agent's behavior when configured to operate over a non-default VRF.
        Ensures correct handling of various advanced DHCP features such as VRF selection, source interface, and server ID override.

    Testcases:
        - "vrf_selection": Validates that the DHCP relay functions properly when `vrf_selection` is enabled.
        - "source_intf": Verifies correct handling when a specific source interface is used and `link_selection` is enabled.
        - "server_id_override": Confirms that the DHCP relay can override the server ID when instructed.

    Key Steps:
        1. Remove IP addresses from involved interfaces.
        2. Create and configure a non-default VRF (`CLIENT_VRF_NAME`).
        3. Bind VLAN and portchannel interfaces to the new VRF.
        4. Re-assign IP addresses and static default routes within the VRF.
        5. Update the CONFIG_DB with test-specific DHCP relay configurations.
        6. Use the PTF test framework to simulate DHCP discover/request flows and validate expected behavior.
        8. Clean up configurations post test (remove VRF, restore IPs, etc.).

    """
    CLIENT_VRF_NAME = "Vrf01"

    testing_mode, duthost = testing_config
    link_selection = source_intf = server_id_override = None    

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        portchannels = dhcp_relay['portchannels_with_ips']
        vlan_ip = "{}/{}".format(dhcp_relay['downlink_vlan_iface']['addr'], dhcp_relay['downlink_vlan_iface']['mask'])

    # Step 1: Remove IPs from interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip remove {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip remove {vlan_iface} {vlan_ip}")

    # Step 2: Create VRF
    duthost.shell(f"sudo config vrf add {CLIENT_VRF_NAME}")

    # Step 3: Bind interfaces to VRF
    for pc in portchannels:
        duthost.shell(f"sudo config interface vrf bind {pc} {CLIENT_VRF_NAME}")

    duthost.shell(f"sudo config interface vrf bind {vlan_iface} {CLIENT_VRF_NAME}")
    # Step 4: Re-add IPs to interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")
    # Step 5: Add default routes via nexthop in Vrf
    first_params = list(portchannels.values())[0]
    duthost.shell(f"sudo config route add prefix vrf {CLIENT_VRF_NAME} 0.0.0.0/0 nexthop vrf {CLIENT_VRF_NAME} {first_params['nexthop']}")

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            duthost.shell(f'config dhcpv4_relay del {vlan_iface}')
            loopback_iface = dhcp_relay["loopback_iface"]

            # Add test-case specific options
            if testcase == "vrf_selection":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} --vrf-selection enable {vlan_iface}')
            elif testcase == "source_intf":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} --vrf-selection enable --source-interface {loopback_iface} --link-selection enable {vlan_iface}')
                link_selection = True
                source_intf = True
            elif testcase == "server_id_override":
                duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} --vrf-selection enable --server-id-override enable {vlan_iface}')
                server_id_override = True

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
                               "kvm_support": True,
                               "link_selection": link_selection,
                               "source_interface": source_intf,
                               "server_id_override": server_id_override,
                               "vrf_selection": True, 
                               "relay_agent" : relay_agent,
                               "client_vrf": CLIENT_VRF_NAME,
                               "portchannels_ip_list": dhcp_relay['portchannels_ip_list'],
                               "link_selection_ip":str(dhcp_relay['downlink_vlan_iface']['link_selection_ip']),
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])
                               },
                       log_file="/tmp/test_dhcp_relay_with_non_default_vrf.DHCPTest.log", is_python3=True)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    #VRF config cleanup
    duthost.shell(f"sudo config route del prefix vrf {CLIENT_VRF_NAME} 0.0.0.0/0 nexthop vrf {CLIENT_VRF_NAME} {first_params['nexthop']}")
    duthost.shell(f'config dhcpv4_relay del {vlan_iface}')
    duthost.shell(f"sudo config vrf del {CLIENT_VRF_NAME}")
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")


@pytest.mark.parametrize("relay_agent", ["sonic-relay-agent"])
def test_dhcp_relay_with_different_non_default_vrf(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist,
                                                  testing_config, setup_standby_ports_on_rand_unselected_tor,
                                                  rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m,
                                                  relay_agent):     # noqa F811
    """
    Test Case: test_dhcp_relay_with_different_non_default_vrf
    
    Objective:
        Verify that the DHCP relay agent correctly relays DHCPv4 packets when the client-facing interface 
        (VLAN interface) and the server-facing interfaces (PortChannels) are bound to different, non-default VRFs.
    
    Test Steps:
        1. Remove existing IPs from VLAN and PortChannel interfaces.
        2. Create two separate VRFs: one for the client and one for the server.
        3. Bind VLAN interface to CLIENT_VRF_NAME and PortChannels to SERVER_VRF_NAME.
        4. Reassign IPs back to the interfaces.
        5. Add default routes in SERVER_VRF_NAME for DHCP server reachability.
        6. Configure DHCP relay with vrf_selection and link_selection enabled.
        7. Run the DHCP relay test from the PTF host.
        8. Optionally validate DHCP relay logs using loganalyzer.
        9. Cleanup: remove routes and VRF bindings, restore original config.
    
    Expected Results:
        - DHCP Discover, Offer, Request, and ACK messages are relayed successfully across different VRFs.
        - Relay behavior matches the expected counters/logs (if enabled).
    
    """

    CLIENT_VRF_NAME = "Vrf01"
    SERVER_VRF_NAME = "Vrf03"

    testing_mode, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        portchannels = dhcp_relay['portchannels_with_ips']
        vlan_ip = "{}/{}".format(dhcp_relay['downlink_vlan_iface']['addr'], dhcp_relay['downlink_vlan_iface']['mask'])

    # Step 1: Remove IPs from interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip remove {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip remove {vlan_iface} {vlan_ip}")

    # Step 2: Create VRF
    duthost.shell(f"sudo config vrf add {CLIENT_VRF_NAME}")
    duthost.shell(f"sudo config vrf add {SERVER_VRF_NAME}")

    # Step 3: Bind interfaces to VRF
    for pc in portchannels:
        duthost.shell(f"sudo config interface vrf bind {pc} {SERVER_VRF_NAME}")

    duthost.shell(f"sudo config interface vrf bind {vlan_iface} {CLIENT_VRF_NAME}")
    # Step 4: Re-add IPs to interfaces
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")
    # Step 5: Add default routes via nexthop in Vrf
    first_params = list(portchannels.values())[0]
    duthost.shell(f"sudo config route add prefix vrf {SERVER_VRF_NAME} 0.0.0.0/0 nexthop vrf {SERVER_VRF_NAME} {first_params['nexthop']}")

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            dhcp_servers = ",".join(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])
            loopback_iface = dhcp_relay["loopback_iface"]
            duthost.shell(f'config dhcpv4_relay del {vlan_iface}')

            duthost.shell(f'config dhcpv4_relay add --dhcpv4-servers {dhcp_servers} --server-vrf {SERVER_VRF_NAME} --vrf-selection enable --source-interface {loopback_iface} --link-selection enable --server-id-override enable {vlan_iface}')

            #duthost.shell(cmd, module_ignore_errors=True)

            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
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
                               "kvm_support": True,
                               "relay_agent" : relay_agent,
                               "client_vrf": CLIENT_VRF_NAME,
                               "link_selection_ip":str(dhcp_relay['downlink_vlan_iface']['link_selection_ip']),
                               "server_vrf": True, 
                               "portchannels_ip_list": dhcp_relay['portchannels_ip_list'],
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file="/tmp/test_dhcp_relay_with_different_non_default_vrf.DHCPTest.log", is_python3=True)

    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    #VRF config cleanup
    duthost.shell(f"sudo config route del prefix vrf {SERVER_VRF_NAME} 0.0.0.0/0 nexthop vrf {SERVER_VRF_NAME} {first_params['nexthop']}")

    duthost.shell(f'config dhcpv4_relay del {vlan_iface}')
    duthost.shell(f"sudo config vrf del {CLIENT_VRF_NAME}")
    duthost.shell(f"sudo config vrf del {SERVER_VRF_NAME}")
    for pc, params in portchannels.items():
        duthost.shell(f"sudo config interface ip add {pc} {params['ip']}")

    duthost.shell(f"sudo config interface ip add {vlan_iface} {vlan_ip}")


def test_dhcp_relay_on_dualtor_standby(ptfhost, dut_dhcp_relay_data, testing_config, rand_unselected_dut, relay_agent):     # noqa F811
    """
    Test the dhcp relay function on dual tor standby host
    The packets are expected to relay to client port.
    """
    testing_mode, duthost = testing_config
    try:
        for dhcp_relay in dut_dhcp_relay_data:
            standby_duthost = rand_unselected_dut
            start_dhcp_monitor_debug_counter(standby_duthost)
            init_dhcpcom_relay_counters(standby_duthost)
            expected_standby_agg_counter_message = (
                r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                r"Discover: +0/ +0, Offer: +1/ +1, Request: +0/ +0, ACK: +1/ +1+"
            ) % (dhcp_relay['downlink_vlan_iface']['name'])
            loganalyzer_standby = LogAnalyzer(ansible_host=standby_duthost, marker_prefix="dhcpmon counter")
            marker_standby = loganalyzer_standby.init()
            loganalyzer_standby.expect_regex = [expected_standby_agg_counter_message]
            start_dhcp_monitor_debug_counter(duthost)
            init_dhcpcom_relay_counters(duthost)
            expected_agg_counter_message = (
                r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                r"Discover: +0/ +0, Offer: +0/ +0, Request: +0/ +0, ACK: +0/ +0+"
            ) % (dhcp_relay['downlink_vlan_iface']['name'])
            loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcpmon counter")
            marker = loganalyzer.init()
            loganalyzer.expect_regex = [expected_agg_counter_message]

            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPPacketsServerToClientTest",
                       platform_dir="ptftests",
                       params={"hostname": duthost.hostname,
                               "client_port_index": dhcp_relay['client_iface']['port_idx'],
                               "other_client_port": repr(dhcp_relay['other_client_ports']),
                               "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                               # use standby uplink port indices to send dhcp packets to standby dut.
                               "leaf_port_indices": repr(dhcp_relay['standby_uplink_port_indices']),
                               "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs']),
                               "server_ip": dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'],
                               "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                               "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                               "relay_iface_netmask": str(dhcp_relay['downlink_vlan_iface']['mask']),
                               "dest_mac_address": BROADCAST_MAC,
                               "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                               # Pass standby dut's loopback ip and uplink mac address
                               "switch_loopback_ip": str(dhcp_relay['standby_dut_lo_addr']),
                               "uplink_mac": str(dhcp_relay['standby_uplink_mac']),
                               "testing_mode": testing_mode,
                               "kvm_support": True,
                               "relay_agent": relay_agent,
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.test_dhcp_relay_on_dualtor_standby.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)
            time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
            loganalyzer.analyze(marker)
            loganalyzer_standby.analyze(marker_standby)
            expected_downlink_counter = {
                "TX": {"Unknown": 1, "Ack": 1, "Offer": 1, "Nak": 1}
            }
            expected_uplink_counter = {
                "RX": {"Unknown": 1, "Nak": 1, "Ack": 1, "Offer": 1}
            }
                # because all packets send to standby dut, the packets are expected to countted on standby's counters.
            validate_dhcpcom_relay_counters(dhcp_relay, standby_duthost,
                                            expected_uplink_counter,
                                            expected_downlink_counter)
            # active dut counters should be all 0
            validate_dhcpcom_relay_counters(dhcp_relay, duthost, {}, {})
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err

    # Clean up - Restart DHCP relay service on DUT to recover original dhcpmon setting
    restart_dhcp_service(duthost)
    restart_dhcp_service(standby_duthost)
    pytest_assert(wait_until(120, 5, 0, check_interface_status, standby_duthost))
    pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost))


def test_dhcp_relay_monitor_checksum_validation(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,                                             # noqa F811
                            rand_unselected_dut, relay_agent):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """

    testing_mode, duthost = testing_config

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            if testing_mode == DUAL_TOR_MODE:
                standby_duthost = rand_unselected_dut
                start_dhcp_monitor_debug_counter(standby_duthost)
                init_dhcpcom_relay_counters(standby_duthost)
            start_dhcp_monitor_debug_counter(duthost)
            init_dhcpcom_relay_counters(duthost)
            # Run the DHCP relay test on the PTF host
            ptf_runner(ptfhost,
                       "ptftests",
                       "dhcp_relay_test.DHCPInvalidChecksumTest",
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
                               "kvm_support": True,
                               "relay_agent": relay_agent,
                               "downlink_vlan_iface_name": str(dhcp_relay['downlink_vlan_iface']['name'])},
                       log_file=("/tmp/dhcp_relay_test.DHCPTest.default.{}.log"
                                 .format(dhcp_relay["downlink_vlan_iface"]["name"])),
                       is_python3=True)
            time.sleep(36)      # dhcpmon debug counter prints every 18 seconds
            if testing_mode == DUAL_TOR_MODE:
                # If the testing mode is DUAL_TOR_MODE, standby tor's dhcpcom relay counters should all be 0
                validate_dhcpcom_relay_counters(dhcp_relay, standby_duthost, {}, {})
            expected_downlink_counter = {
                "RX": {"Malformed": 4}
            }
            expected_uplink_counter = {
                "RX": {"Malformed": 3}
            }
            validate_dhcpcom_relay_counters(dhcp_relay, duthost,
                                            expected_uplink_counter,
                                            expected_downlink_counter)
    except LogAnalyzerError as err:
        logger.error("Unable to find expected log in syslog")
        raise err
