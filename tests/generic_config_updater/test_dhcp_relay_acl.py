import ipaddress
import pytest
import time
import logging
import re

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

from tests.generic_config_updater.gu_utils import expect_op_success
from tests.generic_config_updater.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.generic_config_updater.gu_utils import format_and_apply_template, load_and_apply_json_patch
from tests.generic_config_updater.gu_utils import expect_acl_rule_match
from tests.generic_config_updater.gu_utils import expect_acl_table_match_multiple_bindings

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'

CREATE_DHCP_FORWARD_RULE_FILE = "create_dhcp_forward_rule.json"
CREATE_SECONDARY_DROP_RULE_TEMPLATE = "create_secondary_drop_rule.j2"
CREATE_CUSTOM_TABLE_TYPE_FILE = "create_custom_table_type.json"
CREATE_CUSTOM_TABLE_TEMPLATE = "create_custom_table.j2"


logger = logging.getLogger(__name__)


def create_custom_table_type(rand_selected_dut):
    """Create a new ACL table type that can be used"""

    output = load_and_apply_json_patch(rand_selected_dut, CREATE_CUSTOM_TABLE_TYPE_FILE)

    expect_op_success(rand_selected_dut, output)


def create_custom_table(rand_selected_dut, client_port_name):
    """Create a new ACL table that can be used"""

    extra_vars = {
        'bind_ports': [client_port_name]
        }

    output = format_and_apply_template(rand_selected_dut, CREATE_CUSTOM_TABLE_TEMPLATE, extra_vars)

    expected_bindings = [client_port_name]
    expected_first_line = ["DYNAMIC_ACL_TABLE",
                           "DYNAMIC_ACL_TABLE_TYPE",
                           client_port_name,
                           "DYNAMIC_ACL_TABLE",
                           "ingress",
                           "Active"]

    expect_op_success(rand_selected_dut, output)

    expect_acl_table_match_multiple_bindings(rand_selected_dut,
                                             "DYNAMIC_ACL_TABLE",
                                             expected_first_line,
                                             expected_bindings)


def create_dhcp_forwarding_rule(rand_selected_dut):
    """Create a ACL rule that will forward all DHCP related traffic"""

    output = load_and_apply_json_patch(rand_selected_dut, CREATE_DHCP_FORWARD_RULE_FILE)

    expect_op_success(rand_selected_dut, output)

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                                "DHCP_RULE", "9999",
                                "FORWARD",
                                "IP_PROTOCOL: 17",
                                "L4_DST_PORT: 67",
                                "ETHER_TYPE: 0x0800",
                                "Active"]

    expect_acl_rule_match(rand_selected_dut, "DHCP_RULE", expected_rule_content)


def create_drop_rule(rand_selected_dut, client_port_name):
    """Create a drop rule on the port that we will be sending DHCP traffic requests from"""

    extra_vars = {
        'blocked_port': client_port_name
    }

    output = format_and_apply_template(rand_selected_dut, CREATE_SECONDARY_DROP_RULE_TEMPLATE, extra_vars)

    expected_rule_content = ["DYNAMIC_ACL_TABLE",
                             "RULE_3",
                             "9996",
                             "DROP",
                             "IN_PORTS: " + client_port_name,
                             "Active"]

    expect_op_success(rand_selected_dut, output)

    expect_acl_rule_match(rand_selected_dut, "RULE_3", expected_rule_content)


def set_up_acl_for_testing_via_gcu(rand_selected_dut, client_port_name):
    """Set up our custom ACL table with DHCP Forwarding and a blanket drop rule on the port
    we are sending our DHCP request from"""

    create_checkpoint(rand_selected_dut)

    create_custom_table_type(rand_selected_dut)

    create_custom_table(rand_selected_dut, client_port_name)

    create_dhcp_forwarding_rule(rand_selected_dut)

    create_drop_rule(rand_selected_dut, client_port_name)


def tear_down_acl_for_testing_via_gcu(rand_selected_dut):

    rollback_or_reload(rand_selected_dut)

    delete_checkpoint(rand_selected_dut)


@pytest.fixture(scope="module", autouse=True)
def check_dhcp_server_enabled(duthost):
    feature_status_output = duthost.show_and_parse("show feature status")
    for feature in feature_status_output:
        if feature["feature"] == "dhcp_server" and feature["state"] == "enabled":
            pytest.skip("DHCPv4 relay is not supported when dhcp_server is enabled")


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


@pytest.fixture(scope="module")
def dut_dhcp_relay_data(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    """ Fixture which returns a list of dictionaries where each dictionary contains
        data necessary to test one instance of a DHCP relay agent running on the DuT.
        This fixture is scoped to the module, as the data it gathers can be used by
        all tests in this module. It does not need to be run before each test.
    """

    duthost = duthosts[rand_one_dut_hostname]
    dhcp_relay_data_list = []

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    switch_loopback_ip = mg_facts['minigraph_lo_interfaces'][0]['addr']

    # SONiC spawns one DHCP relay agent per VLAN interface configured on the DUT
    vlan_dict = mg_facts['minigraph_vlans']
    for vlan_iface_name, vlan_info_dict in list(vlan_dict.items()):
        # Filter(remove) PortChannel interfaces from VLAN members list
        vlan_members = [port for port in vlan_info_dict['members'] if 'PortChannel' not in port]

        # Gather information about the downlink VLAN interface this relay agent is listening on
        downlink_vlan_iface = {}
        downlink_vlan_iface['name'] = vlan_iface_name

        for vlan_interface_info_dict in mg_facts['minigraph_vlan_interfaces']:
            if vlan_interface_info_dict['attachto'] == vlan_iface_name:
                downlink_vlan_iface['addr'] = vlan_interface_info_dict['addr']
                downlink_vlan_iface['mask'] = vlan_interface_info_dict['mask']
                break

        # Obtain MAC address of the VLAN interface
        res = duthost.shell('cat /sys/class/net/{}/address'.format(vlan_iface_name))
        downlink_vlan_iface['mac'] = res['stdout']

        downlink_vlan_iface['dhcp_server_addrs'] = mg_facts['dhcp_servers']

        # We choose the physical interface where our DHCP client resides to be index of first interface
        # with alias (ignore PortChannel) in the VLAN
        client_iface = {}
        for port in vlan_members:
            if port in mg_facts['minigraph_port_name_to_alias_map']:
                break
        else:
            continue
        client_iface['name'] = port
        client_iface['alias'] = mg_facts['minigraph_port_name_to_alias_map'][client_iface['name']]
        client_iface['port_idx'] = mg_facts['minigraph_ptf_indices'][client_iface['name']]

        # Obtain uplink port indicies for this DHCP relay agent
        uplink_interfaces = []
        uplink_port_indices = []
        for iface_name, neighbor_info_dict in list(mg_facts['minigraph_neighbors'].items()):
            if neighbor_info_dict['name'] in mg_facts['minigraph_devices']:
                neighbor_device_info_dict = mg_facts['minigraph_devices'][neighbor_info_dict['name']]
                if 'type' in neighbor_device_info_dict and neighbor_device_info_dict['type'] in \
                        ['LeafRouter', 'MgmtLeafRouter']:
                    # If this uplink's physical interface is a member of a portchannel interface,
                    # we record the name of the portchannel interface here, as this is the actual
                    # interface the DHCP relay will listen on.
                    iface_is_portchannel_member = False
                    for portchannel_name, portchannel_info_dict in list(mg_facts['minigraph_portchannels'].items()):
                        if 'members' in portchannel_info_dict and iface_name in portchannel_info_dict['members']:
                            iface_is_portchannel_member = True
                            if portchannel_name not in uplink_interfaces:
                                uplink_interfaces.append(portchannel_name)
                            break
                    # If the uplink's physical interface is not a member of a portchannel,
                    # add it to our uplink interfaces list
                    if not iface_is_portchannel_member:
                        uplink_interfaces.append(iface_name)
                    uplink_port_indices.append(mg_facts['minigraph_ptf_indices'][iface_name])

        other_client_ports_indices = []
        for iface_name in vlan_members:
            if mg_facts['minigraph_ptf_indices'][iface_name] == client_iface['port_idx']:
                pass
            else:
                other_client_ports_indices.append(mg_facts['minigraph_ptf_indices'][iface_name])

        dhcp_relay_data = {}
        dhcp_relay_data['downlink_vlan_iface'] = downlink_vlan_iface
        dhcp_relay_data['client_iface'] = client_iface
        dhcp_relay_data['other_client_ports'] = other_client_ports_indices
        dhcp_relay_data['uplink_interfaces'] = uplink_interfaces
        dhcp_relay_data['uplink_port_indices'] = uplink_port_indices
        dhcp_relay_data['switch_loopback_ip'] = str(switch_loopback_ip)

        # Obtain MAC address of an uplink interface because vlan mac may be different than that of physical interfaces
        res = duthost.shell('cat /sys/class/net/{}/address'.format(uplink_interfaces[0]))
        dhcp_relay_data['uplink_mac'] = res['stdout']
        dhcp_relay_data['default_gw_ip'] = mg_facts['minigraph_mgmt_interface']['gwaddr']

        dhcp_relay_data_list.append(dhcp_relay_data)

    return dhcp_relay_data_list


def check_routes_to_dhcp_server(duthost, dut_dhcp_relay_data):
    """Validate there is route on DUT to each DHCP server
    """
    default_gw_ip = dut_dhcp_relay_data[0]['default_gw_ip']
    dhcp_servers = set()
    for dhcp_relay in dut_dhcp_relay_data:
        dhcp_servers |= set(dhcp_relay['downlink_vlan_iface']['dhcp_server_addrs'])

    for dhcp_server in dhcp_servers:
        rtInfo = duthost.get_ip_route_info(ipaddress.ip_address(dhcp_server))
        nexthops = rtInfo["nexthops"]
        if len(nexthops) == 0:
            logger.info("Failed to find route to DHCP server '{0}'".format(dhcp_server))
            return False
        if len(nexthops) == 1:
            # if only 1 route to dst available - check that it's not default route via MGMT iface
            route_index_in_list = 0
            ip_dst_index = 0
            route_dst_ip = nexthops[route_index_in_list][ip_dst_index]
            if route_dst_ip == ipaddress.ip_address(default_gw_ip):
                logger.info("Found route to DHCP server via default GW(MGMT interface)")
                return False
    return True


@pytest.fixture(scope="module")
def validate_dut_routes_exist(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data):
    """Fixture to valid a route to each DHCP server exist
    """
    pytest_assert(check_routes_to_dhcp_server(duthosts[rand_one_dut_hostname], dut_dhcp_relay_data),
                  "Failed to find route for DHCP server")


def restart_dhcp_service(duthost):
    duthost.shell('systemctl reset-failed dhcp_relay')
    duthost.shell('systemctl restart dhcp_relay')
    duthost.shell('systemctl reset-failed dhcp_relay')

    for retry in range(5):
        time.sleep(30)
        dhcp_status = duthost.shell('docker container top dhcp_relay | grep dhcrelay | cat')["stdout"]
        if dhcp_status != "":
            break
    else:
        assert False, "Failed to restart dhcp docker"

    time.sleep(30)


def get_subtype_from_configdb(duthost):
    # HEXISTS returns 1 if the key exists, otherwise 0
    subtype_exist = int(duthost.shell('redis-cli -n 4 HEXISTS "DEVICE_METADATA|localhost" "subtype"')["stdout"])
    subtype_value = ""
    if subtype_exist:
        subtype_value = duthost.shell('redis-cli -n 4 HGET "DEVICE_METADATA|localhost" "subtype"')["stdout"]
    return subtype_exist, subtype_value


@pytest.fixture(scope="module", params=[SINGLE_TOR_MODE, DUAL_TOR_MODE])
def testing_config(request, duthosts, rand_one_dut_hostname, tbinfo):
    testing_mode = request.param
    duthost = duthosts[rand_one_dut_hostname]
    subtype_exist, subtype_value = get_subtype_from_configdb(duthost)

    if 'dualtor' in tbinfo['topo']['name']:
        if testing_mode == SINGLE_TOR_MODE:
            pytest.skip("skip SINGLE_TOR_MODE tests on Dual ToR testbeds")

        if testing_mode == DUAL_TOR_MODE:
            if not subtype_exist or subtype_value != 'DualToR':
                assert False, "Wrong DHCP setup on Dual ToR testbeds"

            yield testing_mode, duthost, 'dual_testbed'
    elif tbinfo['topo']['name'] in ('t0-54-po2vlan', 't0-56-po2vlan'):
        if testing_mode == SINGLE_TOR_MODE:
            if subtype_exist and subtype_value == 'DualToR':
                assert False, "Wrong DHCP setup on po2vlan testbeds"

            yield testing_mode, duthost, 'single_testbed'

        if testing_mode == DUAL_TOR_MODE:
            pytest.skip("skip DUAL_TOR_MODE tests on po2vlan testbeds")
    else:
        if testing_mode == DUAL_TOR_MODE:
            pytest.skip("skip DUAL_TOR_MODE tests on Single ToR testbeds")

        if testing_mode == SINGLE_TOR_MODE:
            if subtype_exist:
                duthost.shell('redis-cli -n 4 HDEL "DEVICE_METADATA|localhost" "subtype"')
                restart_dhcp_service(duthost)

        if testing_mode == DUAL_TOR_MODE:
            if not subtype_exist or subtype_value != 'DualToR':
                duthost.shell('redis-cli -n 4 HSET "DEVICE_METADATA|localhost" "subtype" "DualToR"')
                restart_dhcp_service(duthost)

        yield testing_mode, duthost, 'single_testbed'

        if testing_mode == DUAL_TOR_MODE:
            duthost.shell('redis-cli -n 4 HDEL "DEVICE_METADATA|localhost" "subtype"')
            restart_dhcp_service(duthost)


def check_interface_status(duthost):
    if ":67" in duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcrelay",
                              module_ignore_errors=True)["stdout"]:
        return True

    return False


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


def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor_m):     # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """

    testing_mode, duthost, testbed_mode = testing_config

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
                expected_agg_counter_message = (
                    r".*dhcp_relay#dhcpmon\[[0-9]+\]: "
                    r"\[\s*Agg-%s\s*-[\sA-Za-z0-9]+\s*rx/tx\] "
                    r"Discover: +1/ +%d, Offer: +1/ +1, Request: +3/ +%d, ACK: +1/ +1+"
                ) % (dhcp_relay['downlink_vlan_iface']['name'], dhcp_server_num, dhcp_server_num * 3)
                loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcpmon counter")
                marker = loganalyzer.init()
                loganalyzer.expect_regex = [expected_agg_counter_message]

            # Create the ACL that we will be using for our test

            set_up_acl_for_testing_via_gcu(duthost, dhcp_relay['client_iface']['name'])

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
                               "testbed_mode": testbed_mode,
                               "testing_mode": testing_mode},
                       log_file="/tmp/dhcp_relay_test.DHCPTest.log", is_python3=True)
            if not skip_dhcpmon:
                time.sleep(18)      # dhcpmon debug counter prints every 18 seconds
                loganalyzer.analyze(marker)
                if testing_mode == DUAL_TOR_MODE:
                    loganalyzer_standby.analyze(marker_standby)

            tear_down_acl_for_testing_via_gcu(duthost)

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
