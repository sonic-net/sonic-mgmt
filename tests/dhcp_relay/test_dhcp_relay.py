import ipaddress
import pytest
import random
import time
import logging
import re

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.dut_utils import check_link_status
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'

logger = logging.getLogger(__name__)


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
    pytest_assert(wait_until(120, 5, 0, check_routes_to_dhcp_server, duthosts[rand_one_dut_hostname],
                             dut_dhcp_relay_data), "Failed to find route for DHCP server")


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


def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            setup_standby_ports_on_rand_unselected_tor,												# noqa F811
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
                               "testbed_mode": testbed_mode,
                               "testing_mode": testing_mode},
                       log_file="/tmp/dhcp_relay_test.DHCPTest.log", is_python3=True)
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
    testing_mode, duthost, testbed_mode = testing_config

    if testbed_mode == 'dual_testbed':
        pytest.skip("skip the link flap testcase on dual tor testbeds")

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('ifconfig {} down'.format(iface))

        pytest_assert(wait_until(50, 5, 0, check_link_status, duthost, dhcp_relay['uplink_interfaces'], "down"),
                      "Not all uplinks go down")

        # Bring all uplink interfaces back up
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('ifconfig {} up'.format(iface))

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
                           "testbed_mode": testbed_mode,
                           "testing_mode": testing_mode},
                   log_file="/tmp/dhcp_relay_test.DHCPTest.log", is_python3=True)


def test_dhcp_relay_start_with_uplinks_down(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config):
    """Test DHCP relay functionality on T0 topology when relay agent starts with uplinks down
       For each DHCP relay agent running on the DuT, bring the uplinks down, then restart the
       relay agent while the uplinks are still down. Then test whether the DHCP relay agent
       relays packets properly.
    """
    testing_mode, duthost, testbed_mode = testing_config

    if testbed_mode == 'dual_testbed':
        pytest.skip("skip the uplinks down testcase on dual tor testbeds")

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('ifconfig {} down'.format(iface))

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
            duthost.shell('ifconfig {} up'.format(iface))

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
                           "testbed_mode": testbed_mode,
                           "testing_mode": testing_mode},
                   log_file="/tmp/dhcp_relay_test.DHCPTest.log", is_python3=True)


def test_dhcp_relay_unicast_mac(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                setup_standby_ports_on_rand_unselected_tor,				 # noqa F811
                                toggle_all_simulator_ports_to_rand_selected_tor_m):     # noqa F811
    """Test DHCP relay functionality on T0 topology with unicast mac
       Instead of using broadcast MAC, use unicast MAC of DUT and verify that DHCP relay functionality is entact.
    """
    testing_mode, duthost, testbed_mode = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

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
                           "dest_mac_address": duthost.facts["router_mac"] if testbed_mode != 'dual_testbed'
                                else str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
                           "switch_loopback_ip": dhcp_relay['switch_loopback_ip'],
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "testbed_mode": testbed_mode,
                           "testing_mode": testing_mode},
                   log_file="/tmp/dhcp_relay_test.DHCPTest.log", is_python3=True)


def test_dhcp_relay_random_sport(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                                 setup_standby_ports_on_rand_unselected_tor,				 # noqa F811
                                 toggle_all_simulator_ports_to_rand_selected_tor_m):    # noqa F811
    """Test DHCP relay functionality on T0 topology with random source port (sport)
       If the client is SNAT'd, the source port could be changed to a non-standard port (i.e., not 68).
       Verify that DHCP relay works with random high sport.
    """
    testing_mode, duthost, testbed_mode = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

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
                           "testbed_mode": testbed_mode,
                           "testing_mode": testing_mode},
                   log_file="/tmp/dhcp_relay_test.DHCPTest.log", is_python3=True)


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
    testing_mode, duthost, testbed_mode = testing_config

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
                           "testbed_mode": testbed_mode,
                           "testing_mode": testing_mode},
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
