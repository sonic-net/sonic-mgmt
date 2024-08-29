import ipaddr
import ipaddress
import pytest
import random
import time
import logging
import re
from collections import namedtuple

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from tests.common.utilities import find_duthost_on_role
from tests.common.utilities import get_upstream_neigh_type

from tests.copp import copp_utils
from tests.common import config_reload, constants
from tests.common.system_utils import docker

pytestmark = [
    pytest.mark.topology('t0', 'm0'),
    pytest.mark.device_type('vs')
]

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
DEFAULT_DHCP_CLIENT_PORT = 68
SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'

logger = logging.getLogger(__name__)

_COPPTestParameters = namedtuple("_COPPTestParameters",
                                 ["nn_target_port",
                                  "swap_syncd",
                                  "topo",
                                  "myip",
                                  "peerip",
                                  "nn_target_interface",
                                  "nn_target_namespace",
                                  "send_rate_limit",
                                  "nn_target_vlanid"])

_TEST_RATE_LIMIT_DEFAULT = 600
_TEST_RATE_LIMIT_MARVELL = 625


@pytest.fixture(scope="module", autouse=True)
def check_dhcp_server_enabled(duthost):
    print("fixture: check dhcp server enable start")
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
    print("fixture: cdut_dhcp_relay_data")
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

        # Obtain all the DHCP client ports and alias
        first_port = None
        client_ports_indices = []
        client_ports_alias = []
        for port in vlan_members:
            if port in mg_facts['minigraph_port_name_to_alias_map']:
                if first_port is None:
                    first_port = port
                client_ports_indices.append(mg_facts['minigraph_ptf_indices'][port])
                client_ports_alias.append(mg_facts['minigraph_port_name_to_alias_map'][port])

        # We choose the physical interface where our DHCP client resides to be index of first interface
        # with alias (ignore PortChannel) in the VLAN
        client_iface = {}
        client_iface['name'] = first_port
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
        dhcp_relay_data['client_ports_indices'] = client_ports_indices
        dhcp_relay_data['client_ports_alias'] = client_ports_alias

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


# copp policy
@pytest.fixture(scope="module")
def copp_testbed(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    creds,
    ptfhost,
    tbinfo,
    duts_minigraph_facts,
    request,
    is_backend_topology
):
    """
        Pytest fixture to handle setup and cleanup for the COPP tests.
    """
    upStreamDuthost = None
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    test_params = _gather_test_params(tbinfo, duthost, request, duts_minigraph_facts)

    if not is_backend_topology:
        # There is no upstream neighbor in T1 backend topology. Test is skipped on T0 backend.
        upStreamDuthost = find_duthost_on_role(duthosts, get_upstream_neigh_type(tbinfo['topo']['type']), tbinfo)

    try:
        _setup_multi_asic_proxy(duthost, creds, test_params, tbinfo)
        _setup_testbed(duthost, creds, ptfhost, test_params, tbinfo, upStreamDuthost, is_backend_topology)
        yield test_params
    finally:
        _teardown_multi_asic_proxy(duthost, creds, test_params, tbinfo)
        _teardown_testbed(duthost, creds, ptfhost, test_params, tbinfo, upStreamDuthost, is_backend_topology)


def _gather_test_params(tbinfo, duthost, request, duts_minigraph_facts):
    """
        Fetches the test parameters from pytest.
    """

    swap_syncd = request.config.getoption("--copp_swap_syncd")
    send_rate_limit = request.config.getoption("--send_rate_limit")
    topo = tbinfo["topo"]["name"]
    mg_fact = duts_minigraph_facts[duthost.hostname]

    port_index_map = {}
    for mg_facts_tuple in mg_fact:
        index, mg_facts = mg_facts_tuple
        # filter out server peer port and only bgp peer ports remain, to support T0 topologies
        bgp_peer_name_set = set([bgp_peer["name"] for bgp_peer in mg_facts["minigraph_bgp"]])
        # get the port_index_map using the ptf_indicies to support multi DUT topologies
        port_index_map.update({
           k: v
           for k, v in list(mg_facts["minigraph_ptf_indices"].items())
           if k in mg_facts["minigraph_ports"] and
           not duthost.is_backend_port(k, mg_facts) and
           mg_facts["minigraph_neighbors"][k]["name"] in bgp_peer_name_set
        })
    # use randam sonic interface for testing
    nn_target_interface = random.choice(list(port_index_map.keys()))
    # get the  ptf port for choosen port
    nn_target_port = port_index_map[nn_target_interface]
    myip = None
    peerip = None
    nn_target_vlanid = None

    for mg_facts_tuple in mg_fact:
        index, mg_facts = mg_facts_tuple
        if nn_target_interface not in mg_facts["minigraph_neighbors"]:
            continue
        for bgp_peer in mg_facts["minigraph_bgp"]:
            if bgp_peer["name"] == mg_facts["minigraph_neighbors"][nn_target_interface]["name"] \
                                   and ipaddr.IPAddress(bgp_peer["addr"]).version == 4:
                myip = bgp_peer["addr"]
                peerip = bgp_peer["peer_addr"]
                nn_target_namespace = mg_facts["minigraph_neighbors"][nn_target_interface]['namespace']
                is_backend_topology = mg_facts.get(constants.IS_BACKEND_TOPOLOGY_KEY, False)
                if is_backend_topology and len(mg_facts["minigraph_vlan_sub_interfaces"]) > 0:
                    nn_target_vlanid = mg_facts["minigraph_vlan_sub_interfaces"][0]["vlan"]
                break

    logger.info("nn_target_port {} nn_target_interface {} nn_target_namespace {} nn_target_vlanid {}"
                .format(nn_target_port, nn_target_interface, nn_target_namespace, nn_target_vlanid))

    return _COPPTestParameters(nn_target_port=nn_target_port,
                               swap_syncd=swap_syncd,
                               topo=topo,
                               myip=myip,
                               peerip=peerip,
                               nn_target_interface=nn_target_interface,
                               nn_target_namespace=nn_target_namespace,
                               send_rate_limit=send_rate_limit,
                               nn_target_vlanid=nn_target_vlanid)


def _setup_testbed(dut, creds, ptf, test_params, tbinfo, upStreamDuthost, is_backend_topology):
    """
        Sets up the testbed to run the COPP tests.
    """
    logger.info("Set up the PTF for COPP tests")
    copp_utils.configure_ptf(ptf, test_params, is_backend_topology)

    rate_limit = _TEST_RATE_LIMIT_DEFAULT
    if dut.facts["asic_type"] == "marvell":
        rate_limit = _TEST_RATE_LIMIT_MARVELL

    logger.info("Update the rate limit for the COPP policer")
    copp_utils.limit_policer(dut, rate_limit, test_params.nn_target_namespace)

    # Multi-asic will not support this mode as of now.
    if test_params.swap_syncd:
        logger.info("Swap out syncd to use RPC image...")
        docker.swap_syncd(dut, creds, test_params.nn_target_namespace)
    else:
        # Set sysctl RCVBUF parameter for tests
        dut.command("sysctl -w net.core.rmem_max=609430500")

        # Set sysctl SENDBUF parameter for tests
        dut.command("sysctl -w net.core.wmem_max=609430500")

        # NOTE: Even if the rpc syncd image is already installed, we need to restart
        # SWSS for the COPP changes to take effect.
        logger.info("Reloading config and restarting swss...")
        config_reload(dut, safe_reload=True, check_intf_up_ports=True)

    if not is_backend_topology:
        # make sure traffic goes over management port by shutdown bgp toward upstream neigh that gives default route
        upStreamDuthost.command("sudo config bgp shutdown all")
        time.sleep(30)

    logger.info("Configure syncd RPC for testing")
    copp_utils.configure_syncd(dut, test_params.nn_target_port, test_params.nn_target_interface,
                               test_params.nn_target_namespace, test_params.nn_target_vlanid,
                               test_params.swap_syncd, creds)


def _teardown_testbed(dut, creds, ptf, test_params, tbinfo, upStreamDuthost, is_backend_topology):
    """
        Tears down the testbed, returning it to its initial state.
    """
    logger.info("Restore PTF post COPP test")
    copp_utils.restore_ptf(ptf)

    logger.info("Restore COPP policer to default settings")
    copp_utils.restore_policer(dut, test_params.nn_target_namespace)

    if test_params.swap_syncd:
        logger.info("Restore default syncd docker...")
        docker.restore_default_syncd(dut, creds, test_params.nn_target_namespace)
    else:
        copp_utils.restore_syncd(dut, test_params.nn_target_namespace)
        logger.info("Reloading config and restarting swss...")
        config_reload(dut, safe_reload=True, check_intf_up_ports=True)

    if not is_backend_topology:
        # Testbed is not a T1 backend device, so bring up bgp session to upstream device
        upStreamDuthost.command("sudo config bgp startup all")


def _setup_multi_asic_proxy(dut, creds, test_params, tbinfo):
    """
        Sets up the testbed to run the COPP tests on multi-asic platfroms via setting proxy.
    """
    if not dut.is_multi_asic:
        return

    logger.info("Adding iptables rules and enabling eth0 port forwarding")
    # Add IP Table rule for http and ptf nn_agent traffic.
    dut.command("sudo sysctl net.ipv4.conf.eth0.forwarding=1")

    if not test_params.swap_syncd:
        mgmt_ip = dut.host.options["inventory_manager"].get_host(dut.hostname).vars["ansible_host"]
        # Add Rule to communicate to http/s proxy from namespace
        dut.command("sudo iptables -t nat -A POSTROUTING -p tcp --dport 8080 -j SNAT --to-source {}".format(mgmt_ip))
    # Add Rule to communicate to ptf nn agent client from namespace
    ns_ip = dut.shell("sudo ip -n {} -4 -o addr show eth0".format(test_params.nn_target_namespace)
                      + " | awk '{print $4}' | cut -d'/' -f1")["stdout"]
    dut.command("sudo iptables -t nat -A PREROUTING -p tcp --dport 10900 -j DNAT --to-destination {}".format(ns_ip))


def _teardown_multi_asic_proxy(dut, creds, test_params, tbinfo):
    """
        Tears down multi asic proxy settings, returning it to its initial state.
    """
    if not dut.is_multi_asic:
        return

    logger.info("Removing iptables rules and disabling eth0 port forwarding")
    dut.command("sudo sysctl net.ipv4.conf.eth0.forwarding=0")
    if not test_params.swap_syncd:
        # Delete IP Table rule for http and ptf nn_agent traffic.
        mgmt_ip = dut.host.options["inventory_manager"].get_host(dut.hostname).vars["ansible_host"]
        # Delete Rule to communicate to http/s proxy from namespace
        dut.command("sudo iptables -t nat -D POSTROUTING -p tcp --dport 8080 -j SNAT --to-source {}".format(mgmt_ip))
    # Delete Rule to communicate to ptf nn agent client from namespace
    ns_ip = dut.shell("sudo ip -n {} -4 -o addr show eth0".format(test_params.nn_target_namespace)
                      + " | awk '{print $4}' | cut -d'/' -f1")["stdout"]
    dut.command("sudo iptables -t nat -D PREROUTING -p tcp --dport 10900 -j DNAT --to-destination {}".format(ns_ip))
# end copp policy


def test_dhcp_relay_stress(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config, copp_testbed):
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
                   "dhcp_relay_stress_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "client_iface_alias": str(dhcp_relay['client_iface']['alias']),
                           "other_client_ports": repr(dhcp_relay['other_client_ports']),
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
                   log_file="/tmp/dhcp_relay_stress_test_with_copp.DHCPTest.log",
                   qlen=100000,
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
