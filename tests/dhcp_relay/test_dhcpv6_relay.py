import ipaddress
import pytest
import time
import netaddr
import logging

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa F401
from tests.common.utilities import skip_release
from tests.ptf_runner import ptf_runner
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # noqa F401
from tests.common.dualtor.dual_tor_utils import config_active_active_dualtor_active_standby                 # noqa F401
from tests.common.dualtor.dual_tor_utils import validate_active_active_dualtor_setup                        # noqa F401
from tests.common.dualtor.dual_tor_common import active_active_ports                                        # noqa F401

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx'),
    pytest.mark.device_type('vs')
]

SINGLE_TOR_MODE = 'single'
DUAL_TOR_MODE = 'dual'
NEW_COUNTER_VALUE_FORMAT = (
    "{'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0','Confirm':'0','Renew':'0','Rebind':'0','Reply':'0',"
    "'Release':'0','Decline':'0','Reconfigure':'0','Information-Request':'0','Relay-Forward':'0','Relay-Reply':'0',"
    "'Malformed':'0'}"
)

logger = logging.getLogger(__name__)


def wait_all_bgp_up(duthost):
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    if not wait_until(180, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())):
        pytest.fail("not all bgp sessions are up after config change")


def check_dhcpv6_relay_counter(duthost, ifname, type, dir):
    # new counter table
    # sonic-db-cli STATE_DB hgetall 'DHCPv6_COUNTER_TABLE|Vlan1000'
    # {'TX': "{'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0','Confirm':'0','Renew':'0','Rebind':'0',
    #  'Reply':'0', 'Release':'0','Decline':'0','Reconfigure':'0','Information-Request':'0','Relay-Forward':'0',
    #  'Relay-Reply':'0','Malformed':'0'}", 'RX': "{'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0',
    #  'Confirm':'0','Renew':'0','Rebind':'0','Reply':'0', 'Release':'0','Decline':'0','Reconfigure':'0',
    #  'Information-Request':'0','Relay-Forward':'0','Relay-Reply':'0','Malformed':'0'}"}
    #
    # old counter table
    # sonic-db-cli STATE_DB hgetall 'DHCPv6_COUNTER_TABLE|Vlan1000'
    # {'Unknown':'0','Solicit':'0','Advertise':'0','Request':'0','Confirm':'0','Renew':'0','Rebind':'0','Reply':'0',
    #  'Release':'0','Decline':'0','Reconfigure':'0','Information-Request':'0','Relay-Forward':'0','Relay-Reply':'0',
    #  'Malformed':'0'}
    #
    cmd_new_version = 'sonic-db-cli STATE_DB hget "DHCPv6_COUNTER_TABLE|{}" {}'.format(ifname, dir)
    cmd_old_version = 'sonic-db-cli STATE_DB hget "DHCPv6_COUNTER_TABLE|{}" {}'.format(ifname, type)
    output_new = duthost.shell(cmd_new_version)['stdout']
    if len(output_new) != 0:
        counters = eval(output_new)
        assert int(counters[type]) > 0, "{}({}) missing {} count".format(ifname, dir, type)
    else:
        # old version only support vlan couting
        if 'Vlan' not in ifname:
            return
        output_old = duthost.shell(cmd_old_version)['stdout']
        assert int(output_old) > 0, "{} missing {} count".format(ifname, type)


def init_counter(duthost, ifname, types):
    cmd_new_version = 'sonic-db-cli STATE_DB hget "DHCPv6_COUNTER_TABLE|{}" RX'.format(ifname)
    output_new = duthost.shell(cmd_new_version)['stdout']
    if len(output_new) != 0:
        counters_str = NEW_COUNTER_VALUE_FORMAT
        cmd = 'sonic-db-cli STATE_DB hmset "DHCPv6_COUNTER_TABLE|{}" "RX" "{}"'.format(ifname, str(counters_str))
        duthost.shell(cmd)
        cmd = 'sonic-db-cli STATE_DB hmset "DHCPv6_COUNTER_TABLE|{}" "TX" "{}"'.format(ifname, str(counters_str))
        duthost.shell(cmd)
    else:
        for type in types:
            cmd = 'sonic-db-cli STATE_DB hmset "DHCPv6_COUNTER_TABLE|{}" {} 0'.format(ifname, type)
            duthost.shell(cmd)


@pytest.fixture(scope="module")
def testing_config(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    subtype_exist, subtype_value = get_subtype_from_configdb(duthost)

    if 'dualtor' in tbinfo['topo']['name']:
        if not subtype_exist or subtype_value != 'DualToR':
            assert False, "Wrong DHCP setup on Dual ToR testbeds"
        yield DUAL_TOR_MODE, duthost
    else:
        yield SINGLE_TOR_MODE, duthost


def get_subtype_from_configdb(duthost):
    # HEXISTS returns 1 if the key exists, otherwise 0
    subtype_exist = int(duthost.shell('redis-cli -n 4 HEXISTS "DEVICE_METADATA|localhost" "subtype"')["stdout"])
    subtype_value = ""
    if subtype_exist:
        subtype_value = duthost.shell('redis-cli -n 4 HGET "DEVICE_METADATA|localhost" "subtype"')["stdout"]
    return subtype_exist, subtype_value


@pytest.fixture(scope="module")
def dut_dhcp_relay_data(duthosts, rand_one_dut_hostname, tbinfo):
    """ Fixture which returns a list of dictionaries where each dictionary contains
        data necessary to test one instance of a DHCP relay agent running on the DuT.
        This fixture is scoped to the module, as the data it gathers can be used by
        all tests in this module. It does not need to be run before each test.
    """
    duthost = duthosts[rand_one_dut_hostname]
    dhcp_relay_data_list = []
    down_interface_link_local = ""

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    # SONiC spawns one DHCP relay agent per VLAN interface configured on the DUT
    vlan_dict = mg_facts['minigraph_vlans']
    for vlan_iface_name, vlan_info_dict in list(vlan_dict.items()):
        # Filter(remove) PortChannel interfaces from VLAN members list
        vlan_members = [port for port in vlan_info_dict['members'] if 'PortChannel' not in port]
        if not vlan_members:
            continue

        # Gather information about the downlink VLAN interface this relay agent is listening on
        downlink_vlan_iface = {}
        downlink_vlan_iface['name'] = vlan_iface_name

        for vlan_interface_info_dict in mg_facts['minigraph_vlan_interfaces']:
            if (vlan_interface_info_dict['attachto'] == vlan_iface_name) and \
               (netaddr.IPAddress(str(vlan_interface_info_dict['addr'])).version == 6):
                downlink_vlan_iface['addr'] = vlan_interface_info_dict['addr']
                downlink_vlan_iface['mask'] = vlan_interface_info_dict['mask']
                break

        # Obtain MAC address of the VLAN interface
        res = duthost.shell('cat /sys/class/net/{}/address'.format(vlan_iface_name))
        downlink_vlan_iface['mac'] = res['stdout']

        downlink_vlan_iface['dhcpv6_server_addrs'] = mg_facts['dhcpv6_servers']

        # We choose the physical interface where our DHCP client resides to be index of first interface in the VLAN
        client_iface = {}
        client_iface['name'] = vlan_members[0]
        client_iface['alias'] = mg_facts['minigraph_port_name_to_alias_map'][client_iface['name']]
        client_iface['port_idx'] = mg_facts['minigraph_ptf_indices'][client_iface['name']]

        # Obtain uplink port indicies for this DHCP relay agent
        uplink_interfaces = []
        uplink_port_indices = []
        topo_type = tbinfo['topo']['type']
        for iface_name, neighbor_info_dict in list(mg_facts['minigraph_neighbors'].items()):
            if neighbor_info_dict['name'] in mg_facts['minigraph_devices']:
                neighbor_device_info_dict = mg_facts['minigraph_devices'][neighbor_info_dict['name']]
                if 'type' not in neighbor_device_info_dict:
                    continue
                nei_type = neighbor_device_info_dict['type']
                if topo_type == 't0' and nei_type == 'LeafRouter' or \
                   topo_type == 'm0' and nei_type == 'MgmtLeafRouter' or \
                   topo_type == 'mx' and nei_type == 'MgmtToRRouter':
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
        if down_interface_link_local == "":
            command = "ip addr show {} | grep inet6 | grep 'scope link' | awk '{{print $2}}' | cut -d '/' -f1"\
                      .format(downlink_vlan_iface['name'])
            res = duthost.shell(command)
            if res['stdout'] != "":
                down_interface_link_local = res['stdout']

        dhcp_relay_data = {}
        dhcp_relay_data['downlink_vlan_iface'] = downlink_vlan_iface
        dhcp_relay_data['client_iface'] = client_iface
        dhcp_relay_data['uplink_interfaces'] = uplink_interfaces
        dhcp_relay_data['uplink_port_indices'] = uplink_port_indices
        dhcp_relay_data['down_interface_link_local'] = down_interface_link_local
        dhcp_relay_data['loopback_iface'] = mg_facts['minigraph_lo_interfaces']
        dhcp_relay_data['loopback_ipv6'] = mg_facts['minigraph_lo_interfaces'][1]['addr']
        if 'dualtor' in tbinfo['topo']['name']:
            dhcp_relay_data['is_dualtor'] = True
        else:
            dhcp_relay_data['is_dualtor'] = False

        res = duthost.shell('cat /sys/class/net/{}/address'.format(uplink_interfaces[0]))
        dhcp_relay_data['uplink_mac'] = res['stdout']

        dhcp_relay_data_list.append(dhcp_relay_data)

    return dhcp_relay_data_list


@pytest.fixture(scope="module")
def validate_dut_routes_exist(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data):
    """Fixture to valid a route to each DHCP server exist
    """
    duthost = duthosts[rand_one_dut_hostname]
    dhcp_servers = set()
    for dhcp_relay in dut_dhcp_relay_data:
        dhcp_servers |= set(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'])

    for dhcp_server in dhcp_servers:
        rtInfo = duthost.get_ip_route_info(ipaddress.ip_address(dhcp_server))
        assert len(rtInfo["nexthops"]) > 0, "Failed to find route to DHCP server '{0}'".format(dhcp_server)


def check_interface_status(duthost):
    if ":547" in duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcp6relay")["stdout"]:
        return True
    return False


def test_interface_binding(duthosts, rand_one_dut_hostname, dut_dhcp_relay_data):
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, ["201911", "202106"])
    if not check_interface_status(duthost):
        config_reload(duthost)
        wait_critical_processes(duthost)
        pytest_assert(wait_until(120, 5, 0, check_interface_status, duthost))
    output = duthost.shell("docker exec -t dhcp_relay ss -nlp | grep dhcp6relay")["stdout"]
    logger.info(output)
    for dhcp_relay in dut_dhcp_relay_data:
        assert ("*:{}".format(dhcp_relay['downlink_vlan_iface']['name']) or "*:*" in output,
                "{} is not found in {}".format("*:{}".format(dhcp_relay['downlink_vlan_iface']['name']), output)) or \
               ("*:*" in output, "dhcp6relay socket is not properly binded")


@pytest.fixture
def setup_active_active_as_active_standby(
    active_active_ports, rand_selected_dut, rand_unselected_dut, tbinfo,                # noqa F811
    config_active_active_dualtor_active_standby, validate_active_active_dualtor_setup): # noqa F811
    if 'dualtor' not in tbinfo['topo']['name']:
        logger.info("Skipping toggle on non-dualtor testbed")

    if active_active_ports:
        # The traffic from active-active mux ports are ECMPed so the DHCP6 Request
        # May land to any TOR.
        # So let's configure the active-active mux ports, to let them work in active-standby mode.
        logger.info("Configuring {} as active".format(rand_selected_dut.hostname))
        logger.info("Configuring {} as standby".format(rand_unselected_dut.hostname))
        config_active_active_dualtor_active_standby(rand_selected_dut, rand_unselected_dut, active_active_ports)

    return


def test_dhcpv6_relay_counter(ptfhost, duthosts, rand_one_dut_hostname, dut_dhcp_relay_data,
                              toggle_all_simulator_ports_to_rand_selected_tor_m, # noqa F811
                              setup_active_active_as_active_standby):            # noqa F811
    """ Test DHCPv6 Counter """
    duthost = duthosts[rand_one_dut_hostname]
    skip_release(duthost, ["201911", "202106"])

    message_types = ["Unknown", "Solicit", "Advertise", "Request", "Confirm", "Renew", "Rebind", "Reply", "Release",
                     "Decline", "Reconfigure", "Information-Request", "Relay-Forward", "Relay-Reply", "Malformed"]

    for dhcp_relay in dut_dhcp_relay_data:
        init_counter(duthost, dhcp_relay['client_iface']['name'], message_types)
        init_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], message_types)
        if dhcp_relay['is_dualtor']:
            init_counter(duthost, dhcp_relay['loopback_iface'][0]['name'], message_types)

        # Send the DHCP relay traffic on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcpv6_counter_test.DHCPCounterTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']),
                           "server_ip": str(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'][0]),
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_link_local": str(dhcp_relay['down_interface_link_local']),
                           "dut_mac": str(dhcp_relay['uplink_mac']),
                           "vlan_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "loopback_ipv6": str(dhcp_relay['loopback_ipv6']),
                           "is_dualtor": str(dhcp_relay['is_dualtor'])},
                   log_file="/tmp/dhcpv6_relay_test.DHCPCounterTest.log", is_python3=True)

        for type in message_types:
            if type in ["Solicit", "Request", "Confirm", "Renew", "Rebind", "Release", "Decline",
                        "Information-Request"]:
                check_dhcpv6_relay_counter(duthost, dhcp_relay['client_iface']['name'], type, "RX")
                check_dhcpv6_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "RX")
            if type in ["Malformed"]:
                # Malformed DHCPv6 Client packet, depend on malformed content. If Type is good but option is malformed
                # First Type will be increased on downlink Ethernet interface first. Then increase Malformed counter
                # on downlink_vlan_iface.
                check_dhcpv6_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "RX")
            if type in ["Unknown"]:
                # From Server Relay-Reply Unknown DHCPv6 type, it's a valid Relay-Reply so Relay-Reply counter
                # is normal increased. But in relay message type is unknown type so drop on downlink_vlan_iface
                # interface
                check_dhcpv6_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "RX")
            if type in ["Advertise", "Reply", "Reconfigure"]:
                check_dhcpv6_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "TX")
                check_dhcpv6_relay_counter(duthost, dhcp_relay['client_iface']['name'], type, "TX")
            if type in ["Relay-Forward"]:
                # Relay-Forward, send out from downlink_vlan_iface first, then send out from uplink interfaces
                check_dhcpv6_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "TX")
                # TBD, add uplink interface TX counter check in future
            if type in ["Relay-Reply"]:
                if dhcp_relay['is_dualtor']:
                    # dual tor, Relay-Reply will be received on loopback interface
                    check_dhcpv6_relay_counter(duthost, dhcp_relay['loopback_iface'][0]['name'], type, "RX")
                else:
                    # Single tor, Relay-Reply will be received on downlink_vlan_iface
                    check_dhcpv6_relay_counter(duthost, dhcp_relay['downlink_vlan_iface']['name'], type, "RX")


def test_dhcp_relay_default(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,
                            toggle_all_simulator_ports_to_rand_selected_tor_m, # noqa F811
                            setup_active_active_as_active_standby):            # noqa F811
    """Test DHCP relay functionality on T0 topology.
       For each DHCP relay agent running on the DuT, verify DHCP packets are relayed properly
    """
    _, duthost = testing_config
    skip_release(duthost, ["201811", "201911", "202106"])  # TO-DO: delete skip release on 201811 and 201911

    # Please note: relay interface always means vlan interface
    for dhcp_relay in dut_dhcp_relay_data:
        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcpv6_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']),
                           "server_ip": str(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'][0]),
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_link_local": str(dhcp_relay['down_interface_link_local']),
                           "vlan_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "loopback_ipv6": str(dhcp_relay['loopback_ipv6']),
                           "is_dualtor": str(dhcp_relay['is_dualtor'])},
                   log_file="/tmp/dhcpv6_relay_test.DHCPTest.log", is_python3=True)


def test_dhcp_relay_after_link_flap(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config):
    """Test DHCP relay functionality on T0 topology after uplinks flap
       For each DHCP relay agent running on the DuT, with relay agent running, flap the uplinks,
       then test whether the DHCP relay agent relays packets properly.
    """
    testing_mode, duthost = testing_config
    skip_release(duthost, ["201811", "201911", "202106"])

    if testing_mode == DUAL_TOR_MODE:
        pytest.skip("skip the link flap testcase on dual tor testbeds")

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('ifconfig {} down'.format(iface))

        # Sleep a bit to ensure uplinks are down
        time.sleep(20)

        # Bring all uplink interfaces back up
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('ifconfig {} up'.format(iface))

        # Sleep a bit to ensure uplinks are up
        wait_all_bgp_up(duthost)

        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcpv6_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']),
                           "server_ip": str(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'][0]),
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_link_local": str(dhcp_relay['down_interface_link_local']),
                           "vlan_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "loopback_ipv6": str(dhcp_relay['loopback_ipv6']),
                           "is_dualtor": str(dhcp_relay['is_dualtor'])},
                   log_file="/tmp/dhcpv6_relay_test.DHCPTest.log", is_python3=True)


def test_dhcp_relay_start_with_uplinks_down(ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config):
    """Test DHCP relay functionality on T0 topology when relay agent starts with uplinks down
       For each DHCP relay agent running on the DuT, bring the uplinks down, then restart the
       relay agent while the uplinks are still down. Then test whether the DHCP relay agent
       relays packets properly.
    """
    testing_mode, duthost = testing_config
    skip_release(duthost, ["201811", "201911", "202106"])

    if testing_mode == DUAL_TOR_MODE:
        pytest.skip("skip the uplinks down testcase on dual tor testbeds")

    for dhcp_relay in dut_dhcp_relay_data:
        # Bring all uplink interfaces down
        for iface in dhcp_relay['uplink_interfaces']:
            duthost.shell('ifconfig {} down'.format(iface))

        # Sleep a bit to ensure uplinks are down
        time.sleep(20)

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

        # Sleep a bit to ensure uplinks are up
        wait_all_bgp_up(duthost)

        # Run the DHCP relay test on the PTF host
        ptf_runner(ptfhost,
                   "ptftests",
                   "dhcpv6_relay_test.DHCPTest",
                   platform_dir="ptftests",
                   params={"hostname": duthost.hostname,
                           "client_port_index": dhcp_relay['client_iface']['port_idx'],
                           "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                           "num_dhcp_servers": len(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']),
                           "server_ip": str(dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs'][0]),
                           "relay_iface_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                           "relay_link_local": str(dhcp_relay['down_interface_link_local']),
                           "vlan_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                           "uplink_mac": str(dhcp_relay['uplink_mac']),
                           "loopback_ipv6": str(dhcp_relay['loopback_ipv6']),
                           "is_dualtor": str(dhcp_relay['is_dualtor'])},
                   log_file="/tmp/dhcpv6_relay_test.DHCPTest.log", is_python3=True)
