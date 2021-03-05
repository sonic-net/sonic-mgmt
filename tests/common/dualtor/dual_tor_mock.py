import json
import logging
import os
import pytest

from ipaddress import ip_interface, IPv4Interface, IPv6Interface, \
                      ip_address, IPv4Address

from tests.common.dualtor.dual_tor_utils import tor_mux_intfs

__all__ = ['apply_active_state_to_orchagent', 'apply_dual_tor_neigh_entries', 'apply_dual_tor_peer_switch_route', 'apply_mock_dual_tor_kernel_configs',
           'apply_mock_dual_tor_tables', 'apply_mux_cable_table_to_dut', 'apply_peer_switch_table_to_dut', 'apply_standby_state_to_orchagent', 'apply_tunnel_table_to_dut',
           'mock_peer_switch_loopback_ip', 'mock_server_base_ip_addr']

logger = logging.getLogger(__name__)

'''
Fixtures and helper methods to configure a single ToR testbed to mock the standby or active ToR in a dual ToR testbed

Test functions wishing to apply the full mock config must use the following fixtures:
    - apply_mock_dual_tor_tables
    - apply_mock_dual_tor_kernel_configs
    - apply_active_state_to_orchagent OR apply_standby_state_to_orchagent
'''

def _apply_config_to_swss(dut, swss_config_str, swss_filename='swss_config_file'):
    '''
    Applies a given configuration string to the SWSS container

    Args:
        dut: DUT object
        swss_config_str: String containing the configuration to be applied
        swss_filename: The filename to use for copying the config file around (default='swss_config_file')
    '''

    dut_filename = os.path.join('/tmp',swss_filename)

    dut.shell('echo "{}" > {}'.format(swss_config_str, dut_filename))
    dut.shell('docker cp {} swss:{}'.format(dut_filename, swss_filename))
    dut.shell('docker exec swss sh -c "swssconfig {}"'.format(swss_filename))


def _apply_dual_tor_state_to_orchagent(dut, state, tor_mux_intfs):
    '''
    Helper function to configure active/standby state in orchagent

    Args:
        dut: DUT object
        state: either 'active' or 'standby'
    '''

    logger.info("Applying {} state to orchagent".format(state))

    intf_configs = []

    for intf in tor_mux_intfs:
        '''
        For each VLAN interface, create one configuration to be applied to orchagent
        Each interface configuration has the following structure:

        {
            "MUX_CABLE_TABLE:<intf name>": {
                "state": <active/standby>
            }
            "OP": "SET"
        }
        '''
        intf_config_dict = {}
        state_dict = {}

        state_key = '"MUX_CABLE_TABLE:{}"'.format(intf)
        state_dict = {'"state"': '"{}"'.format(state)}
        intf_config_dict[state_key] = state_dict
        intf_config_dict['"OP"'] = '"SET"'

        intf_configs.append(intf_config_dict)

    swss_config_str = json.dumps(intf_configs, indent=4)
    logger.debug('SWSS config string is {}'.format(swss_config_str))
    swss_filename = '/mux{}.json'.format(state)
    _apply_config_to_swss(dut, swss_config_str, swss_filename)

    yield
    logger.info("Removing {} state from orchagent".format(state))

    for i in range(len(intf_configs)):
        intf_configs[i]['"OP"'] = '"DEL"'

    swss_config_str = json.dumps(intf_configs, indent=4)
    swss_filename = '/mux{}.json'.format(state)
    _apply_config_to_swss(dut, swss_config_str, swss_filename)


@pytest.fixture(scope='module')
def apply_active_state_to_orchagent(rand_selected_dut, tor_mux_intfs):
    dut = rand_selected_dut

    for func in _apply_dual_tor_state_to_orchagent(dut, 'active', tor_mux_intfs):
        yield func


@pytest.fixture(scope='module')
def apply_standby_state_to_orchagent(rand_selected_dut, tor_mux_intfs):
    dut = rand_selected_dut

    for func in _apply_dual_tor_state_to_orchagent(dut, 'standby', tor_mux_intfs):
        yield func


@pytest.fixture(scope='module')
def mock_peer_switch_loopback_ip(rand_selected_dut):
    '''
    Returns the mocked peer switch loopback IP

    The peer switch loopback is always the next IP address after the DUT loopback

    Returns:
        IPv4Interface object
    '''

    dut = rand_selected_dut
    lo_facts = dut.get_running_config_facts()['LOOPBACK_INTERFACE']
    loopback_intf = list(lo_facts.keys())[0]

    peer_ipv4_loopback = None

    for ip_addr_str in lo_facts[loopback_intf]:
        ip_addr = ip_interface(ip_addr_str)

        if type(ip_addr) is IPv4Interface:
            peer_ipv4_loopback = ip_addr + 1

    logger.debug("Mocked peer switch loopback is {}".format(peer_ipv4_loopback))
    return peer_ipv4_loopback


@pytest.fixture(scope='module')
def mock_server_base_ip_addr(rand_selected_dut):
    '''
    Calculates the IP address of the first server

    These base addresses are always the next IPs after the VLAN address

    Returns:
        IPv4Interface and IPv6 interface objects reperesenting the first server addresses
    '''
    dut = rand_selected_dut
    vlan_interface = dut.get_running_config_facts()['VLAN_INTERFACE']

    vlan = list(vlan_interface.keys())[0]

    server_ipv4_base_addr = None
    server_ipv6_base_addr = None

    for ip_addr_str in vlan_interface[vlan].keys():
        ip_addr = ip_interface(ip_addr_str)

        if type(ip_addr) is IPv4Interface:
            server_ipv4_base_addr = ip_addr + 1
        elif type(ip_addr) is IPv6Interface:
            server_ipv6_base_addr = ip_addr + 1

    logger.debug("Mocked server IP base addresses are: {} and {}".format(server_ipv4_base_addr, server_ipv6_base_addr))
    return server_ipv4_base_addr, server_ipv6_base_addr


@pytest.fixture(scope='module')
def apply_dual_tor_neigh_entries(rand_selected_dut, ptfadapter, tbinfo, mock_server_base_ip_addr, tor_mux_intfs):
    '''
    Apply neighber table entries for servers
    '''
    logger.info("Applying dual ToR neighbor entries")

    dut = rand_selected_dut

    server_ipv4_base_addr, _ = mock_server_base_ip_addr

    server_ip_to_mac_map = {}

    dut_ptf_intf_map = dut.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']

    for i, intf in enumerate(tor_mux_intfs):
        # For each VLAN interface, get the corresponding PTF interface MAC
        ptf_port_index = dut_ptf_intf_map[intf]
        ptf_mac = ptfadapter.dataplane.ports[(0, ptf_port_index)].mac()
        server_ip_to_mac_map[server_ipv4_base_addr.ip + i] = ptf_mac

    vlan_interface = dut.get_running_config_facts()['VLAN_INTERFACE']
    vlan = list(vlan_interface.keys())[0]

    cmds = []
    for ip, mac in server_ip_to_mac_map.items():
        # Use `ip neigh replace` in case entries already exist for the target IP
        # If there are no pre-existing entries, equivalent to `ip neigh add`
        cmds.append('ip -4 neigh replace {} lladdr {} dev {}'.format(ip, mac, vlan))
    dut.shell_cmds(cmds=cmds)

    yield

    logger.info("Removing dual ToR neighbor entries")

    cmds = []
    for ip in server_ip_to_mac_map.keys():
        cmds.append('ip -4 neigh del {} dev {}'.format(ip, vlan))
    dut.shell_cmds(cmds=cmds)


@pytest.fixture(scope='module')
def apply_dual_tor_peer_switch_route(rand_selected_dut, mock_peer_switch_loopback_ip):
    '''
    Apply the tunnel route to reach the peer switch via the T1 switches
    '''
    logger.info("Applying dual ToR peer switch loopback route")
    dut = rand_selected_dut
    bgp_neighbors = dut.bgp_facts()['ansible_facts']['bgp_neighbors'].keys()

    ipv4_neighbors = []

    for neighbor in bgp_neighbors:
        neighbor_ip = ip_address(neighbor)

        if type(neighbor_ip) is IPv4Address:
            ipv4_neighbors.append(neighbor)

    nexthop_str = ''
    for neighbor in ipv4_neighbors:
        nexthop_str += 'nexthop via {} '.format(neighbor)

    # Use `ip route replace` in case a rule already exists for this IP
    # If there are no pre-existing routes, equivalent to `ip route add`
    dut.shell('ip route replace {} {}'.format(mock_peer_switch_loopback_ip, nexthop_str))

    yield

    logger.info("Removing dual ToR peer switch loopback route")

    dut.shell('ip route del {}'.format(mock_peer_switch_loopback_ip))


@pytest.fixture(scope='module')
def apply_peer_switch_table_to_dut(rand_selected_dut, mock_peer_switch_loopback_ip):
    '''
    Adds the PEER_SWITCH table to config DB and the peer_switch field to the device metadata
    Also adds the 'subtype' field in the device metadata table and sets it to 'DualToR'
    '''
    logger.info("Applying PEER_SWITCH table")
    dut = rand_selected_dut
    peer_switch_hostname = 'switch_hostname'
    peer_switch_key = 'PEER_SWITCH|{}'.format(peer_switch_hostname)
    device_meta_key = 'DEVICE_METADATA|localhost'

    dut.shell('redis-cli -n 4 HSET "{}" "address_ipv4" "{}"'.format(peer_switch_key, mock_peer_switch_loopback_ip.ip))
    dut.shell('redis-cli -n 4 HSET "{}" "{}" "{}"'.format(device_meta_key, 'subtype', 'dualToR'))
    dut.shell('redis-cli -n 4 HSET "{}" "{}" "{}"'.format(device_meta_key, 'peer_switch', peer_switch_hostname))

    yield
    logger.info("Removing peer switch table")

    dut.shell('redis-cli -n 4 DEL "{}"'.format(peer_switch_key))
    dut.shell('redis-cli -n 4 HDEL"{}" "{}" "{}"'.format(device_meta_key, 'subtype', 'dualToR'))
    dut.shell('redis-cli -n 4 HDEL "{}" "{}" "{}"'.format(device_meta_key, 'peer_switch', peer_switch_hostname))


@pytest.fixture(scope='module')
def apply_tunnel_table_to_dut(rand_selected_dut, mock_peer_switch_loopback_ip):
    '''
    Adds the TUNNEL table to config DB
    '''
    logger.info("Applying TUNNEL table")
    dut = rand_selected_dut

    dut_loopback = (mock_peer_switch_loopback_ip - 1).ip

    tunnel_key = 'TUNNEL|MuxTunnel0'
    tunnel_params = {
        'dscp_mode': 'uniform',
        'dst_ip': dut_loopback,
        'ecn_mode': 'copy_from_outer',
        'encap_ecn_mode': 'standard',
        'ttl_mode': 'pipe',
        'tunnel_type': 'IPINIP'
    }

    for param, value in tunnel_params.items():
        dut.shell('redis-cli -n 4 HSET "{}" "{}" "{}"'.format(tunnel_key, param, value))

    yield
    logger.info("Removing tunnel table")

    dut.shell('redis-cli -n 4 DEL "{}"'.format(tunnel_key))


@pytest.fixture(scope='module')
def apply_mux_cable_table_to_dut(rand_selected_dut, mock_server_base_ip_addr, tor_mux_intfs):
    '''
    Adds the MUX_CABLE table to config DB
    '''
    logger.info("Applying MUX_CABLE table")
    dut = rand_selected_dut

    server_ipv4_base_addr, server_ipv6_base_addr = mock_server_base_ip_addr

    keys_inserted = []

    cmds = []
    for i, intf in enumerate(tor_mux_intfs):
        server_ipv4 = str(server_ipv4_base_addr + i)
        server_ipv6 = str(server_ipv6_base_addr + i)
        key = 'MUX_CABLE|{}'.format(intf)
        keys_inserted.append(key)
        cmds.append('redis-cli -n 4 HSET "{}" "server_ipv4" "{}"'.format(key, server_ipv4))
        cmds.append('redis-cli -n 4 HSET "{}" "server_ipv6" "{}"'.format(key, server_ipv6))
        cmds.append('redis-cli -n 4 HSET "{}" "state" "auto"'.format(key))
    dut.shell_cmds(cmds=cmds)

    yield
    logger.info("Removing mux cable table")

    cmds = []
    for key in keys_inserted:
        cmds.append('redis-cli -n 4 DEL "{}"'.format(key))
    dut.shell_cmds(cmds=cmds)


@pytest.fixture(scope='module')
def apply_mock_dual_tor_tables(request, tbinfo):
    '''
    Wraps all table fixtures for convenience
    '''
    if tbinfo["topo"]["name"] == "t0":
        request.getfixturevalue("apply_mux_cable_table_to_dut")
        request.getfixturevalue("apply_tunnel_table_to_dut")
        request.getfixturevalue("apply_peer_switch_table_to_dut")
        logger.info("Done applying database tables for dual ToR mock")


@pytest.fixture(scope='module')
def apply_mock_dual_tor_kernel_configs(request, tbinfo):
    '''
    Wraps all kernel related (routes and neighbor entries) fixtures for convenience
    '''
    if tbinfo["topo"]["name"] == "t0":
        request.getfixturevalue("apply_dual_tor_peer_switch_route")
        request.getfixturevalue("apply_dual_tor_neigh_entries")
        logger.info("Done applying kernel configs for dual ToR mock")
