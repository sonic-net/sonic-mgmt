import json
import logging
import os
import pytest

from ipaddress import ip_interface, IPv4Interface, IPv6Interface, \
                      ip_address, IPv4Address

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


def _apply_dual_tor_state_to_orchagent(dut, state):
    '''
    Helper function to configure active/standby state in orchagent

    Args:
        dut: DUT object
        state: either 'active' or 'standby'
    '''

    logger.info("Applying {} state to orchagent".format(state))

    vlan_intfs = sorted(dut.get_vlan_intfs(), key=lambda intf: int(intf.replace('Ethernet', '')))

    intf_configs = []

    for intf in vlan_intfs:
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
def apply_active_state_to_orchagent(duthosts, rand_one_dut_hostname):
    dut = duthosts[rand_one_dut_hostname] 

    for func in _apply_dual_tor_state_to_orchagent(dut, 'active'):
        yield func


@pytest.fixture(scope='module')
def apply_standby_state_to_orchagent(duthosts, rand_one_dut_hostname):
    dut = duthosts[rand_one_dut_hostname]

    for func in _apply_dual_tor_state_to_orchagent(dut, 'standby'):
        yield func


@pytest.fixture(scope='module')
def mock_peer_switch_loopback_ip(duthosts, rand_one_dut_hostname):
    '''
    Returns the mocked peer switch loopback IP

    The peer switch loopback is always the next IP address after the DUT loopback

    Returns:
        IPv4Interface object
    '''

    dut = duthosts[rand_one_dut_hostname]
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
def mock_server_base_ip_addr(duthosts, rand_one_dut_hostname):
    '''
    Calculates the IP address of the first server

    These base addresses are always the next IPs after the VLAN address

    Returns:
        IPv4Interface and IPv6 interface objects reperesenting the first server addresses
    '''
    dut = duthosts[rand_one_dut_hostname]
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
def apply_dual_tor_neigh_entries(duthosts, rand_one_dut_hostname, ptfadapter, tbinfo, mock_server_base_ip_addr):
    '''
    Apply neighber table entries for servers
    '''
    logger.info("Applying dual ToR neighbor entries")

    dut = duthosts[rand_one_dut_hostname]

    server_ipv4_base_addr, _ = mock_server_base_ip_addr

    server_ip_to_mac_map = {}

    vlan_intfs = sorted(dut.get_vlan_intfs(), key=lambda intf: int(intf.replace('Ethernet', '')))
    dut_ptf_intf_map = dut.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']

    for i, intf in enumerate(vlan_intfs):
        # For each VLAN interface, get the corresponding PTF interface MAC
        ptf_port_index = dut_ptf_intf_map[intf]
        ptf_mac = ptfadapter.dataplane.ports[(0, ptf_port_index)].mac()
        server_ip_to_mac_map[server_ipv4_base_addr.ip + i] = ptf_mac

    vlan_interface = dut.get_running_config_facts()['VLAN_INTERFACE']
    vlan = list(vlan_interface.keys())[0]

    for ip, mac in server_ip_to_mac_map.items():
        # Use `ip neigh replace` in case entries already exist for the target IP
        # If there are no pre-existing entries, equivalent to `ip neigh add`
        dut.shell('ip -4 neigh replace {} lladdr {} dev {}'.format(ip, mac, vlan))

    yield

    logger.info("Removing dual ToR neighbor entries")

    for ip in server_ip_to_mac_map.keys():
        dut.shell('ip -4 neigh del {} dev {}'.format(ip, vlan))


@pytest.fixture(scope='module')
def apply_dual_tor_peer_switch_route(duthosts, rand_one_dut_hostname, mock_peer_switch_loopback_ip):
    '''
    Apply the tunnel route to reach the peer switch via the T1 switches
    '''
    logger.info("Applying dual ToR peer switch loopback route")
    dut = duthosts[rand_one_dut_hostname]
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
def apply_peer_switch_table_to_dut(duthosts, rand_one_dut_hostname, mock_peer_switch_loopback_ip):
    '''
    Adds the PEER_SWITCH table to config DB
    '''
    logger.info("Applying PEER_SWITCH table")
    dut = duthosts[rand_one_dut_hostname]
    peer_switch_key = 'PEER_SWITCH|switch_hostname'

    dut.shell('redis-cli -n 4 HSET "{}" "address_ipv4" "{}"'.format(peer_switch_key, mock_peer_switch_loopback_ip))

    yield 
    logger.info("Removing peer switch table")

    dut.shell('redis-cli -n 4 DEL "{}"'.format(peer_switch_key))


@pytest.fixture(scope='module')
def apply_tunnel_table_to_dut(duthosts, rand_one_dut_hostname, mock_peer_switch_loopback_ip):
    '''
    Adds the TUNNEL table to config DB
    '''
    logger.info("Applying TUNNEL table")
    dut = duthosts[rand_one_dut_hostname]

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
def apply_mux_cable_table_to_dut(duthosts, rand_one_dut_hostname, mock_server_base_ip_addr):
    '''
    Adds the MUX_CABLE table to config DB
    '''
    logger.info("Applying MUX_CABLE table")
    dut = duthosts[rand_one_dut_hostname]

    server_ipv4_base_addr, server_ipv6_base_addr = mock_server_base_ip_addr

    vlan_intfs = sorted(dut.get_vlan_intfs(), key=lambda intf: int(intf.replace('Ethernet', '')))

    keys_inserted = []

    for i, intf in enumerate(vlan_intfs):
        server_ipv4 = str(server_ipv4_base_addr + i)
        server_ipv6 = str(server_ipv6_base_addr + i)
        key = 'MUX_CABLE|{}'.format(intf)
        keys_inserted.append(key)

        dut.shell('redis-cli -n 4 HSET "{}" "server_ipv4" "{}"'.format(key, server_ipv4))
        dut.shell('redis-cli -n 4 HSET "{}" "server_ipv6" "{}"'.format(key, server_ipv6))
        dut.shell('redis-cli -n 4 HSET "{}" "state" "auto"'.format(key))

    yield
    logger.info("Removing mux cable table")

    for key in keys_inserted:
        dut.shell('redis-cli -n 4 DEL "{}"'.format(key))


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
