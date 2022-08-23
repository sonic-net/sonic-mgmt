import json
import logging
import os
import pytest
import time

from ipaddress import ip_interface, IPv4Interface, IPv6Interface, \
                      ip_address, IPv4Address
from tests.common import config_reload
from tests.common.dualtor.dual_tor_utils import tor_mux_intfs
from tests.common.helpers.assertions import pytest_require, pytest_assert

__all__ = [
    'require_mocked_dualtor',
    'apply_active_state_to_orchagent',
    'apply_dual_tor_neigh_entries',
    'apply_dual_tor_peer_switch_route',
    'apply_mock_dual_tor_kernel_configs',
    'apply_mock_dual_tor_tables',
    'apply_mux_cable_table_to_dut',
    'apply_peer_switch_table_to_dut',
    'apply_standby_state_to_orchagent',
    'apply_tunnel_table_to_dut',
    'cleanup_mocked_configs',
    'mock_peer_switch_loopback_ip',
    'mock_server_base_ip_addr',
    'mock_server_ip_mac_map',
    'mock_server_ipv6_mac_map',
    'set_dual_tor_state_to_orchagent',
    'del_dual_tor_state_from_orchagent',
    'is_t0_mocked_dualtor',
    'is_mocked_dualtor',
    'set_mux_state'
]

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


def set_dual_tor_state_to_orchagent(dut, state, tor_mux_intfs):
    """
    Helper function for setting active/standby state to orchagent
    """
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


def del_dual_tor_state_from_orchagent(dut, state, tor_mux_intfs):
    """
    Helper function for deleting active/standby state to orchagent
    """
    logger.info("Removing {} state from orchagent".format(state))
    intf_configs = []

    for intf in tor_mux_intfs:
        intf_config_dict = {}
        state_dict = {}

        state_key = '"MUX_CABLE_TABLE:{}"'.format(intf)
        state_dict = {'"state"': '"{}"'.format(state)}
        intf_config_dict[state_key] = state_dict
        intf_config_dict['"OP"'] = '"DEL"'

        intf_configs.append(intf_config_dict)

    swss_config_str = json.dumps(intf_configs, indent=4)
    swss_filename = '/mux{}.json'.format(state)
    _apply_config_to_swss(dut, swss_config_str, swss_filename)


def _apply_dual_tor_state_to_orchagent(dut, state, tor_mux_intfs):
    '''
    Helper function to configure active/standby state in orchagent

    Args:
        dut: DUT object
        state: either 'active' or 'standby'
    '''

    set_dual_tor_state_to_orchagent(dut, state, tor_mux_intfs)
    yield
    del_dual_tor_state_from_orchagent(dut, state, tor_mux_intfs)


def is_mocked_dualtor(tbinfo):
    return 'dualtor' not in tbinfo['topo']['name']


@pytest.fixture
def require_mocked_dualtor(tbinfo):
    pytest_require(is_t0_mocked_dualtor(tbinfo), "This testcase is designed for "
        "single tor testbed with mock dualtor config. Skip this testcase on real dualtor testbed")


def set_mux_state(dut, tbinfo, state, itfs, toggle_all_simulator_ports):
    if is_mocked_dualtor(tbinfo):
        set_dual_tor_state_to_orchagent(dut, state, itfs)
    else:
        dut_index = tbinfo['duts'].index(dut.hostname)
        if dut_index == 0 and state == 'active' or dut_index == 1 and state == 'standby':
            side = 'upper_tor'
        else:
            side = 'lower_tor'
        toggle_all_simulator_ports(side)


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
def mock_server_base_ip_addr(rand_selected_dut, tbinfo):
    '''
    Calculates the IP address of the first server

    These base addresses are always the next IPs after the VLAN address

    Returns:
        IPv4Interface and IPv6 interface objects reperesenting the first server addresses
    '''
    dut = rand_selected_dut
    vlan_interfaces = dut.get_extended_minigraph_facts(tbinfo)['minigraph_vlan_interfaces']

    server_ipv4_base_addr = None
    server_ipv6_base_addr = None

    for vlan_intf in vlan_interfaces:
        ip_addr = ip_interface(vlan_intf['addr'])

        if type(ip_addr) is IPv4Interface:
            server_ipv4_base_addr = ip_addr + 1
        elif type(ip_addr) is IPv6Interface:
            server_ipv6_base_addr = ip_addr + 1

    logger.debug("Mocked server IP base addresses are: {} and {}".format(server_ipv4_base_addr, server_ipv6_base_addr))
    return server_ipv4_base_addr, server_ipv6_base_addr


@pytest.fixture(scope='module')
def mock_server_ip_mac_map(rand_selected_dut, tbinfo, ptfadapter, mock_server_base_ip_addr, tor_mux_intfs):
    dut = rand_selected_dut

    server_ipv4_base_addr, _ = mock_server_base_ip_addr

    server_ip_mac_map = {}

    dut_ptf_intf_map = dut.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']

    for i, intf in enumerate(tor_mux_intfs):
        # For each VLAN interface, get the corresponding PTF interface MAC
        ptf_port_index = dut_ptf_intf_map[intf]
        for retry in range(10):
            ptf_mac = ptfadapter.dataplane.get_mac(0, ptf_port_index)
            if ptf_mac != None:
                break
            else:
                time.sleep(2)
        pytest_assert(ptf_mac != None, "fail to get mac address of interface {}".format(ptf_port_index))

        server_ip_mac_map[server_ipv4_base_addr.ip + i] = ptf_mac

    return server_ip_mac_map


@pytest.fixture(scope='module')
def mock_server_ipv6_mac_map(rand_selected_dut, tbinfo, ptfadapter, mock_server_base_ip_addr, tor_mux_intfs):
    dut = rand_selected_dut
    _, server_ipv6_base_addr = mock_server_base_ip_addr
    server_ipv6_mac_map = {}
    dut_ptf_intf_map = dut.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']

    for i, intf in enumerate(tor_mux_intfs):
        # For each VLAN interface, get the corresponding PTF interface MAC
        ptf_port_index = dut_ptf_intf_map[intf]
        for retry in range(10):
            ptf_mac = ptfadapter.dataplane.get_mac(0, ptf_port_index)
            if ptf_mac != None:
                break
            else:
                time.sleep(2)
        pytest_assert(ptf_mac != None, "fail to get mac address of interface {}".format(ptf_port_index))

        server_ipv6_mac_map[server_ipv6_base_addr.ip + i] = ptf_mac

    return server_ipv6_mac_map


@pytest.fixture(scope='module')
def apply_dual_tor_neigh_entries(cleanup_mocked_configs, rand_selected_dut, tbinfo, mock_server_ip_mac_map, mock_server_ipv6_mac_map):
    '''
    Apply neighbor table entries for servers
    '''
    logger.info("Applying dual ToR neighbor entries")

    dut = rand_selected_dut

    vlan = dut.get_extended_minigraph_facts(tbinfo)['minigraph_vlans'].keys()[0]

    cmds = []
    for ip, mac in mock_server_ip_mac_map.items():
        # Use `ip neigh replace` in case entries already exist for the target IP
        # If there are no pre-existing entries, equivalent to `ip neigh add`
        cmds.append('ip -4 neigh replace {} lladdr {} dev {}'.format(ip, mac, vlan))

    for ipv6, mac in mock_server_ipv6_mac_map.items():
        cmds.append('ip -6 neigh replace {} lladdr {} dev {}'.format(ipv6, mac, vlan))
    dut.shell_cmds(cmds=cmds)

    return


@pytest.fixture(scope='module')
def apply_dual_tor_peer_switch_route(cleanup_mocked_configs, rand_selected_dut, mock_peer_switch_loopback_ip):
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

    return


@pytest.fixture(scope='module')
def apply_peer_switch_table_to_dut(cleanup_mocked_configs, rand_selected_dut, mock_peer_switch_loopback_ip):
    '''
    Adds the PEER_SWITCH table to config DB and the peer_switch field to the device metadata
    Also adds the 'subtype' field in the device metadata table and sets it to 'DualToR'
    '''
    logger.info("Applying PEER_SWITCH table")
    dut = rand_selected_dut
    peer_switch_hostname = 'switch_hostname'
    peer_switch_key = 'PEER_SWITCH|{}'.format(peer_switch_hostname)
    device_meta_key = 'DEVICE_METADATA|localhost'
    restart_swss = False
    if dut.get_asic_name() in ['th2', 'td3']:
        restart_swss = True
    cmd = 'redis-cli -n 4 HSET "{}" "{}" "{}"'.format(device_meta_key, 'subtype', 'DualToR')
    dut.shell(cmd=cmd)
    if restart_swss:
        # Restart swss on TH2 or TD3 platform to trigger syncd restart to regenerate config.bcm
        # We actually need to restart syncd only, but restarting syncd will also trigger swss
        # being restarted, and it costs more time than restarting swss
        logger.info("Restarting swss service to regenerate config.bcm")
        dut.shell('systemctl restart swss')
        time.sleep(120)

    cmds = ['redis-cli -n 4 HSET "{}" "address_ipv4" "{}"'.format(peer_switch_key, mock_peer_switch_loopback_ip.ip),
            'redis-cli -n 4 HSET "{}" "{}" "{}"'.format(device_meta_key, 'peer_switch', peer_switch_hostname)]
    dut.shell_cmds(cmds=cmds)
    if restart_swss:
        # Restart swss on TH2 or TD3 platform to apply changes
        logger.info("Restarting swss service")
        dut.shell('systemctl restart swss')
        time.sleep(120)

    yield
    logger.info("Removing peer switch table")

    cmds=['redis-cli -n 4 DEL "{}"'.format(peer_switch_key),
          'redis-cli -n 4 HDEL"{}" "{}" "{}"'.format(device_meta_key, 'subtype', 'DualToR'),
          'redis-cli -n 4 HDEL "{}" "{}" "{}"'.format(device_meta_key, 'peer_switch', peer_switch_hostname)]
    dut.shell_cmds(cmds=cmds)
    if restart_swss:
        # Restart swss on TH2 or TD3 platform to remove changes
        logger.info("Restarting swss service")
        dut.shell('systemctl restart swss')
        time.sleep(120)
        
    return


@pytest.fixture(scope='module')
def apply_tunnel_table_to_dut(cleanup_mocked_configs, rand_selected_dut, mock_peer_switch_loopback_ip):
    '''
    Adds the TUNNEL table to config DB
    '''
    logger.info("Applying TUNNEL table")
    dut = rand_selected_dut

    dut_loopback = (mock_peer_switch_loopback_ip - 1).ip

    tunnel_params = {
        'TUNNEL': {
            'MuxTunnel0': {
                'dscp_mode': 'uniform',
                'dst_ip': str(dut_loopback),
                'ecn_mode': 'copy_from_outer',
                'encap_ecn_mode': 'standard',
                'ttl_mode': 'pipe',
                'tunnel_type': 'IPINIP'
            }
        }
    }

    dut.copy(content=json.dumps(tunnel_params, indent=2), dest="/tmp/tunnel_params.json")
    dut.shell("sonic-cfggen -j /tmp/tunnel_params.json --write-to-db")

    return


@pytest.fixture(scope='module')
def apply_mux_cable_table_to_dut(cleanup_mocked_configs, rand_selected_dut, mock_server_base_ip_addr, tor_mux_intfs):
    '''
    Adds the MUX_CABLE table to config DB
    '''
    logger.info("Applying MUX_CABLE table")
    dut = rand_selected_dut

    server_ipv4_base_addr, server_ipv6_base_addr = mock_server_base_ip_addr

    mux_cable_params = dict()
    for i, intf in enumerate(tor_mux_intfs):
        server_ipv4 = str(server_ipv4_base_addr + i)
        server_ipv6 = str(server_ipv6_base_addr + i)
        mux_cable_params.update(
            {intf: {
                'server_ipv4':server_ipv4,
                'server_ipv6':server_ipv6,
                'state': 'auto'
                }
            })

    mux_cable_params = {'MUX_CABLE': mux_cable_params}
    dut.copy(content=json.dumps(mux_cable_params, indent=2), dest="/tmp/mux_cable_params.json")
    dut.shell("sonic-cfggen -j /tmp/mux_cable_params.json --write-to-db")
    return


def is_t0_mocked_dualtor(tbinfo):
    return tbinfo["topo"]["type"] == "t0" and 'dualtor' not in tbinfo["topo"]["name"]


@pytest.fixture(scope='module')
def apply_mock_dual_tor_tables(request, tbinfo):
    '''
    Wraps all table fixtures for convenience
    '''
    if is_t0_mocked_dualtor(tbinfo):
        request.getfixturevalue("apply_mux_cable_table_to_dut")
        request.getfixturevalue("apply_tunnel_table_to_dut")
        request.getfixturevalue("apply_peer_switch_table_to_dut")
        logger.info("Done applying database tables for dual ToR mock")


@pytest.fixture(scope='module')
def apply_mock_dual_tor_kernel_configs(request, tbinfo):
    '''
    Wraps all kernel related (routes and neighbor entries) fixtures for convenience
    '''
    if is_t0_mocked_dualtor(tbinfo):
        request.getfixturevalue("apply_dual_tor_peer_switch_route")
        request.getfixturevalue("apply_dual_tor_neigh_entries")
        logger.info("Done applying kernel configs for dual ToR mock")


@pytest.fixture(scope="module")
def cleanup_mocked_configs(duthost, tbinfo):
    """Config reload to reset the mocked configs applied to DUT."""

    yield

    if is_t0_mocked_dualtor(tbinfo):
        logger.info("Load minigraph to reset the DUT %s", duthost.hostname)
        config_reload(duthost, config_source="minigraph")
