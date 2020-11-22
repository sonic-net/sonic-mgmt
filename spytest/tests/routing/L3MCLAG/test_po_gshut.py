##########################################################################################
# Title: MCLAG PO Graceful-shutdown script
# Author: Sneha Ann Mathew <sneha.mathew@broadcom.com>
##########################################################################################

import pytest
import sys
from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan
import apis.switching.mac as mac
import apis.system.interface as intf
import apis.system.port as port
import apis.system.reboot as boot
import apis.switching.portchannel as po
import apis.switching.mclag as mclag
import apis.routing.arp as arp
import apis.routing.ip as ip
import apis.routing.bgp as bgp
import apis.routing.ip_bgp as ip_bgp
import apis.common.asic as asicapi
from mclag_vars_mm import *

import utilities.common as co_utils
import utilities.utils as utils
import utilities.parallel as pll


data = SpyTestDict()
po_data = {}
mclag_data = {}
mclag_intf_data = {}

session_def_time = 30
wait_time = 30+2
#wait_time = 0

pll_exec = True
dbg_exec = False
TECHSUPPORT = True
techsupport_enable = True

def print_log(message,alert_type="LOW"):
    '''
    Uses st.log procedure with some formatting to display proper log messages
    :param message: Message to be printed
    :param alert_level:
    :return:
    '''
    log_start = "\n======================================================================================\n"
    log_end =   "\n======================================================================================"
    log_delimiter ="\n###############################################################################################\n"

    if alert_type == "HIGH":
        st.log("{} {} {}".format(log_delimiter,message,log_delimiter))
    elif alert_type == "MED":
        st.log("{} {} {}".format(log_start,message,log_end))
    elif alert_type == "LOW":
        st.log(message)
    elif alert_type == "ERROR":
        st.error("{} {} {}".format(log_start,message,log_start))

def get_test_func_name(level=1):
    return sys._getframe(level).f_code.co_name

def collect_techsupport():
    global TECHSUPPORT, techsupport_enable

    test_func = str(get_test_func_name(level=2))
    if TECHSUPPORT and techsupport_enable:
        st.generate_tech_support(dut=None, name=test_func)
    TECHSUPPORT = False

def get_tgen_handles():
    global tg_h, tgn_port, tgn_handle

    tg_h = tgapi.get_chassis(vars)
    tgn_port = {}
    tgn_handle = {}
    ### Assigning TGEN type
    if 'ixia' in vars['tgen_list'][0]:
        data.tgen_type = 'ixia'
    else:
        data.tgen_type = 'stc'

    ### TGN links returned is like [dut_port, peer_device_name, peer_port]. Hence index for TGN port is 2.
    tgn_port_index = 2
    for dut in dut_list:
        #first tgen port
        tgn_port.update({(dut,1): st.get_tg_links(dut)[0][tgn_port_index]})
        tgn_handle.update({(dut,1): tg_h.get_port_handle(tgn_port[(dut,1)])})
        #second tgen port
        tgn_port.update({(dut,2): st.get_tg_links(dut)[1][tgn_port_index]})
        tgn_handle.update({(dut,2): tg_h.get_port_handle(tgn_port[(dut,2)])})


def initialize_topology():
    global vars, dut1, dut2, dut3, dut4, dut_list, dut_tgn_port

    ### Verify Minimum topology requirement is met
    vars = st.ensure_min_topology("D1D2:4", "D1D3:4", "D2D3:4", "D1D4:4", "D2D4:4", "D1T1:2", "D2T1:2", "D3T1:2", "D4T1:2")

    print_log(
        "Test Topology Description\n==============================\n\
        - Test script uses mclag topology with D1 and D2 as peers and D3 and D4 as clients.\n\
        - Between each pair of DUTs, 4 links will be there and 2 TGEN ports per dut.\n\
        - PO-1 and PO-2 will be configured between mclag peers.\n\
        - Mclag interfaces PO-3 will be configured between D1,D2 and D3.\n\
        - Mclag interfaces PO-4 and PO-5 will be configured between D1,D2 and D4.\n\
        - Traffic streams used follow below MAC pattern.\n\
        00:<src_dut_no><src_tgn_port>:<vlan>:<stream_id>:00:xx <---> 00:<dst_dut_no><dst_tgn_port>:<vlan>:<stream_id>:00:xx \n\
        \tvlan: can be 80 & 81\n\
        \txx: will be 01 & 02 and corresponds to number of MACs per stream\n\
        In addition, each test case will have trigger configs/unconfigs and corresponding streams used",'HIGH')

    ### Initialize DUT variables and ports
    dut_list = vars.dut_list
    dut1 = vars.D1
    dut2 = vars.D2
    dut3 = vars.D3
    dut4 = vars.D4
    data.mclag_peers= [dut1, dut2]
    data.mclag_clients = [dut3, dut4]
    data.mclag_interfaces = ['PortChannel3','PortChannel4','PortChannel5']

    ### Initialize TGEN connected DUT ports
    dut_tgn_port = {}
    for dut in dut_list:
        # first tgen port
        dut_tgn_port.update({(dut,1): st.get_tg_links(dut)[0][0]})
        # second tgen port
        dut_tgn_port.update({(dut,2): st.get_tg_links(dut)[1][0]})

    ### Initialize TGEN side ports and handles
    get_tgen_handles()

    ### Setting expect values
    data.total_vlans = [3+trunk_vlan_count,3+trunk_vlan_count,1+trunk_vlan_count,1+trunk_vlan_count]

    mclag_data.update({
        dut1: {
            'domain_id': mclag_domain,
            'local_ip': peer1_ip,
            'peer_ip': peer2_ip,
            'session_status': 'OK',
            'peer_link_inf': 'PortChannel2',
            'node_role': 'Active',
            'mclag_intfs': len(data.mclag_interfaces),
            'keep_alive': 1,
            'session_timeout': session_def_time
        }
    })
    mclag_data.update({
        dut2: {
            'domain_id': mclag_domain,
            'local_ip': peer2_ip,
            'peer_ip': peer1_ip,
            'session_status': 'OK',
            'peer_link_inf': 'PortChannel2',
            'node_role': 'Standby',
            'mclag_intfs': len(data.mclag_interfaces),
            'keep_alive': 1,
            'session_timeout': session_def_time
        }
    })

    mclag_intf_data.update({
        dut1: {
            'domain_id': mclag_domain,
            'PortChannel3': {
                'local_state':'Up',
                'remote_state':'Up',
                'traffic_disable':'No'
            },
            'PortChannel4': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'traffic_disable': 'No'
            },
            'PortChannel5': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'traffic_disable': 'No'
            }
        }
    })
    mclag_intf_data.update({
        dut2: {
            'domain_id': mclag_domain,
            'PortChannel3': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'traffic_disable': 'No'
            },
            'PortChannel4': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'traffic_disable': 'No'
            },
            'PortChannel5': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'traffic_disable': 'No'
            }
        }
    })
    ## Expected total mac counts on each dut
    strm_vlans = 2
    no_of_macs= strm_mac_count * strm_vlans
    base_strm_cnt = [6, 6, 3, 3]
    flood_strm_cnt = [0, 0, 3, 3]
    system_macs = [1, 1, 0, 0]
    data.mac_expect_list = [2 * base_strm_cnt[i] * no_of_macs + flood_strm_cnt[i] * no_of_macs + system_macs[i]
                                    for i in range(len(dut_list))]

def validate_topology():
    # Enable all links in the topology and verify links up
    dut_port_dict = {}
    for dut in dut_list:
        port_list = st.get_dut_links_local(dut, peer=None, index=None)
        dut_port_dict[dut] = port_list
    #Usage: exec_all(use_threads, list_of_funcs)
    [result, exceptions] = co_utils.exec_all(pll_exec, [[intf.interface_operation, dut, dut_port_dict[dut], 'startup',False]
                                          for dut in dut_port_dict.keys()])
    if not all(i is None for i in exceptions):
        print_log(exceptions)

    return False if False in result else True


@pytest.fixture(scope="module",autouse=True)
def prologue_epilogue():
    print_log("Starting to initialize and validate topology...",'MED')
    initialize_topology()
    validate_topology()
    api_list = []
    api_list.append([l3mclag_traffic_config])
    api_list.append([mclag_module_config])
    co_utils.exec_all(pll_exec, api_list, True)
    # start traffic
    run_traffic()
    mclag_basic_validations()
    yield
    run_traffic(action='STOP')
    mclag_module_unconfig()


def configure_portchannel(po_data):
    '''
    Sample po_data structure
    po_data['PortChannel3'] = {'duts': [dut1, dut2, dut3],
                                 'po_members': {dut1: [vars.D1D3P1, vars.D1D3P2],
                                                dut2: [vars.D2D3P1, vars.D2D3P2],
                                                dut3: [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2]}}
    '''
    for po_id in po_data.keys():
        if po_id in ['PortChannel3', 'PortChannel4', 'PortChannel5']:
            co_utils.exec_all(pll_exec, [[po.create_portchannel, dut, po_id, True] for dut in data.mclag_peers])
            co_utils.exec_all(pll_exec, [[po.create_portchannel, dut, po_id, False] for dut in data.mclag_clients])
        else:
            co_utils.exec_all(pll_exec, [[po.create_portchannel, dut, po_id, False] for dut in po_data[po_id]['duts']])
        co_utils.exec_all(pll_exec, [[po.add_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in
                              po_data[po_id]['duts']])


def unconfigure_portchannel(po_data):
    '''
    Sample po_data structure
    po_data['PortChannel3'] = {'duts': [dut1, dut2, dut3],
                                 'po_members': {dut1: [vars.D1D3P1, vars.D1D3P2],
                                                dut2: [vars.D2D3P1, vars.D2D3P2],
                                                dut3: [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2]}}
    '''
    for po_id in po_data.keys():
        co_utils.exec_all(pll_exec, [[po.delete_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in po_data[po_id]['duts']])
        co_utils.exec_all(pll_exec, [[po.delete_portchannel, dut, po_id] for dut in po_data[po_id]['duts']])


def mclag_config_verify():
    mclag_module_config()
    mclag_basic_validations()

def config_vlan():
    ### Create vlan on all duts and assign to respective member ports
    api_list = []
    api_list.append([vlan.create_vlan, dut1, tg12_vlan])
    api_list.append([vlan.create_vlan, dut2, tg22_vlan])
    co_utils.exec_all(pll_exec, api_list)

    co_utils.exec_all(pll_exec, [[vlan.create_vlan, dut, [access_vlan]] for dut in dut_list])
    api_list = []
    api_list.append([vlan.add_vlan_member, dut1, tg12_vlan, dut_tgn_port[(dut1, 2)], False])
    api_list.append([vlan.add_vlan_member, dut2, tg22_vlan, dut_tgn_port[(dut2, 2)], True])
    api_list.append([vlan.add_vlan_member, dut4, access_vlan, dut_tgn_port[(dut4, 1)], False])
    co_utils.exec_all(pll_exec, api_list)

    ### Create trunk VLANs on all DUTs using range command
    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range, dut, trunk_vlan_range] for dut in dut_list])
    # Configure trunk vlans on second TGEN ports of 2nd Mclag client
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, dut_tgn_port[(dut, 2)]] for dut in
                          [dut4]])

    ### Configure vlans on all PortChannels
    co_utils.exec_all(pll_exec,
                   [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel2', True] for dut in data.mclag_peers])
    co_utils.exec_all(pll_exec,
                   [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel4'] for dut in [dut1, dut2, dut4]])

    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel2']
                          for dut in data.mclag_peers])
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel5']
                          for dut in [dut1, dut2, dut4]])

    ### Configure Mclag vlan for
    co_utils.exec_all(pll_exec, [[vlan.create_vlan, dut, mclag_vlan] for dut in data.mclag_peers])
    co_utils.exec_all(pll_exec,
                   [[vlan.add_vlan_member, dut, mclag_vlan, 'PortChannel1', True] for dut in data.mclag_peers])

def config_ip_v4_v6():
    ### Assign IP addresses to TGEN interfaces
    ### Assign IPv6 addresses to TGEN interfaces
    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, vars.D1T1P1, tg11_ip[0], v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, vars.D2T1P1, tg21_ip[0], v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut3, vars.D3T1P1, tg31_ip[0], v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, vars.D1T1P1, tg11_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, vars.D2T1P1, tg21_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut3, vars.D3T1P1, tg31_ip6[0], v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(tg12_vlan), tg12_ip[0], v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(tg22_vlan), tg22_ip[0], v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut3, vars.D3T1P2, tg32_ip[0], v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(tg12_vlan), tg12_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(tg22_vlan), tg22_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut3, vars.D3T1P2, tg32_ip6[0], v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    ### Assign IP addresses to MCLAG interfaces
    ### Assign IPv6 addresses to MCLAG interfaces
    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, data.mclag_interfaces[0], po3_ip_d1, v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, data.mclag_interfaces[0], po3_ip_d2, v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut3, data.mclag_interfaces[0], po3_ip_d3, v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(access_vlan), po4_ip_d1, v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(access_vlan), po4_ip_d2, v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut4, 'Vlan' + str(access_vlan), po4_ip_d4, v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(trunk_base_vlan), po5_ip_d1, v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(trunk_base_vlan), po5_ip_d2, v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut4, 'Vlan' + str(trunk_base_vlan), po5_ip_d4, v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, data.mclag_interfaces[0], po3_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, data.mclag_interfaces[0], po3_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut3, data.mclag_interfaces[0], po3_ip6_d3, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(access_vlan), po4_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(access_vlan), po4_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut4, 'Vlan' + str(access_vlan), po4_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(trunk_base_vlan), po5_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(trunk_base_vlan), po5_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut4, 'Vlan' + str(trunk_base_vlan), po5_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)



def config_mclag():
    ### Configure Mclag domain and interfaces
    ### Configure IP on PO-1 for L3 reachability between peers
    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(mclag_vlan), peer1_ip, v4_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(mclag_vlan), peer2_ip, v4_mask])
    co_utils.exec_all(pll_exec, api_list)
    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(mclag_vlan), peer1_ip6, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(mclag_vlan), peer2_ip6, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    dict1 = {'domain_id':mclag_domain, 'local_ip': mclag_data[dut1]['local_ip'], 'peer_ip': mclag_data[dut1]['peer_ip'], 'peer_interface':mclag_data[dut1]['peer_link_inf']}
    dict2 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut2]['local_ip'], 'peer_ip': mclag_data[dut2]['peer_ip'], 'peer_interface': mclag_data[dut2]['peer_link_inf']}
    pll.exec_parallel(pll_exec, data.mclag_peers, mclag.config_domain, [dict1, dict2])

    co_utils.exec_foreach(pll_exec, data.mclag_peers, mclag.config_mclag_system_mac, domain_id=mclag_domain, mac=mclag_sys_mac, config='add')

    co_utils.exec_all(pll_exec, [[mclag.config_interfaces, dut, mclag_domain, data.mclag_interfaces]
                          for dut in data.mclag_peers])
    # config unique_ip
    for vlan in [access_vlan, trunk_base_vlan]:
        co_utils.exec_foreach(pll_exec, data.mclag_peers, mclag.config_uniqueip, op_type='add', vlan='Vlan' + str(vlan))


def config_bgp():
    ##########################################################################
    st.banner("BGP-config: Configure BGP routers on MCLAG peers and client-2")
    ###########################################################################
    dict1 = {'local_as': as_num, 'router_id': lb_ip_d1,
             'redistribute': 'connected', 'config_type_list': ['router_id', 'redist']}
    dict2 = {'local_as': as_num, 'router_id': lb_ip_d2,
             'redistribute': 'connected', 'config_type_list': ['router_id', 'redist']}
    dict4 = {'local_as': as_num, 'router_id': lb_ip_d4,
         'redistribute': 'connected', 'config_type_list': ['router_id', 'redist']}
    pll.exec_parallel(pll_exec, [dut1,dut2,dut4], bgp.config_bgp, [dict1, dict2, dict4])

    ### BGP timers Global Config
    co_utils.exec_foreach(pll_exec, [dut1,dut2,dut4], bgp.config_bgp_router, as_num, router_id='', keep_alive=bgp_keepalive, hold=bgp_holdtime)

    ####################################################################################
    st.banner("BGP-config: Configure non-default ECMP paths under IPv4 address family")
    #####################################################################################
    dict1 = {'local_as': as_num, 'max_path_ibgp': 8, 'config_type_list': ["max_path_ibgp"]}
    dict2 = {'local_as': as_num, 'max_path_ibgp': 8, 'config_type_list': ["max_path_ibgp"]}
    dict4 = {'local_as': as_num, 'max_path_ibgp': 8, 'config_type_list': ["max_path_ibgp"]}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    for route_type in ['connected']:
        dict1 = {'local_as': as_num, 'redistribute': route_type,  'addr_family': 'ipv6',
                 'config_type_list': ['redist']}
        dict2 = {'local_as': as_num, 'redistribute': route_type, 'addr_family': 'ipv6',
                 'config_type_list': ['redist']}
        dict4 = {'local_as': as_num, 'redistribute': route_type, 'addr_family': 'ipv6',
                 'config_type_list': ['redist']}
        pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    ##########################################################################
    st.banner("BGP-config: Configure BGPv4 neighbors between MCLAG peers and client-2")
    ##########################################################################
    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po4_ip_d2, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po4_ip_d4, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po4_ip_d1, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1,dut2,dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po4_ip_d4, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po4_ip_d1, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po4_ip_d2, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po5_ip_d2, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po5_ip_d4, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po5_ip_d1, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po5_ip_d4, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po5_ip_d1, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num, 'neighbor': po5_ip_d2, 'local_as': as_num,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    ##########################################################################
    st.banner("BGP-config: Advertise TGN31 and TGN32 IPv4 networks to BGP")
    ##########################################################################
    def func(dut):
        bgp.config_bgp(dut, local_as=as_num, addr_family='ipv4',
                       network=tg31_ip[2], config_type_list=['network'])
        bgp.config_bgp(dut, local_as=as_num, addr_family='ipv4',
                       network=tg32_ip[2], config_type_list=['network'])
    st.exec_each([dut1, dut2], func)

    ####################################################################################
    st.banner("BGP-config: Configure non-default ECMP paths under IPv6 address family")
    #####################################################################################
    dict1 = {'local_as': as_num, 'max_path_ibgp': 8, 'addr_family': 'ipv6', 'config_type_list': ["max_path_ibgp"]}
    dict2 = {'local_as': as_num, 'max_path_ibgp': 8, 'addr_family': 'ipv6', 'config_type_list': ["max_path_ibgp"]}
    dict4 = {'local_as': as_num, 'max_path_ibgp': 8, 'addr_family': 'ipv6', 'config_type_list': ["max_path_ibgp"]}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    ##########################################################################
    st.banner("BGP-config: Configure BGPv6 neighbors between MCLAG peers and client-2")
    ##########################################################################
    dict1 = {'config_type_list': ['neighbor', 'activate'], 'remote_as': as_num, 'neighbor': po4_ip6_d2,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po4_ip6_d4,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po4_ip6_d1,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po4_ip6_d4,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po4_ip6_d1,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po4_ip6_d2,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po5_ip6_d2,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po5_ip6_d4,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po5_ip6_d1,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po5_ip6_d4,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po5_ip6_d1,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num, 'neighbor': po5_ip6_d2,
             'local_as': as_num, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    ##########################################################################
    st.banner("BGP-config: Advertise TGN31 and TGN32 IPv6 networks to BGP")
    ##########################################################################
    def func_v6(dut):
        bgp.config_bgp(dut, local_as=as_num, addr_family='ipv6',
                       network=tg31_ip6[2], config_type_list=['network'])
        bgp.config_bgp(dut, local_as=as_num, addr_family='ipv6',
                       network=tg32_ip6[2], config_type_list=['network'])
    st.exec_each([dut1, dut2], func_v6)


def config_static_routes(config='yes'):
    if config == 'yes':
        api_name = ip.create_static_route
        operation = "Configure"
    else:
        api_name = ip.delete_static_route
        operation = "Unconfigure"

    st.banner("{} IPv4 static routes".format(operation))
    dict1 = {'next_hop': po3_ip_d3, 'static_ip': tg31_ip[2], 'family': 'ipv4'}
    dict2 = {'next_hop': po3_ip_d3, 'static_ip': tg31_ip[2], 'family': 'ipv4'}
    dict3 = {'next_hop': po3_ip_d1, 'static_ip': tg41_ip[2], 'family': 'ipv4'}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut3], api_name, [dict1, dict2, dict3])

    dict1 = {'next_hop': po3_ip_d3, 'static_ip': tg32_ip[2], 'family': 'ipv4'}
    dict2 = {'next_hop': po3_ip_d3, 'static_ip': tg32_ip[2], 'family': 'ipv4'}
    dict3 = {'next_hop': po3_ip_d1, 'static_ip': tg42_ip[2], 'family': 'ipv4'}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut3], api_name, [dict1, dict2, dict3])

    api_name(dut3, next_hop=po3_ip_d1, static_ip=tg11_ip[2])
    api_name(dut3, next_hop=po3_ip_d1, static_ip=tg12_ip[2])
    api_name(dut3, next_hop=po3_ip_d1, static_ip=tg21_ip[2])
    api_name(dut3, next_hop=po3_ip_d1, static_ip=tg22_ip[2])

    st.banner("{} IPv6 static routes".format(operation))
    dict1 = {'next_hop': po3_ip6_d3, 'static_ip': tg31_ip6[2], 'family': 'ipv6'}
    dict2 = {'next_hop': po3_ip6_d3, 'static_ip': tg31_ip6[2], 'family': 'ipv6'}
    dict3 = {'next_hop': po3_ip6_d1, 'static_ip': tg41_ip6[2], 'family': 'ipv6'}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut3], api_name, [dict1, dict2, dict3])

    dict1 = {'next_hop': po3_ip6_d3, 'static_ip': tg32_ip6[2], 'family': 'ipv6'}
    dict2 = {'next_hop': po3_ip6_d3, 'static_ip': tg32_ip6[2], 'family': 'ipv6'}
    dict3 = {'next_hop': po3_ip6_d1, 'static_ip': tg42_ip6[2], 'family': 'ipv6'}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut3], api_name, [dict1, dict2, dict3])

    api_name(dut3, next_hop=po3_ip6_d1, static_ip=tg11_ip6[2], family='ipv6')
    api_name(dut3, next_hop=po3_ip6_d1, static_ip=tg12_ip6[2], family='ipv6')
    api_name(dut3, next_hop=po3_ip6_d1, static_ip=tg21_ip6[2], family='ipv6')
    api_name(dut3, next_hop=po3_ip6_d1, static_ip=tg22_ip6[2], family='ipv6')


def mclag_module_config():
    '''
    - Configure PO and add members
    - Configure vlans and add members
    - Configure IP on Mclag peers
    - Configure Mclag domain & interfaces.
    '''
    print_log("Starting MCLAG Base Configurations...\n\
    STEPS:\n\
    - Configure PO and add members \n\
    - Configure vlans and add member ports\n\
    - Configure IP on Mclag peers\n\
    - Configure Mclag domain & interfaces.", "HIGH")

    po_data.update({'PortChannel1': {'duts' : data.mclag_peers ,
                                 'po_members' : { dut1:[vars.D1D2P1,vars.D1D2P2] ,
                                                  dut2:[vars.D2D1P1,vars.D2D1P2]}}})
    po_data.update({'PortChannel2': {'duts': data.mclag_peers,
                                       'po_members': {dut1: [vars.D1D2P3, vars.D1D2P4],
                                                      dut2: [vars.D2D1P3, vars.D2D1P4]}}})
    po_data.update({'PortChannel3': {'duts': [dut1, dut2, dut3],
                                 'po_members': {dut1: [vars.D1D3P1, vars.D1D3P2],
                                                dut2: [vars.D2D3P1, vars.D2D3P2],
                                                dut3: [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2]}}})
    po_data.update({'PortChannel4': {'duts': [dut1, dut2, dut4],
                                       'po_members': {dut1: [vars.D1D4P1, vars.D1D4P2],
                                                      dut2: [vars.D2D4P1, vars.D2D4P2],
                                                      dut4: [vars.D4D1P1, vars.D4D1P2, vars.D4D2P1, vars.D4D2P2]}}})
    po_data.update({'PortChannel5': {'duts': [dut1, dut2, dut4],
                                       'po_members': {dut1: [vars.D1D4P3, vars.D1D4P4],
                                                      dut2: [vars.D2D4P3, vars.D2D4P4],
                                                      dut4: [vars.D4D1P3, vars.D4D1P4, vars.D4D2P3, vars.D4D2P4]}}})
    configure_portchannel(po_data)
    config_vlan()
    config_mclag()
    config_ip_v4_v6()
    config_static_routes()
    config_bgp()

def unconfig_vlan():
    ### UnConfigure Mclag vlan on PO-1
    co_utils.exec_all(pll_exec, [[vlan.delete_vlan_member, dut, mclag_vlan, 'PortChannel1', True] for dut in data.mclag_peers])
    co_utils.exec_all(pll_exec, [[vlan.delete_vlan, dut, mclag_vlan] for dut in data.mclag_peers])

    ###UnConfigure vlan on TGEN ports
    api_list = []
    api_list.append([vlan.delete_vlan_member, dut1, tg12_vlan, dut_tgn_port[(dut1, 2)], False])
    api_list.append([vlan.delete_vlan_member, dut2, tg22_vlan, dut_tgn_port[(dut2, 2)], True])
    api_list.append([vlan.delete_vlan_member, dut4, access_vlan, dut_tgn_port[(dut4, 1)], False])
    co_utils.exec_all(pll_exec, api_list)

    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    # UnConfigure trunk vlans on second TGEN ports of 2nd Mclag client
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, dut_tgn_port[(dut, 2)], 'del'] for dut in
                             [dut4]])

    ### UnConfigure vlans on all PortChannels
    co_utils.exec_all(pll_exec,
                      [[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel2', True] for dut in data.mclag_peers])
    co_utils.exec_all(pll_exec,
                      [[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel4'] for dut in [dut1, dut2, dut4]])

    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel2', 'del']
                             for dut in data.mclag_peers])
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel5', 'del']
                             for dut in [dut1, dut2, dut4]])

    ### Delete trunk VLANs on all DUTs using range command
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range, dut, trunk_vlan_range, 'del'] for dut in dut_list])

    ### Delete vlan on all duts and assign to respective member ports
    api_list = []
    api_list.append([vlan.delete_vlan, dut1, tg12_vlan])
    api_list.append([vlan.delete_vlan, dut2, tg22_vlan])
    co_utils.exec_all(pll_exec, api_list)

    co_utils.exec_all(pll_exec, [[vlan.delete_vlan, dut, [access_vlan]] for dut in dut_list])


def unconfig_ip_v4_v6():
    ### UnConfigure IP on PO-1 for L3 reachability between peers
    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(mclag_vlan), peer1_ip, v4_mask])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(mclag_vlan), peer2_ip, v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(mclag_vlan), peer1_ip6, v6_mask,'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(mclag_vlan), peer2_ip6, v6_mask,'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    ### Assign IP addresses to TGEN interfaces
    ### Assign IPv6 addresses to TGEN interfaces
    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, vars.D1T1P1, tg11_ip[0], v4_mask])
    api_list.append([ip.delete_ip_interface, dut2, vars.D2T1P1, tg21_ip[0], v4_mask])
    api_list.append([ip.delete_ip_interface, dut3, vars.D3T1P1, tg31_ip[0], v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, vars.D1T1P1, tg11_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, vars.D2T1P1, tg21_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut3, vars.D3T1P1, tg31_ip6[0], v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(tg12_vlan), tg12_ip[0], v4_mask])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(tg22_vlan), tg22_ip[0], v4_mask])
    api_list.append([ip.delete_ip_interface, dut3, vars.D3T1P2, tg32_ip[0], v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(tg12_vlan), tg12_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(tg22_vlan), tg22_ip6[0], v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut3, vars.D3T1P2, tg32_ip6[0], v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    ### Assign IP addresses to MCLAG interfaces
    ### Assign IPv6 addresses to MCLAG interfaces
    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, data.mclag_interfaces[0], po3_ip_d1, v4_mask])
    api_list.append([ip.delete_ip_interface, dut2, data.mclag_interfaces[0], po3_ip_d2, v4_mask])
    api_list.append([ip.delete_ip_interface, dut3, data.mclag_interfaces[0], po3_ip_d3, v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(access_vlan), po4_ip_d1, v4_mask])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(access_vlan), po4_ip_d2, v4_mask])
    api_list.append([ip.delete_ip_interface, dut4, 'Vlan' + str(access_vlan), po4_ip_d4, v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(trunk_base_vlan), po5_ip_d1, v4_mask])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(trunk_base_vlan), po5_ip_d2, v4_mask])
    api_list.append([ip.delete_ip_interface, dut4, 'Vlan' + str(trunk_base_vlan), po5_ip_d4, v4_mask])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, data.mclag_interfaces[0], po3_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, data.mclag_interfaces[0], po3_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut3, data.mclag_interfaces[0], po3_ip6_d3, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(access_vlan), po4_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(access_vlan), po4_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut4, 'Vlan' + str(access_vlan), po4_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(trunk_base_vlan), po5_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(trunk_base_vlan), po5_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut4, 'Vlan' + str(trunk_base_vlan), po5_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)



def unconfig_mclag():
    co_utils.exec_foreach(pll_exec, data.mclag_peers, mclag.config_mclag_system_mac, domain_id=mclag_domain,
                          mac=mclag_sys_mac, config='del')

    dict1 = {'domain_id': mclag_domain, 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'config': 'del'}
    pll.exec_parallel(pll_exec, data.mclag_peers, mclag.config_domain, [dict1, dict2])


def unconfig_bgp():
    ### Unconfigure BGP
    ##########################################################################
    st.banner("BGP-Unconfig: Delete BGP routers globally from all DUTs")
    ##########################################################################
    dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as': as_num}
    dict2 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as': as_num}
    dict4 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as': as_num}
    pll.exec_parallel(pll_exec, [dut1,dut2,dut4], bgp.config_bgp, [dict1, dict2, dict4])


def mclag_module_unconfig():
    print_log("Starting MCLAG Base UnConfigurations...", "HIGH")
    unconfig_bgp()
    config_static_routes(config='no')
    unconfig_ip_v4_v6()
    unconfig_mclag()
    unconfig_vlan()
    unconfigure_portchannel(po_data)
    ### Save cleaned up config since we do config save in reboot TCs
    co_utils.exec_all(pll_exec, [[boot.config_save, dut] for dut in dut_list])


def check_ping(src_dut,dest_ip_list,family="ipv4"):
    '''
    Verify ping to given list of IPs from src_dut
    :param src_dut: dut in which ping initiated
    :param dest_ip_list: list of IPs which need to be ping
    :return:
    '''
    dest_ip_list = [dest_ip_list] if type(dest_ip_list) is str else dest_ip_list
    ver_flag = True
    for ip_addr in dest_ip_list:
        if family == "ipv4":
            result = ip.ping(src_dut, ip_addr)
        elif family == "ipv6":
            result = ip.ping(src_dut, ip_addr,'ipv6')
        if not result:
            print_log("FAIL:Ping failed to {} ".format(ip_addr),'ERROR')
            ver_flag = False

    return ver_flag


def verify_mclag_state(mclag_data):
    '''
    Verify MCLAG state and other attributes
    :param mclag_data: dictionary  of attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the MCLAG domain state and attributes", 'MED')
    dict1 = {'domain_id': mclag_domain,'local_ip': mclag_data[dut1]['local_ip'], 'peer_ip': mclag_data[dut1]['peer_ip'],\
              'mclag_intfs': mclag_data[dut1]['mclag_intfs'],\
             'session_status':mclag_data[dut1]['session_status'], 'node_role':mclag_data[dut1]['node_role'],\
             'keepalive_timer':mclag_data[dut1]['keep_alive'], 'session_timer':mclag_data[dut1]['session_timeout']}
    dict2 = {'domain_id': mclag_domain,'local_ip': mclag_data[dut2]['local_ip'],'peer_ip': mclag_data[dut2]['peer_ip'], \
             'mclag_intfs': mclag_data[dut2]['mclag_intfs'], \
             'session_status': mclag_data[dut2]['session_status'], 'node_role': mclag_data[dut2]['node_role'],\
             'keepalive_timer':mclag_data[dut1]['keep_alive'], 'session_timer':mclag_data[dut1]['session_timeout']}
    [result, exceptions] = pll.exec_parallel(pll_exec, data.mclag_peers, mclag.verify_domain, [dict1, dict2])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('MCLAG -{} state verification FAILED'.format(mclag_domain),'ERROR')
        ver_flag = False
    return ver_flag


def verify_mclag_intf_state(mclag_intf_data):
    '''
        Verify MCLAG Interface state and other attributes
        :param mclag_intf_data: dictionary  of attributes to be verified
        :return:
        '''
    ver_flag = True

    for po in data.mclag_interfaces:
        print_log("Verify MCLAG Interface state of {}".format(po),'MED')

        dict1 = {'domain_id': mclag_domain, 'mclag_intf': po,\
                 'mclag_intf_local_state': mclag_intf_data[dut1][po]['local_state'], \
                 'mclag_intf_peer_state': mclag_intf_data[dut1][po]['remote_state'],\
                 'traffic_disable': mclag_intf_data[dut1][po]['traffic_disable']}
        dict2 = {'domain_id': mclag_domain, 'mclag_intf': po,
                 'mclag_intf_local_state': mclag_intf_data[dut2][po]['local_state'], \
                 'mclag_intf_peer_state': mclag_intf_data[dut2][po]['remote_state'],\
                 'traffic_disable': mclag_intf_data[dut2][po]['traffic_disable']}

        [result, exceptions] = pll.exec_parallel(pll_exec, data.mclag_peers, mclag.verify_interfaces, [dict1, dict2])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log('MCLAG Interface-{} state verification FAILED'.format(po), 'ERROR')
            ver_flag = False
    return ver_flag


def verify_bgp():
    ###########################################################
    st.banner("BGP verify: Verify BGP sessions are UP")
    ############################################################
    nbr_list = [po4_ip_d2, po4_ip_d4, po5_ip_d2, po5_ip_d4, po4_ip6_d2, po4_ip6_d4, po5_ip6_d2, po5_ip6_d4]
    dict1 = {'nbr_list': nbr_list, 'state_list': ['Established'] * len(nbr_list)}
    nbr_list = [po4_ip_d1, po4_ip_d4, po5_ip_d1, po5_ip_d4, po4_ip6_d1, po4_ip6_d4, po5_ip6_d1, po5_ip6_d4]
    dict2 = {'nbr_list': nbr_list, 'state_list': ['Established'] * len(nbr_list)}
    nbr_list = [po4_ip_d2, po4_ip_d1, po5_ip_d2, po5_ip_d1, po4_ip6_d2, po4_ip6_d1, po5_ip6_d2, po5_ip6_d1]
    dict4 = {'nbr_list': nbr_list, 'state_list': ['Established'] * len(nbr_list)}
    if not utils.retry_parallel(ip_bgp.check_bgp_session, dut_list=[dut1, dut2, dut4],
                                dict_list=[dict1, dict2, dict4],retry_count=5, delay=2):
        st.error("One or more BGP sessions did not come up")
        return False
    return True


def verify_routes():
    st.banner("Verify Routes")

    def d1_routes():
        ver_flag = True
        res_v4_flag = []
        res_v4_flag += [ip.verify_ip_route(dut1, ip_address=tg22_ip[2], nexthop=po4_ip_d2, type='B',interface='Vlan'+str(access_vlan))]
        res_v4_flag += [ip.verify_ip_route(dut1, ip_address=tg32_ip[2], nexthop=po3_ip_d3, type='S', interface='PortChannel3')]
        if False in res_v4_flag:
            print_log("IPv4 Routes verification failed in Dut:{}".format(dut1), "ERROR")
            ver_flag = False
        else:
            print_log("IPv4 Routes verification passed in Dut:{}".format(dut1), "MED")

        res_v6_flag = []
        res_v6_flag += [ip.verify_ip_route(dut1, family='ipv6', ip_address=tg22_ip6[2], type='B',
                                           interface='Vlan'+str(access_vlan))]
        res_v6_flag += [ip.verify_ip_route(dut1, family='ipv6', ip_address=tg32_ip6[2], nexthop=po3_ip6_d3, type='S',
                                            interface='PortChannel3')]
        if False in res_v6_flag:
            print_log("IPv6 Routes verification failed in Dut:{}".format(dut1), "ERROR")
            ver_flag = False
        else:
            print_log("IPv6 Routes verification passed in Dut:{}".format(dut1), "MED")
        return ver_flag

    def d2_routes():
        ver_flag = True
        res_v4_flag = []
        res_v4_flag += [ip.verify_ip_route(dut2, ip_address=tg11_ip[2], nexthop=po4_ip_d1, type='B',interface='Vlan'+str(access_vlan))]
        res_v4_flag += [ip.verify_ip_route(dut2, ip_address=tg41_ip[2], type='C', interface='Vlan'+str(access_vlan))]
        if False in res_v4_flag:
            print_log("IPv4 Routes verification failed in Dut:{}".format(dut2), "ERROR")
            ver_flag = False
        else:
            print_log("IPv4 Routes verification passed in Dut:{}".format(dut2), "MED")

        res_v6_flag = []
        res_v6_flag += [ip.verify_ip_route(dut2, family='ipv6', ip_address=tg11_ip6[2], type='B',
                                           interface='Vlan'+str(access_vlan))]
        res_v6_flag += [ip.verify_ip_route(dut2, family='ipv6', ip_address=tg41_ip6[2], type='C',
                               interface='Vlan'+str(access_vlan))]
        if False in res_v6_flag:
            print_log("IPv6 Routes verification failed in Dut:{}".format(dut2), "ERROR")
            ver_flag = False
        else:
            print_log("IPv6 Routes verification passed in Dut:{}".format(dut2), "MED")
        return ver_flag

    def d3_routes():
        ver_flag = True
        res_v4_flag = []
        res_v4_flag += [ip.verify_ip_route(dut3, ip_address=tg41_ip[2], nexthop=po3_ip_d1, type='S', interface='PortChannel3')]
        res_v4_flag += [ip.verify_ip_route(dut3, ip_address=tg42_ip[2], nexthop=po3_ip_d1, type='S', interface='PortChannel3')]
        res_v4_flag += [ip.verify_ip_route(dut3, ip_address=tg12_ip[2], nexthop=po3_ip_d1, type='S', interface='PortChannel3')]
        if False in res_v4_flag:
            print_log("IPv4 Routes verification failed in Dut:{}".format(dut3), "ERROR")
            ver_flag = False
        else:
            print_log("IPv4 Routes verification passed in Dut:{}".format(dut3), "MED")

        res_v6_flag = []
        res_v6_flag += [ip.verify_ip_route(dut3, family='ipv6', ip_address=tg41_ip6[2], nexthop=po3_ip6_d1, type='S',
                                           interface='PortChannel3')]
        res_v6_flag += [ip.verify_ip_route(dut3, family='ipv6', ip_address=tg42_ip6[2], nexthop=po3_ip6_d1, type='S',
                                           interface='PortChannel3')]
        res_v6_flag += [ip.verify_ip_route(dut3, family='ipv6', ip_address=tg12_ip6[2], nexthop=po3_ip6_d1, type='S',
                                            interface='PortChannel3')]
        if False in res_v6_flag:
            print_log("IPv6 Routes verification failed in Dut:{}".format(dut3), "ERROR")
            ver_flag = False
        else:
            print_log("IPv6 Routes verification passed in Dut:{}".format(dut3), "MED")
        return ver_flag

    def d4_routes():
        ver_flag = True
        res_v4_flag = []
        res_v4_flag += [ip.verify_ip_route(dut4, ip_address=tg31_ip[2], nexthop=po4_ip_d1, type='B',
                                           interface='Vlan' + str(access_vlan))]
        res_v4_flag += [ip.verify_ip_route(dut4, ip_address=tg32_ip[2], nexthop=po5_ip_d2, type='B',
                                           interface='Vlan' + str(trunk_base_vlan))]
        res_v4_flag += [ip.verify_ip_route(dut4, ip_address=tg21_ip[2], nexthop=po5_ip_d2, type='B', interface='Vlan'+str(trunk_base_vlan))]
        if False in res_v4_flag:
            print_log("IPv4 Routes verification failed in Dut:{}".format(dut4), "ERROR")
            ver_flag = False
        else:
            print_log("IPv4 Routes verification passed in Dut:{}".format(dut4), "MED")

        res_v6_flag = []
        res_v6_flag += [ip.verify_ip_route(dut4, family='ipv6', ip_address=tg31_ip6[2], type='B',
                                           interface='Vlan' + str(access_vlan))]
        res_v6_flag += [ip.verify_ip_route(dut4, family='ipv6', ip_address=tg32_ip6[2], type='B',
                                           interface='Vlan' + str(trunk_base_vlan))]
        res_v6_flag += [ip.verify_ip_route(dut4, family='ipv6', ip_address=tg21_ip6[2], type='B',
                                            interface='Vlan'+str(trunk_base_vlan))]
        if False in res_v6_flag:
            print_log("IPv6 Routes verification failed in Dut:{}".format(dut4), "ERROR")
            ver_flag = False
        else:
            print_log("IPv6 Routes verification passed in Dut:{}".format(dut4), "MED")
        return ver_flag

    [results, exceptions] = co_utils.exec_all(pll_exec, [[d1_routes], [d2_routes], [d3_routes], [d4_routes]])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in results:
        return False
    return True


def verify_arp_nd():
    st.banner("Verify ARP entries")
    def d1_arp():
        ver_flag = True
        arp_res = []
        arp_res += [arp.verify_arp(dut1, po3_ip_d3, interface="PortChannel3")]
        arp_res += [arp.verify_arp(dut1, po4_ip_d4, interface="PortChannel4", vlan=access_vlan)]
        arp_res += [arp.verify_arp(dut1, po5_ip_d4, interface="PortChannel5", vlan=trunk_base_vlan)]
        arp_res += [arp.verify_arp(dut1, peer2_ip, interface="PortChannel1", vlan=mclag_vlan)]
        if False in arp_res:
            print_log("ARP verification failed in Dut:{}".format(dut1), "MED")
            ver_flag = False
        else:
            print_log("ARP verification passed in Dut:{}".format(dut1), "MED")

        nd_res = []
        nd_res += [arp.verify_ndp(dut1, po3_ip6_d3, interface="PortChannel3")]
        ##SHOW NDP FILTERING with interface will not work in case of interface part of vlan
        nd_res += [arp.verify_ndp(dut1, po4_ip6_d4, vlan=access_vlan)]
        nd_res += [arp.verify_ndp(dut1, po5_ip6_d4, vlan=trunk_base_vlan)]
        if False in nd_res:
            print_log("ND verification failed in Dut:{}".format(dut1), "MED")
            ver_flag = False
        else:
            print_log("ND verification passed in Dut:{}".format(dut1), "MED")
        return ver_flag

    def d2_arp():
        ver_flag = True
        arp_res = []
        arp_res += [arp.verify_arp(dut2, po3_ip_d3, interface="PortChannel3")]
        arp_res += [arp.verify_arp(dut2, po4_ip_d4, interface="PortChannel4", vlan=access_vlan)]
        arp_res += [arp.verify_arp(dut2, po5_ip_d4, interface="PortChannel5", vlan=trunk_base_vlan)]
        arp_res += [arp.verify_arp(dut2, peer1_ip, interface="PortChannel1", vlan=mclag_vlan)]
        if False in arp_res:
            print_log("ARP verification failed in Dut:{}".format(dut2), "MED")
            ver_flag = False
        else:
            print_log("ARP verification passed in Dut:{}".format(dut2), "MED")

        nd_res = []
        nd_res += [arp.verify_ndp(dut2, po3_ip6_d3, interface="PortChannel3")]
        nd_res += [arp.verify_ndp(dut2, po4_ip6_d4, vlan=access_vlan)]
        nd_res += [arp.verify_ndp(dut2, po5_ip6_d4, vlan=trunk_base_vlan)]
        if False in nd_res:
            print_log("ND verification failed in Dut:{}".format(dut2), "MED")
            ver_flag = False
        else:
            print_log("ND verification passed in Dut:{}".format(dut2), "MED")
        return ver_flag

    def d3_arp():
        ver_flag = True
        arp_res = []
        arp_res += [arp.verify_arp(dut3, po3_ip_d1, interface="PortChannel3")]
        if False in arp_res:
            print_log("ARP verification failed in Dut:{}".format(dut3), "MED")
            ver_flag = False
        else:
            print_log("ARP verification passed in Dut:{}".format(dut3), "MED")

        nd_res = []
        nd_res += [arp.verify_ndp(dut3, po3_ip6_d1, interface="PortChannel3")]
        if False in nd_res:
            print_log("ND verification failed in Dut:{}".format(dut3), "MED")
            ver_flag = False
        else:
            print_log("ND verification passed in Dut:{}".format(dut3), "MED")
        return ver_flag

    def d4_arp():
        ver_flag = True
        arp_res = []
        #arp_res += [arp.verify_arp(dut4, po3_ip_d1, interface="PortChannel3")]
        arp_res += [arp.verify_arp(dut4, po4_ip_d1, interface="PortChannel4", vlan=access_vlan)]
        arp_res += [arp.verify_arp(dut4, po4_ip_d2, interface="PortChannel4", vlan=access_vlan)]
        arp_res += [arp.verify_arp(dut4, po5_ip_d1, interface="PortChannel5", vlan=trunk_base_vlan)]
        arp_res += [arp.verify_arp(dut4, po5_ip_d2, interface="PortChannel5", vlan=trunk_base_vlan)]
        if False in arp_res:
            print_log("ARP verification failed in Dut:{}".format(dut4), "MED")
            ver_flag = False
        else:
            print_log("ARP verification passed in Dut:{}".format(dut4), "MED")

        nd_res = []
        #nd_res += [arp.verify_ndp(dut4, po3_ip6_d1, interface="PortChannel3")]
        nd_res += [arp.verify_ndp(dut4, po4_ip6_d1, vlan=access_vlan)]
        nd_res += [arp.verify_ndp(dut4, po4_ip6_d2, vlan=access_vlan)]
        nd_res += [arp.verify_ndp(dut4, po5_ip6_d1, vlan=trunk_base_vlan)]

        nd_res += [arp.verify_ndp(dut4, po5_ip6_d2, vlan=trunk_base_vlan)]
        if False in nd_res:
            print_log("ND verification failed in Dut:{}".format(dut4), "MED")
            ver_flag = False
        else:
            print_log("ND verification passed in Dut:{}".format(dut4), "MED")
        return ver_flag

    [results, exceptions] = co_utils.exec_all(pll_exec, [[d1_arp], [d2_arp], [d3_arp], [d4_arp]])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in results:
        return False
    return True


def mclag_basic_validations():
    '''
    1. Verify PO summary.
    2. Verify vlan count.
    3. Verify L3 reachability
    4. Verify Mclag State and Interfaces

    '''
    final_result = True
    vlan_fail = 0
    po_fail = 0
    ping_fail = 0
    mclag_state_fail = 0
    mclag_intf_fail = 0
    bgp_fail  = 0
    route_fail = 0
    arp_fail = 0
    traffic_forward_fail = 0

    print_log("Verify all the LAGs configured in the topology is up", 'MED')
    if not utils.retry_api(verify_po_members,po_name_list=po_data.keys(),retry_count=5,delay=5):
        final_result=False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    ### Verify vlans configured in all DUTs
    print_log("Verify the VLANS configured in all DUTs", 'MED')
    [result,exceptions] = co_utils.exec_all(pll_exec,[[verify_vlan_count,dut_list[i],data.total_vlans[i]] for i in range(len(dut_list))])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("VLAN Table verification FAILED", "HIGH")
        vlan_fail += 1
        final_result = False
    else:
        print_log("VLAN Table verification PASSED", "HIGH")

    ### Display IP interfaces
    co_utils.exec_all(pll_exec, [[ip.get_interface_ip_address, dut] for dut in dut_list])
    ### Display IPv6 interfaces
    co_utils.exec_all(pll_exec, [[ip.get_interface_ip_address, dut, None, 'ipv6'] for dut in dut_list])

    ### Verify L3 reachability is fine
    print_log("Verify L3 reachability is fine across Mclag peers", 'MED')
    if utils.retry_api(check_ping,src_dut=dut1,dest_ip_list=peer2_ip):
        print_log("Ipv4 reachabilty between Mclag Peers PASSED", "HIGH")
    else:
        print_log("IPv4 reachabilty between Mclag Peers FAILED", "HIGH")
        ping_fail += 1
        final_result = False

    print_log("Verify IPv6 reachability is fine across Mclag peers", 'MED')
    if utils.retry_api(check_ping, src_dut=dut2, dest_ip_list=peer1_ip6, family="ipv6"):
        print_log("IPv6 reachabilty between Mclag Peers PASSED", "HIGH")
    else:
        print_log("IPv6 reachabilty between Mclag Peers FAILED", "HIGH")
        ping_fail += 1
        final_result = False

    ### Verify MCLAG domain and attributes
    if utils.retry_api(verify_mclag_state,mclag_data=mclag_data,retry_count=3,delay=3):
        print_log("MCLAG Domain State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG Interface states
    if utils.retry_api(verify_mclag_intf_state,mclag_intf_data=mclag_intf_data,retry_count=3,delay=3):
        print_log("MCLAG Interfaces State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

    ### Verify BGP neighborship
    if verify_bgp():
        print_log("BGP neighborship verification PASSED", "HIGH")
    else:
        print_log("BGP neighborship verification FAILED", "HIGH")
        bgp_fail += 1
        final_result = False

    ### Verify Routes
    if verify_routes():
        print_log("Route Table verification PASSED", "HIGH")
    else:
        print_log("Route Table verification FAILED", "HIGH")
        route_fail += 1
        final_result = False

    ### Verify BGP neighborship
    if verify_arp_nd():
        print_log("ARP-ND verification PASSED", "HIGH")
    else:
        print_log("ARP-ND verification FAILED", "HIGH")
        arp_fail += 1
        final_result = False

    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        print_log("Traffic Forwarding with Base Config FAILED", "HIGH")
        final_result = False
    else:
        print_log("Traffic Forwarding with Base Config PASSED", "HIGH")

    if not final_result:
        fail_msg = ''
        if vlan_fail > 0:
            fail_msg += 'Vlan count Failed:'
        if po_fail > 0:
            fail_msg += 'PortChannel not UP:'
        if ping_fail > 0:
            fail_msg += 'Ping Failed:'
        if mclag_state_fail > 0:
            fail_msg += 'MCLAG state Failed:'
        if mclag_intf_fail > 0:
            fail_msg += 'MCLAG Interface state Failed:'
        if bgp_fail > 0:
            fail_msg += 'BGP neighborship Failed:'
        if route_fail > 0:
            fail_msg += 'Routes Verification Failed:'
        if arp_fail > 0:
            fail_msg += 'ARP entries Failed:'
        if traffic_forward_fail > 0:
            fail_msg += 'Base Traffic Forwarding Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))

def l3mclag_traffic_config():
    ### Config TGEN host interfaces
    ### Configure Bound streams between L3 interfaces
    tg_host_31 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut3,1)], mode='config',
                                                     intf_ip_addr=tg31_ip[1],gateway=tg31_ip[0], gateway_step='0.0.0.0',
                                                     arp_send_req='1', count=tg_host_count)
    tg_host_32 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut3,2)], mode='config',
                                                     intf_ip_addr=tg32_ip[1],gateway=tg32_ip[0], gateway_step='0.0.0.0',
                                                     arp_send_req='1', count=tg_host_count)
    tg_host_41 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut4,1)], mode='config',
                                                     intf_ip_addr=tg41_ip[1],gateway=tg41_ip[0], gateway_step='0.0.0.0',
                                                     arp_send_req='1', count=tg_host_count)
    tg_host_42 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut4, 2)], mode='config',
                                                    vlan='1', vlan_id=trunk_base_vlan,
                                                     intf_ip_addr=tg42_ip[1], gateway=tg42_ip[0],gateway_step='0.0.0.0',
                                                     arp_send_req='1', count=tg_host_count)
    tg_v6host_31 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut3, 1)], mode='config',
                                                    ipv6_intf_addr=tg31_ip6[1], ipv6_prefix_length=v6_mask,
                                                    ipv6_gateway=tg31_ip6[0], ipv6_intf_addr_step='::1',
                                                    arp_send_req='1', count=tg_host_count)
    tg_v6host_32 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut3, 2)], mode = 'config',
                                                    ipv6_intf_addr=tg32_ip6[1], ipv6_prefix_length = v6_mask,
                                                    ipv6_gateway = tg32_ip6[0], ipv6_intf_addr_step = '::1',
                                                    arp_send_req = '1', count = tg_host_count)
    tg_v6host_41 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut4, 1)], mode='config',
                                                    ipv6_intf_addr=tg41_ip6[1], ipv6_prefix_length=v6_mask,
                                                    ipv6_gateway=tg41_ip6[0], ipv6_intf_addr_step='::1',
                                                    arp_send_req='1', count=tg_host_count)
    tg_v6host_42 = tg_h.tg_interface_config(port_handle=tgn_handle[(dut4, 2)], mode = 'config',
                                                    vlan='1', vlan_id=trunk_base_vlan,
                                                    ipv6_intf_addr =tg42_ip6[1], ipv6_prefix_length = v6_mask,
                                                    ipv6_gateway = tg42_ip6[0], ipv6_intf_addr_step ='::1',
                                                    arp_send_req = '1', count = tg_host_count)
    # Configuring bound streams.
    data.v4_src_streams = []
    data.v6_src_streams = []
    data.v4_dst_streams = []
    data.v6_dst_streams = []
    data.base_streams = []
    data.stream_handles = {}
    data.stream_details = {}
    data.stream_port = {}

    st.banner("IPv4 stream From TGN31 to TGN41")
    tg_ph_src = tgn_handle[(dut3,1)]
    tg_ph_dst = tgn_handle[(dut4,1)]
    tg_prt_src = tgn_port[(dut3,1)]
    tg_prt_dst = tgn_port[(dut4,1)]
    src_ip = tg31_ip[1]
    dst_ip = tg41_ip[1]
    vlan = None
    if data.tgen_type == "ixia":
        ip.ping(dut3, tg31_ip[1])
        ip.ping(dut3, tg31_ip6[1], family='ipv6')
        ip.ping(dut3, tg32_ip[1])
        ip.ping(dut3, tg32_ip6[1], family='ipv6')
        ip.ping(dut4, tg41_ip[1])
        ip.ping(dut4, tg41_ip6[1], family='ipv6')
        ip.ping(dut4, tg42_ip[1])
        ip.ping(dut4, tg42_ip6[1], family='ipv6')


    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_host_31['handle'],
                                                 emulation_dst_handle=tg_host_41['handle'], circuit_endpoint_type='ipv4',
                                                 mode='create', transmit_mode='continuous', length_mode='fixed',
                                                 rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v4_stream_31_41'] = stream['stream_id']
    data.v4_src_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv4 traffic stream:{} \n==> TGN31:{} --> TGN41:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    st.banner("IPv4 stream From TGN32 to TGN42")
    tg_ph_src = tgn_handle[(dut3, 2)]
    tg_ph_dst = tgn_handle[(dut4, 2)]
    tg_prt_src = tgn_port[(dut3, 2)]
    tg_prt_dst = tgn_port[(dut4, 2)]
    src_ip = tg32_ip[1]
    dst_ip = tg42_ip[1]
    vlan = None
    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_host_32['handle'],
                                   emulation_dst_handle=tg_host_42['handle'], circuit_endpoint_type='ipv4',
                                   mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v4_stream_32_42'] = stream['stream_id']
    data.v4_src_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv4 traffic stream:{} \n==> TGN32:{} --> TGN42:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    st.banner("IPv4 stream From TGN41 to TGN31")
    tg_ph_src = tgn_handle[(dut4, 1)]
    tg_ph_dst = tgn_handle[(dut3, 1)]
    tg_prt_src = tgn_port[(dut4, 1)]
    tg_prt_dst = tgn_port[(dut3, 1)]
    src_ip = tg41_ip[1]
    dst_ip = tg31_ip[1]
    vlan = None
    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_host_41['handle'],
                                   emulation_dst_handle=tg_host_31['handle'], circuit_endpoint_type='ipv4',
                                   mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v4_stream_41_31'] = stream['stream_id']
    data.v4_dst_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv4 traffic stream:{} \n==> TGN41:{} --> TGN31:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    st.banner("IPv4 stream From TGN42 to TGN32")
    tg_ph_src = tgn_handle[(dut4, 2)]
    tg_ph_dst = tgn_handle[(dut3, 2)]
    tg_prt_src = tgn_port[(dut4, 2)]
    tg_prt_dst = tgn_port[(dut3, 2)]
    src_ip = tg42_ip[1]
    dst_ip = tg32_ip[1]
    vlan = trunk_base_vlan
    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_host_42['handle'],
                                   emulation_dst_handle=tg_host_32['handle'], circuit_endpoint_type='ipv4',
                                   mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v4_stream_42_32'] = stream['stream_id']
    data.v4_dst_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv4 traffic stream:{} \n==> TGN42:{} --> TGN32:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    st.banner("IPv6 stream From TGN31 to TGN41")
    tg_ph_src = tgn_handle[(dut3, 1)]
    tg_ph_dst = tgn_handle[(dut4, 1)]
    tg_prt_src = tgn_port[(dut3, 1)]
    tg_prt_dst = tgn_port[(dut4, 1)]
    src_ip = tg31_ip6[1]
    dst_ip = tg41_ip6[1]
    vlan = None
    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_v6host_31['handle'],
                                   emulation_dst_handle=tg_v6host_41['handle'], circuit_endpoint_type='ipv6',
                                   mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v6_stream_31_41'] = stream['stream_id']
    data.v6_src_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv6 traffic stream:{} \n==> TGN31:{} --> TGN41:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    st.banner("IPv6 stream From TGN32 to TGN42")
    tg_ph_src = tgn_handle[(dut3, 2)]
    tg_ph_dst = tgn_handle[(dut4, 2)]
    tg_prt_src = tgn_port[(dut3, 2)]
    tg_prt_dst = tgn_port[(dut4, 2)]
    src_ip = tg32_ip6[1]
    dst_ip = tg42_ip6[1]
    vlan = None
    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_v6host_32['handle'],
                                   emulation_dst_handle=tg_v6host_42['handle'], circuit_endpoint_type='ipv6',
                                   mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v6_stream_32_42'] = stream['stream_id']
    data.v6_src_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv6 traffic stream:{} \n==> TGN32:{} --> TGN42:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    st.banner("IPv6 stream From TGN41 to TGN31")
    tg_ph_src = tgn_handle[(dut4, 1)]
    tg_ph_dst = tgn_handle[(dut3, 1)]
    tg_prt_src = tgn_port[(dut4, 1)]
    tg_prt_dst = tgn_port[(dut3, 1)]
    src_ip = tg41_ip6[1]
    dst_ip = tg31_ip6[1]
    vlan = None
    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_v6host_41['handle'],
                                   emulation_dst_handle=tg_v6host_31['handle'], circuit_endpoint_type='ipv6',
                                   mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v6_stream_41_31'] = stream['stream_id']
    data.v6_dst_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv6 traffic stream:{} \n==> TGN41:{} --> TGN31:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    st.banner("IPv6 stream From TGN42 to TGN32")
    tg_ph_src = tgn_handle[(dut4, 2)]
    tg_ph_dst = tgn_handle[(dut3, 2)]
    tg_prt_src = tgn_port[(dut4, 2)]
    tg_prt_dst = tgn_port[(dut3, 2)]
    src_ip = tg42_ip6[1]
    dst_ip = tg32_ip6[1]
    vlan = trunk_base_vlan
    stream = tg_h.tg_traffic_config(port_handle=tg_ph_src, emulation_src_handle=tg_v6host_42['handle'],
                                   emulation_dst_handle=tg_v6host_32['handle'], circuit_endpoint_type='ipv6',
                                   mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=tgen_rate_pps, port_handle2=tg_ph_dst)
    data.stream_handles['v6_stream_42_32'] = stream['stream_id']
    data.v6_dst_streams += [stream['stream_id']]
    data.stream_port[stream['stream_id']] = {'src': tg_prt_src, 'dst': tg_prt_dst}
    data.stream_details[stream['stream_id']] = "IPv6 traffic stream:{} \n==> TGN42:{} --> TGN32:{}, " \
                                               "VLAN-ID:{}," \
                                               "SRC-IP:{}, DEST IP:{}" \
        .format(stream['stream_id'], tg_prt_src, tg_prt_dst, vlan, src_ip, dst_ip)

    data.base_streams = data.v4_src_streams + data.v6_src_streams + data.v4_dst_streams + data.v6_dst_streams
    data.base_src_streams = data.v4_src_streams + data.v6_src_streams
    data.base_dst_streams = data.v4_dst_streams + data.v6_dst_streams

def run_traffic(action='START',stream_list='ALL',duration=traffic_run_time,clear_flag='YES'):
    if stream_list == 'ALL':
        stream_list = data.base_streams
    else:
        stream_list = [stream_list] if type(stream_list) is str else stream_list
    tg_handles = []
    for dut in dut_list:
        tg_handles += [tgn_handle[(dut, 1)]] + [tgn_handle[(dut, 2)]]

    if action == 'START' or action == 'both':
        st.log(" #### Starting Traffic #####")
        if clear_flag == 'YES':
            ### Clear counters on dut ports
            print_log("Clear Interface counters", 'MED')
            co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])
            tg_h.tg_traffic_control(action='clear_stats',port_handle=tg_handles)
        tg_h.tg_traffic_control(action='run', stream_handle=stream_list)
        print_log("Display Interface counters to Verify traffic start", 'MED')
        co_utils.exec_all(pll_exec, [[port.get_interface_counters_all, dut] for dut in dut_list])

    if action == 'both':
        st.wait(duration)

    if action == 'STOP' or action == 'both':
        st.log(" #### Stopping Traffic #####")
        tg_h.tg_traffic_control(action='stop', stream_handle=stream_list)
        print_log("Display Interface counters to Verify traffic stop", 'MED')
        co_utils.exec_all(pll_exec, [[port.get_interface_counters_all, dut] for dut in dut_list])


def verify_traffic(src_stream_list='ALL', dest_stream_list='ALL', tx_rx_ratio=1, comp_type='packet_rate', direction="both"):
    ver_flag = True
    if src_stream_list =='ALL':
        src_stream_list = data.base_src_streams
    if dest_stream_list == 'ALL':
        dest_stream_list = data.base_dst_streams
    if type(tx_rx_ratio) is int:
        tx_rx_ratio = [tx_rx_ratio]* len(src_stream_list)
    elif type(tx_rx_ratio) is list:
        if len(src_stream_list) != len(tx_rx_ratio):
            print_log('Need both SRC stream list & tx_rx_ratio list to be of same length','ERROR')
            st.report_fail("operation_failed")

    src_stream_list = [src_stream_list] if type(src_stream_list) is str else src_stream_list
    dest_stream_list = [dest_stream_list] if type(dest_stream_list) is str else dest_stream_list

    if len(src_stream_list) != len(dest_stream_list):
        ###Compare both source and dest stream_lists are of same length else fail
        if direction == 'both':
            print_log(
                'Need both SRC and DEST stream list to be of same length if bi-directional traffic to be verified',
                'ERROR')
            st.report_fail("operation_failed")
        else:
            ### For single direction traffic verification destination stream_list not needed.
            dest_stream_list = ['ANY'] * len(src_stream_list)

    for src_stream_id, dest_stream_id, tx_rx in zip(src_stream_list, dest_stream_list, tx_rx_ratio):
        tg_src_port = data.stream_port[src_stream_id]['src']
        tg_dest_port = data.stream_port[src_stream_id]['dst']
        traffic_data = {
            '1': {
                'tx_ports': [tg_src_port],
                'tx_obj': [tg_h],
                'exp_ratio': [tx_rx],
                'rx_ports': [tg_dest_port],
                'rx_obj': [tg_h],
                'stream_list': [[src_stream_id]],
            },
        }
        if direction == 'both':
            traffic_data['2'] = {
                'tx_ports': [tg_dest_port],
                'tx_obj': [tg_h],
                'exp_ratio': [tx_rx],
                'rx_ports': [tg_src_port],
                'rx_obj': [tg_h],
                'stream_list': [[dest_stream_id]],
            }

        # verify traffic mode stream level
        streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='streamblock', comp_type=comp_type)
        if streamResult:
            print_log(
                'Traffic verification PASSED for {}, Direction:<<{}>>'.format(data.stream_details[src_stream_id],direction),
                'MED')
        else:
            ver_flag = False
            print_log(
                'Traffic verification FAILED for {}, Direction:<<{}>>'.format(data.stream_details[src_stream_id],direction),
                'ERROR')
    return ver_flag


def mclag_traffic_unconfig():
    # reset statistics and delete if any existing streamblocks
    for dut in dut_list:
        tg_h.tg_traffic_control(action="stop", port_handle=tgn_handle[(dut, 1)])
        tg_h.tg_traffic_control(action="reset", port_handle=tgn_handle[(dut, 1)])
        if dut == dut1 or dut ==dut2:
            tg_h.tg_traffic_control(action="stop", port_handle=tgn_handle[(dut, 2)])
            tg_h.tg_traffic_control(action="reset", port_handle=tgn_handle[(dut, 2)])


def verify_traffic_rate(duts,port_list,expect_rate_list,threshold_list):
    '''
        Verify given list of ports is flooding traffic with tx_rate greater than threshold
        :param duts:
        :param port_list:
        :param expect_rate_list:
        :param threshold_list:
        :return: False:, If given port is transmitting less than expect_rate
        :return: True:, If given port is transmitting more than expect_rate
        '''
    # Getting interfaces counter values on DUT
    if len(expect_rate_list) != len(threshold_list):
        print_log('expect_rate_list & threshold_list should have same length.', 'ERROR')
        return False
    expect_rate_list = [expect_rate_list[x]-threshold_list[x] for x in range(len(expect_rate_list))]
    for port_num,expect_rate,dut in zip(port_list,expect_rate_list,duts):
        ver_loop_flag = False
        ver_loop_ctr = 0
        ver_loop_limit = 3
        while ver_loop_ctr < ver_loop_limit:
            DUT_tx_value = port.get_interface_counters(dut, port_num, "tx_pps")
            print_log("port:{}, tx_rate:{}".format(port_num, DUT_tx_value), 'MED')
            if not DUT_tx_value:
                print_log('Expected port:{} not seen in output'.format(port), 'ERROR')
                return False
            for i in DUT_tx_value:
                print_log("port:{}, tx_value:{}, i:{}".format(port_num, DUT_tx_value, i), 'MED')
                p_txmt = i['tx_pps']
                if p_txmt == 'N/A' or p_txmt is None: return False
                p_txmt = p_txmt.replace(",", "")
                p_txmt = p_txmt.strip('/s')
                if int(float(p_txmt)) < expect_rate:
                    #ver_flag = False
                    print_log(
                        "Iteration:-{} FAIL: Expect tx_rate {} > {} for port:{} in DUT:{}".format(ver_loop_ctr + 1,
                                                                                                  DUT_tx_value,
                                                                                                  expect_rate, port_num,
                                                                                                  dut), 'ERROR')
                else:
                    ver_loop_flag = True
                    break
            if ver_loop_flag:
                break
            else:
                ### wait for tx rate to update
                st.wait(1)
                ver_loop_ctr += 1
        if not ver_loop_flag:
            return False
    return True

def debug_po_fail():
    print_log("Dumping Debug data for PO fail", 'HIGH')
    co_utils.exec_all(dbg_exec, [[po.get_portchannel_list, dut] for dut in dut_list])
    co_utils.exec_foreach(dbg_exec, data.mclag_peers, mclag.verify_domain, domain_id=mclag_domain)
    for po_name in data.mclag_interfaces:
        co_utils.exec_foreach(dbg_exec, data.mclag_peers, mclag.verify_interfaces, domain_id=mclag_domain,
                              mclag_intf=po_name)
        co_utils.exec_foreach(dbg_exec, data.mclag_peers, po.verify_lacp_fallback, port_channel_name=po_name)
    print_log("End of Dumping Debug data for PO fail", 'MED')

def debug_traffic_fail():
    print_log("Dumping Debug data for Traffic Fail", 'HIGH')
    co_utils.exec_all(dbg_exec, [[po.get_portchannel_list, dut] for dut in dut_list])
    ### Display IP interfaces
    co_utils.exec_all(dbg_exec, [[ip.get_interface_ip_address, dut] for dut in dut_list])
    ### Display IPv6 interfaces
    co_utils.exec_all(dbg_exec, [[ip.get_interface_ip_address, dut, None, 'ipv6'] for dut in dut_list])
    ### Display IPv4 routes and ARPs
    co_utils.exec_all(dbg_exec, [[ip.show_ip_route, dut] for dut in dut_list])
    co_utils.exec_all(dbg_exec, [[arp.show_arp, dut] for dut in dut_list])
    ### Display IPv6 routes and ARPs
    co_utils.exec_all(dbg_exec, [[ip.show_ip_route, dut, 'ipv6'] for dut in dut_list])
    co_utils.exec_all(dbg_exec, [[arp.show_ndp, dut] for dut in dut_list])
    co_utils.exec_all(dbg_exec, [[port.get_interface_counters_all, dut] for dut in dut_list])
    co_utils.exec_foreach(dbg_exec, data.mclag_peers, mclag.verify_iccp_macs, domain_id=mclag_domain, return_type='NULL')
    co_utils.exec_all(dbg_exec, [[mac.get_mac, dut] for dut in dut_list])
    co_utils.exec_all(dbg_exec, [[vlan.show_vlan_brief, dut] for dut in dut_list])
    co_utils.exec_all(dbg_exec, [[asicapi.dump_vlan, dut] for dut in dut_list])
    co_utils.exec_all(dbg_exec, [[asicapi.dump_l2, dut] for dut in dut_list])
    co_utils.exec_all(dbg_exec, [[asicapi.dump_ports_info, dut] for dut in dut_list])
    print_log("End of Dumping Debug data for Traffic Fail", 'MED')


def show_verify_mac_table(dut,expect_mac,vlan=None,port=None,type=None,mac_search=None,comp_flag='equal'):
    mac_count = mac.get_mac_address_count(dut, vlan=vlan, port=port, type=type, mac_search=mac_search)
    if comp_flag == 'equal':
        if mac_count != expect_mac:
            print_log(
                "FAIL:Verify MAC with filter vlan={} port={} type={} on {} failed, Expect: {} = Got: {}".format(vlan,
                                                                                                            port,
                                                                                                                type,
                                                                                                                dut,
                                                                                                                expect_mac,
                                                                                                                mac_count),
                'ERROR')
            return False
        else:
            print_log(
                "PASS:Verify MAC with filter vlan={} port={} type={} on {} passed, Expect: {} = Got: {}".format(vlan,
                                                                                                                port,
                                                                                                                type,
                                                                                                                dut,
                                                                                                                expect_mac,
                                                                                                                mac_count),
                'MED')
            return True
    elif comp_flag == 'minimum':
        if mac_count < expect_mac:
            print_log(
                "FAIL:Verify MAC with filter vlan={} port={} type={} on {} failed, Expect: {} <= Got: {}".format(vlan,
                                                                                                            port,
                                                                                                                type,
                                                                                                                dut,
                                                                                                                expect_mac,
                                                                                                                mac_count),
                'ERROR')
            return False
        else:
            print_log(
                "PASS:Verify MAC with filter vlan={} port={} type={} on {} passed, Expect: {} <= Got: {}".format(vlan,
                                                                                                                port,
                                                                                                                type,
                                                                                                                dut,
                                                                                                                expect_mac,
                                                                                                                mac_count),
                'MED')
            return True
    elif comp_flag == 'not-equal':
        if mac_count == expect_mac:
            print_log(
                "FAIL:Verify MAC with filter vlan={} port={} type={} on {} failed, Expect: {} != Got: {}".format(vlan,
                                                                                                                 port,
                                                                                                                 type,
                                                                                                                 dut,
                                                                                                                 expect_mac,
                                                                                                                 mac_count),
                'ERROR')
            return False
        else:
            print_log(
                "PASS:Verify MAC with filter vlan={} port={} type={} on {} passed, Expect: {} != Got: {}".format(vlan,
                                                                                                                 port,
                                                                                                                 type,
                                                                                                                 dut,
                                                                                                                 expect_mac,
                                                                                                                 mac_count),
                'MED')
            return True


def check_mac_count(dut,expect_mac,comp_flag='equal'):
    mac_count = mac.get_mac_count(dut)
    if comp_flag == 'equal':
        if mac_count != expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} = Got: {}".format(dut,expect_mac,mac_count),'ERROR')
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True
    elif comp_flag == 'minimum':
        if mac_count < expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} <= Got: {}".format(dut,expect_mac,mac_count),'ERROR')
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} <= Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True
    elif comp_flag == 'not-equal':
        if mac_count == expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'ERROR')
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True


def verify_mac_table_count(dut_list,expect_mac_list,comp_flag='equal'):
    '''
    Verify MAC count in given list of duts is as in expect_mac_list
    It can compare the values are equal or not-equal based on comp_flag
    '''
    print_log("Verifying MAC Table DUTs:{}, MACs:{}".format(dut_list,expect_mac_list),'MED')
    dut_list = dut_list if isinstance(dut_list, list) else [dut_list]
    expect_mac_list = expect_mac_list if isinstance(expect_mac_list, list) else [expect_mac_list]
    expect_dict = []
    for i in range(len(dut_list)):
        expect_dict += [{'expect_mac':expect_mac_list[i], 'comp_flag':comp_flag}]
    if not utils.retry_parallel(check_mac_count, dict_list=expect_dict, dut_list=dut_list, retry_count=3, delay=2):
        print_log("MAC Count verification FAILED", "HIGH")
        ### Display MAC table
        co_utils.exec_all(dbg_exec, [[show_verify_mac_table, dut, expected_mac, None, None, None, None, comp_flag] \
                               for dut, expected_mac in zip(dut_list, expect_mac_list)])
        return False
    else:
        print_log("MAC Count verification PASSED", "HIGH")
        return True


def verify_vlan_count(dut,expect_vlan_count):
    print_log("Verifying VLAN count on {} = {}".format(dut, expect_vlan_count),"MED")
    ver_flag = True
    actual_vlan_count = vlan.get_vlan_count(dut)
    if actual_vlan_count != expect_vlan_count:
        print_log("FAIL: Total vlan on {} failed, Expect: {}, Got: {}".format(dut, expect_vlan_count, actual_vlan_count),'ERROR')
        ver_flag = False
        asicapi.dump_vlan(dut)
    else:
        print_log("PASS: Total vlan on {} passed, Expect: {}, Got: {}".format(dut, expect_vlan_count, actual_vlan_count),'MED')

    return ver_flag


def verify_po_members(po_name_list,state='up'):
    ver_flag = True
    ###Verify all member ports in each PO is UP
    for po_name in po_name_list:
        print_log("Verify member ports in {} is {}".format(po_name, state), 'MED')
        duts = po_data[po_name]["duts"]
        dut_po_members = po_data[po_name]["po_members"]
        ### Verify PO member port state
        [result, exceptions] = co_utils.exec_all(pll_exec,[[po.verify_portchannel_member_state,dut,po_name,dut_po_members[dut],state]
                                                    for dut in duts ])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log("Verify PortChannel-{} Member State:{} Failed".format(po_name, state))
            ver_flag = False
        else:
            print_log("Verify PortChannel-{} Member State:{} Passed".format(po_name, state))

    return ver_flag


def verify_portchannel(po_name,duts,expect_states):
    ver_flag = True
    duts = duts if type(duts) is list else [duts]
    state_dict = []
    for i in range(len(duts)):
        state_dict += [{'portchannel': po_name, 'state': expect_states[i]}]
    ### Verify PO state is as expected
    if not utils.retry_parallel(po.verify_portchannel_state, dict_list=state_dict, dut_list=duts, retry_count=3, delay=2):
        print_log("Verify PortChannel-{} State FAILED".format(po_name), "ERROR")
        ver_flag = False
    else:
        print_log("Verify PortChannel-{} State PASSED".format(po_name), "MED")

    for i in range(len(duts)):
        state_dict[i] = {'portchannel': po_name, 'state': expect_states[i], 'members_list': po_data[po_name]["po_members"][duts[i]]}
    st.log("DICT:{}".format(state_dict))

    ### Verify PO member state is as expected
    if not utils.retry_parallel(po.verify_portchannel_member_state, dict_list=state_dict, dut_list=duts, retry_count=3, delay=2):
        print_log("Verify PortChannel-{} Member Ports State FAILED".format(po_name), "ERROR")
        ver_flag = False
    else:
        print_log("Verify PortChannel-{} Member Ports State PASSED".format(po_name), "MED")

    return ver_flag



@pytest.fixture(scope="function",autouse=True)
def pre_result_handler():
    global final_result, clear_mac_fail, traffic_forward_fail, flooding_fail, route_fail, bum_traffic_fail, \
        mac_aging_fail, po_fail, intf_fail, arp_count_fail, nd_count_fail, fb_fail
    global TECHSUPPORT

    print_log("FLAG reset", 'MED')

    final_result = True
    TECHSUPPORT = True
    route_fail = 0
    clear_mac_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    bum_traffic_fail = 0
    mac_aging_fail = 0
    arp_count_fail = 0
    nd_count_fail = 0
    po_fail = 0
    intf_fail = 0
    fb_fail = 0

def post_result_handler():
    global final_result, clear_mac_fail, traffic_forward_fail, flooding_fail, route_fail, bum_traffic_fail,\
            mac_aging_fail, po_fail, intf_fail, fb_fail
    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg = ''
        if route_fail > 0:
            fail_msg += 'Route Verification Failed:'
        if clear_mac_fail > 0:
            fail_msg += 'Clear MAC Failed:'
        if traffic_forward_fail > 0:
            fail_msg += 'Traffic Forwarding Failed:'
        if mac_aging_fail > 0:
            fail_msg += 'MAC aging Failed:'
        if flooding_fail > 0:
            fail_msg += 'Flooding Verification Failed:'
        if bum_traffic_fail > 0:
            fail_msg += 'BUM traffic Failed:'
        if po_fail > 0:
            fail_msg += 'PO Verification Failed:'
        if intf_fail > 0:
            fail_msg += 'Interface not up after reboot:'
        if fb_fail > 0:
            fail_msg += 'Mclag Fallback state failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))


def add_new_PO():
    ###Configure PO-6 between D1-D2 and D3
    co_utils.exec_all(pll_exec, [[po.create_portchannel, dut, 'PortChannel6'] for dut in [dut1, dut2, dut3]])
    api_list = []
    api_list.append([po.add_portchannel_member, dut1, 'PortChannel6', [vars.D1D3P3, vars.D1D3P4]])
    api_list.append([po.add_portchannel_member, dut2, 'PortChannel6', [vars.D2D3P3, vars.D2D3P4]])
    api_list.append(
        [po.add_portchannel_member, dut3, 'PortChannel6', [vars.D3D1P3, vars.D3D1P4, vars.D3D2P3, vars.D3D2P4]])
    co_utils.exec_all(pll_exec, api_list)
    po_data.update({'PortChannel6': {'duts': [dut1, dut2, dut3],
                                     'po_members': {dut1: [vars.D1D3P3, vars.D1D3P4],
                                                    dut2: [vars.D2D3P3, vars.D2D3P4],
                                                    dut3: [vars.D3D1P3, vars.D3D1P4, vars.D3D2P3, vars.D3D2P4]}}})
    ### Add Po-6 as Mclag interface
    co_utils.exec_all(pll_exec, [[mclag.config_interfaces, dut, mclag_domain, 'PortChannel6']
                          for dut in data.mclag_peers])

def  del_new_PO():
    ### Remove PO6 from Mclag
    co_utils.exec_foreach(pll_exec, data.mclag_peers, mclag.config_interfaces, mclag_domain, 'PortChannel6', config='del')

    ###UnConfigure PO-6 between D1-D2 and D3
    api_list = []
    api_list.append([po.delete_portchannel_member, dut1, 'PortChannel6', [vars.D1D3P3, vars.D1D3P4]])
    api_list.append([po.delete_portchannel_member, dut2, 'PortChannel6', [vars.D2D3P3, vars.D2D3P4]])
    api_list.append(
        [po.delete_portchannel_member, dut3, 'PortChannel6', [vars.D3D1P3, vars.D3D1P4, vars.D3D2P3, vars.D3D2P4]])
    co_utils.exec_all(pll_exec, api_list)
    co_utils.exec_all(pll_exec, [[po.delete_portchannel, dut, 'PortChannel6'] for dut in [dut1, dut2, dut3]])

    ### Remove PO-6 from PO data
    del po_data["PortChannel6"]


def del_PO(po_id):
    co_utils.exec_all(pll_exec, [[po.delete_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in
                          po_data[po_id]['duts']])
    co_utils.exec_all(pll_exec, [[po.delete_portchannel, dut, po_id] for dut in po_data[po_id]['duts']])


def add_PO(po_id):
    co_utils.exec_all(pll_exec, [[po.create_portchannel, dut, po_id] for dut in po_data[po_id]['duts']])
    co_utils.exec_all(pll_exec, [[po.add_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in
                          po_data[po_id]['duts']])

def test_po_gshut_add_del_PO():
    global final_result, traffic_forward_fail, route_fail, arp_count_fail, nd_count_fail, po_fail
    ##PO gshut functionality
    tc1_result = True
    tc1_msg = ''
    ## Add new PO in gshut
    tc2_result = True
    tc2_msg = ''
    ## Del PO in gshutver
    tc3_result = True
    tc3_msg = ''
    ## Unconfig PO gshut
    tc4_result = True
    tc4_msg = ''
    tc_list = ['FtRtMclagPOMM', 'FtRtMclagPOMMAddPO', 'FtRtMclagUnconfigPOMM', 'FtRtMclagPOMMDelPO', 'FtRtMclagMMCli001']
    print_log(
        "START of TC:test_po_gshut_add_del_PO ==>Sub-Test:Verify PortChannel graceful shutdown\n TCs:<{}>".format(
            tc_list),
        "HIGH")

    print_log("TC Summary :==> Sub-Test:Enable PO gshut and verify PO and its members are down.", "MED")
    po.config_portchannel_gshut(dut1,exception_po_list='PortChannel1')
    st.report_tc_pass('FtRtMclagMMCli001', "test_case_passed")

    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['down','up']):
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("Verify PO states in Maintenance mode FAILED",'ERROR')
        tc1_msg += "PO Maintenance Mode Failed:"
        tc1_result = False
    else:
        print_log("Verify PO states in Maintenance mode PASSED", 'MED')

    #st.wait(wait_time)
    st.banner("Verify Backup static route")
    results = []
    results += [ip.verify_ip_route(dut4, family='ipv4', ip_address=tg31_ip[2], nexthop=po4_ip_d2, type='B',
                                interface='Vlan' + str(access_vlan))]
    results += [ip.verify_ip_route(dut4, family='ipv4', ip_address=tg32_ip[2], nexthop=po5_ip_d2, type='B',
                                interface='Vlan' + str(trunk_base_vlan))]
    if False in results:
        print_log("D4 to D3 IPv4 route Failed",'ERROR')
        route_fail += 1
        tc1_result = False
        tc1_msg += "IPv4 Route verification Failed:"
    else:
        print_log("D4 to D3 IPv4 route Passed", 'MED')


    results = []
    results += [ip.verify_ip_route(dut4, family='ipv6', ip_address=tg31_ip6[2], type='B',
                                  interface='Vlan' + str(access_vlan))]
    results += [ip.verify_ip_route(dut4, family='ipv6', ip_address=tg32_ip6[2], type='B',
                                  interface='Vlan' + str(trunk_base_vlan))]
    if False in results:
        print_log("D4 to D3 IPv6 route Failed", 'ERROR')
        route_fail += 1
        tc1_result = False
        tc1_msg += "IPv6 Route verification Failed:"
    else:
        print_log("D4 to D3 IPv6 route Passed", 'MED')

    ### Clear counters on dut ports
    print_log("Clear Interface counters", 'MED')
    co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])

    #st.wait(60)
    if not utils.retry_api(verify_traffic, src_stream_list=data.base_src_streams,
                           dest_stream_list=data.base_dst_streams, retry_count=5, delay=5):
        traffic_forward_fail += 1
        tc1_result = False
        tc1_msg += "Traffic forwarding Failed when  PO gshut enabled in active peer:"
        debug_traffic_fail()
        collect_techsupport()
    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMM', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMM", "test_case_failure_message",
                          "Verify PO in Maintenance Mode=>{}".format(tc1_msg.strip(':')))


    print_log("TC Summary :==> Sub-Test:Add new PO and verify PO and its members are down.", "MED")
    add_new_PO()
    ### Verify PO state &  interface counters
    for po_name in ['PortChannel6']:
        if not verify_portchannel(po_name,data.mclag_peers,['down','up']):
            print_log("Add new PO-6 in Maintenance Mode FAILED", 'ERROR')
            po_fail += 1
            tc2_result = False
            tc2_msg += "New PO6 state in Maintenance Mode Failed:"
        else:
            print_log("Add new PO-6 in Maintenance Mode Passed", 'HIGH')


    print_log("TC Summary :==> Sub-Test:Unconfigure Maintenance mode and verify add PO operation is in effect.", "MED")
    ### Unconfigure MM
    po.config_portchannel_gshut(dut1,config='del')
    st.wait(wait_time)
    ### Verify PO state
    for po_name in ['PortChannel6']:
        if not verify_portchannel(po_name,data.mclag_peers,['up','up']):
            print_log("FAIL: New PO-6 added in Maintenance Mode is not operational", 'ERROR')
            po_fail += 1
            tc2_result = False
            tc2_msg += "New PO6 not operational with  Maintenance Mode unconfig:"
        else:
            print_log("PASS:New PO-6 added in Maintenance Mode is operational", 'MED')

    if tc2_result:
        st.report_tc_pass('FtRtMclagPOMMAddPO', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMMAddPO", "test_case_failure_message","{}".format(tc2_msg.strip(':')))


    print_log("TC Summary :==> Sub-Test:Delete PO6 and verify operation is allowed in Maintenance Mode.", "MED")
    ### Config GSHUT on standby Node.
    #po.config_portchannel_gshut(dut2)
    po.config_portchannel_gshut(dut2, exception_po_list='PortChannel1')
    ### Delete PO6
    del_new_PO()

    [results, exceptions] = co_utils.exec_all(pll_exec, [[po.verify_portchannel, dut, 'PortChannel6'] for dut in data.mclag_peers])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if True in results:
        print_log("PO-6 delete in Maintenance Mode FAILED", 'ERROR')
        tc3_result = False
        po_fail += 1
        tc3_msg += "PO-6 delete in Maintenance Mode Failed:"
    else:
        print_log("PO-6 delete in Maintenance Mode Passed", 'MED')

    if tc3_result:
        st.report_tc_pass('FtRtMclagPOMMDelPO', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMMDelPO", "test_case_failure_message", "{}".format(tc3_msg.strip(':')))

    print_log("TC Summary :==> Sub-Test:Unconfigure Maintenance Mode and verify all POs operational.", "MED")
    ### Config GSHUT on standby Node.
    po.config_portchannel_gshut(dut2,config='del')
    st.wait(wait_time)

    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['up','up']):
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("FAIL: All POs not operational after PO gshut Disable", 'ERROR')
        tc4_msg += "PO Maintenance Mode Unconfig Failed:"
        tc4_result = False
    else:
        print_log("PASS: All POs operational after PO gshut Disable", 'MED')

    ### Clear counters on dut ports
    print_log("Clear Interface counters", 'MED')
    co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])

    ### Verify traffic load balancing
    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        print_log("FAIL: Traffic forwarding after PO gshut Disable", 'ERROR')
        traffic_forward_fail += 1
        tc4_result = False
        tc4_msg += "Traffic forwarding Failed after PO gshut Disabled:"
        debug_traffic_fail()
        collect_techsupport()
    else:
        print_log("PASS: Traffic forwarding after PO gshut Disable", 'MED')

    if tc4_result:
        st.report_tc_pass('FtRtMclagUnconfigPOMM', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagUnconfigPOMM", "test_case_failure_message", "{}".format(tc4_msg.strip(':')))

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 or route_fail > 0:
        final_result = False
        print_log("{}\n{}\n{}\n{}".format(tc1_msg, tc2_msg, tc3_msg, tc4_msg),'HIGH')
    post_result_handler()


def test_po_gshut_add_del_ports():
    global final_result, traffic_forward_fail, arp_count_fail, nd_count_fail, po_fail

    tc_list = ['FtRtMclagPOMMAddDelMemberPorts']
    print_log(
        "START of TC:test_po_gshut_add_del_ports ==>Sub-Test:Verify PO member ports add/del in GSHUT mode.\n TCs:<{}>".format(
            tc_list),
        "HIGH")

    ##PO gshut member port add/del
    tc1_result = True
    tc1_msg = ''
    print_log("TC Summary :==> Sub-Test:Enable PO gshut and verify add/del member ports to PO3.", "MED")

    ### Configure PO gshut on D1
    #po.config_portchannel_gshut(dut1)
    po.config_portchannel_gshut(dut1, exception_po_list='PortChannel1')
    po_members = {}
    ### Add new ports to PO3 and delete one exisitng port
    po_members[dut1] = [vars.D1D3P3, vars.D1D3P4]
    po_members[dut3] = [vars.D3D1P3, vars.D3D1P4]
    po_id = 'PortChannel3'
    co_utils.exec_all(pll_exec, [[po.add_portchannel_member, dut, po_id, po_members[dut]] for dut in
                             [dut1,dut3]])

    po_members[dut1] = [vars.D1D3P2]
    po_members[dut3] = [vars.D3D1P2]
    po_id = 'PortChannel3'
    co_utils.exec_all(pll_exec, [[po.delete_portchannel_member, dut, po_id, po_members[dut]] for dut in
                             [dut1,dut3]])

    ### Update po_data
    po_data.update({'PortChannel3': {'duts': [dut1, dut2, dut3],
                                     'po_members': {dut1: [vars.D1D3P1, vars.D1D3P3, vars.D1D3P4],
                                                    dut2: [vars.D2D3P1, vars.D2D3P2],
                                                    dut3: [vars.D3D1P1, vars.D3D1P3, vars.D3D1P4, vars.D3D2P1, vars.D3D2P2]}}})

    ### Verify PO state in gshut mode with new members
    loop_result = True
    for po_name in ['PortChannel3']:
        if not verify_portchannel(po_name,data.mclag_peers,['down','up']):
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("Verify PO3 states in Maintenance mode after add/del member ports FAILED",'ERROR')
        tc1_msg += "add/del ports to PO3 in Maintenance Mode Failed:"
        tc1_result = False
    else:
        print_log("Verify PO3 states in Maintenance mode after add/del member ports PASSED", 'MED')

    ### Unconfigure PO MM
    po.config_portchannel_gshut(dut1,config='del')
    st.wait(wait_time)
    ### Verify PO state with new member ports
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['up','up']):
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("FAIL:Member ports added to PO3 in Maintenance mode didn't come up with ghsut disable",'ERROR')
        tc1_msg += "Member ports added in PO gshut Mode not operational with GSHUT disable:"
        tc1_result = False
    else:
        print_log("PASS:Member ports added to PO3 in Maintenance mode comes up with ghsut disable", 'MED')

    ### Clear counters on dut ports
    print_log("Clear Interface counters", 'MED')
    co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])

    ### Verify traffic forwarding & counters 0 in deleted ports
    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        tc1_result = False
        tc1_msg += "Traffic forwarding Failed with PO member ports altered in Maintenance mode:"
        debug_traffic_fail()
        collect_techsupport()
    ### Revert PO member ports
    po_members[dut1] = [vars.D1D3P3, vars.D1D3P4]
    po_members[dut3] = [vars.D3D1P3, vars.D3D1P4]
    po_id = 'PortChannel3'
    co_utils.exec_all(pll_exec, [[po.delete_portchannel_member, dut, po_id, po_members[dut]] for dut in
                                 [dut1, dut3]])

    po_members[dut1] = [vars.D1D3P2]
    po_members[dut3] = [vars.D3D1P2]
    po_id = 'PortChannel3'
    co_utils.exec_all(pll_exec, [[po.add_portchannel_member, dut, po_id, po_members[dut]] for dut in
                                 [dut1, dut3]])

    ### Update po_data
    po_data.update({'PortChannel3': {'duts': [dut1, dut2, dut3],
                                         'po_members': {dut1: [vars.D1D3P1, vars.D1D3P2],
                                                        dut2: [vars.D2D3P1, vars.D2D3P2],
                                                        dut3: [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2]}}})
    ### Verify PO state with original member ports
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['up','up']):
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("Verify PO states with GSHUT disable FAILED",'ERROR')
        tc1_msg += "PO states failed with GSHUT disable and member ports reverted:"
        tc1_result = False
    else:
        print_log("Verify PO states with GSHUT disable PASSED", 'MED')

    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMAddDelMemberPorts', "test_case_passed")
    else:
        st.report_tc_fail('FtRtMclagPOMMAddDelMemberPorts', "test_case_failure_message", "{}".format(tc1_msg.strip(':')))

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 :
        final_result = False
        print_log("{}".format(tc1_msg), 'HIGH')
    post_result_handler()


def test_po_gshut_shut_noshut_PO():
    global final_result, traffic_forward_fail, arp_count_fail, nd_count_fail, po_fail

    tc_list = ['FtRtMclagPOMMShutNoShutPO', 'FtRtMclagPOMMActiveStandby']
    print_log(
        "START of TC:test_po_gshut_shut_noshut_PO ==>Sub-Test:Verify PO shut/no-shut in GSHUT mode\n TCs:<{}>".format(
            tc_list),
        "HIGH")

    ##PO gshut functionality on standby
    tc1_result = True
    tc1_msg = ''
    print_log("TC Summary :==> Sub-Test:Enable PO gshut on standby and verify all PO and its members are down.", "MED")

    #po.config_portchannel_gshut(dut2)
    po.config_portchannel_gshut(dut2, exception_po_list='PortChannel1')
    po_result = True
    for po_name in ['PortChannel3','PortChannel4','PortChannel5']:
        if not verify_portchannel(po_name,data.mclag_peers,['up','down']):
            po_result = False

    if not po_result:
        print_log("PO gshut on  Standby Mclag peer FAILED", 'ERROR')
        po_fail += 1
        tc1_result = False
        tc1_msg += "PO gshut on  Standby Mclag peer Failed:"
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("PO gshut on  Standby Mclag peer PASSED", 'MED')
    ### no shut one PO, PO4 and verify it is still down
    port_list = {}
    port_list[dut2] = 'PortChannel4'
    co_utils.exec_all(pll_exec, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut2]])
    ### Verify traffic counters that  P04 on D2 not Tx/Rx traffic
    for po_name in ['PortChannel4']:
        if not verify_portchannel(po_name,data.mclag_peers,['up','down']):
            print_log("NO-shut PO-4 in Maintenance Mode of Standby Mclag peer FAILED", 'ERROR')
            po_fail += 1
            tc1_result = False
            tc1_msg += "NO-shut PO-4 in Maintenance Mode of Standby Mclag peer Failed:"
            debug_po_fail()
            collect_techsupport()
        else:
            print_log("NO-shut PO-4 in Maintenance Mode of Standby Mclag peer PASSED", 'HIGH')

    ### Clear counters on dut ports
    print_log("Clear Interface counters", 'MED')
    co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])

    ### Verify traffic load balancing
    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        tc1_result = False
        tc1_msg += "Traffic forwarding Failed when PO4 no-shut done in Maintenance mode of standby Peer:"
        debug_traffic_fail()
        collect_techsupport()

    ### shut PO in MM
    tc2_result = True
    tc2_msg = ''
    print_log("TC Summary :==> Sub-Test:Shutdown a PO in ghsut mode and  verify it is down after gshut disabled", "MED")

    ### shutdown PO4 on D2  & unconfigure MM
    co_utils.exec_all(pll_exec, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut2]])
    po.config_portchannel_gshut(dut2,config='del')
    st.wait(wait_time)

    ### Verify all POs except PO4, is up
    loop_result = True
    for po_name in ['PortChannel3','PortChannel5']:
        if not verify_portchannel(po_name,data.mclag_peers,['up','up']):
            loop_result = False
            po_fail += 1
    if not loop_result:
        tc1_result = False
        tc1_msg += "Disable Maintenance Mode of Standby Mclag peer Failed:"
        debug_po_fail()
        collect_techsupport()

    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMActiveStandby', "test_case_passed")
    else:
        st.report_tc_fail('FtRtMclagPOMMActiveStandby', "test_case_failure_message", "{}".format(tc1_msg.strip(':')))

    for po_name in ['PortChannel4']:
        if not verify_portchannel(po_name,data.mclag_peers,['up','down']):
            print_log("Shut PO-4 in Maintenance Mode of Standby Mclag peer FAILED", 'ERROR')
            po_fail += 1
            tc2_result = False
            tc2_msg += "Shut PO-4 in Maintenance Mode of Standby Mclag peer Failed:"
            debug_po_fail()
            collect_techsupport()
        else:
            print_log("Shut PO-4 in Maintenance Mode of Standby Mclag peer PASSED", 'HIGH')

    ### Clear counters on dut ports
    print_log("Clear Interface counters", 'MED')
    co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])

    ### Verify traffic load balancing
    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        tc2_result = False
        tc2_msg += "Traffic forwarding Failed when PO4 shut in Maintenance mode:"
        debug_traffic_fail()
        collect_techsupport()
    ### no shut PO4 and verify it is up
    co_utils.exec_all(pll_exec, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut2]])
    for po_name in ['PortChannel4']:
        if not verify_portchannel(po_name,data.mclag_peers,['up','up']):
            print_log("Disable Maintenance Mode of Standby Mclag peer FAILED", 'ERROR')
            po_fail += 1
            tc2_result = False
            tc2_msg += "No-Shut PO-4 in Standby Mclag peer with gshut disabled Failed:"
            debug_po_fail()
            collect_techsupport()
        else:
            print_log("Disable Maintenance Mode of Standby Mclag peer PASSED", 'HIGH')

    if tc2_result:
        st.report_tc_pass('FtRtMclagPOMMShutNoShutPO', "test_case_passed")
    else:
        st.report_tc_fail('FtRtMclagPOMMShutNoShutPO', "test_case_failure_message", "{}".format(tc2_msg.strip(':')))

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 :
        print_log("{}\n{}".format(tc1_msg,tc2_msg),'HIGH')
        final_result = False
    post_result_handler()


def remove_client_configs():
    ###Remove PO member ports
    print_log("Remove PortChannel Member ports from PO on  Client Nodes",'MED')
    api_list = []
    api_list.append([po.delete_portchannel_member, dut4, "PortChannel5", po_data['PortChannel5']['po_members'][dut4]])
    co_utils.exec_all(pll_exec, api_list)

    ###Disable client ports
    print_log("Shut unconfigured PortChannel Member ports on  Client Nodes", 'MED')
    api_list = []
    api_list.append([intf.interface_operation, dut4, po_data['PortChannel5']['po_members'][dut4], 'shutdown', False])
    co_utils.exec_all(pll_exec, api_list)

    ###Configure trunk  vlans on client member ports.
    print_log("Configure member vlans on PortChannel Member ports on  Client Nodes", 'MED')
    member_port_list = {}
    member_port_list[dut4] = po_data['PortChannel5']['po_members'][dut4]
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, member_port_list[dut]] for dut in
                          [dut4]])

    ### Disable PO4 in all nodes so that L3 traffic fwd gets verified with fallback states of PO5
    port_list = {}
    port_list[dut1] = 'PortChannel4'
    port_list[dut2] = 'PortChannel4'
    port_list[dut4] = 'PortChannel4'
    co_utils.exec_all(pll_exec, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut1, dut2, dut4]])

def verify_mclag_fallback(po_name,fb_cfg_states,fb_op_states,report_failure='YES',comparison_flag=True):
    ver_flag = True
    if comparison_flag is True:
        print_log("Check If Mclag fallback Operational state for the PO:{} is {}-{}".format(po_name,fb_op_states[0],fb_op_states[1]), 'MED')
    else:
        print_log("Check If Mclag fallback Operational state for the PO:{} is NOT {}-{}".format(po_name, fb_op_states[0], fb_op_states[1]),
                  'MED')
    dict1 = {'port_channel_name': po_name, 'fallback_config': fb_cfg_states[0], 'fallback_oper_status':fb_op_states[0]}
    dict2 = {'port_channel_name': po_name, 'fallback_config': fb_cfg_states[1], 'fallback_oper_status':fb_op_states[1]}
    [result, exceptions] = pll.exec_parallel(pll_exec, data.mclag_peers, po.verify_lacp_fallback, [dict1, dict2])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        if report_failure == 'YES':
            print_log('Portchannel-{} fallback state not as expected'.format(po_name), 'ERROR')
        ver_flag = False
    return ver_flag


def test_po_gshut_with_fallback():
    global final_result, traffic_forward_fail, arp_count_fail, nd_count_fail, po_fail, fb_fail

    tc_list = ['FtRtMclagPOMMfallbackPO']
    print_log(
        "START of TC:test_po_gshut_with_fallback ==>Sub-Test:Verify PortChannel graceful shutdown with fallback mode Enabled\n TCs:<{}>".format(
            tc_list),
        "HIGH")

    ##PO gshut functionality with LACP fallback
    tc1_result = True
    tc1_msg = ''
    print_log("TC Summary :==> Sub-Test:Make PO5 fallback state operational and verify PO gshut .", "MED")
    ### Remove member ports from client & enable first link so that fallback in enabled in D1.
    remove_client_configs()
    st.banner("Enable client side member port towards D1 and then enable one port towards D2")
    ###Enaable client ports
    port_list = {}
    port_list[dut4] = [vars.D4D1P3]
    co_utils.exec_all(pll_exec, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut4]])
    ### Enable second link towards D2
    port_list = {}
    port_list[dut4] = [vars.D4D2P3]
    co_utils.exec_all(pll_exec, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut4]])

    if not verify_mclag_fallback("PortChannel5",["Enabled","Enabled"],["Enabled","Disabled"]):
        fb_fail += 1
        print_log("PortChannel5 Fallback state without PO gshut FAILED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2), 'HIGH')
        fail_msg = "PO-5 fallback state without PO gshut failed:"
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))
    else:
        print_log("PortChannel5 Fallback state without PO gshut PASSED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2),
                  'HIGH')

    ### Enable PO GSHUT in D1
    #po.config_portchannel_gshut(dut1)
    po.config_portchannel_gshut(dut1, exception_po_list='PortChannel1')
    ### Verfy all POs down in D1 and fallback enabled in D2
    loop_result = True
    for po_name in ['PortChannel5']:
        if not verify_portchannel(po_name,[dut1],['down']):
            po_fail += 1
            loop_result = False
    for po_name in ['PortChannel5']:
        [results,exceptions] = co_utils.exec_all(pll_exec, [[po.verify_portchannel_state, dut, po_name, 'up'] for dut in [dut2]])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in results:
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("Verify PO states with fallback & gshut enabled in active node FAILED",'ERROR')
        tc1_result = False
        tc1_msg += "PO-5 states failed with fallback & gshut enabled in active node:"
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states with fallback & gshut enabled in active node PASSED", 'MED')

    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
        fb_fail += 1
        tc1_result = False
        tc1_msg += "PO-5 fallback state didn't switch to standby peer D2 with GSHUT enabled in active peer D1:"
        print_log("PortChannel5 Fallback state FAILED, Expect Disabled in {} and Enabled in {}".format(dut1, dut2),
                  'HIGH')
    ### Verify traffic counters
    ### Clear counters on dut ports
    print_log("Clear Interface counters", 'MED')
    co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])

    ### Verify traffic forwarding
    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        tc1_result = False
        tc1_msg += "Traffic forwarding Failed with GSHUT enabled in active Mclag & fallback operational in standby Mclag:"
        debug_traffic_fail()
        collect_techsupport()
    ### Add member port to LACP in D1 and verify PO still down in D1 & fallback enabled in D2
    st.banner("Enable LACP on member port towards D1 and verify PO-5 still down in D1 and fallback operational in D2",width=100)
    member_port_list = {}
    # member_port_list[dut3] = po_data['PortChannel3']['po_members'][dut3]
    member_port_list[dut4] = po_data['PortChannel5']['po_members'][dut4]
    co_utils.exec_all(pll_exec, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, member_port_list[dut],'del'] for dut in
                          [dut4]])

    api_list = []
    #api_list.append([po.add_portchannel_member, dut3, "PortChannel3", vars.D3D1P2])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", vars.D4D1P3])
    co_utils.exec_all(pll_exec, api_list)
    loop_result = True
    for po_name in ['PortChannel5']:
        if not verify_portchannel(po_name,dut1,['down']):
            po_fail += 1
            loop_result = False
    for po_name in ['PortChannel5']:
        [results,exceptions] = co_utils.exec_all(pll_exec, [[po.verify_portchannel_state, dut, po_name, 'up'] for dut in [dut2]])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in results:
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("FAIL:PO-5 state not down in gshut enabled active node, when LACP sent from client",'ERROR')
        tc1_result = False
        tc1_msg += "PO-5 state not down in gshut enabled active node, when LACP sent from client:"
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("PASS:PO-5 state is down in gshut enabled active node, when LACP sent from client", 'MED')

    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
        fb_fail += 1
        tc1_result = False
        tc1_msg += "PO-5 fallback state not operational in standby peer D2 when LACP sent to gshut enabled D1:"
        print_log("PortChannel5 Fallback state FAILED, Expect Disabled in {} and Enabled in {}".format(dut1, dut2),
                  'HIGH')

    ### Add member port to LACP in D2 and verify PO is LACP up in D2 & down in D1
    st.banner("Enable LACP on member port towards D2 and verify PO-5 fallback is non-operatonal in D2")
    api_list = []
    #api_list.append([po.add_portchannel_member, dut3, "PortChannel3", vars.D3D1P2])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", vars.D4D2P3])
    co_utils.exec_all(pll_exec, api_list)

    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Disabled"]):
        fb_fail += 1
        tc1_result = False
        tc1_msg += "PO-5 fallback state is still operational in standby peer D2 when LACP sent from client:"
        print_log("PortChannel5 Fallback state FAILED, Expect Disabled in {} and Disabled in {}".format(dut1, dut2),
                  'HIGH')
    ### Verify PO5 is UP in client
    loop_result = True
    for po_name in ['PortChannel5']:
        if not verify_portchannel(po_name, [dut1], ['down']):
            po_fail += 1
            loop_result = False
    for po_name in ['PortChannel5']:
        [results, exceptions] = co_utils.exec_all(pll_exec,
                                                  [[po.verify_portchannel_state, dut, po_name, 'up'] for dut in
                                                   [dut2, dut4]])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in results:
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("Verify PO states with fallback non-operational in standby & gshut enabled in active node FAILED", 'ERROR')
        tc1_result = False
        tc1_msg += "PO-5 states failed with fallbacknon-operational in standby & gshut enabled in active node:"
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states with fallback non-operational in standby & gshut enabled in active node PASSED", 'MED')

    ### Disable PO GSHUT in D1 and verify all POs LACP up in both duts
    st.banner("Disable PO gshut in D1 and revert client side PO5 configuration")
    po.config_portchannel_gshut(dut1,config='del')
    st.wait(wait_time)
    ### add back all member ports to LACP at client side.
    api_list = []
    #api_list.append([po.add_portchannel_member, dut3, "PortChannel3", vars.D3D1P2])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", [vars.D4D1P4,vars.D4D2P4]])
    co_utils.exec_all(pll_exec, api_list)
    port_list = {}
    port_list[dut4] = [vars.D4D1P4,vars.D4D2P4]
    co_utils.exec_all(pll_exec, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut4]])

    loop_result = True
    for po_name in data.mclag_interfaces:
        if po_name == "PortChannel3":
            duts = [dut1, dut2, dut3]
            states= ['up','up','up']
        elif po_name == "PortChannel4":
            duts = [dut1, dut2, dut4]
            states= ['down', 'down', 'down']
        elif po_name == "PortChannel5":
            duts = [dut1, dut2, dut4]
            states= ['up', 'up', 'up']
        if not verify_portchannel(po_name,duts,states):
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("Verify PO states after disabling GSHUT & fallback FAILED",'ERROR')
        tc1_msg += "PO states after disabling GSHUT & fallback Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states after disabling GSHUT & fallback PASSED", 'MED')

    ### Enable back PO4 on all nodes and verify it is up.
    print_log("Enable back PO4 on all nodes and verify it is up",'MED')
    port_list = {}
    port_list[dut1] = 'PortChannel4'
    port_list[dut2] = 'PortChannel4'
    port_list[dut4] = 'PortChannel4'
    co_utils.exec_all(pll_exec, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut1, dut2, dut4]])

    loop_result = True
    states = ['up', 'up', 'up']
    for po_name in data.mclag_interfaces:
        if po_name == "PortChannel3":
            duts = [dut1, dut2, dut3]
        else:
            duts = [dut1, dut2, dut4]
        if not verify_portchannel(po_name, duts, states):
            po_fail += 1
            loop_result = False
    if not loop_result:
        print_log("Verify PO states after disabling GSHUT & fallback FAILED", 'ERROR')
        tc1_msg += "PO states after disabling GSHUT & fallback Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states after disabling GSHUT & fallback PASSED", 'MED')

    ### Clear counters on dut ports
    print_log("Clear Interface counters", 'MED')
    co_utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])

    ### Verify traffic forwarding
    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        tc1_result = False
        tc1_msg += "Traffic forwarding Failed after disabling GSHUT & fallback in active mclag peer:"
        debug_traffic_fail()
        collect_techsupport()

    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMfallbackPO', "test_case_passed")
    else:
        st.report_tc_fail('FtRtMclagPOMMfallbackPO', "test_case_failure_message", "{}".format(tc1_msg.strip(':')))

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 :
        final_result = False
        print_log("{}".format(tc1_msg),'HIGH')
    post_result_handler()





