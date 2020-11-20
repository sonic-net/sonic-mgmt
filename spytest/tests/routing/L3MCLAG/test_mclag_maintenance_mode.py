##########################################################################################
# Title: MCLAG Maintenance Mode script
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
import apis.routing.ospf as ospf
import apis.routing.evpn as evpn
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
flap_wait = 60

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
    data.mclag_interfaces = ['PortChannel4','PortChannel5']

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
    run_traffic()
    mclag_basic_validations()
    run_traffic(action='STOP')
    yield
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
        if po_id in data.mclag_interfaces:
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
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(access_vlan), po4_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(access_vlan), po4_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut4, 'Vlan' + str(access_vlan), po4_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(trunk_base_vlan), po5_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(trunk_base_vlan), po5_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.config_ip_addr_interface, dut4, 'Vlan' + str(trunk_base_vlan), po5_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    ### Assign IP addresses to Uplink interfaces
    ### Assign IPv6 addresses to Uplink interfaces
    def func(dut):
        d1 = bool(dut == dut1)
        d2 = bool(dut == dut2)
        d3 = bool(dut == dut3)

        if d1:
            ip.config_ip_addr_interface(dut, 'PortChannel3', po3_ip_d1, v4_mask)
            ip.config_ip_addr_interface(dut, 'PortChannel3', po3_ip6_d1, v6_mask, 'ipv6')
        if d2:
            ip.config_ip_addr_interface(dut, 'PortChannel6', po6_ip_d2, v4_mask)
            ip.config_ip_addr_interface(dut, 'PortChannel6', po6_ip6_d2, v6_mask, 'ipv6')
        if d3:
            ip.config_ip_addr_interface(dut, 'PortChannel3', po3_ip_d3, v4_mask)
            ip.config_ip_addr_interface(dut, 'PortChannel3', po3_ip6_d3, v6_mask, 'ipv6')

            ip.config_ip_addr_interface(dut, 'PortChannel6', po6_ip_d3, v4_mask)
            ip.config_ip_addr_interface(dut, 'PortChannel6', po6_ip6_d3, v6_mask, 'ipv6')
    st.exec_each([dut1, dut2, dut3], func)



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
    ##########################################################################
    dict1 = {'local_as': as_num_1, 'router_id': lb_ip_d1,
             'redistribute': 'connected', 'config_type_list': ['router_id', 'redist']}
    dict2 = {'local_as': as_num_2, 'router_id': lb_ip_d2,
             'redistribute': 'connected', 'config_type_list': ['router_id', 'redist']}
    dict3 = {'local_as': as_num_3, 'router_id': lb_ip_d3,
             'redistribute': 'connected', 'config_type_list': ['router_id', 'redist']}
    dict4 = {'local_as': as_num_4, 'router_id': lb_ip_d4,
             'redistribute': 'connected', 'config_type_list': ['router_id', 'redist']}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut3, dut4], bgp.config_bgp, [dict1, dict2, dict3, dict4])

    api_list = []
    api_list.append([bgp.config_bgp_router, dut1, as_num_1, '', bgp_keepalive, bgp_holdtime])
    api_list.append([bgp.config_bgp_router, dut2, as_num_2, '', bgp_keepalive, bgp_holdtime])
    api_list.append([bgp.config_bgp_router, dut3, as_num_3, '', bgp_keepalive, bgp_holdtime])
    api_list.append([bgp.config_bgp_router, dut4, as_num_4, '', bgp_keepalive, bgp_holdtime])
    co_utils.exec_all(pll_exec, api_list)

    ###################################################################################
    st.banner("BGP-config: Configure non-default ECMP paths under IPv4 address family")
    ###################################################################################
    dict1 = {'local_as': as_num_1, 'max_path_ebgp':8, 'config_type_list': ["max_path_ebgp"]}
    dict2 = {'local_as': as_num_2, 'max_path_ebgp':8, 'config_type_list': ["max_path_ebgp"]}
    dict3 = {'local_as': as_num_3, 'max_path_ebgp':8, 'config_type_list': ["max_path_ebgp", "multipath-relax"]}
    dict4 = {'local_as': as_num_4, 'max_path_ebgp':8, 'config_type_list': ["max_path_ebgp", "multipath-relax"]}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut3, dut4], bgp.config_bgp, [dict1, dict2, dict3, dict4])

    ####################################################################################
    st.banner("BGP-config: Configure BGPv4 neighbors between MCLAG peers and client-2")
    ####################################################################################
    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num_2, 'neighbor': po4_ip_d2, 'local_as': as_num_1,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num_4, 'neighbor': po4_ip_d4, 'local_as': as_num_2,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num_1, 'neighbor': po4_ip_d1, 'local_as': as_num_4,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1,dut2,dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num_4, 'neighbor': po4_ip_d4, 'local_as': as_num_1,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num_1, 'neighbor': po4_ip_d1, 'local_as': as_num_2,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num_2, 'neighbor': po4_ip_d2, 'local_as': as_num_4,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num_2, 'neighbor': po5_ip_d2, 'local_as': as_num_1,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num_4, 'neighbor': po5_ip_d4, 'local_as': as_num_2,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num_1, 'neighbor': po5_ip_d1, 'local_as': as_num_4,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor'], 'remote_as': as_num_4, 'neighbor': po5_ip_d4, 'local_as': as_num_1,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor'], 'remote_as': as_num_1, 'neighbor': po5_ip_d1, 'local_as': as_num_2,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor'], 'remote_as': as_num_2, 'neighbor': po5_ip_d2, 'local_as': as_num_4,
             'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    for route_type in ['ospf']:
        dict1 = {'local_as': as_num_1, 'redistribute': route_type,  'addr_family': 'ipv4',
                 'config_type_list': ['redist']}
        dict2 = {'local_as': as_num_2, 'redistribute': route_type, 'addr_family': 'ipv4',
                 'config_type_list': ['redist']}
        pll.exec_parallel(pll_exec, [dut1, dut2], bgp.config_bgp, [dict1, dict2])

    ###################################################################################
    st.banner("BGP-config: Configure non-default ECMP paths under IPv6 address family")
    ###################################################################################
    dict1 = {'local_as': as_num_1, 'max_path_ebgp': 8, 'addr_family': 'ipv6', 'config_type_list': ["max_path_ebgp"]}
    dict2 = {'local_as': as_num_2, 'max_path_ebgp': 8, 'addr_family': 'ipv6', 'config_type_list': ["max_path_ebgp"]}
    dict3 = {'local_as': as_num_3, 'max_path_ebgp': 8, 'addr_family': 'ipv6', 'config_type_list': ["max_path_ebgp","multipath-relax"]}
    dict4 = {'local_as': as_num_4, 'max_path_ebgp': 8, 'addr_family': 'ipv6', 'config_type_list': ["max_path_ebgp","multipath-relax"]}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut3, dut4], bgp.config_bgp, [dict1, dict2, dict3, dict4])

    ##########################################################################
    st.banner("BGP-config: Configure BGPv6 neighbors between MCLAG peers and client-2")
    ##########################################################################
    dict1 = {'config_type_list': ['neighbor', 'activate'], 'remote_as': as_num_2, 'neighbor': po4_ip6_d2,
             'local_as': as_num_1, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_4, 'neighbor': po4_ip6_d4,
             'local_as': as_num_2, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_1, 'neighbor': po4_ip6_d1,
             'local_as': as_num_4, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_4, 'neighbor': po4_ip6_d4,
             'local_as': as_num_1, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_1, 'neighbor': po4_ip6_d1,
             'local_as': as_num_2, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_2, 'neighbor': po4_ip6_d2,
             'local_as': as_num_4, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_2, 'neighbor': po5_ip6_d2,
             'local_as': as_num_1, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_4, 'neighbor': po5_ip6_d4,
             'local_as': as_num_2, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_1, 'neighbor': po5_ip6_d1,
             'local_as': as_num_4, 'addr_family': 'ipv6','keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])

    dict1 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_4, 'neighbor': po5_ip6_d4,
             'local_as': as_num_1, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict2 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_1, 'neighbor': po5_ip6_d1,
             'local_as': as_num_2, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    dict4 = {'config_type_list': ['neighbor','activate'], 'remote_as': as_num_2, 'neighbor': po5_ip6_d2,
             'local_as': as_num_4, 'addr_family': 'ipv6', 'keepalive': bgp_keepalive, 'holdtime': bgp_holdtime}
    pll.exec_parallel(pll_exec, [dut1, dut2, dut4], bgp.config_bgp, [dict1, dict2, dict4])


    def func(dut):
        d1 = bool(dut == dut1)
        d2 = bool(dut == dut2)
        d3 = bool(dut == dut3)

        if d1:
            bgp.config_bgp(dut, local_as=as_num_1, neighbor=po3_ip6_d3, remote_as=as_num_3, addr_family='ipv6',
                           keepalive=bgp_keepalive, holdtime=bgp_holdtime, config_type_list=['neighbor', 'activate'])
        if d2:
            bgp.config_bgp(dut, local_as=as_num_2, neighbor=po6_ip6_d3, remote_as=as_num_3, addr_family='ipv6',
                           keepalive=bgp_keepalive, holdtime=bgp_holdtime, config_type_list=['neighbor', 'activate'])
        if d3:
            bgp.config_bgp(dut, local_as=as_num_3, neighbor=po3_ip6_d1, remote_as=as_num_1, addr_family='ipv6',
                           keepalive=bgp_keepalive, holdtime=bgp_holdtime, config_type_list=['neighbor', 'activate'])
            bgp.config_bgp(dut, local_as=as_num_3, neighbor=po6_ip6_d2, remote_as=as_num_2, addr_family='ipv6',
                           keepalive=bgp_keepalive, holdtime=bgp_holdtime, config_type_list=['neighbor', 'activate'])
    st.exec_each([dut1, dut2, dut3], func)

    for route_type in ['connected']:
        dict1 = {'local_as': as_num_1, 'redistribute': route_type, 'addr_family': 'ipv6',
                 'config_type_list': ['redist']}
        dict2 = {'local_as': as_num_2, 'redistribute': route_type, 'addr_family': 'ipv6',
                 'config_type_list': ['redist']}
        dict3 = {'local_as': as_num_3, 'redistribute': route_type, 'addr_family': 'ipv6',
                 'config_type_list': ['redist']}
        dict4 = {'local_as': as_num_4, 'redistribute': route_type, 'addr_family': 'ipv6',
                 'config_type_list': ['redist']}
        pll.exec_parallel(pll_exec, [dut1, dut2, dut3, dut4], bgp.config_bgp, [dict1, dict2, dict3, dict4])


def config_ospf():
    st.banner("Enable OSPF routing between Mclag peers and spine D3",width=100,delimiter='=')
    def func(dut):
        d1 = bool(dut == dut1)
        d2 = bool(dut == dut2)
        d3 = bool(dut == dut3)

        if d1:
            ospf.config_ospf_router_id(dut,router_id=lb_ip_d1)
            ospf.config_ospf_network(dut, networks=[po3_ip_nw, po1_ip_nw, tg11_ip[2], tg12_ip[2]], area='0.0.0.0')
            ospf.redistribute_into_ospf(dut,route_type='connected')
        if d2:
            ospf.config_ospf_router_id(dut,router_id=lb_ip_d2)
            ospf.config_ospf_network(dut,networks=[po6_ip_nw, po1_ip_nw, tg21_ip[2], tg22_ip[2]], area='0.0.0.0')
            ospf.redistribute_into_ospf(dut,route_type='connected')
        if d3:
            ospf.config_ospf_router_id(dut,router_id=lb_ip_d3)
            ospf.config_ospf_network(dut,networks=[po3_ip_nw, po6_ip_nw, tg31_ip[2], tg32_ip[2]], area='0.0.0.0')
            ospf.redistribute_into_ospf(dut,route_type='connected')

    st.exec_each([dut1, dut2, dut3], func)


def config_static_routes(config='yes'):
    if config == 'yes':
        api_name = ip.create_static_route
        operation = "Configure"
    else:
        api_name = ip.delete_static_route
        operation = "Unconfigure"

    st.banner("{} IPv6 static routes".format(operation))
    ### Config backup route from dut4 to dut3
    api_name(dut4, next_hop=po4_ip6_d1, static_ip=tg31_ip6[2], family='ipv6')
    api_name(dut4, next_hop=po5_ip6_d1, static_ip=tg32_ip6[2], family='ipv6')
    api_name(dut4, next_hop=po4_ip6_d2, static_ip=tg31_ip6[2], family='ipv6')
    api_name(dut4, next_hop=po5_ip6_d2, static_ip=tg32_ip6[2], family='ipv6')


def config_graceful_shut(dut,config='yes'):
    if config == 'yes':
        ospf_config = 'yes'
        bgp_config = 'add'
        po_config = 'add'
    elif config == 'no':
        ospf_config = 'no'
        bgp_config = 'del'
        po_config = 'del'
    if dut == dut1:
        current_as = as_num_1
    elif dut == dut2:
        current_as = as_num_2
    ospf.config_ospf_router_max_metric(dut, mmetric_type='administrative', mmetric_value='',config=ospf_config)
    bgp.config_bgp_graceful_shutdown(dut, local_asn=current_as, config=bgp_config)
    po.config_portchannel_gshut(dut, exception_po_list='PortChannel1', config=po_config)
    ### Save GR commands configured or unconfigrued
    boot.config_save(dut)


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
    po_data.update({'PortChannel3': {'duts': [dut1, dut3],
                                        'po_members': {dut1: [vars.D1D3P1, vars.D1D3P2],
                                                dut3: [vars.D3D1P1, vars.D3D1P2]}}})
    po_data.update({'PortChannel6': {'duts': [dut2, dut3],
                                        'po_members': {dut2: [vars.D2D3P1, vars.D2D3P2],
                                                    dut3: [vars.D3D2P1, vars.D3D2P2]}}})
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
    #config_static_routes()
    config_ospf()
    config_bgp()


def unconfig_vlan():
    ### UnConfigure Mclag vlan on PO-1
    co_utils.exec_all(pll_exec, [[vlan.delete_vlan_member, dut, mclag_vlan, 'PortChannel1', True]
                                 for dut in data.mclag_peers])
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
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(access_vlan), po4_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(access_vlan), po4_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut4, 'Vlan' + str(access_vlan), po4_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(trunk_base_vlan), po5_ip6_d1, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(trunk_base_vlan), po5_ip6_d2, v6_mask, 'ipv6'])
    api_list.append([ip.delete_ip_interface, dut4, 'Vlan' + str(trunk_base_vlan), po5_ip6_d4, v6_mask, 'ipv6'])
    co_utils.exec_all(pll_exec, api_list)

    ### Assign IP addresses to Uplink interfaces
    ### Assign IPv6 addresses to Uplink interfaces
    def func(dut):
        d1 = bool(dut == dut1)
        d2 = bool(dut == dut2)
        d3 = bool(dut == dut3)

        if d1:
            ip.delete_ip_interface(dut, 'PortChannel3', po3_ip_d1, v4_mask)
            ip.delete_ip_interface(dut, 'PortChannel3', po3_ip6_d1, v6_mask, 'ipv6')
        if d2:
            ip.delete_ip_interface(dut, 'PortChannel6', po6_ip_d2, v4_mask)
            ip.delete_ip_interface(dut, 'PortChannel6', po6_ip6_d2, v6_mask, 'ipv6')
        if d3:
            ip.delete_ip_interface(dut, 'PortChannel3', po3_ip_d3, v4_mask)
            ip.delete_ip_interface(dut, 'PortChannel3', po3_ip6_d3, v6_mask, 'ipv6')

            ip.delete_ip_interface(dut, 'PortChannel6', po6_ip_d3, v4_mask)
            ip.delete_ip_interface(dut, 'PortChannel6', po6_ip6_d3, v6_mask, 'ipv6')
    st.exec_each([dut1, dut2, dut3], func)

    
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
    dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as': as_num_1}
    dict2 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as': as_num_2}
    dict3 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as': as_num_3}
    dict4 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'local_as': as_num_4}
    pll.exec_parallel(pll_exec, [dut1,dut2,dut3,dut4], bgp.config_bgp, [dict1, dict2, dict3, dict4])


def unconfig_ospf():
    st.banner("Disable OSPF routing between Mclag peers and spine D3", width=100, delimiter='=')
    config_mode = 'no'
    def func(dut):
        d1 = bool(dut == dut1)
        d2 = bool(dut == dut2)
        d3 = bool(dut == dut3)

        if d1:
            ospf.redistribute_into_ospf(dut,route_type='bgp',config=config_mode)
            ospf.redistribute_into_ospf(dut,route_type='connected',config=config_mode)
            ospf.config_ospf_network(dut,networks=[po3_ip_nw, po1_ip_nw, tg11_ip[2], tg12_ip[2]], area='0.0.0.0',config=config_mode)
            ospf.config_ospf_router_id(dut,router_id=lb_ip_d1,config=config_mode)
        if d2:
            ospf.redistribute_into_ospf(dut,route_type='bgp',config=config_mode)
            ospf.redistribute_into_ospf(dut,route_type='connected',config=config_mode)
            ospf.config_ospf_network(dut,networks=[po6_ip_nw, po1_ip_nw, tg21_ip[2], tg22_ip[2]], area='0.0.0.0',config=config_mode)
            ospf.config_ospf_router_id(dut,router_id=lb_ip_d2,config=config_mode)
        if d3:
            ospf.redistribute_into_ospf(dut,route_type='bgp',config=config_mode)
            ospf.redistribute_into_ospf(dut,route_type='connected',config=config_mode)
            ospf.config_ospf_network(dut,networks=[po3_ip_nw, po6_ip_nw, tg31_ip[2], tg32_ip[2]], area='0.0.0.0',config=config_mode)
            ospf.config_ospf_router_id(dut,router_id=lb_ip_d3,config=config_mode)
    st.exec_each([dut1, dut2, dut3], func)


def mclag_module_unconfig():
    print_log("Starting MCLAG Base UnConfigurations...", "HIGH")
    #config_graceful_shut(dut1,config='no')
    unconfig_bgp()
    unconfig_ospf()
    #config_static_routes(config='no')
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
    nbr_list = [po4_ip_d2,po4_ip_d4,po5_ip_d2,po5_ip_d4,po4_ip6_d2,po4_ip6_d4,po5_ip6_d2,po5_ip6_d4,po3_ip6_d3]
    dict1 = {'nbr_list':nbr_list, 'state_list':['Established']*len(nbr_list)}
    nbr_list = [po4_ip_d1,po4_ip_d4,po5_ip_d1,po5_ip_d4,po4_ip6_d1,po4_ip6_d4,po5_ip6_d1,po5_ip6_d4,po6_ip6_d3]
    dict2 = {'nbr_list':nbr_list, 'state_list':['Established']*len(nbr_list)}
    nbr_list = [po3_ip6_d1,po6_ip6_d2]
    dict3 = {'nbr_list':nbr_list, 'state_list':['Established']*len(nbr_list)}
    nbr_list = [po4_ip_d2, po4_ip_d1, po5_ip_d2, po5_ip_d1, po4_ip6_d2, po4_ip6_d1, po5_ip6_d2, po5_ip6_d1]
    dict4 = {'nbr_list':nbr_list, 'state_list':['Established']*len(nbr_list)}
    if not utils.retry_parallel(ip_bgp.check_bgp_session, dut_list=[dut1,dut2,dut3,dut4], dict_list=[dict1,dict2,dict3,dict4],
                                retry_count=5, delay=2):
        st.error("One or more BGP sessions did not come up")
        return False
    return True

def verify_ospf():
    ###########################################################
    st.banner("Verify OSPF sessions are UP")
    ############################################################
    def func(dut):
        if dut == dut1:
            result = ospf.verify_ospf_neighbor_state(dut, ospf_links=['PortChannel3', 'Vlan100'], states=['Full', 'Full'],
                                    vrf='default', addr_family='ipv4')
        if dut == dut2:
            result = ospf.verify_ospf_neighbor_state(dut, ospf_links=['PortChannel6', 'Vlan100'], states=['Full', 'Full'],
                                    vrf='default', addr_family='ipv4')
        if dut == dut3:
            result = ospf.verify_ospf_neighbor_state(dut, ospf_links=['PortChannel6', 'PortChannel3'], states=['Full', 'Full'],
                                    vrf='default', addr_family='ipv4')
        return result
    [results, exceptions] = st.exec_each([dut1, dut2, dut3], func)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in results:
        return False
    return True

def verify_routes():
    st.banner("Verify Routes")

    def d1_routes():
        ver_flag = True
        res_v4_flag = []
        res_v4_flag += [ip.verify_ip_route(dut1, ip_address=tg22_ip[2], nexthop=peer2_ip, type='O',interface='Vlan'+str(mclag_vlan))]
        res_v4_flag += [ip.verify_ip_route(dut1, ip_address=tg32_ip[2], nexthop=po3_ip_d3, type='O', interface='PortChannel3')]
        if False in res_v4_flag:
            print_log("IPv4 Routes verification failed in Dut:{}".format(dut1), "ERROR")
            ver_flag = False
        else:
            print_log("IPv4 Routes verification passed in Dut:{}".format(dut1), "MED")

        res_v6_flag = []
        res_v6_flag += [ip.verify_ip_route(dut1, family='ipv6', ip_address=tg22_ip6[2], type='B',
                                           interface='Vlan'+str(access_vlan))]
        res_v6_flag += [ip.verify_ip_route(dut1, family='ipv6', ip_address=tg32_ip6[2], type='B',
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
        res_v4_flag += [ip.verify_ip_route(dut2, ip_address=tg11_ip[2], nexthop=peer1_ip, type='O',interface='Vlan'+str(mclag_vlan))]
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
        res_v4_flag += [ip.verify_ip_route(dut3, ip_address=tg41_ip[2], nexthop=po3_ip_d1, type='O', interface='PortChannel3')]
        res_v4_flag += [ip.verify_ip_route(dut3, ip_address=tg42_ip[2], nexthop=po6_ip_d2, type='O', interface='PortChannel6')]
        res_v4_flag += [ip.verify_ip_route(dut3, ip_address=tg12_ip[2], nexthop=po3_ip_d1, type='O', interface='PortChannel3')]
        if False in res_v4_flag:
            print_log("IPv4 Routes verification failed in Dut:{}".format(dut3), "ERROR")
            ver_flag = False
        else:
            print_log("IPv4 Routes verification passed in Dut:{}".format(dut3), "MED")

        res_v6_flag = []
        res_v6_flag += [ip.verify_ip_route(dut3, family='ipv6', ip_address=tg41_ip6[2], type='B',
                                           interface='PortChannel3')]
        res_v6_flag += [ip.verify_ip_route(dut3, family='ipv6', ip_address=tg42_ip6[2], type='B',
                                           interface='PortChannel6')]
        res_v6_flag += [ip.verify_ip_route(dut3, family='ipv6', ip_address=tg12_ip6[2], type='B',
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
        res_v4_flag += [ip.verify_ip_route(dut4, ip_address=tg31_ip[2], nexthop=po4_ip_d1, type='B',interface='Vlan' + str(access_vlan))]
        res_v4_flag += [ip.verify_ip_route(dut4, ip_address=tg32_ip[2], nexthop=po5_ip_d1, type='B', interface='Vlan'+str(trunk_base_vlan))]
        res_v4_flag += [ip.verify_ip_route(dut4, ip_address=tg21_ip[2], nexthop=po5_ip_d2, type='B', interface='Vlan'+str(trunk_base_vlan))]
        if False in res_v4_flag:
            print_log("IPv4 Routes verification failed in Dut:{}".format(dut4), "ERROR")
            ver_flag = False
        else:
            print_log("IPv4 Routes verification passed in Dut:{}".format(dut4), "MED")

        res_v6_flag = []
        res_v6_flag += [ip.verify_ip_route(dut4, family='ipv6', ip_address=tg31_ip6[2], type='B',
                                           interface='Vlan'+str(access_vlan))]
        res_v6_flag += [ip.verify_ip_route(dut4, family='ipv6', ip_address=tg32_ip6[2], type='B',
                                           interface='Vlan'+str(trunk_base_vlan))]
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
        arp_res += [arp.verify_arp(dut2, po6_ip_d3, interface="PortChannel6")]
        arp_res += [arp.verify_arp(dut2, po4_ip_d4, interface="PortChannel4", vlan=access_vlan)]
        arp_res += [arp.verify_arp(dut2, po5_ip_d4, interface="PortChannel5", vlan=trunk_base_vlan)]
        arp_res += [arp.verify_arp(dut2, peer1_ip, interface="PortChannel1", vlan=mclag_vlan)]
        if False in arp_res:
            print_log("ARP verification failed in Dut:{}".format(dut2), "MED")
            ver_flag = False
        else:
            print_log("ARP verification passed in Dut:{}".format(dut2), "MED")

        nd_res = []
        nd_res += [arp.verify_ndp(dut2, po6_ip6_d3, interface="PortChannel6")]
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
        nd_res += [arp.verify_ndp(dut3, po6_ip6_d2, interface="PortChannel6")]
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
    ospf_fail = 0
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

    ### Verify OSPF neighborship
    if utils.retry_api(verify_ospf,retry_count=3,delay=3):
        print_log("OSPF neighborship verification PASSED", "HIGH")
    else:
        print_log("OSPF neighborship verification FAILED", "HIGH")
        ospf_fail += 1
        final_result = False

    ### Verify Routes
    if utils.retry_api(verify_routes,retry_count=3,delay=3):
        print_log("Route Table verification PASSED", "HIGH")
    else:
        print_log("Route Table verification FAILED", "HIGH")
        route_fail += 1
        final_result = False

    ### Verify BGP neighborship
    if utils.retry_api(verify_arp_nd,retry_count=3,delay=3):
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
        if ospf_fail > 0:
            fail_msg += 'OSPF neighborship Failed:'
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
    co_utils.exec_all(dbg_exec,[[po.get_portchannel_list, dut] for dut in dut_list])
    co_utils.exec_foreach(dbg_exec, data.mclag_peers, mclag.verify_domain, domain_id=mclag_domain)
    for po_name in data.mclag_interfaces:
        co_utils.exec_foreach(dbg_exec, data.mclag_peers, mclag.verify_interfaces, domain_id=mclag_domain, mclag_intf=po_name)
        co_utils.exec_foreach(dbg_exec, data.mclag_peers, po.verify_lacp_fallback, port_channel_name=po_name)


def debug_traffic_fail():
    print_log("Dumping Debug data", 'HIGH')
    co_utils.exec_all(dbg_exec, [[po.get_portchannel_list, dut] for dut in dut_list])
    ### Display IP interfaces
    co_utils.exec_all(pll_exec, [[ip.get_interface_ip_address, dut] for dut in dut_list])
    ### Display IPv6 interfaces
    co_utils.exec_all(pll_exec, [[ip.get_interface_ip_address, dut, None, 'ipv6'] for dut in dut_list])
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

def verify_tx_rx_rate(stream_list,tx_rx_ratio=1,comp_type='packet_rate'):
    ver_flag = True
    if type(tx_rx_ratio) is int:
        tx_rx_ratio = [tx_rx_ratio]* len(stream_list)
    elif type(tx_rx_ratio) is list:
        if len(stream_list) != len(tx_rx_ratio):
            print_log('Need both stream list & tx_rx_ratio list to be of same length','ERROR')
            st.report_fail("operation_failed")
    traffic_data = {}
    i = 0
    for stream,tx_rx in zip(stream_list,tx_rx_ratio):
        tg_src_port = data.stream_port[stream]['src']
        tg_dst_port = data.stream_port[stream]['dst']
        i += 1
        traffic_data.update({
            str(i): {
                'tx_ports': [tg_src_port],
                'tx_obj': [tg_h],
                'exp_ratio': [tx_rx],
                'rx_ports': [tg_dst_port],
                'rx_obj': [tg_h],
                'stream_list': [[stream]],
            }
        })

    # verify traffic mode stream level
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='streamblock', comp_type=comp_type, tolerance_factor=2)
    if aggrResult:
        print_log(
            'Tx-Rx Rate verification PASSED ','MED')
    else:
        ver_flag = False
        print_log(
            'Tx-Rx Rate verification FAILED ','ERROR')

    return ver_flag


def measure_convergence_time(src_stream_id,traffic_rate_pps,tg_mode='aggregate'):
    print_log("Measure traffic convergence time", 'MED')
    tg_src_port = data.stream_port[src_stream_id]['src']
    tg_dest_port = data.stream_port[src_stream_id]['dst']

    tg_src_ph = tg_h.get_port_handle(tg_src_port)
    tg_dest_ph = tg_h.get_port_handle(tg_dest_port)
    if tg_mode == 'aggregate':
        comp_type = 'packet_count'
        traffic_stats_p1 = tg_h.tg_traffic_stats(port_handle=tg_src_ph, mode=tg_mode)
        traffic_stats_p2 = tg_h.tg_traffic_stats(port_handle=tg_dest_ph, mode=tg_mode)
        tx_counter_name = tgapi.get_counter_name(tg_mode, tg_h.tg_type, comp_type, 'tx')
        rx_counter_name = tgapi.get_counter_name(tg_mode, tg_h.tg_type, comp_type, 'rx')
        tx_pkt_count = int(traffic_stats_p1[tg_src_ph][tg_mode]['tx'][tx_counter_name])
        rx_pkt_count = int(traffic_stats_p2[tg_dest_ph][tg_mode]['rx'][rx_counter_name])
    elif tg_mode == 'streamblock':
        ### DISCLAIMER:- Below code Not verified. Using tg_mode=aggregate for now.
        comp_type = 'packet_count'
        stream_mode = 'streams' if tg_h.tg_type == 'stc' else 'traffic_item'
        ##-stream_index = 'stream' if tg_h.tg_type == 'stc' else 'traffic_item'
        ##-stc--int(rx_stats[tx_ph]['stream'][strelem]['tx'][tx_counter_name])
        ##-ixia--float(rx_stats['traffic_item'][strelem]['tx'][tx_counter_name])
        traffic_stats_p1 = tg_h.tg_traffic_stats(port_handle=tg_src_ph, mode=stream_mode, streams=src_stream_id)
        traffic_stats_p2 = tg_h.tg_traffic_stats(port_handle=tg_dest_ph, mode=stream_mode, streams=src_stream_id)
        tx_counter_name = tgapi.get_counter_name(tg_mode, tg_h.tg_type, comp_type, 'tx')
        rx_counter_name = tgapi.get_counter_name(tg_mode, tg_h.tg_type, comp_type, 'rx')
        if tg_h.tg_type == 'stc':
            tx_pkt_count = int(traffic_stats_p1[tg_src_ph]['stream'][src_stream_id]['tx'][tx_counter_name])
            # rx_pkt_count = int(traffic_stats_p2[tg_dest_ph]['stream'][src_stream_id]['rx'][rx_counter_name]) ---tg_dest_ph key error
            tx_pkt_count = int(traffic_stats_p2[tg_src_ph]['stream'][src_stream_id]['tx'][tx_counter_name])
            rx_pkt_count = int(traffic_stats_p2[tg_src_ph]['stream'][src_stream_id]['rx'][rx_counter_name])
            '''
            Tx:
                rx_stats = rx_obj.tg_traffic_stats(port_handle=rx_ph,mode='streams',streams=strelem)
                exp_val = int(rx_stats[tx_ph]['stream'][strelem]['tx'][tx_counter_name])
                    
            Rx:
                real_rx_val = int(rx_stats[tx_ph]['stream'][strelem]['rx'][rx_counter_name]
            
            '''
        else:
            tx_pkt_count = int(traffic_stats_p1['traffic_item'][src_stream_id]['tx'][tx_counter_name])
            rx_pkt_count = int(traffic_stats_p2['traffic_item'][src_stream_id]['rx'][rx_counter_name])
            '''
            Tx:
                rx_stats = rx_obj.tg_traffic_stats(port_handle=rx_ph,mode='traffic_item')
                exp_val = float(rx_stats['traffic_item'][strelem]['tx'][tx_counter_name])
            Rx:
                real_rx_val = float(rx_stats['traffic_item'][strelem]['rx'][rx_counter_name])
                '''

    # convergence =  total_tx-total_rx / traffic_rate
    #pkt_loss = abs(tx_pkt_count - rx_pkt_count)
    pkt_loss = tx_pkt_count - rx_pkt_count
    convergence_time = pkt_loss / int(traffic_rate_pps)
    print_log("PACKET LOSS={} => Traffic Rate = {}, Tx={}, Rx={}\n Stream Data: {}.".format(pkt_loss,traffic_rate_pps,
                                                                            tx_pkt_count, rx_pkt_count, data.stream_details[src_stream_id]))

    print_log("CONVERGENCE TIME: {} seconds.".format(convergence_time), "MED")

    return convergence_time


def verify_l3traffic_convergence(stream_list,traffic_rate_pps,trigger_string,trigger_dut,threshold=3):
    '''
    :param src_stream_list: can be a list of stream_ids but has to be on same tgen port
    :param dest_stream_list: destination stream_ids corresponding to src_stream_handle
    :param traffic_rate_pps: traffic sending rate in paket per seconds
    :param trigger_string: predefined string based on which trigger need to be defined/done in this procedure
    :param threshold: convergence time threshold
    :param clear_flag:
    :return:
    '''
    stream_list = [stream_list] if type(stream_list) is str else stream_list

    ### Create list of port_handles in use & clear stats
    port_handles = []
    for stream in stream_list:
        tg_src_port = data.stream_port[stream]['src']
        tg_dst_port = data.stream_port[stream]['dst']
        port_handles.append(tg_h.get_port_handle(tg_src_port))
        port_handles.append(tg_h.get_port_handle(tg_dst_port))

    tg_h.tg_traffic_control(action="clear_stats", port_handle=port_handles)
    tg_h.tg_traffic_control(action='run', handle=stream_list)

    #Verify traffic forwarding fine before trigger
    if utils.retry_api(verify_tx_rx_rate, stream_list, retry_count=3, delay=2):
        print_log("PASS: Traffic Forwarding is fine before convergence trigger:{}".format(trigger_string), 'MED')
    else:
        print_log("FAIL: Traffic Forwarding fails before convergence trigger:{}".format(trigger_string), 'ERROR')
        debug_traffic_fail()
        st.report_fail("test_case_failure_message", "Traffic Forwarding fails before convergence trigger")

    tg_h.tg_traffic_control(action='stop', handle=stream_list)
    tg_h.tg_traffic_control(action="clear_stats", port_handle=port_handles)
    st.wait(2)
    tg_h.tg_traffic_control(action='run', handle=stream_list)

    if trigger_string == 'config_reload':
        print_log("TC Summary :==> Sub-Test:Config Reload MCLAG peer to measure convergence", "MED")
        co_utils.exec_foreach(True, [trigger_dut], boot.config_reload)
        #st.wait(10)
    elif trigger_string == 'cold_reboot':
        print_log("TC Summary :==> Sub-Test:Reboot MCLAG peer to measure convergence", "MED")
        co_utils.exec_foreach(True, [trigger_dut], st.reboot)
        # st.wait(10)
    elif trigger_string == 'warm_reboot':
        print_log("TC Summary :==> Sub-Test:Warm Reboot MCLAG peer to measure convergence", "MED")
        co_utils.exec_foreach(True, [trigger_dut], boot.config_warm_restart, oper="enable", tasks=["system"])
        co_utils.exec_foreach(True, [trigger_dut], st.reboot,'warm')
    elif trigger_string == 'fast_reboot':
        print_log("TC Summary :==> Sub-Test:Fast Reboot MCLAG peer to measure convergence", "MED")
        co_utils.exec_foreach(True, [trigger_dut], st.reboot, 'fast')
        # st.wait(10)
    #verify_tx_rx_rate()
    if utils.retry_api(verify_tx_rx_rate, stream_list, retry_count=5, delay=5):
        print_log("PASS: Traffic has converged after trigger:{}".format(trigger_string),'MED')
    else:
        print_log("FAIL: Traffic failed to converge after trigger:{}".format(trigger_string), 'ERROR')
        debug_traffic_fail()
        #collect_techsupport()
        st.report_fail("test_case_failure_message", "Traffic Convergence failed after trigger:{}".format(trigger_string))


    #print_log("Wait for 5 sec for stablization check")
    st.wait(10,'Wait for traffic stablization after {} trigger'.format(trigger_string))
    tg_h.tg_traffic_control(action='stop', handle=stream_list)

    for stream in stream_list:
        print_log("Measure Traffic convergence time for {}".format(data.stream_details[stream]),'HIGH')
        convergence_time = measure_convergence_time(stream,traffic_rate_pps)
        print_log(
        "Traffic Convergence time in Maintenance mode with trigger:{} is {} seconds.\n {}".format(trigger_string,
                                                                                                  convergence_time,
                                                                                                  data.stream_details[stream]), 'MED')
        if convergence_time > threshold:
            print_log(
                "Traffic Draining in Maintenance mode FAILED Got:{}sec expected:<{}sec".format(convergence_time,
                                                                                               threshold), 'HIGH')
            st.report_fail("test_case_failure_message","Traffic Convergence time failed, Got:{}sec expected:<{}sec".format(convergence_time,
                                                                                               threshold))
        else:
            print_log(
                "Traffic Draining in Maintenance mode PASSED Got:{}sec expected:<{}sec".format(convergence_time,
                                                                                               threshold), 'HIGH')

@pytest.fixture(scope="function")
def revert_d1_gshut():
    yield
    config_graceful_shut(dut1,config='no')


@pytest.fixture(scope="function")
def revert_d2_gshut():
    yield
    config_graceful_shut(dut2,config='no')
    
    
def test_mclag_gshut_config_reload(revert_d1_gshut):
    global final_result, traffic_forward_fail, route_fail, arp_count_fail, nd_count_fail, po_fail
    ##PO gshut functionality
    tc1_result = True
    tc1_msg = ''

    tc_list = ['FtRtMclagPOMMSaveReload' ]
    print_log(
        "START of TC:test_mclag_gshut_config_reload ==>Sub-Test:Verify traffic draining with config reload:<{}>".format(
            tc_list),
        "HIGH")

    print_log("TC Summary :==> Sub-Test:Enable OSPF,BGP,PO gshut and verify traffic draining.", "MED")
    config_graceful_shut(dut1)

    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['down','up']):
            loop_result = False

    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2','PortChannel3']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down']*len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode FAILED",'ERROR')
        tc1_msg += "PO state in Maintenance Mode Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode PASSED", 'MED')

    st.wait(flap_wait)
    stream_list = [data.stream_handles['v4_stream_31_41'], data.stream_handles['v4_stream_41_31'],
                   data.stream_handles['v6_stream_32_42'], data.stream_handles['v6_stream_42_32']]
    verify_l3traffic_convergence(stream_list, traffic_rate_pps=tgen_rate_pps, trigger_string='config_reload',
                                                trigger_dut=dut1, threshold=3)
    run_traffic()
    ### Verify trigger node is still in Maintenance mode
    ### Verify traffic counters
    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['down', 'up']):
            loop_result = False

    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2', 'PortChannel3']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down'] * len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode after config reload FAILED", 'ERROR')
        tc1_msg += "PO state in Maintenance Mode after config reload Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode after config reload PASSED", 'MED')

    ### Unconfigure and verify traffic load balanced
    config_graceful_shut(dut1,config='no')

    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        print_log("Traffic Forwarding after GSHUT disable FAILED", "HIGH")
        tc1_msg += "Traffic Forwarding Failed after gshut disable:"
        tc1_result = False
        debug_traffic_fail()
        collect_techsupport()
    else:
        print_log("Traffic Forwarding after GSHUT disable PASSED", "HIGH")

    run_traffic(action='STOP')
    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMSaveReload', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMMSaveReload", "test_case_failure_message",
                          "Traffic Draining with Config Reload=>{}".format(tc1_msg.strip(':')))

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 or route_fail > 0:
        final_result = False

    post_result_handler()


def test_mclag_gshut_cold_reboot(revert_d1_gshut):
    global final_result, traffic_forward_fail, route_fail, arp_count_fail, nd_count_fail, po_fail
    ##PO gshut functionality
    tc1_result = True
    tc1_msg = ''
    tc1_msg = ''

    tc_list = ['FtRtMclagPOMMColdReboot' ]
    print_log(
        "START of TC:test_mclag_gshut_cold_reboot ==>Sub-Test:Verify traffic draining with cold reboot:<{}>".format(
            tc_list),
        "HIGH")

    print_log("TC Summary :==> Sub-Test:Enable OSPF,BGP,PO gshut and verify traffic draining.", "MED")
    config_graceful_shut(dut1)

    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['down','up']):
            loop_result = False

    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2', 'PortChannel3']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down'] * len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode FAILED",'ERROR')
        tc1_msg += "PO state in Maintenance Mode Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode PASSED", 'MED')
    st.wait(flap_wait)
    stream_list = [data.stream_handles['v4_stream_31_41'], data.stream_handles['v4_stream_41_31'],
                   data.stream_handles['v6_stream_32_42'], data.stream_handles['v6_stream_42_32']]
    verify_l3traffic_convergence(stream_list, traffic_rate_pps=tgen_rate_pps, trigger_string='cold_reboot',
                                                trigger_dut=dut1, threshold=3)
    run_traffic()
    ### Verify trigger node is still in Maintenance mode
    ### Verify traffic counters
    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['down', 'up']):
            loop_result = False
    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2', 'PortChannel3']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down'] * len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode after cold reboot FAILED", 'ERROR')
        tc1_msg += "PO state in Maintenance Mode after cold reboot Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode after cold reboot PASSED", 'MED')

    ### Unconfigure and verify traffic load balanced
    config_graceful_shut(dut1,config='no')

    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        print_log("Traffic Forwarding after GSHUT disable FAILED", "HIGH")
        tc1_msg += "Traffic Forwarding Failed after gshut disable:"
        tc1_result = False
        debug_traffic_fail()
        collect_techsupport()
    else:
        print_log("Traffic Forwarding after GSHUT disable PASSED", "HIGH")

    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMColdReboot', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMMColdReboot", "test_case_failure_message",
                          "Traffic Draining with cold reboot=>{}".format(tc1_msg.strip(':')))

    run_traffic(action='STOP')

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 or route_fail > 0:
        final_result = False

    post_result_handler()


def test_mclag_gshut_fast_reboot(revert_d2_gshut):
    global final_result, traffic_forward_fail, route_fail, arp_count_fail, nd_count_fail, po_fail
    ##PO gshut functionality
    tc1_result = True
    tc1_msg = ''
    tc1_msg = ''

    tc_list = ['FtRtMclagPOMMFastReboot' ]
    print_log(
        "START of TC:test_mclag_gshut_fast_reboot ==>Sub-Test:Verify traffic draining with fast reboot:<{}>".format(
            tc_list),
        "HIGH")

    print_log("TC Summary :==> Sub-Test:Enable OSPF,BGP,PO gshut and verify traffic draining.", "MED")
    config_graceful_shut(dut2)

    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['up','down']):
            loop_result = False

    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2', 'PortChannel6']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down'] * len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode FAILED",'ERROR')
        tc1_msg += "PO state in Maintenance Mode Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode PASSED", 'MED')
    st.wait(flap_wait)
    stream_list = [data.stream_handles['v4_stream_31_41'], data.stream_handles['v4_stream_41_31'],
                   data.stream_handles['v6_stream_32_42'], data.stream_handles['v6_stream_42_32']]
    verify_l3traffic_convergence(stream_list, traffic_rate_pps=tgen_rate_pps, trigger_string='fast_reboot',
                                                trigger_dut=dut2, threshold=3)
    run_traffic()
    ### Verify trigger node is still in Maintenance mode
    ### Verify traffic counters
    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['up', 'down']):
            loop_result = False

    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2', 'PortChannel6']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down'] * len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode after fast reboot FAILED", 'ERROR')
        tc1_msg += "PO state in Maintenance Mode after fast reboot Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode after fast reboot PASSED", 'MED')

    ### Unconfigure and verify traffic load balanced
    config_graceful_shut(dut2,config='no')

    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        print_log("Traffic Forwarding after GSHUT disable FAILED", "HIGH")
        tc1_msg += "Traffic Forwarding Failed after gshut disable:"
        tc1_result = False
        debug_traffic_fail()
        collect_techsupport()
    else:
        print_log("Traffic Forwarding after GSHUT disable PASSED", "HIGH")

    run_traffic(action='STOP')

    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMFastReboot', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMMFastReboot", "test_case_failure_message",
                          "Traffic Draining with Fast Reboot=>{}".format(tc1_msg.strip(':')))

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 or route_fail > 0:
        final_result = False

    post_result_handler()

def test_mclag_gshut_warm_reboot(revert_d1_gshut):
    global final_result, traffic_forward_fail, route_fail, arp_count_fail, nd_count_fail, po_fail
    ##PO gshut functionality
    tc1_result = True
    tc1_msg = ''

    tc_list = ['FtRtMclagPOMMWarmReboot' ]
    print_log(
        "START of TC:test_mclag_gshut_warm_reboot ==>Sub-Test:Verify traffic draining with warm reboot:<{}>".format(
            tc_list),
        "HIGH")

    print_log("TC Summary :==> Sub-Test:Enable OSPF,BGP,PO gshut and verify traffic draining.", "MED")
    config_graceful_shut(dut1)

    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name,data.mclag_peers,['down','up']):
            loop_result = False

    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2', 'PortChannel3']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down'] * len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode FAILED",'ERROR')
        tc1_msg += "PO state in Maintenance Mode Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode PASSED", 'MED')
    st.wait(flap_wait)
    stream_list = [data.stream_handles['v4_stream_31_41'], data.stream_handles['v4_stream_41_31'],
                   data.stream_handles['v6_stream_32_42'], data.stream_handles['v6_stream_42_32']]
    verify_l3traffic_convergence(stream_list, traffic_rate_pps=tgen_rate_pps, trigger_string='warm_reboot',
                                                trigger_dut=dut1, threshold=3)

    run_traffic()
    ### Verify trigger node is still in Maintenance mode
    ### Verify traffic counters
    ### Verify PO state
    loop_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['down', 'up']):
            loop_result = False

    for po_name in ['PortChannel1']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['up'] * len(po_data[po_name]['duts'])):
            loop_result = False
    for po_name in ['PortChannel2', 'PortChannel3']:
        if not verify_portchannel(po_name, po_data[po_name]['duts'], ['down'] * len(po_data[po_name]['duts'])):
            loop_result = False
    if not loop_result:
        po_fail += 1
        print_log("Verify PO states in Maintenance mode after warm reboot FAILED", 'ERROR')
        tc1_msg += "PO state in Maintenance Mode after warm reboot Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states in Maintenance mode after warm reboot PASSED", 'MED')

    ### Unconfigure and verify traffic load balanced
    config_graceful_shut(dut1,config='no')

    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        print_log("Traffic Forwarding after GSHUT disable FAILED", "HIGH")
        tc1_msg += "Traffic Forwarding Failed after gshut disable:"
        tc1_result = False
        debug_traffic_fail()
        collect_techsupport()
    else:
        print_log("Traffic Forwarding after GSHUT disable PASSED", "HIGH")

    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMWarmReboot', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMMWarmReboot", "test_case_failure_message",
                          "Traffic Draining with warm reboot=>{}".format(tc1_msg.strip(':')))

    run_traffic(action='STOP')

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 or route_fail > 0:
        final_result = False

    post_result_handler()

def config_link_track(dut):
    evpn.create_linktrack(dut, track_group_name="mclag_up_link_track", config='yes')
    evpn.update_linktrack_interface(dut, track_group_name="mclag_up_link_track", upinterface='PortChannel6', timeout=10, config='yes')

def unconfig_link_track(dut):
    evpn.update_linktrack_interface(dut, track_group_name="mclag_up_link_track", upinterface='PortChannel6', timeout=10, config='no')
    evpn.create_linktrack(dut, track_group_name="mclag_up_link_track", config='no')


def test_mclag_PO_MM_link_track():
    global final_result, traffic_forward_fail, route_fail, arp_count_fail, nd_count_fail, po_fail
    ##PO gshut functionality
    tc1_result = True
    tc1_msg = ''

    tc_list = ['FtRtMclagPOMMLinkTrack']
    print_log(
        "START of TC:test_mclag_PO_MM_link_track ==>Sub-Test:Verify link track functionality with PO gshut:<{}>".format(
            tc_list),
        "HIGH")
    run_traffic()
    print_log("TC Summary :==> Sub-Test:Enable link-track,  shut upstream interface and verify PO states.", "MED")
    config_link_track(dut2)
    intf.interface_shutdown(dut2, 'PortChannel6')
    ### Verify MCLAGs go down
    po_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['up', 'down']):
            po_result = False
    if not verify_po_members(['PortChannel1','PortChannel2'],'up'):
        po_result = False
    if not verify_po_members(['PortChannel6'], 'down'):
        po_result = False
    if not po_result:
        po_fail += 1
        print_log("Verify PO states with link-track enabled FAILED", 'ERROR')
        tc1_msg += "PO state with link-tracking Failed:"
        tc1_result = False
        evpn.verify_linktrack_summary(dut2, name='mclag_up_link_track')
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states with link-track enabled PASSED", 'MED')

    print_log("TC Summary :==> Sub-Test:Enable PO ghsut with link-track and verify PO states.", "MED")
    #po.config_portchannel_gshut(dut2)
    po.config_portchannel_gshut(dut2, exception_po_list='PortChannel1')

    po_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['up', 'down']):
            po_result = False
    if not verify_po_members(['PortChannel1'],'up'):
        po_result = False
    if not verify_po_members(['PortChannel2','PortChannel6'], 'down'):
        po_result = False
    if not po_result:
        po_fail += 1
        print_log("Verify PO states with link-track and PO gshut enabled FAILED", 'ERROR')
        tc1_msg += "PO state with link-track and PO gshut enabled Failed:"
        tc1_result = False
        evpn.verify_linktrack_summary(dut2, name='mclag_up_link_track')
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states with link-track and PO gshut enabled PASSED", 'MED')

    print_log("TC Summary :==> Sub-Test:Enable upstream interface and verify PO states still down.", "MED")
    intf.interface_noshutdown(dut2, 'PortChannel6')
    ##wait for link-track timer
    st.wait(10,"Wait For link track timer expiry")
    ### Verify PO state
    po_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['up', 'down']):
            po_result = False
    if not verify_po_members(['PortChannel1'], 'up'):
        po_result = False
    if not verify_po_members(['PortChannel2', 'PortChannel6'], 'down'):
        po_result = False
    if not po_result:
        po_fail += 1
        print_log("Verify PO states with upstream link no-shut and PO gshut enabled FAILED", 'ERROR')
        tc1_msg += "PO state with upstream link no-shut and PO gshut enabled Failed:"
        tc1_result = False
        evpn.verify_linktrack_summary(dut2, name='mclag_up_link_track')
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states with upstream link no-shut and PO gshut enabled PASSED", 'MED')

    print_log("TC Summary :==> Sub-Test:Disable link-track and verify PO states still down.", "MED")
    unconfig_link_track(dut2)
    ### Verify PO state
    po_result = True
    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['up', 'down']):
            po_result = False
    if not verify_po_members(['PortChannel1'], 'up'):
        po_result = False
    if not verify_po_members(['PortChannel2', 'PortChannel6'], 'down'):
        po_result = False
    if not po_result:
        po_fail += 1
        print_log("Verify PO states with link-track disabled and PO gshut enabled FAILED", 'ERROR')
        tc1_msg += "PO state with link-track disabled and PO gshut enabled Failed:"
        tc1_result = False
        evpn.verify_linktrack_summary(dut2, name='mclag_up_link_track')
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states with link-track disabled and PO gshut enabled PASSED", 'MED')

    print_log("TC Summary :==> Sub-Test:Disable PO gshut and verify all PO states UP.", "MED")
    ### Unconfigure and verify traffic load balanced
    po.config_portchannel_gshut(dut2, config='del')
    st.wait(wait_time)

    for po_name in data.mclag_interfaces:
        if not verify_portchannel(po_name, data.mclag_peers, ['up', 'up']):
            po_result = False

    if not verify_po_members(['PortChannel1', 'PortChannel2', 'PortChannel6'], 'up'):
        po_result = False
    if not po_result:
        po_fail += 1
        print_log("Verify PO states with link-track disabled and PO gshut disabled FAILED", 'ERROR')
        tc1_msg += "PO state with link-track disabled and PO gshut disabled Failed:"
        tc1_result = False
        debug_po_fail()
        collect_techsupport()
    else:
        print_log("Verify PO states with link-track disabled and PO gshut disabled PASSED", 'MED')


    if not utils.retry_api(verify_traffic,src_stream_list=data.base_src_streams,dest_stream_list=data.base_dst_streams,retry_count=3, delay=3):
        traffic_forward_fail += 1
        print_log("Traffic Forwarding after GSHUT disable FAILED", "HIGH")
        tc1_msg += "Traffic Forwarding Failed after gshut disable:"
        tc1_result = False
        debug_traffic_fail()
        collect_techsupport()
    else:
        print_log("Traffic Forwarding after GSHUT disable PASSED", "HIGH")

    if tc1_result:
        st.report_tc_pass('FtRtMclagPOMMLinkTrack', "test_case_passed")
    else:
        st.report_tc_fail("FtRtMclagPOMMLinkTrack", "test_case_failure_message",
                          "{}".format(tc1_msg.strip(':')))

    run_traffic(action='STOP')

    ### test_function result
    if po_fail > 0 or traffic_forward_fail > 0 or arp_count_fail > 0 or nd_count_fail > 0 or route_fail > 0:
        final_result = False

    post_result_handler()
