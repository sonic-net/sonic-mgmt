##########################################################################################
# Title: L2 MCLAG script
# Author: Sneha Ann Mathew <sneha.mathew@broadcom.com>
##########################################################################################

import pytest
import time

from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan
import apis.routing.ip as ip
import apis.switching.mac as mac
import apis.system.interface as intf
import apis.system.port as port
import apis.system.reboot as boot
import apis.switching.portchannel as po
import apis.switching.mclag as mclag
import apis.system.basic as basic
import apis.common.asic as asicapi
from mclag_vars import *

import utilities.common as utils
import utilities.parallel as pll

data = SpyTestDict()
itr_ctr_limit = 4
session_def_time = 30

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


def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if func(args,**kwargs):
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def retry_func(func,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 2)
    comp_flag = kwargs.get("comp_flag", True)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    if 'comp_flag' in kwargs: del kwargs['comp_flag']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if kwargs.keys() == []:
            if comp_flag:
                if func():
                    return True
            else:
                if not func():
                    return False
        else:
            if comp_flag:
                if func(**kwargs):
                    return True
            else:
                if not func(**kwargs):
                    return False
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    if comp_flag:
        return False
    else:
        return True


def retry_parallel(func,dict_list=[],dut_list=[],retry_count=5,delay=1):
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        result = pll.exec_parallel(True,dut_list,func,dict_list)
        if False not in result[0]:
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def get_tgen_handles():
    global tg_h
    global tgn_port
    global tgn_handle
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
    global dut_list
    global dut1
    global dut2
    global dut3
    global dut4
    global dut_list
    global mclag_peers
    global mclag_interfaces
    global dut_tgn_port
    global stream_data
    global total_vlans
    global mclag_data
    global mclag_intf_data
    global mac_expect_list
    global vars

    ### Verify Minimum topology requirement is met
    vars = st.ensure_min_topology("D1D2:4", "D1D3:4", "D2D3:4", "D1D4:4", "D2D4:4", "D1T1:2", "D2T1:2", "D3T1:1", "D4T1:1")

    print_log("Start Test with topology D1D2:4,D1D3:4,D2D3:4,D1D4:4,D2D4:4,D1T1:2,D2T1:2,D3T1:1,D4T1:1",'HIGH')

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
        \tstream_id: will be unique for one set of bidirection streams as explained below\n\
        \t\tAB for traffic from D1 to D2 and D2 to D1\n\
        \t\tAC for traffic from D1 to D3 and D3 to D1\n\
        \t\tBC for traffic from D2 to D3 and D2 to D3\n\
        \t\tBD for traffic from D2 to D4 and D2 to D4\n\
        \t\tCD for traffic from D3 to D4 and D4 to D3\n\
        In addition, each test case will have trigger configs/unconfigs and corresponding streams used",'HIGH')

    ### Initialize DUT variables and ports
    #globals()['dut_list'] = st.get_dut_names()
    dut_list = vars.dut_list
    print_log("st.get_dut_names:{}".format(st.get_dut_names()))
    print_log("vars.dut_list:{}".format(vars.dut_list))
    dut1 = dut_list[0]
    dut2 = dut_list[1]
    dut3 = dut_list[2]
    dut4 = dut_list[3]
    dut_list = [dut1, dut2, dut3, dut4]
    print_log("mclag dut_list:{}".format(dut_list))
    mclag_peers = [dut1, dut2]
    mclag_interfaces = ['PortChannel3','PortChannel4','PortChannel5']
    ### Initialize TGEN connected DUT ports
    dut_tgn_port = {}
    for dut in dut_list:
        # first tgen port
        dut_tgn_port.update({(dut,1): st.get_tg_links(dut)[0][0]})
        # second tgen port
        dut_tgn_port.update({(dut,2): st.get_tg_links(dut)[1][0]})

    ### Initialize TGEN side ports and handles
    get_tgen_handles()
    stream_data = {}

    ### Setting expect values
    total_vlans = [2+trunk_vlan_count,2+trunk_vlan_count,1+trunk_vlan_count,1+trunk_vlan_count]

    mclag_data = {}
    mclag_data.update({
        dut1: {
            'domain_id': mclag_domain,
            'local_ip': peer1_ip,
            'peer_ip': peer2_ip,
            'session_status': 'OK',
            'peer_link_inf': 'PortChannel2',
            'node_role': 'Active',
            'mclag_intfs': len(mclag_interfaces),
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
            'mclag_intfs': len(mclag_interfaces),
            'keep_alive': 1,
            'session_timeout': session_def_time
        }
    })

    mclag_intf_data = {}
    mclag_intf_data.update({
        dut1: {
            'domain_id': mclag_domain,
            'PortChannel3': {
                'local_state':'Up',
                'remote_state':'Up',
                'isolate_with_peer':'Yes',
                'traffic_disable':'No'
            },
            'PortChannel4': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'isolate_with_peer': 'Yes',
                'traffic_disable': 'No'
            },
            'PortChannel5': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'isolate_with_peer': 'Yes',
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
                'isolate_with_peer': 'Yes',
                'traffic_disable': 'No'
            },
            'PortChannel4': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'isolate_with_peer': 'Yes',
                'traffic_disable': 'No'
            },
            'PortChannel5': {
                'local_state': 'Up',
                'remote_state': 'Up',
                'isolate_with_peer': 'Yes',
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
    mac_expect_list = [2 * base_strm_cnt[i] * no_of_macs + flood_strm_cnt[i] * no_of_macs + system_macs[i]
                                    for i in range(len(dut_list))]

def validate_topology():
    # Enable all links in the topology and verify links up
    dut_port_dict = {}
    for dut in dut_list:
        port_list = st.get_dut_links_local(dut, peer=None, index=None)
        dut_port_dict[dut] = port_list
    #Usage: exec_all(use_threads, list_of_funcs)
    [result, exceptions] = utils.exec_all(True, [[intf.interface_operation, dut, dut_port_dict[dut], 'startup',False]
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
    api_list.append([mclag_traffic_config])
    api_list.append([mclag_module_config])
    utils.exec_all(True, api_list, True)
    mclag_basic_validations()
    yield
    mclag_module_unconfig()
    #api_list = []
    #api_list.append([mclag_traffic_unconfig])
    #api_list.append([mclag_module_unconfig])
    #utils.exec_all(True, api_list, True)


def configure_portchannel(po_data):
    '''
    Sample po_data structure
    po_data['PortChannel3'] = {'duts': [dut1, dut2, dut3],
                                 'po_members': {dut1: [vars.D1D3P1, vars.D1D3P2],
                                                dut2: [vars.D2D3P1, vars.D2D3P2],
                                                dut3: [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2]}}
    '''
    for po_id in po_data.keys():
        utils.exec_all(True, [[po.create_portchannel, dut, po_id] for dut in po_data[po_id]['duts']])
        utils.exec_all(True, [[po.add_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in po_data[po_id]['duts']])


def unconfigure_portchannel(po_data):
    '''
    Sample po_data structure
    po_data['PortChannel3'] = {'duts': [dut1, dut2, dut3],
                                 'po_members': {dut1: [vars.D1D3P1, vars.D1D3P2],
                                                dut2: [vars.D2D3P1, vars.D2D3P2],
                                                dut3: [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2]}}
    '''
    for po_id in po_data.keys():
        utils.exec_all(True, [[po.delete_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in po_data[po_id]['duts']])
        utils.exec_all(True, [[po.delete_portchannel, dut, po_id] for dut in po_data[po_id]['duts']])


def mclag_config_verify():
    mclag_module_config()
    mclag_basic_validations()

def mclag_module_config():
    global po_data
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

    po_data = {}
    po_data.update({'PortChannel1': {'duts' : mclag_peers ,
                                 'po_members' : { dut1:[vars.D1D2P1,vars.D1D2P2] ,
                                                  dut2:[vars.D2D1P1,vars.D2D1P2]}}})
    po_data.update({'PortChannel2': {'duts': mclag_peers,
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

    ### Create access vlan on all duts
    utils.exec_all(True, [[vlan.create_vlan, dut, access_vlan] for dut in dut_list ])
    #Configure access vlan on first TGEN ports of Mclag Peers as untagged
    utils.exec_all(True, [[vlan.add_vlan_member, dut, access_vlan, dut_tgn_port[(dut,1)] ] for dut in mclag_peers ])
    #Configure access vlan on first TGEN ports of Mclag clients as tagged
    utils.exec_all(True, [[vlan.add_vlan_member, dut, access_vlan, dut_tgn_port[(dut,1)], True] for dut in [dut3,dut4] ])

    ### Create trunk VLANs on all DUTs using range command
    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    utils.exec_all(True,[[vlan.config_vlan_range, dut, trunk_vlan_range] for dut in dut_list])
    #Configure trunk vlans on second TGEN ports of Mclag peers
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, dut_tgn_port[(dut,2)] ] for dut in mclag_peers ])
    #Configure trunk vlans on first TGEN ports of Mclag clients
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, dut_tgn_port[(dut,1)]] for dut in
                          [dut3, dut4]])

    ### Configure vlans on all PortChannels
    utils.exec_all(True,
                   [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel2', True] for dut in mclag_peers])
    utils.exec_all(True,
                   [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel3', True] for dut in [dut1, dut2, dut3]])
    utils.exec_all(True,
                   [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel4'] for dut in [dut1, dut2, dut4]])

    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel2']
                          for dut in mclag_peers])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel3']
                          for dut in [dut1, dut2, dut3]])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel5']
                          for dut in [dut1, dut2, dut4]])

    ### Configure Mclag vlan for
    utils.exec_all(True, [[vlan.create_vlan, dut, mclag_vlan] for dut in mclag_peers])
    utils.exec_all(True,
                   [[vlan.add_vlan_member, dut, mclag_vlan, 'PortChannel1', True] for dut in mclag_peers])

    ### Configure IP on PO-1 for L3 reachability between peers
    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(mclag_vlan), peer1_ip, ip_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(mclag_vlan), peer2_ip, ip_mask])
    utils.exec_all(True, api_list)

    ### Configure Mclag domain and interfaces
    dict1 = {'domain_id':mclag_domain, 'local_ip': mclag_data[dut1]['local_ip'], 'peer_ip': mclag_data[dut1]['peer_ip'], 'peer_interface':mclag_data[dut1]['peer_link_inf']}
    dict2 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut2]['local_ip'], 'peer_ip': mclag_data[dut2]['peer_ip'], 'peer_interface': mclag_data[dut2]['peer_link_inf']}
    pll.exec_parallel(True, mclag_peers,mclag.config_domain, [dict1, dict2])

    utils.exec_all(True,[[mclag.config_interfaces, dut, mclag_domain, mclag_interfaces]
                         for dut in mclag_peers])
    #timer_dict = {'domain_id': mclag_domain, 'session_timeout': session_def_time}
    #pll.exec_parallel(True, mclag_peers, mclag.config_timers, [timer_dict, timer_dict])

def mclag_module_unconfig():
    print_log("Starting MCLAG Base UnConfigurations...", "HIGH")

    utils.exec_foreach(True, mclag_peers, mclag.config_interfaces,  mclag_domain, mclag_interfaces, config='del')

    ### UnConfigure Mclag domain and interfaces
    '''dict1 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut1]['local_ip'],
             'peer_ip': mclag_data[dut1]['peer_ip'], 'peer_interface': mclag_data[dut1]['peer_link_inf'], 'config':'del'}
    dict2 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut2]['local_ip'],
             'peer_ip': mclag_data[dut2]['peer_ip'], 'peer_interface': mclag_data[dut2]['peer_link_inf'], 'config':'del'}'''
    dict1 = {'domain_id': mclag_domain, 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'config': 'del'}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    ### UnConfigure IP on PO-1 for L3 reachability between peers
    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(mclag_vlan), peer1_ip, ip_mask])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(mclag_vlan), peer2_ip, ip_mask])
    utils.exec_all(True, api_list)

    ### UnConfigure Mclag vlan on PO-1
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, mclag_vlan, 'PortChannel1', True] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.delete_vlan, dut, mclag_vlan] for dut in mclag_peers])

    ### UnConfigure vlans on all PortChannels
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel2', True] for dut in mclag_peers])
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel3', True] for dut in [dut1, dut2, dut3]])
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel4'] for dut in [dut1, dut2, dut4]])

    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel2', 'del'] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel3', 'del'] for dut in [dut1, dut2, dut3]])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel5', 'del'] for dut in [dut1, dut2, dut4]])

    # UnConfigure access vlan on first TGEN ports of Mclag Peers as untagged
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, access_vlan, dut_tgn_port[(dut, 1)]] for dut in mclag_peers])
    # UnConfigure access vlan on first TGEN ports of Mclag clients as tagged
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, dut_tgn_port[(dut, 1)], True] for dut in [dut3, dut4]])
    ### Delete access vlan on all duts
    utils.exec_all(True, [[vlan.delete_vlan, dut, access_vlan] for dut in dut_list])

    # UnConfigure trunk vlans on second TGEN ports of Mclag peers
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, dut_tgn_port[(dut, 2)], 'del'] for dut in
                          mclag_peers])
    # UnConfigure trunk vlans on first TGEN ports of Mclag clients
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, dut_tgn_port[(dut, 1)], 'del'] for dut in
                          [dut3, dut4]])
    ### Delete trunk VLANs on all DUTs using range command
    utils.exec_all(True, [[vlan.config_vlan_range, dut, trunk_vlan_range, 'del'] for dut in dut_list])

    unconfigure_portchannel(po_data)
    ### Save cleaned up config
    utils.exec_all(True, [[boot.config_save, dut] for dut in dut_list])

def config_static_mac_streams():
    global static_src_streams
    global static_dst_streams
    global static_neg_streams
    print_log("config_static_mac_streams: Configure static MAC streams between D1<->D3 & D2<->D4",'HIGH')
    # Static MAC on untagged port:Traffic stream - Traffic in access_vlan between DUT1 &  DUT3
    vlan = access_vlan
    st_key = str(vlan) + ':E1'
    src_mac = '00:11:' + st_key + ':00:01'
    dst_mac = '00:31:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut1, 1)], tgn_handle[(dut3, 1)]]
    tgen_ports = [tgn_port[(dut1, 1)], tgn_port[(dut3, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': 1,
                           'vlan_mode': {'src': 'U', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}

    # Traffic stream - Traffic in access_vlan between DUT2 &  DUT4
    vlan = access_vlan
    st_key = str(vlan) + ':E2'
    src_mac = '00:21:' + st_key + ':00:01'
    dst_mac = '00:41:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut2, 1)], tgn_handle[(dut4, 1)]]
    tgen_ports = [tgn_port[(dut2, 1)], tgn_port[(dut4, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': 1,
                           'vlan_mode': {'src': 'U', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}

    # Traffic stream - Traffic in static_vlan between DUT1 &  DUT3
    static_vlan = 83
    vlan = static_vlan
    st_key = str(vlan) + ':E1'
    src_mac = '00:12:' + st_key + ':00:01'
    dst_mac = '00:31:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut1, 2)], tgn_handle[(dut3, 1)]]
    tgen_ports = [tgn_port[(dut1, 2)], tgn_port[(dut3, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': 1,
                           'vlan_mode': {'src': 'T', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}
    # Traffic stream - Traffic in static_vlan between DUT2 &  DUT4
    vlan = static_vlan
    st_key = str(vlan) + ':E2'
    src_mac = '00:22:' + st_key + ':00:01'
    dst_mac = '00:41:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut2, 2)], tgn_handle[(dut4, 1)]]
    tgen_ports = [tgn_port[(dut2, 2)], tgn_port[(dut4, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': 1,
                           'vlan_mode': {'src': 'T', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}

    static_src_streams = []
    static_dst_streams = []
    static_neg_streams = []
    #globals()['strm_port'] = {}
    for st_key in ['80:E1','80:E2','83:E1','83:E2']:
        stdata = stream_data[st_key]
        tg_ph_src = stdata['tg_port_handles'][0]
        tg_ph_dst = stdata['tg_port_handles'][1]
        tg_port_src = stdata['tg_ports'][0]
        tg_port_dst = stdata['tg_ports'][1]
        ### Creating source stream
        if stdata['vlan_mode']['src'] == 'T':
            stream1 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_src, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph_dst)
        elif stdata['vlan_mode']['src'] == 'U':
            stream1 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_src, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_dst)
        stream_data[st_key]['staticStrmXY'] = stream1['stream_id']
        static_src_streams.append(stream1['stream_id'])
        strm_port[stream1['stream_id']] = {'src': tg_port_src, 'dst': tg_port_dst}
        print_log(
            "Static MAC traffic stream= STREAM:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream1['stream_id'],
                                                                                               tg_port_src, tg_port_dst,
                                                                                               stdata['src_mac'],
                                                                                               stdata['dst_mac']),
            'MED')
        ### Creating destination stream
        if stdata['vlan_mode']['dst'] == 'T':
            stream2 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph_src)

        elif stdata['vlan_mode']['dst'] == 'U':
            stream2 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_src)
        stream_data[st_key]['staticStrmYX'] = stream2['stream_id']
        static_dst_streams.append(stream2['stream_id'])
        strm_port[stream2['stream_id']] = {'src': tg_port_dst, 'dst': tg_port_src}
        print_log(
            "Static MAC traffic stream= STREAM:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream2['stream_id'],
                                                                                               tg_port_dst, tg_port_src,
                                                                                               stdata['dst_mac'],
                                                                                               stdata['src_mac']),
            'MED')
    ### Create single direction negative static stream from tgn12 and tgn22 in access_vlan 80 to check mac move prohibted with static MAC on orphan ports
    print_log("config_static_mac_streams: Configure negative streams from  D1, D3, D2 & D4 which will drop when static MAC configured", 'HIGH')
    vlan = access_vlan
    st_key = str(vlan) + ':E1'
    src_mac = '00:11:' + st_key + ':00:01'
    dst_mac = '00:31:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut1, 2)], tgn_handle[(dut3, 1)]]
    tgen_ports = [tgn_port[(dut1, 2)], tgn_port[(dut3, 1)]]
    stream = tg_h.tg_traffic_config(mode='create', port_handle=tg_port_handles[0], rate_pps=tgen_rate_pps,
                                     mac_src=src_mac, mac_src_mode="increment",
                                     mac_src_count=1, transmit_mode="continuous",
                                     mac_src_step="00:00:00:00:00:01", mac_dst=dst_mac,
                                     mac_dst_mode="increment", duration=traffic_run_time,
                                     mac_dst_count=1, mac_dst_step="00:00:00:00:00:01",
                                     l2_encap='ethernet_ii_vlan',
                                     vlan_id=vlan, vlan_id_count=1, vlan="enable",
                                     vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_port_handles[1])
    stream_data[st_key]['negStrm'] = stream['stream_id']
    static_neg_streams.append(stream['stream_id'])
    strm_port[stream['stream_id']] = {'src': tgen_ports[0], 'dst': tgen_ports[1]}
    print_log(
        "Static MAC negative stream= STREAM:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream['stream_id'],
                                                                                            tgen_ports[0],
                                                                                            tgen_ports[1], src_mac,
                                                                                            dst_mac),
        'MED')
    vlan = access_vlan
    st_key = str(vlan) + ':E2'
    src_mac = '00:11:' + st_key + ':00:01'
    dst_mac = '00:41:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut2, 2)], tgn_handle[(dut4, 1)]]
    tgen_ports = [tgn_port[(dut2, 2)], tgn_port[(dut4, 1)]]
    stream = tg_h.tg_traffic_config(mode='create', port_handle=tg_port_handles[0], rate_pps=tgen_rate_pps,
                                    mac_src=src_mac, mac_src_mode="increment",
                                    mac_src_count=1, transmit_mode="continuous",
                                    mac_src_step="00:00:00:00:00:01", mac_dst=dst_mac,
                                    mac_dst_mode="increment", duration=traffic_run_time,
                                    mac_dst_count=1, mac_dst_step="00:00:00:00:00:01",
                                    l2_encap='ethernet_ii_vlan',
                                    vlan_id=vlan, vlan_id_count=1, vlan="enable",
                                    vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_port_handles[1])
    stream_data[st_key]['negStrm'] = stream['stream_id']
    static_neg_streams.append(stream['stream_id'])
    strm_port[stream['stream_id']] = {'src': tgen_ports[0], 'dst': tgen_ports[1]}
    print_log(
        "Static MAC negative stream= STREAM:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream['stream_id'], tgen_ports[0],
                                                                          tgen_ports[1],src_mac,dst_mac),
        'MED')
    ### Create single direction negative static stream from tgn31 and tgn41 in static_vlan 83 to check mac move prohibted with static MAC on Mclag interfaces
    vlan = static_vlan
    st_key = str(vlan) + ':E1'
    src_mac = '00:31:' + st_key + ':00:01'
    dst_mac = '00:12:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut4, 1)], tgn_handle[(dut1, 2)]]
    tgen_ports = [tgn_port[(dut4, 1)], tgn_port[(dut1, 2)]]
    stream = tg_h.tg_traffic_config(mode='create', port_handle=tg_port_handles[0], rate_pps=tgen_rate_pps,
                                    mac_src=src_mac, mac_src_mode="increment",
                                    mac_src_count=1, transmit_mode="continuous",
                                    mac_src_step="00:00:00:00:00:01", mac_dst=dst_mac,
                                    mac_dst_mode="increment", duration=traffic_run_time,
                                    mac_dst_count=1, mac_dst_step="00:00:00:00:00:01",
                                    l2_encap='ethernet_ii_vlan',
                                    vlan_id=vlan, vlan_id_count=1, vlan="enable",
                                    vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_port_handles[1])
    stream_data[st_key]['negStrm'] = stream['stream_id']
    static_neg_streams.append(stream['stream_id'])
    strm_port[stream['stream_id']] = {'src': tgen_ports[0], 'dst': tgen_ports[1]}
    print_log(
        "Static MAC negative stream= STREAM:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream['stream_id'],
                                                                                            tgen_ports[0],
                                                                                            tgen_ports[1], src_mac,
                                                                                            dst_mac),
        'MED')
    vlan = static_vlan
    st_key = str(vlan) + ':E2'
    src_mac = '00:41:' + st_key + ':00:01'
    dst_mac = '00:22:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut3, 1)], tgn_handle[(dut2, 2)]]
    tgen_ports = [tgn_port[(dut3, 1)], tgn_port[(dut2, 2)]]
    stream = tg_h.tg_traffic_config(mode='create', port_handle=tg_port_handles[0], rate_pps=tgen_rate_pps,
                                    mac_src=src_mac, mac_src_mode="increment",
                                    mac_src_count=1, transmit_mode="continuous",
                                    mac_src_step="00:00:00:00:00:01", mac_dst=dst_mac,
                                    mac_dst_mode="increment", duration=traffic_run_time,
                                    mac_dst_count=1, mac_dst_step="00:00:00:00:00:01",
                                    l2_encap='ethernet_ii_vlan',
                                    vlan_id=vlan, vlan_id_count=1, vlan="enable",
                                    vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_port_handles[1])
    stream_data[st_key]['negStrm'] = stream['stream_id']
    static_neg_streams.append(stream['stream_id'])
    strm_port[stream['stream_id']] = {'src': tgen_ports[0], 'dst': tgen_ports[1]}
    print_log(
        "Static MAC negative stream= STREAM:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream['stream_id'],
                                                                                            tgen_ports[0],
                                                                                            tgen_ports[1], src_mac,
                                                                                            dst_mac),
        'MED')

def config_BUM_streams():
    global bum_src_streams
    print_log("config_BUM_streams: Configure Unknown-unicast, Multicast and Broadcast traffic streams between D1<->D3 & D2<->D4",'HIGH')
    bum_vlan = 82
    vlan = bum_vlan
    bum_src_streams = []
    # Traffic stream - Traffic in bum_vlan between DUT1 &  DUT3
    st_key = str(vlan) + ':F1'
    src_mac = '00:12:' + st_key + ':00:01'
    dst_mac_list = ['00:31:82:00:00:31','01:00:5E:0F:00:31','FF:FF:FF:FF:FF:FF']
    tg_port_handles = [tgn_handle[(dut1, 2)], tgn_handle[(dut3, 1)]]
    tgen_ports = [tgn_port[(dut1, 2)], tgn_port[(dut3, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac_list, 'mac_count': 1,
                           'vlan_mode': {'src': 'T', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}

    # Traffic stream - Traffic in bum_vlan between DUT2 &  DUT4
    st_key = str(vlan) + ':F2'
    src_mac = '00:22:' + st_key + ':00:01'
    dst_mac_list = ['00:41:82:00:00:41', '01:00:5E:0F:00:41', 'FF:FF:FF:FF:FF:FF']
    tg_port_handles = [tgn_handle[(dut2, 2)], tgn_handle[(dut4, 1)]]
    tgen_ports = [tgn_port[(dut2, 2)], tgn_port[(dut4, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac_list, 'mac_count': 1,
                           'vlan_mode': {'src': 'T', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}

    # Traffic stream - Traffic in bum_vlan between DUT3 &  DUT1
    st_key = str(vlan) + ':F3'
    src_mac = '00:31:' + st_key + ':00:01'
    dst_mac_list = ['00:11:82:00:00:11', '01:00:5E:0F:00:11', 'FF:FF:FF:FF:FF:FF']
    tg_port_handles = [tgn_handle[(dut3, 1)], tgn_handle[(dut1, 2)]]
    tgen_ports = [tgn_port[(dut3, 1)], tgn_port[(dut1, 2)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac_list, 'mac_count': 1,
                           'vlan_mode': {'src': 'T', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}

    # Traffic stream - Traffic in bum_vlan between DUT4 &  DUT2
    st_key = str(vlan) + ':F4'
    src_mac = '00:41:' + st_key + ':00:01'
    dst_mac_list = ['00:22:82:00:00:22', '01:00:5E:0F:00:22', 'FF:FF:FF:FF:FF:FF']
    tg_port_handles = [tgn_handle[(dut4, 1)], tgn_handle[(dut2, 2)]]
    tgen_ports = [tgn_port[(dut4, 1)], tgn_port[(dut2, 2)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac_list, 'mac_count': 1,
                           'vlan_mode': {'src': 'T', 'dst': 'T'}, 'vlan': vlan, 'vlan_count': 1, \
                           'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports}

    for st_key in ['82:F1', '82:F2', '82:F3', '82:F4']:
        print_log("bum key:{}".format(st_key))
        stdata = stream_data[st_key]
        tg_ph_src = stdata['tg_port_handles'][0]
        tg_ph_dst = stdata['tg_port_handles'][1]
        tg_port_src = stdata['tg_ports'][0]
        tg_port_dst = stdata['tg_ports'][1]
        for dst_mac in stdata['dst_mac']:
            print_log("DA MAC:{}".format(dst_mac))
            stream = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_src, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=dst_mac,
                                             mac_dst_mode="increment",
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph_dst)
            if '01:00:5E:' in dst_mac:
                stream_data[st_key]['multicastStrm'] = stream['stream_id']
                print_log(
                    "Multicast traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream['stream_id'],
                                                                                          tg_port_src, tg_port_dst,
                                                                                          stdata['src_mac'],
                                                                                          dst_mac), 'MED')
            elif 'FF:FF:FF:' in dst_mac:
                stream_data[st_key]['broadcastStrm'] = stream['stream_id']
                print_log(
                    "Broadcast traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream['stream_id'],
                                                                                               tg_port_src, tg_port_dst,
                                                                                               stdata['src_mac'],
                                                                                               dst_mac), 'MED')
            else:
                stream_data[st_key]['unknownStrm'] = stream['stream_id']
                print_log(
                    "Unknown Unicast traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream['stream_id'],
                                                                                               tg_port_src, tg_port_dst,
                                                                                               stdata['src_mac'],
                                                                                               dst_mac), 'MED')
            bum_src_streams.append(stream['stream_id'])
            strm_port[stream['stream_id']] = {'src': tg_port_src, 'dst': tg_port_dst}


def mclag_traffic_config():
    global base_src_streams
    global base_dst_streams
    global mac_move_src_streams
    global mac_move_dst_streams
    global strm_port
    # reset statistics and delete if any existing streamblocks
    for dut in dut_list:
        tg_h.tg_traffic_control(action="stop", port_handle=tgn_handle[(dut, 1)])
        tg_h.tg_traffic_control(action="reset", port_handle=tgn_handle[(dut, 1)])
        if dut == dut1 or dut ==dut2:
            tg_h.tg_traffic_control(action="stop", port_handle=tgn_handle[(dut, 2)])
            tg_h.tg_traffic_control(action="reset", port_handle=tgn_handle[(dut, 2)])

    print_log("mclag_traffic_config: Configure base traffic streams between MCLAG peers and clients", 'HIGH')
    # Traffic stream - Traffic in access_vlan between DUT1 &  DUT2
    vlan = access_vlan
    ### st_key will be like 80:AB, 80:AC, 80:AD, 80:BC, ...80:CD, 81:AB,...81:CD
    st_key = str(vlan)+':AB'
    src_mac = '00:11:' + st_key + ':00:01'
    dst_mac = '00:21:' + st_key + ':00:01'
    tg_port_handles= [tgn_handle[(dut1, 1)], tgn_handle[(dut2, 1)]]
    tgen_ports = [tgn_port[(dut1, 1)], tgn_port[(dut2, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac,'mac_count': strm_mac_count, \
                           'vlan_mode': {'src':'U','dst':'U'}, 'vlan': vlan, 'vlan_count': 1,\
                                'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports }

    # Traffic stream - Traffic in access_vlan between DUT1 &  DUT3
    vlan = access_vlan
    st_key = str(vlan)+':AC'
    src_mac = '00:11:' + st_key + ':00:01'
    dst_mac = '00:31:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut1, 1)], tgn_handle[(dut3, 1)]]
    tgen_ports = [tgn_port[(dut1, 1)], tgn_port[(dut3, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': strm_mac_count,
                                'vlan_mode': {'src':'U','dst':'T'}, 'vlan': vlan, 'vlan_count': 1,\
                                    'rate_pps': tgen_rate_pps,'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports }

    # Traffic stream - Traffic in access_vlan between DUT1 &  DUT4
    vlan = access_vlan
    st_key = str(vlan) + ':AD'
    src_mac = '00:11:' + st_key + ':00:01'
    dst_mac = '00:41:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut1, 1)], tgn_handle[(dut4, 1)]]
    tgen_ports = [tgn_port[(dut1, 1)], tgn_port[(dut4, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': strm_mac_count,
                                'vlan_mode': {'src':'U','dst':'T'}, 'vlan': vlan, 'vlan_count': 1,\
                                    'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports }

    # Traffic stream - Traffic in access_vlan between DUT2 &  DUT3
    vlan = access_vlan
    st_key = str(vlan) + ':BC'
    src_mac = '00:21:' + st_key + ':00:01'
    dst_mac = '00:31:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut2, 1)], tgn_handle[(dut3, 1)]]
    tgen_ports = [tgn_port[(dut2, 1)], tgn_port[(dut3, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': strm_mac_count,
                                'vlan_mode': {'src':'U','dst':'T'}, 'vlan': vlan, 'vlan_count': 1,\
                                    'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports }

    # Traffic stream - Traffic in access_vlan between DUT2 &  DUT4
    vlan = access_vlan
    st_key = str(vlan) + ':BD'
    src_mac = '00:21:' + st_key + ':00:01'
    dst_mac = '00:41:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut2, 1)], tgn_handle[(dut4, 1)]]
    tgen_ports = [tgn_port[(dut2, 1)], tgn_port[(dut4, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': strm_mac_count,
                                'vlan_mode': {'src':'U','dst':'T'}, 'vlan': vlan, 'vlan_count': 1,\
                                    'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports }

    # Traffic stream - Traffic in access_vlan between DUT3 &  DUT4
    vlan = access_vlan
    st_key = str(vlan) + ':CD'
    src_mac = '00:31:' + st_key + ':00:01'
    dst_mac = '00:41:' + st_key + ':00:01'
    tg_port_handles = [tgn_handle[(dut3, 1)], tgn_handle[(dut4, 1)]]
    tgen_ports = [tgn_port[(dut3, 1)], tgn_port[(dut4, 1)]]
    stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': strm_mac_count,
                                'vlan_mode': {'src':'T','dst':'T'}, 'vlan': vlan, 'vlan_count': 1,\
                                    'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports }

    # Traffic stream - Traffic in trunk_vlan between DUT1 &  DUT2
    vlan = trunk_base_vlan
    for (src_n,src_c) in [(1,'A'),(2,'B'),(3,'C'),(4,'D')]:
        for (dst_n,dst_c) in [(1,'A'),(2,'B'),(3,'C'),(4,'D')]:
            if src_n >= dst_n:
                continue
            if (src_c,dst_c) == ('A','B'):
                src_port = 2
                dst_port = 2
            elif (src_c,dst_c) == ('C','D'):
                src_port = 1
                dst_port = 1
            else:
                src_port = 2
                dst_port = 1

            st_key = str(vlan) + ':' + src_c + dst_c
            src_mac = '00:'+ str(src_n) + str(src_port) + ':' + st_key + ':00:01'
            dst_mac = '00:'+ str(dst_n) + str(dst_port) + ':' + st_key + ':00:01'
            tg_port_handles = [tgn_handle[(dut_list[src_n-1], src_port)], tgn_handle[(dut_list[dst_n-1], dst_port)]]
            tgen_ports = [tgn_port[(dut_list[src_n-1], src_port)], tgn_port[(dut_list[dst_n-1], dst_port)]]
            stream_data[st_key] = {'src_mac': src_mac, 'dst_mac': dst_mac, 'mac_count': strm_mac_count,
                                        'vlan_mode': {'src':'T','dst':'T'}, 'vlan': vlan, 'vlan_count': 1,\
                                        'rate_pps': tgen_rate_pps, 'tg_port_handles': tg_port_handles, 'tg_ports': tgen_ports }

    base_src_streams = []
    base_dst_streams = []
    mac_move_src_streams = []
    mac_move_dst_streams = []
    strm_port = {}
    for st_key,stdata in stream_data.items():
        tg_ph_src = stdata['tg_port_handles'][0]
        tg_ph_dst = stdata['tg_port_handles'][1]
        tg_port_src = stdata['tg_ports'][0]
        tg_port_dst = stdata['tg_ports'][1]
        ### Creating source stream
        if stdata['vlan_mode']['src'] == 'T':
            stream1 = tg_h.tg_traffic_config(mode='create', port_handle= tg_ph_src,rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph_dst)
            stream3 = tg_h.tg_traffic_config(mode='create', port_handle= tg_ph_src,rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph_dst)
        elif stdata['vlan_mode']['src'] == 'U':
            stream1 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_src, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_dst)
            stream3 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_src, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_dst)
        stream_data[st_key]['streamXY'] = stream1['stream_id']
        base_src_streams.append(stream1['stream_id'])
        strm_port[stream1['stream_id']] = {'src': tg_port_src, 'dst':tg_port_dst}
        print_log(
            "Base traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream1['stream_id'],
                                    tg_port_src, tg_port_dst, stdata['src_mac'], stdata['dst_mac']), 'MED')
        #print_log("Base traffic stream= STREAM:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream1['stream_id'],tg_port_src,tg_port_dst),'MED')
        #stream_data[stream1['stream_id']] = {'src': tg_port_src, 'dst':tg_port_dst}
        stream_data[st_key]['macMoveXY'] = stream3['stream_id']
        mac_move_src_streams.append(stream3['stream_id'])
        strm_port[stream3['stream_id']] = {'src': tg_port_src, 'dst': tg_port_dst}
        print_log(
            "Mac Move traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream3['stream_id'],
                                                                                      tg_port_src, tg_port_dst,
                                                                                      stdata['dst_mac'],
                                                                                      stdata['src_mac']),
            'MED')
        ### Creating destination stream
        if stdata['vlan_mode']['dst'] == 'T':
            stream2 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph_src)
            stream4 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph_src)
        elif stdata['vlan_mode']['dst'] == 'U':
            stream2 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_src)
            stream4 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment", duration=traffic_run_time,
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_src)
        stream_data[st_key]['streamYX'] = stream2['stream_id']
        base_dst_streams.append(stream2['stream_id'])
        strm_port[stream2['stream_id']] = {'src': tg_port_dst, 'dst': tg_port_src}
        print_log(
            "Base traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream2['stream_id'],
                                                                                  tg_port_dst, tg_port_src,
                                                                                  stdata['dst_mac'], stdata['src_mac']),
            'MED')
        # stream_data[stream2['stream_id']] = {'src': tg_port_dst, 'dst':tg_port_src}
        stream_data[st_key]['macMoveYX'] = stream4['stream_id']
        mac_move_dst_streams.append(stream4['stream_id'])
        strm_port[stream4['stream_id']] = {'src': tg_port_dst, 'dst': tg_port_src}
        print_log(
            "Mac Move traffic stream=:{}, FROM:{} --- TO:{}, SRC:{}--->DST:{}".format(stream4['stream_id'],
                                                                                  tg_port_dst, tg_port_src,
                                                                                  stdata['src_mac'], stdata['dst_mac']),
            'MED')
    config_static_mac_streams()
    config_BUM_streams()

def mclag_traffic_unconfig():
    # reset statistics and delete if any existing streamblocks
    for dut in dut_list:
        tg_h.tg_traffic_control(action="stop", port_handle=tgn_handle[(dut, 1)])
        tg_h.tg_traffic_control(action="reset", port_handle=tgn_handle[(dut, 1)])
        if dut == dut1 or dut ==dut2:
            tg_h.tg_traffic_control(action="stop", port_handle=tgn_handle[(dut, 2)])
            tg_h.tg_traffic_control(action="reset", port_handle=tgn_handle[(dut, 2)])


def start_stop_traffic(src_stream_list='ALL', dest_stream_list='ALL',direction="both",duration=traffic_run_time,action_ctrl='both',clear_flag='YES'):
    '''
    :param duration: duration for which traffic needs to run
    :param src_stream_list: If source stream list=ALL start traffic using port handles else using this stream handle
    :param dest_stream_list: If source stream list=ALL start reverse traffic using port_handles else using this stream handle
                                Used only when direction is "both"
    :param direction:  Value can be single or both. Default is "both". When "single" only src_stream_list will be started
    :param duration: Duration for which traffic needs to be run when action_ctrl is both
    :param action_ctrl: specifies traffic actions to be done; can be <'START'|'STOP'|'both'>
    :return:
    '''
    if clear_flag == 'YES':
        ### Clear stats on all reserved TGEN ports
        tgn_handles = []
        for dut in dut_list:
            tgn_handles.append(tgn_handle[(dut, 1)])
            if dut == dut1 or dut == dut2:
                tgn_handles.append(tgn_handle[(dut, 2)])
        tg_h.tg_traffic_control(action="clear_stats", port_handle=tgn_handles)
        ### Clear counters on dut ports
        print_log("Clear Interface counters", 'MED')
        utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])
    if src_stream_list == 'ALL':
        src_stream_list = base_src_streams
    if dest_stream_list == 'ALL':
        dest_stream_list = base_dst_streams

    src_stream_list = [src_stream_list] if type(src_stream_list) is str else src_stream_list
    dest_stream_list = [dest_stream_list] if type(dest_stream_list) is str else dest_stream_list
    if direction == 'both':
        if len(src_stream_list) != len(dest_stream_list):
            ###Compare both source and dest stream_lists are of same length else fail
            print_log('Need both SRC and DEST stream list to be of same length if bi-directional traffic to be run','ERROR')
            st.report_fail("operation_failed")
    else:
        ### For single direction traffic verification destination stream_list not needed.
        dest_stream_list = ['ANY'] * len(src_stream_list)

    stream_list = src_stream_list
    if action_ctrl == 'START' or  action_ctrl == 'both':
        #tg_h.tg_traffic_control(action='run', handle=src_stream_list, duration=duration)
        tg_h.tg_traffic_control(action='run', handle=src_stream_list)
        ### Add sleep in ixia/stc to make sure SA macs from src_strm_list is flooded on all duts first.
        ### Needed to get better control on count of flood MACs on client nodes
        if data.tgen_type == 'ixia':
            st.wait(2)
        elif data.tgen_type == 'stc':
            st.wait(0)
        print_log("Check Interface counters output to Verify SA mac streams are flooded",'MED')
        utils.exec_all(True, [[port.get_interface_counters_all, dut] for dut in dut_list])
        print_log("Check MAC table to see flooding MACs are learned", 'MED')
        utils.exec_all(True, [[mac.get_mac, dut] for dut in dut_list])
        if direction == "both":
            stream_list = stream_list + dest_stream_list
            #tg_h.tg_traffic_control(action='run', handle=dest_stream_list, duration=duration)
            tg_h.tg_traffic_control(action='run', handle=dest_stream_list)

    if action_ctrl == 'both':
        st.wait(duration)

    if action_ctrl == 'STOP' or  action_ctrl == 'both':
        #tg_h.tg_traffic_control(action='stop', handle=src_stream_list)
        stream_list = src_stream_list
        if direction == "both":
            stream_list = stream_list + dest_stream_list
        tg_h.tg_traffic_control(action='stop', handle=stream_list)


def verify_traffic_path():
    '''
    traffic_rate[dut] = {'interface': 'PortChannel3', 'rate': 3*int(tgen_rate_pps)}
    :param interface_list:
    :param expect_rate_list:
    :return:
    '''
    utils.exec_all(True, [[port.get_interface_counters_all, dut] for dut in dut_list])


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
        ver_loop_limit = 5
        while ver_loop_ctr < ver_loop_limit:
            DUT_tx_value = port.get_interface_counters(dut, port_num, "tx_pps")
            print_log("port:{}, tx_rate:{}".format(port_num, DUT_tx_value), 'MED')
            if not DUT_tx_value:
                print_log('Expected port:{} not seen in output'.format(port_num), 'ERROR')
                return False
            for i in DUT_tx_value:
                print_log("port_num:{}, tx_value:{}, i:{}".format(port_num, DUT_tx_value, i), 'MED')
                p_txmt = i['tx_pps']
                if p_txmt == 'N/A' or p_txmt is None: return False
                p_txmt = p_txmt.replace(",", "")
                p_txmt = p_txmt.strip('/s')
                if int(float(p_txmt)) < expect_rate:
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
                st.wait(3,'Sleep for 3 sec for interface counters to update')
                ver_loop_ctr += 1
        if not ver_loop_flag:
            return False
    return True

def debug_traffic_fail():
    print_log("Dumping Debug data", 'HIGH')
    utils.exec_all(False, [[port.get_interface_counters_all, dut] for dut in dut_list])
    utils.exec_foreach(False, mclag_peers, mclag.verify_iccp_macs, domain_id=mclag_domain, return_type='NULL')
    utils.exec_all(False, [[mac.get_mac, dut] for dut in dut_list])
    utils.exec_all(False, [[vlan.show_vlan_brief, dut] for dut in dut_list])
    utils.exec_all(False, [[asicapi.dump_vlan, dut] for dut in dut_list])
    utils.exec_all(False, [[asicapi.dump_l2, dut] for dut in dut_list])
    utils.exec_all(False, [[asicapi.dump_ports_info, dut] for dut in dut_list])

def verify_traffic(src_stream_list='ALL', dest_stream_list='ALL', tx_rx_ratio=1, comp_type='packet_count', direction="both"):
    ver_flag = True
    if src_stream_list == 'ALL':
        src_stream_list = base_src_streams
    if dest_stream_list == 'ALL':
        dest_stream_list = base_dst_streams
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
            dest_stream_list = ['ANY' for i in src_stream_list]

    for src_stream_id, dest_stream_id, tx_rx in zip(src_stream_list, dest_stream_list, tx_rx_ratio):
        tg_src_port = strm_port[src_stream_id]['src']
        tg_dest_port = strm_port[src_stream_id]['dst']
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
        streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode='streamblock', comp_type=comp_type,
                                             delay_factor=0.2, tolerance_factor=4.5)
        if streamResult:
            print_log(
                'Traffic verification PASSED for mode streamblock {} <---> {}'.format(src_stream_id, dest_stream_id),
                'MED')
        else:
            ver_flag = False
            print_log(
                'Traffic verification FAILED for mode streamblock {} <---> {}'.format(src_stream_id, dest_stream_id),
                'ERROR')
    if not ver_flag:
        debug_traffic_fail()
    return ver_flag


def debug_mac_learn(dut):
    print_log("Dumping MAC internal tables for debugging", 'HIGH')
    asicapi.dump_l2(dut)
    ### Collect ICCP FDB table
    if dut in mclag_peers:
        mclag.verify_iccp_macs(dut, domain_id=mclag_domain, return_type='NULL')
    mclag.show_stateDB_macs(dut)
    mclag.show_appDB_macs(dut)
    mclag.show_asicDB_macs(dut)

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
    if not retry_parallel(check_mac_count, dict_list=expect_dict, dut_list=dut_list, retry_count=3, delay=2):
        print_log("MAC Count verification FAILED", "HIGH")
        ### Display MAC table
        utils.exec_all(False, [[show_verify_mac_table, dut, expected_mac, None, None, None, None, comp_flag] \
                              for dut, expected_mac in zip(dut_list, expect_mac_list)])
        utils.exec_all(False, [[debug_mac_learn, dut] for dut, expected_mac in zip(dut_list, expect_mac_list)])
        return False
    else:
        print_log("MAC Count verification PASSED", "HIGH")
        return True



def toggle_lag_ports(po_name_list,port_operation="disable",port_order="odd"):
    global po_reconfig_flag
    res_flag = True
    po_link_min_req =2
    for po_name in po_name_list:
        toggle_port_list = {}
        for dut in po_data[po_name]['duts']:
            member_ports = po_data[po_name]['po_members'][dut]
            if len(member_ports) < po_link_min_req:
                print_log("TC cannot be run as min required links-{} not present in LAG-{}".format(po_link_min_req, po_name), 'MED')
                fail_msg = 'Portchannel:{} in dut:{} min req links for TC not present'.format(po_name, dut)
                st.report_fail("test_case_failure_message", fail_msg)
            ### Get list of ports to be flapped.
            if port_order == 'even':
                toggle_port_list[dut] = member_ports[::2]
            elif port_order == 'odd':
                toggle_port_list[dut] = member_ports[1::2]

        if port_operation == "disable":
            [result, exceptions] = utils.exec_all(True, [[intf.interface_shutdown, dut, toggle_port_list[dut]] \
                                        for dut in po_data[po_name]['duts'] ])
        elif port_operation == "enable":
            [result, exceptions] = utils.exec_all(True, [[intf.interface_noshutdown, dut, toggle_port_list[dut]] \
                                                         for dut in po_data[po_name]['duts']])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log("LAG port flap failed for {}".format(po_name))
            res_flag = False
            po_reconfig_flag += 1
            fail_msg = 'Portchannel-{} member port {} Failed'.format(po_name, port_operation)
            st.report_fail("test_case_failure_message", fail_msg)
    return res_flag


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


def verify_po_state(po_name_list,state='up'):
    '''
    Verify whether PO state is 'up' or 'down'
    Doesn't verify member port states.
    :param po_name_list: list of keys to PO dictionary
    :param state: up or down
    :return:  True or False
    '''
    ver_flag = True
    for po_name in po_name_list:
        print_log("Verify {} state is {}".format(po_name, state), 'MED')
        [result, exceptions] = utils.exec_foreach(True, po_data[po_name]["duts"],po.verify_portchannel_state,portchannel=po_name, state=state)
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log('FAIL: Portchannel-{} is not {} in some of the duts:{}'.format(po_name, state, po_data[po_name]["duts"]), 'ERROR')
            ver_flag = False

    return ver_flag


def check_ping(src_dut,dest_ip_list):
    '''
    Verify ping to given list of IPs from src_dut
    :param src_dut: dut in which ping initiated
    :param dest_ip_list: list of IPs which need to be ping
    :return:
    '''
    dest_ip_list = [dest_ip_list] if type(dest_ip_list) is str else dest_ip_list
    ver_flag = True
    for ip_addr in dest_ip_list:
        result = ip.ping(src_dut, ip_addr)
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
             'peer_link_inf': mclag_data[dut1]['peer_link_inf'], 'mclag_intfs': mclag_data[dut1]['mclag_intfs'],\
             'session_status':mclag_data[dut1]['session_status'], 'node_role':mclag_data[dut1]['node_role'],\
             'keepalive_timer':mclag_data[dut1]['keep_alive'], 'session_timer':mclag_data[dut1]['session_timeout']}
    dict2 = {'domain_id': mclag_domain,'local_ip': mclag_data[dut2]['local_ip'],'peer_ip': mclag_data[dut2]['peer_ip'], \
             'peer_link_inf': mclag_data[dut2]['peer_link_inf'], 'mclag_intfs': mclag_data[dut2]['mclag_intfs'], \
             'session_status': mclag_data[dut2]['session_status'], 'node_role': mclag_data[dut2]['node_role'],\
             'keepalive_timer':mclag_data[dut1]['keep_alive'], 'session_timer':mclag_data[dut1]['session_timeout']}
    [result, exceptions] = pll.exec_parallel(True, mclag_peers, mclag.verify_domain, [dict1, dict2])

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

    for po in mclag_interfaces:
        print_log("Verify MCLAG Interface state of {}".format(po),'MED')

        dict1 = {'domain_id': mclag_domain, 'mclag_intf': po,\
                 'mclag_intf_local_state': mclag_intf_data[dut1][po]['local_state'], \
                 'mclag_intf_peer_state': mclag_intf_data[dut1][po]['remote_state'],\
                 'isolate_peer_link': mclag_intf_data[dut1][po]['isolate_with_peer'], \
                 'traffic_disable': mclag_intf_data[dut1][po]['traffic_disable']}
        dict2 = {'domain_id': mclag_domain, 'mclag_intf': po,
                 'mclag_intf_local_state': mclag_intf_data[dut2][po]['local_state'], \
                 'mclag_intf_peer_state': mclag_intf_data[dut2][po]['remote_state'],\
                 'isolate_peer_link': mclag_intf_data[dut2][po]['isolate_with_peer'], \
                 'traffic_disable': mclag_intf_data[dut2][po]['traffic_disable']}

        [result, exceptions] = pll.exec_parallel(True, mclag_peers, mclag.verify_interfaces, [dict1, dict2])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log('MCLAG Interface-{} state verification FAILED'.format(po), 'ERROR')
            ver_flag = False
    return ver_flag

def flap_all_mclag_interfaces():
    port_list = {}
    port_list[dut1] = 'PortChannel4'
    port_list[dut2] = ['PortChannel3','PortChannel5']
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in mclag_peers])
    st.wait(2)
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in mclag_peers])

def po_iteration_check(po_chk_list, state='up',iteration_limit=5):
    global  iterations
    po_up_flag = False
    itr_counter = 0
    #itr_ctr_limit = iteration_limit
    while (itr_counter < iteration_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        if verify_portchannel(po_chk_list, state=state):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            if itr_counter < iteration_limit:
                st.wait(5)
    iterations = itr_counter
    return po_up_flag

def mclag_basic_validations():
    '''
    1. Verify PO summary.
    2. Verify vlan count.
    3. Verify L3 reachability
    4. Verify Mclag State and Interfaces

    '''
    global iterations
    ### Verify all the LAGs configured in the topology is up
    final_result = True
    vlan_fail = 0
    po_fail = 0
    ping_fail = 0
    mclag_state_fail = 0
    mclag_intf_fail = 0

    print_log("Verify all the LAGs configured in the topology is up", 'MED')

    if not po_iteration_check(po_data.keys(), state='up', iteration_limit=itr_ctr_limit):
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    ### Verify vlans configured in all DUTs
    print_log("Verify the VLANS configured in all DUTs", 'MED')
    [result,exceptions] = utils.exec_all(True,[[verify_vlan_count,dut_list[i],total_vlans[i]] for i in range(len(dut_list))])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("VLAN Table verification FAILED", "HIGH")
        vlan_fail += 1
        final_result = False
    else:
        print_log("VLAN Table verification PASSED", "HIGH")

    ### Display IP interfaces
    utils.exec_all(True, [[ip.get_interface_ip_address, dut] for dut in mclag_peers])

    ### Display MAC entries in kernel
    utils.exec_foreach(True, mclag_peers, asicapi.dump_kernel_fdb, vlan_id=mclag_vlan)

    ### Verify L3 reachability is fine
    print_log("Verify L3 reachability is fine across Mclag peers", 'MED')
    if retry_func(check_ping,src_dut=dut1,dest_ip_list=peer2_ip):
        print_log("L3 reachabilty between Mclag Peers PASSED", "HIGH")
    else:
        print_log("L3 reachabilty between Mclag Peers FAILED", "HIGH")
        ping_fail += 1
        final_result = False
        utils.exec_foreach(False, mclag_peers, asicapi.dump_kernel_fdb)

    ### Verify MCLAG domain and attributes
    if retry_api(verify_mclag_state,mclag_data,retry_count=3,delay=3):
        print_log("MCLAG Domain State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG Interface states
    if retry_api(verify_mclag_intf_state,mclag_intf_data,retry_count=3,delay=3):
        print_log("MCLAG Interfaces State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

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
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))


def pre_result_handler():
    global final_result
    global mac_count_fail
    global clear_mac_fail
    global traffic_forward_fail
    global flooding_fail
    global bum_traffic_fail
    global mac_aging_fail
    global mclag_state_fail
    global mclag_intf_fail
    global po_fail
    global intf_fail
    print_log("FLAG reset", 'MED')
    final_result = True
    mac_count_fail = 0
    clear_mac_fail = 0
    traffic_forward_fail = 0
    flooding_fail = 0
    bum_traffic_fail = 0
    mac_aging_fail = 0
    mclag_state_fail = 0
    mclag_intf_fail = 0
    po_fail = 0
    intf_fail = 0


def post_result_handler():
    global final_result, clear_mac_fail, traffic_forward_fail, flooding_fail, mac_count_fail, bum_traffic_fail,\
            mac_aging_fail, mclag_state_fail, mclag_intf_fail, po_fail, intf_fail
    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg = ''
        if mac_count_fail > 0:
            fail_msg += 'MAC Verification Failed:'
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
        if mclag_state_fail > 0:
            fail_msg += 'MCLAG state Failed:'
        if mclag_intf_fail > 0:
            fail_msg += 'MCLAG Interface state Failed:'
        if po_fail > 0:
            fail_msg += 'PO Verification Failed:'
        if intf_fail > 0:
            fail_msg += 'Interface not up after reboot:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))

def clear_mac_verify(duts,mac_count_list=[1,1,0,0]):
    global clear_mac_fail, final_result

    utils.exec_all(True, [[mac.clear_mac, dut] for dut in duts])
    dict_list = []
    for i in range(len(mac_count_list)):
        dict_list += [{'expect_mac': mac_count_list[i]}]
    if not retry_parallel(check_mac_count, dict_list=dict_list, dut_list=duts, retry_count=3, delay=2):
        print_log("MAC on all Duts in Failed state")
        utils.exec_all(True, [[mac.get_mac, dut] for dut in dut_list])
        final_result = False
        clear_mac_fail += 1

def test_mclag_bringup():
    '''
        Verify MCLAG bring up with PortChannel Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagCli001', 'FtOpSoSwL2MclagFn002','FtOpSoSwL2MclagFn011','FtOpSoSwL2MclagPe006']
    ##- Verify all config and show CLIs of MCLAG
    tc_result_traffic = 0
    fail_msg_traffic = ''
    ##- Verify MAC learning on orphan ports, peer-link and mclag enabled interfaces
    tc_result_mac_learn = 0
    fail_msg_mac_learn = ''

    print_log("START of TC:test_mclag_bringup ==>Sub-Test:Verify MCLAG functionality with PO\n TCs:<{}>".format(tc_list), "HIGH")
    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)
    start_stop_traffic()
    if not verify_mac_table_count(dut_list,mac_expect_list):
        final_result = False
        mac_count_fail += 1
        fail_msg_mac_learn += "Mac Learning Failed:"
        tc_result_mac_learn += 1

    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1
        fail_msg_traffic += "Traffic Forwarding Failed:"
        tc_result_traffic += 1
    ### Report TC wise PASS/FAIL
    if tc_result_mac_learn > 0:
        st.report_tc_fail("FtOpSoSwL2MclagFn011", "test_case_failure_message", fail_msg_mac_learn.strip(':'))
    else:
        st.report_tc_pass('FtOpSoSwL2MclagFn011', "test_case_passed")
    if tc_result_traffic > 0:
        st.report_tc_fail("FtOpSoSwL2MclagPe006", "test_case_failure_message", fail_msg_traffic.strip(':'))
    else:
        st.report_tc_pass('FtOpSoSwL2MclagPe006', "test_case_passed")
    post_result_handler()


def verify_portchannel(po_name_list,state='up'):
    ver_flag = True
    ###Verify all member ports in each PO is UP
    for po_name in po_name_list:
        print_log("Verify member ports in {} is {}".format(po_name, state), 'MED')
        duts = po_data[po_name]["duts"]
        dut_po_members = po_data[po_name]["po_members"]
        ### Verify PO member port state
        [result, exceptions] = utils.exec_all(True,[[po.verify_portchannel_member_state,dut,po_name,dut_po_members[dut],state]
                                                    for dut in duts ])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log("Verify PortChannel-{} State:{} FAILED".format(po_name, state), "HIGH")
            ver_flag = False
        else:
            print_log("Verify PortChannel-{} State:{} PASSED".format(po_name, state), "HIGH")

    return ver_flag


@pytest.fixture(scope="function")
def lag_function_fixture():
    ### Verify all the LAGs configured in the topology and its members are up
    print_log('Verify all the LAGs configured in the topology and its members are up','MED')
    if not verify_portchannel(po_data.keys(),state='up'):
        fail_msg = 'PortChannel or its members not UP:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))
    yield


def test_mclag_POs(lag_function_fixture):
    '''
    Verify MCLAG after disable enable of member ports
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn004']
    print_log(
        "START of TC:test_mclag_POs ==>Sub-Test:Verify MCLAG functionality after toggling PO member ports\n TCs:<{}>".format(tc_list),
        "HIGH")

    print_log("TC Summary :==> Sub-Test:Disable Even member ports in LAG", "MED")
    if not toggle_lag_ports(po_data.keys(),port_operation="disable",port_order="even"):
        final_result = False

    print_log('Verify PO is UP after disabling even member ports', 'MED')

    if not verify_po_state(po_data.keys(), state='up'):
        po_fail += 1
        final_result = False
    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG INterface states
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interface State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Interface State verification FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)
    ### Start traffic
    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1

    #Enable back all ports
    print_log("TC Summary :==> Sub-Test:Enable Even member ports in LAG", "MED")
    if not toggle_lag_ports(po_data.keys(),port_operation="enable",port_order="even"):
        final_result = False
    if not po_iteration_check(po_data.keys(), state='up', iteration_limit=3):
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)
    # Verify traffic and MAC table
    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    post_result_handler()


def test_flap_orphanPorts_clientPorts():
    '''
        Verify MCLAG bring up with PortChannel Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn016','FtOpSoSwL2MclagFn018']
    print_log("START of TC:test_flap_orphanPorts_clientPorts ==>Sub-Test:Verify shut/no-shut of MCLAG orphan ports and MCLAG Client side ports\n TCs:<{}>".format(tc_list), "HIGH")

    print_log("TC Summary :==> Sub-Test:Disable one orphan port each in both MCLAG peers", "MED")
    port_list = {}
    port_list[dut1] = dut_tgn_port[(dut1, 1)]
    port_list[dut2] = dut_tgn_port[(dut2, 2)]
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in mclag_peers])

    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)
    start_stop_traffic()
    rem_mac_list = [6*strm_mac_count, 6*strm_mac_count, 2*strm_mac_count, 2*strm_mac_count]
    expect_mac_tc = [mac_expect_list[i]- rem_mac_list[i] for i in range(len(dut_list))]
    if not verify_mac_table_count(dut_list,expect_mac_tc):
        final_result = False
        mac_count_fail += 1

    print_log("TC Summary :==> Sub-Test:Disable PO member ports in MCLAG Clients", "MED")
    po_member_list = {}
    po_member_list[dut3] = [vars.D3D1P1, vars.D3D1P2]
    po_member_list[dut4] = [vars.D4D2P1, vars.D4D2P2]
    utils.exec_all(True, [[intf.interface_shutdown, dut, po_member_list[dut]] for dut in [dut3,dut4]])

    print_log("TC Summary :==> Sub-Test:Enable back orphan ports in both MCLAG peers", "MED")
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in mclag_peers])

    mclag_intf_data[dut1]['PortChannel3']['local_state'] = 'Down'
    mclag_intf_data[dut1]['PortChannel3']['remote_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel3']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut1]['PortChannel3']['traffic_disable'] = 'Yes'

    mclag_intf_data[dut1]['PortChannel4']['local_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel4']['remote_state'] = 'Down'
    mclag_intf_data[dut1]['PortChannel4']['isolate_with_peer'] = 'No'
    mclag_intf_data[dut1]['PortChannel4']['traffic_disable'] = 'No'

    mclag_intf_data[dut2]['PortChannel3']['local_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel3']['remote_state'] = 'Down'
    mclag_intf_data[dut2]['PortChannel3']['isolate_with_peer'] = 'No'
    mclag_intf_data[dut2]['PortChannel3']['traffic_disable'] = 'No'

    mclag_intf_data[dut2]['PortChannel4']['local_state'] = 'Down'
    mclag_intf_data[dut2]['PortChannel4']['remote_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel4']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut2]['PortChannel4']['traffic_disable'] = 'Yes'

    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False
    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)
    start_stop_traffic()
    if not verify_mac_table_count(dut_list,mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1


    print_log("TC Summary :==> Sub-Test:Enable PO member ports in MCLAG Clients", "MED")
    utils.exec_all(True, [[intf.interface_noshutdown, dut, po_member_list[dut]] for dut in [dut3,dut4]])

    mclag_intf_data[dut1]['PortChannel3']['local_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel3']['remote_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel3']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut1]['PortChannel3']['traffic_disable'] = 'No'

    mclag_intf_data[dut1]['PortChannel4']['local_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel4']['remote_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel4']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut1]['PortChannel4']['traffic_disable'] = 'No'

    mclag_intf_data[dut2]['PortChannel3']['local_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel3']['remote_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel3']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut2]['PortChannel3']['traffic_disable'] = 'No'

    mclag_intf_data[dut2]['PortChannel4']['local_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel4']['remote_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel4']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut2]['PortChannel4']['traffic_disable'] = 'No'

    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)
    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    post_result_handler()


def test_flap_mclag_interfaces():
    '''
        Verify MCLAG functionality after disable PO-4 in Dut1 and PO-3 in Dut2
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn017']
    print_log("START of TC:test_flap_mclag_interfaces ==>Sub-Test:Verify shut/no-shut of MCLAG interfaces\n TCs:<{}>".format(tc_list), "HIGH")

    print_log("TC Summary :==> Sub-Test:Disable one Mclag Interface each in both MCLAG peers", "MED")
    port_list = {}
    port_list[dut1] = 'PortChannel4'
    port_list[dut2] = 'PortChannel3'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in mclag_peers])

    mclag_intf_data[dut2]['PortChannel3']['local_state'] = 'Down'
    mclag_intf_data[dut2]['PortChannel3']['remote_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel3']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut2]['PortChannel3']['traffic_disable'] = 'Yes'

    mclag_intf_data[dut2]['PortChannel4']['local_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel4']['remote_state'] = 'Down'
    mclag_intf_data[dut2]['PortChannel4']['isolate_with_peer'] = 'No'
    mclag_intf_data[dut2]['PortChannel4']['traffic_disable'] = 'No'

    mclag_intf_data[dut1]['PortChannel3']['local_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel3']['remote_state'] = 'Down'
    mclag_intf_data[dut1]['PortChannel3']['isolate_with_peer'] = 'No'
    mclag_intf_data[dut1]['PortChannel3']['traffic_disable'] = 'No'

    mclag_intf_data[dut1]['PortChannel4']['local_state'] = 'Down'
    mclag_intf_data[dut1]['PortChannel4']['remote_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel4']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut1]['PortChannel4']['traffic_disable'] = 'Yes'
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False
    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)
    start_stop_traffic()
    if not verify_mac_table_count(dut_list,mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1

    print_log("TC Summary :==> Sub-Test:Enable back the Mclag Interfaces on both MCLAG peers", "MED")
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in mclag_peers])

    #CHANGE
    po_up_flag = False
    itr_counter = 0
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        if verify_po_state(['PortChannel3', 'PortChannel4', 'PortChannel5'], state='up'):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(5)

    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    mclag_intf_data[dut1]['PortChannel3']['local_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel3']['remote_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel3']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut1]['PortChannel3']['traffic_disable'] = 'No'

    mclag_intf_data[dut1]['PortChannel4']['local_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel4']['remote_state'] = 'Up'
    mclag_intf_data[dut1]['PortChannel4']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut1]['PortChannel4']['traffic_disable'] = 'No'

    mclag_intf_data[dut2]['PortChannel3']['local_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel3']['remote_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel3']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut2]['PortChannel3']['traffic_disable'] = 'No'

    mclag_intf_data[dut2]['PortChannel4']['local_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel4']['remote_state'] = 'Up'
    mclag_intf_data[dut2]['PortChannel4']['isolate_with_peer'] = 'Yes'
    mclag_intf_data[dut2]['PortChannel4']['traffic_disable'] = 'No'
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False
    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)
    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    post_result_handler()

def test_flap_ICCP():
    '''
        Verify MCLAG states and functionality after flapping ICCP link
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn006']
    print_log("START of TC:test_flap_ICCP ==>Sub-Test:Verify MCLAG states and functionality after flapping ICCP link\n TCs:<{}>".format(tc_list), "HIGH")

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)

    ### Disable/enable the ICCP link
    port_list = {}
    port_list[dut1] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut1]])
    #st.wait(1)
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut1]])

    #CHANGE
    ### Verify all mclag POs and member ports are UP
    po_up_flag = False
    itr_counter = 0
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        if verify_portchannel(mclag_interfaces, state='up'):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(5)
    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification after ICCP flap PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification after ICCP flap FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG Interface states
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification after ICCP flap PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification after ICCP flap FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

    start_stop_traffic()

    if not verify_mac_table_count(dut_list,mac_expect_list):
        final_result = False
        mac_count_fail += 1
    post_result_handler()


def test_mclag_timers():
    '''
        Verify MCLAG states and functionality with non-default timers
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn010']
    print_log(
        "START of TC:test_flap_ICCP ==>Sub-Test:Verify MCLAG states and functionality with non-default timers\n TCs:<{}>".format(
            tc_list), "HIGH")

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)
    ### Configure keep-alive time of 3 sec and session timeout as 9 sec
    timer_dict = {'domain_id': mclag_domain, 'keep_alive': 3, 'session_timeout':9}
    pll.exec_parallel(True, mclag_peers, mclag.config_timers, [timer_dict, timer_dict])

    mclag_data[dut1]['keep_alive'] = 3
    mclag_data[dut1]['session_timeout'] = 9
    mclag_data[dut2]['keep_alive'] = 3
    mclag_data[dut2]['session_timeout'] = 9

    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification with non-default timers PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification with non-default timers FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG Interface states
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification with non-default timers PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification with non-default timers FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

    start_stop_traffic()

    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1


    print_log(
        "START of TC:test_flap_ICCP ==>Sub-Test:Verify MCLAG states and functionality after reverting timers\n TCs:<{}>".format(
            tc_list), "HIGH")

    ### Revert keep-alive time to 1 sec and session tiemout to 30 sec
    timer_dict = {'domain_id': mclag_domain, 'keep_alive': 1, 'session_timeout':session_def_time}
    pll.exec_parallel(True, mclag_peers, mclag.config_timers, [timer_dict, timer_dict])

    mclag_data[dut1]['keep_alive'] = 1
    mclag_data[dut1]['session_timeout'] = session_def_time
    mclag_data[dut2]['keep_alive'] = 1
    mclag_data[dut2]['session_timeout'] = session_def_time
    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification with default timers PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification with default timers FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG Interface states
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification with default timers PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification with default timers FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False
    post_result_handler()

def test_add_rem_mclag_interface(lag_function_fixture):
    '''
        Verify MCLAG functionality with add/rem of Mclag Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn005']
    print_log(
        "START of TC:test_add_rem_mclag_interface ==>Sub-Test:Verify MCLAG functionality after unconfig of Mclag Interfaces\n TCs:<{}>".format(
            tc_list), "HIGH")

    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)
    ### Unconfig Mclag Intf PO-3 on DUT1 and Mclag Intf PO-4 and PO-5 on DUT2
    dict1 = {'domain_id': mclag_domain, 'interface_list': ['PortChannel3'], 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'interface_list': ['PortChannel4','PortChannel5'], 'config': 'del'}
    pll.exec_parallel(True, mclag_peers, mclag.config_interfaces, [dict1, dict2])

    mclag_data[dut1]['mclag_intfs'] = len(['PortChannel4','PortChannel5'])
    mclag_data[dut2]['mclag_intfs'] = len(['PortChannel3'])
    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification after rem Mclag Interface PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification after rem Mclag Interface FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False
    ###Verify one side Mclag Interface is down -- after fix of 12842
    ### Verify MCLAG intf on standby peer is down
    po_up_flag = False
    itr_counter = 0
    po_state = {}
    po_state.update({(dut1, "PortChannel3"): 'up'})
    po_state.update({(dut2, "PortChannel3"): 'down'})
    po_state.update({(dut1, "PortChannel4"): 'up'})
    po_state.update({(dut2, "PortChannel4"): 'down'})
    po_state.update({(dut1, "PortChannel5"): 'up'})
    po_state.update({(dut2, "PortChannel5"): 'down'})
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        loop_result = True
        for po_name in mclag_interfaces:
            api_list = []
            api_list.append([po.verify_portchannel_state, dut1, po_name, po_state[(dut1, po_name)]])
            api_list.append([po.verify_portchannel_state, dut2, po_name, po_state[(dut2, po_name)]])
            if po_name == "PortChannel3":
                api_list.append([po.verify_portchannel_state, dut3, po_name, 'up'])
            elif po_name == "PortChannel4" or po_name == "PortChannel5":
                api_list.append([po.verify_portchannel_state, dut4, po_name, 'up'])
            [result, exceptions] = utils.exec_all(True, api_list)
            if not all(i is None for i in exceptions):
                print_log(exceptions)
            if False in result:
                loop_result = False
        if not loop_result:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(5)
        else:
            po_up_flag = True
            break
    if not po_up_flag:
        ### Commenting for now to collect logs on regression TB
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    print_log(
        "START of TC:test_add_rem_mclag_interface ==>Sub-Test:Verify MCLAG functionality after adding back Mclag Interfaces\n TCs:<{}>".format(
            tc_list), "HIGH")

    ### Add back Mclag Intf PO-3 on DUT1 and Mclag Intf PO-4 and PO-5 on DUT2
    dict1 = {'domain_id': mclag_domain, 'interface_list': ['PortChannel3']}
    dict2 = {'domain_id': mclag_domain, 'interface_list': ['PortChannel4','PortChannel5']}
    pll.exec_parallel(True, mclag_peers, mclag.config_interfaces, [dict1, dict2])

    po_up_flag = False
    itr_counter = 0
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        if verify_po_state(['PortChannel3', 'PortChannel4', 'PortChannel5'], state='up'):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(10)
    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    mclag_data[dut1]['mclag_intfs'] = len(mclag_interfaces)
    mclag_data[dut2]['mclag_intfs'] = len(mclag_interfaces)
    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification after adding Mclag Interface PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification after adding Mclag Interface FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    mclag_intf_data[dut1]['PortChannel3'] = {'local_state': 'Up', 'remote_state': 'Up', 'isolate_with_peer': 'Yes',
                                               'traffic_disable': 'No'}
    mclag_intf_data[dut1]['PortChannel4'] = {'local_state': 'Up', 'remote_state': 'Up', 'isolate_with_peer': 'Yes',
                                               'traffic_disable': 'No'}
    mclag_intf_data[dut1]['PortChannel5'] = {'local_state': 'Up', 'remote_state': 'Up', 'isolate_with_peer': 'Yes',
                                               'traffic_disable': 'No'}
    mclag_intf_data[dut2]['PortChannel3'] = {'local_state': 'Up', 'remote_state': 'Up', 'isolate_with_peer': 'Yes',
                                               'traffic_disable': 'No'}
    mclag_intf_data[dut2]['PortChannel4'] = {'local_state': 'Up', 'remote_state': 'Up', 'isolate_with_peer': 'Yes',
                                               'traffic_disable': 'No'}
    mclag_intf_data[dut2]['PortChannel5'] = {'local_state': 'Up', 'remote_state': 'Up', 'isolate_with_peer': 'Yes',
                                               'traffic_disable': 'No'}
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification after adding Mclag Interface PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification after adding Mclag Interface FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

    ### Clear MAC
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)

    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1
    post_result_handler()


def test_peer_link_down():
    '''
        Verify MCLAG bring up with PortChannel Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    #return
    tc_list = ['FtOpSoSwL2MclagFn008']
    print_log("START of TC:test_peer_link_down ==>Sub-Test:Verify MCLAG forwarding when peer link down\n TCs:<{}>".format(tc_list), "HIGH")
    ### Disable the peer link
    port_list = {}
    port_list[dut2] = 'PortChannel2'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut2]])
    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification after peer link down  PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification after peer link down  FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG Interface states
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification after peer link down  PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification after peer link down  FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)

    start_stop_traffic()
    rem_mac_list = [6 * strm_mac_count, 6 * strm_mac_count, -2 * strm_mac_count, -2 * strm_mac_count]
    expect_mac_tc = [mac_expect_list[i] - rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [37, 37, 36, 36]
    if not verify_mac_table_count(mclag_peers,expect_mac_tc[0:2]):
        final_result = False
        mac_count_fail += 1
    ### Since traffic from client to A & B can hash to any of the peer node and those MACs not synced between the 2 nodes, flooding expected
    if not verify_mac_table_count([dut3,dut4],expect_mac_tc[2:4],comp_flag='minimum'):
        final_result = False
        mac_count_fail += 1
    ###Verify traffic from orphan port to MCLAG client gets forwarded.

    utils.exec_all(True, [[mac.get_mac, dut] for dut in dut_list])

    print_log("TC Summary :==> Sub-Test:Enable back the peer link", "MED")
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut2]])
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)

    start_stop_traffic()
    if not verify_mac_table_count(dut_list,mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1
    post_result_handler()

def test_peer_connection_down(lag_function_fixture):
    '''
        Verify MCLAG bring up with PortChannel Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn007','FtOpSoSwL2MclagFn009']
    print_log("START of TC:test_peer_connection_down ==>Sub-Test:Verify MCLAG functionality with keepalive link failure\n TCs:<{}>".format(tc_list), "HIGH")
    ### Disable/enable the ICCP link
    port_list = {}
    port_list[dut1] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut1]])
    ### Verify MCLAG domain and attributes after waiting for session_timeout timer + 2 sec delay
    wait_time = session_def_time + 2
    st.wait(wait_time)
    mclag_data[dut1]['session_status'] = 'ERROR'
    mclag_data[dut2]['session_status'] = 'ERROR'
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification with ICCP link down PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification with ICCP link down FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    ### Verify MCLAG intf on standby peer is down
    po_up_flag = False
    itr_counter = 0

    po_state = {}
    po_state.update({(dut1, "PortChannel3"): 'up'})
    po_state.update({(dut2, "PortChannel3"): 'down'})
    po_state.update({(dut3, "PortChannel3"): 'up'})
    po_state.update({(dut1, "PortChannel4"): 'up'})
    po_state.update({(dut2, "PortChannel4"): 'down'})
    po_state.update({(dut4, "PortChannel4"): 'up'})
    po_state.update({(dut1, "PortChannel5"): 'up'})
    po_state.update({(dut2, "PortChannel5"): 'down'})
    po_state.update({(dut4, "PortChannel5"): 'up'})
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        loop_result = True
        for po_name in mclag_interfaces:
            api_list = []
            api_list.append([po.verify_portchannel_state, dut1, po_name, po_state[(dut1,po_name)]])
            api_list.append([po.verify_portchannel_state, dut2, po_name, po_state[(dut2,po_name)]])
            if po_name == "PortChannel3":
                api_list.append([po.verify_portchannel_state, dut3, po_name, po_state[(dut3, po_name)]])
            elif po_name == "PortChannel4" or po_name == "PortChannel5":
                api_list.append([po.verify_portchannel_state, dut4, po_name, po_state[(dut4, po_name)]])
            [result, exceptions] = utils.exec_all(True, api_list)
            if not all(i is None for i in exceptions):
                print_log(exceptions)
            if False in result:
                loop_result = False
        if not loop_result:
            itr_counter += 1
            if itr_counter < itr_ctr_limit :
                st.wait(5)
        else:
            po_up_flag = True
            break
    if not po_up_flag:
        ### Commenting for now to collect logs on regression TB
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list,[0,0,0,0])

    start_stop_traffic()
    #rem_mac_list = [6 * strm_mac_count, 6 * strm_mac_count, -4 * strm_mac_count, -4 * strm_mac_count]
    #expect_mac_tc = [mac_expect_list[i] - rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [36, 12, 32, 32] -- if all PO in D1 Up
    #expect_mac_tc = [24, 24, 24, 24] -- if PO3 in D1 Up and PO4 & PO5 in D2 Up.
    ### When all POs Down in standby node D2
    expect_mac_tc = [36, 12, 32, 32]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
    ###Verify all traffic from client goes to active peer
    #if not verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams):
    #    final_result = False
    #    traffic_forward_fail += 1

    ### Disable MCLAG intf on active node and make sure standby PO comes up and all traffic goes via standby
    print_log("TC Summary :==> Sub-Test:Verify MCLAG functionality with peer device failure", "MED")
    port_list = {}
    port_list[dut1] = ['PortChannel2','PortChannel3','PortChannel4','PortChannel5']
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut1]])

    ### Verify MCLAG intf on active peer is down
    po_up_flag = False
    itr_counter = 0
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        loop_result = True
        for po_name in mclag_interfaces:
            api_list = []
            api_list.append([po.verify_portchannel_state, dut1, po_name, 'down'])
            api_list.append([po.verify_portchannel_state, dut2, po_name, 'up'])
            if po_name == "PortChannel3":
                api_list.append([po.verify_portchannel_state, dut3, po_name, 'up'])
            elif po_name == "PortChannel4" or po_name == "PortChannel5":
                api_list.append([po.verify_portchannel_state, dut4, po_name, 'up'])
            [result, exceptions] = utils.exec_all(True, api_list)
            if not all(i is None for i in exceptions):
                print_log(exceptions)
            if False in result:
                loop_result = False
        if not loop_result:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(5)
        else:
            po_up_flag = True
            break
    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list,[0,0,0,0])

    start_stop_traffic()
    # rem_mac_list = [6 * strm_mac_count, 6 * strm_mac_count, -4 * strm_mac_count, -4 * strm_mac_count]
    # expect_mac_tc = [mac_expect_list[i] - rem_mac_list[i] for i in range(len(dut_list))]
    expect_mac_tc = [12, 36, 32, 32]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1

    ### Enable back ICCP link and Mclag interfaces on active node
    print_log("TC Summary :==> Sub-Test:Enable back ICCP link, Peer link and Mclag interfaces on active node", "MED")
    port_list = {}
    port_list[dut1] = ['PortChannel2','PortChannel3', 'PortChannel4', 'PortChannel5']
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut1]])
    port_list = {}
    port_list[dut1] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut1]])
    ### Wait for keep-alive timer to detect session up
    st.wait(2)
    mclag_data[dut1]['session_status'] = 'OK'
    mclag_data[dut2]['session_status'] = 'OK'
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification after reverting ICCP session and other POs PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification after reverting ICCP session and other POs FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    #CHANGE
    po_up_flag = False
    itr_counter = 0
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        if verify_portchannel(po_data.keys(),state='up'):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(10)
    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)

    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1
    post_result_handler()

def test_add_rem_vlans(lag_function_fixture):
    '''
        Verify MCLAG bring up with PortChannel Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn020']
    print_log("START of TC:test_add_rem_vlans ==>Sub-Test:Verify MCLAG functionality with add/rem vlans from Mclag Interfaces\n TCs:<{}>".format(tc_list), "HIGH")
    print_log(" Clear fdb entries before config change.", 'MED')
    clear_mac_verify(dut_list)
    ###Configure PO-6 between D1-D2 and D3
    utils.exec_all(True, [[po.create_portchannel, dut, 'PortChannel6'] for dut in [dut1, dut2, dut3]])
    api_list = []
    api_list.append([po.add_portchannel_member, dut1, 'PortChannel6', [vars.D1D3P3, vars.D1D3P4]])
    api_list.append([po.add_portchannel_member, dut2, 'PortChannel6', [vars.D2D3P3, vars.D2D3P4]])
    api_list.append([po.add_portchannel_member, dut3, 'PortChannel6', [vars.D3D1P3, vars.D3D1P4, vars.D3D2P3, vars.D3D2P4]])
    utils.exec_all(True, api_list)
    po_data.update({'PortChannel6': {'duts': [dut1, dut2, dut3],
                                       'po_members': {dut1: [vars.D1D3P3, vars.D1D3P4],
                                                      dut2: [vars.D2D3P3, vars.D2D3P4],
                                                      dut3: [vars.D3D1P3, vars.D3D1P4, vars.D3D2P3, vars.D3D2P4]}}})
    ### Add Po-6 as Mclag interface
    utils.exec_all(True, [[mclag.config_interfaces, dut, mclag_domain, 'PortChannel6']
                          for dut in mclag_peers])
    ###Remove vlan 81 from PO3 and add to PO6 as untagged
    utils.exec_all(True,
                   [[vlan.delete_vlan_member, dut, trunk_base_vlan, 'PortChannel3', True] for dut in [dut1, dut2, dut3]])
    utils.exec_all(True,
                   [[vlan.add_vlan_member, dut, trunk_base_vlan, 'PortChannel6'] for dut in [dut1, dut2, dut3]])

    ###Remove untagged vlan 80 from PO4 and add to PO5 as tagged
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel4'] for dut in [dut1, dut2, dut4]])
    utils.exec_all(True, [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel5', True] for dut in [dut1, dut2, dut4]])
    print_log(
        "START of TC:test_add_rem_vlans ==>Sub-Test:Verify MCLAG functionality after below steps:\n \
        \t\t Added new PO6 to client1 \n \
        \t\t Unconfigured tagged vlan 81 from PO3 and add as untagged vlan 81 in PO6\n \
        \t\t Unconfigured untagged vlan 80 from PO4 and add as tagged vlan 80 in PO5", 'MED')

    po_list = po_data.keys() + ["PortChannel6"]
    if not retry_func(verify_portchannel,po_name_list=po_list,state='up'):
        po_fail += 1
        final_result = False

    #print_log(" Clear fdb entries and start traffic streams.",'MED')
    #clear_mac_verify(dut_list)

    start_stop_traffic()
    if not verify_mac_table_count(dut_list,mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1

    ### Revert the vlan configurations
    utils.exec_all(True,
                   [[vlan.delete_vlan_member, dut, trunk_base_vlan, 'PortChannel6'] for dut in [dut1, dut2, dut3]])
    utils.exec_all(True,[[vlan.add_vlan_member, dut, trunk_base_vlan, 'PortChannel3', True] for dut in [dut1, dut2, dut3]])


    utils.exec_all(True,
                   [[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel5', True] for dut in [dut1, dut2, dut4]])
    utils.exec_all(True,
                   [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel4'] for dut in [dut1, dut2, dut4]])

    ###UnConfigure PO-6 between D1-D2 and D3
    api_list = []
    api_list.append([po.delete_portchannel_member, dut1, 'PortChannel6', [vars.D1D3P3, vars.D1D3P4]])
    api_list.append([po.delete_portchannel_member, dut2, 'PortChannel6', [vars.D2D3P3, vars.D2D3P4]])
    api_list.append(
        [po.delete_portchannel_member, dut3, 'PortChannel6', [vars.D3D1P3, vars.D3D1P4, vars.D3D2P3, vars.D3D2P4]])
    utils.exec_all(True, api_list)
    utils.exec_all(True, [[po.delete_portchannel, dut, 'PortChannel6'] for dut in [dut1, dut2, dut3]])

    utils.exec_foreach(True, mclag_peers, mclag.config_interfaces, mclag_domain, 'PortChannel6', config='del')
    ### Remove PO-6 from PO data
    del po_data["PortChannel6"]

    print_log(
        "START of TC:test_add_rem_vlans ==>Sub-Test:Verify MCLAG functionality after reverting to base config:\n \
        \t\t Remove new PO6 to client1 \n \
        \t\t Unconfigured untagged vlan 81 from PO6 and add as tagged vlan 81 in PO3\n \
        \t\t Unconfigured tagged vlan 80 from PO5 and add as untagged vlan 80 in PO4", 'MED')

    if not verify_po_state(po_data.keys(), state='up'):
        po_fail += 1
        final_result = False


    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)

    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    post_result_handler()


@pytest.fixture(scope="function")
def config_deconfig_mclag_ethernet():
    ###Unconfigure mclag domain & Configure with ethernet
    ### UnConfigure Mclag domain and interfaces
    '''dict1 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut1]['local_ip'],
             'peer_ip': mclag_data[dut1]['peer_ip'], 'peer_interface': mclag_data[dut1]['peer_link_inf'],
             'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut2]['local_ip'],
             'peer_ip': mclag_data[dut2]['peer_ip'], 'peer_interface': mclag_data[dut2]['peer_link_inf'],
             'config': 'del'}'''
    dict1 = {'domain_id': mclag_domain, 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'config': 'del'}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    ###Remove one member port from PO-1
    api_list = []
    api_list.append([po.delete_portchannel_member, dut1, 'PortChannel1', vars.D1D2P1])
    api_list.append([po.delete_portchannel_member, dut2, 'PortChannel1', vars.D2D1P1])
    utils.exec_all(True, api_list)
    ###Remove one member port from PO-2
    api_list = []
    api_list.append([po.delete_portchannel_member, dut1, 'PortChannel2', vars.D1D2P3])
    api_list.append([po.delete_portchannel_member, dut2, 'PortChannel2', vars.D2D1P3])
    utils.exec_all(True, api_list)
    ### Configure ethernet with an IP
    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, vars.D1D2P1, peer1_lb_ip, ip_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, vars.D2D1P1, peer2_lb_ip, ip_mask])
    utils.exec_all(True, api_list)
    #ip.create_static_route(leaf1, data.mclag1_ips[1], data.ip_3_nw[1])

    ### Disable PO1 to avoid sys MAC learned on vlan 100
    port_list = {}
    port_list[dut1] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut1]])

    ### Remove Mclag vlans from  peer-link PO2
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel2', True] for dut in mclag_peers])
    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel2', 'del'] for dut in
                          mclag_peers])
    ### Add Mclag vlans to peer-link interfaces
    peer_link_port = {}
    peer_link_port[dut1] = vars.D1D2P3
    peer_link_port[dut2] = vars.D2D1P3
    utils.exec_all(True, [[vlan.add_vlan_member, dut, access_vlan, peer_link_port[dut],True] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, peer_link_port[dut]] for dut in
                          mclag_peers])
    dict1 = {'domain_id': mclag_domain, 'local_ip': peer1_lb_ip,'peer_ip': peer2_lb_ip, 'peer_interface': vars.D1D2P3}
    dict2 = {'domain_id': mclag_domain, 'local_ip': peer2_lb_ip,'peer_ip': peer1_lb_ip, 'peer_interface': vars.D2D1P3}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    utils.exec_all(True, [[mclag.config_interfaces, dut, mclag_domain, mclag_interfaces]
                          for dut in mclag_peers])

    ### Updating Mclag DS
    mclag_data[dut1]['local_ip'] = peer1_lb_ip
    mclag_data[dut1]['peer_ip'] = peer2_lb_ip
    mclag_data[dut1]['peer_link_inf'] = vars.D1D2P3
    mclag_data[dut2]['peer_link_inf'] = vars.D2D1P3
    mclag_data[dut2]['local_ip'] = peer2_lb_ip
    mclag_data[dut2]['peer_ip'] = peer1_lb_ip
    yield
    ### Enable back PO1
    port_list = {}
    port_list[dut1] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut1]])

    ### Remove IP from eth interfaces
    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, vars.D1D2P1, peer1_lb_ip, ip_mask])
    api_list.append([ip.delete_ip_interface, dut2, vars.D2D1P1, peer2_lb_ip, ip_mask])
    utils.exec_all(True, api_list)
    ### Remove Mclag vlans from peer-link interfaces
    peer_link_port = {}
    peer_link_port[dut1] = vars.D1D2P3
    peer_link_port[dut2] = vars.D2D1P3
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, access_vlan, peer_link_port[dut], True] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, peer_link_port[dut],'del'] for dut in
                          mclag_peers])
    ### Add Mclag vlans to  peer-link PO2
    utils.exec_all(True, [[vlan.add_vlan_member, dut, access_vlan, 'PortChannel2', True] for dut in mclag_peers])
    #trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel2'] for dut in
                          mclag_peers])
    ### Add member ports back to PO-1 and PO-2
    api_list = []
    api_list.append([po.add_portchannel_member, dut1, 'PortChannel1', vars.D1D2P1])
    api_list.append([po.add_portchannel_member, dut2, 'PortChannel1', vars.D2D1P1])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([po.add_portchannel_member, dut1, 'PortChannel2', vars.D1D2P3])
    api_list.append([po.add_portchannel_member, dut2, 'PortChannel2', vars.D2D1P3])
    utils.exec_all(True, api_list)
    ### Delete mclag domain with ethernet
    '''dict1 = {'domain_id': mclag_domain, 'local_ip': peer1_lb_ip, 'peer_ip': peer2_lb_ip,
             'peer_interface': vars.D1D2P3,'config':'del'}
    dict2 = {'domain_id': mclag_domain, 'local_ip': peer2_lb_ip, 'peer_ip': peer1_lb_ip,
             'peer_interface': vars.D2D1P3,'config':'del'}'''
    dict1 = {'domain_id': mclag_domain, 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'config': 'del'}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])
    ### Updating Mclag DS
    mclag_data[dut1]['local_ip'] = peer1_ip
    mclag_data[dut1]['peer_ip'] = peer2_ip
    mclag_data[dut1]['peer_link_inf'] = 'PortChannel2'
    mclag_data[dut2]['peer_link_inf'] = 'PortChannel2'
    mclag_data[dut2]['local_ip'] = peer2_ip
    mclag_data[dut2]['peer_ip'] = peer1_ip
    #Configure back mclag with PO
    dict1 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut1]['local_ip'],
             'peer_ip': mclag_data[dut1]['peer_ip'], 'peer_interface': mclag_data[dut1]['peer_link_inf']}
    dict2 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut2]['local_ip'],
             'peer_ip': mclag_data[dut2]['peer_ip'], 'peer_interface': mclag_data[dut2]['peer_link_inf']}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    utils.exec_all(True, [[mclag.config_interfaces, dut, mclag_domain, mclag_interfaces]
                          for dut in mclag_peers])
    mclag_basic_validations()


def test_mclag_ethernet(config_deconfig_mclag_ethernet):
    '''
        Verify MCLAG bring up with Ethernet Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn001']
    print_log("START of TC:test_mclag_ethernet ==>Sub-Test:Verify MCLAG functionality with Ethernet Interfaces\n TCs:<{}>".format(tc_list), "HIGH")

    ### Display IP interfaces
    utils.exec_all(True, [[ip.get_interface_ip_address, dut] for dut in mclag_peers])
    ### Verify L3 reachability is fine
    print_log("Verify L3 reachability is fine across Mclag peers", 'MED')
    if check_ping(dut1, peer2_lb_ip):
        print_log("L3 reachabilty between Mclag Peers PASSED", "HIGH")
    else:
        print_log("L3 reachabilty between Mclag Peers FAILED", "HIGH")
        st.report_fail("test_case_failure_message", "Ping between MCLAG peers Fail")

    mclag_data[dut1]['mclag_intfs'] = len(mclag_interfaces)
    mclag_data[dut2]['mclag_intfs'] = len(mclag_interfaces)
    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification with Ethernet Interface PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification with Ethernet Interface FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    #CHANGE
    ### Verify Mclag interfaces are UP
    po_up_flag = False
    itr_counter = 0
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        if verify_po_state(['PortChannel3', 'PortChannel4', 'PortChannel5'], state='up'):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(5)
    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    # Sleep for sometime for mclag interface to come up.
    if itr_counter < 2:
        st.wait(5)
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification with Ethernet Interface PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification with Ethernet Interface FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list,[0,0,0,0])

    start_stop_traffic()
    ### MAC will not be learned on physical ethernet ports as it is L3 interface (not part of any vlan)
    rem_mac_list = [1, 1, 0, 0]
    expect_mac_tc = [mac_expect_list[i] - rem_mac_list[i] for i in range(len(dut_list))]
    if not verify_mac_table_count(dut_list,expect_mac_tc):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1
    post_result_handler()

@pytest.fixture(scope="function")
def deconfig_l2mclag_mac_operations():
    global age_time_cleanup, static_mac_cleanup
    age_time_cleanup = 1
    static_mac_cleanup = 1
    yield
    if static_mac_cleanup:
        api_list = []
        api_list.append([mac.delete_mac, dut1, '00:11:80:E1:00:01', 80])
        api_list.append([mac.delete_mac, dut2, '00:21:80:E2:00:01', 80])
        utils.exec_all(True, api_list)
        api_list = []
        api_list.append([mac.delete_mac, dut1, '00:31:80:E1:00:01', 80])
        api_list.append([mac.delete_mac, dut2, '00:41:80:E2:00:01', 80])
        utils.exec_all(True, api_list)
        ### unconfig rest of the static MAC
        api_list = []
        api_list.append([mac.delete_mac, dut1, '00:12:83:E1:00:01', 83])
        api_list.append([mac.delete_mac, dut2, '00:22:83:E2:00:01', 83])
        utils.exec_all(True, api_list)
        api_list = []
        api_list.append([mac.delete_mac, dut1, '00:31:83:E1:00:01', 83])
        api_list.append([mac.delete_mac, dut2, '00:41:83:E2:00:01', 83])
        utils.exec_all(True, api_list)
    if age_time_cleanup:
        api_list = []
        api_list.append([mac.config_mac_agetime, dut1, default_macage])
        api_list.append([mac.config_mac_agetime, dut2, default_macage])
        utils.exec_all(True, api_list)


def test_l2mclag_mac_operations(lag_function_fixture,deconfig_l2mclag_mac_operations):
    '''
        Verify MCLAG bring up with PortChannel Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mac_aging_fail, mclag_state_fail, mclag_intf_fail, po_fail
    global age_time_cleanup, static_mac_cleanup
    tc_list = ['FtOpSoSwL2MclagFn012','FtOpSoSwL2MclagFn013','FtOpSoSwL2MclagFn014','FtOpSoSwL2MclagFn015']
    ##- Verify MAC aging works fine with non-default age-time
    tc_result_age = 0
    fail_msg_age = ''
    ##- Verify clear MAC on MCLAG peer
    tc_result_clear = 0
    fail_msg_clear = ''
    ##- Verify static MAC over MCLAG
    tc_result_static = 0
    fail_msg_static = ''
    ##- Verify MAC move between orphan ports and mclag interfaces
    tc_result_mac_move = 0
    fail_msg_mac_move = ''

    print_log("START of TC:test_mac_aging_l2mclag ==>Sub-Test:Verify MAC aging, clear MAC and static MACs on MCLAG peers\n TCs:<{}>".format(tc_list), "HIGH")
    ###Configure different age time in Active and Standby peers and verify only local MACs age out
    api_list = []
    api_list.append([mac.config_mac_agetime, dut1, 30])
    api_list.append([mac.config_mac_agetime, dut2, 10])
    utils.exec_all(True, api_list)

    age_time = {}
    age_time[dut1] = 30
    age_time[dut2] = 10
    [actual_age, exceptions] = utils.exec_foreach(True, mclag_peers, mac.get_mac_agetime)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if actual_age[0] != age_time[dut1] or actual_age[1] != age_time[dut2]:
        print_log("Failed to configure Mac aging time.", "ERROR")
        final_result = False
        mac_aging_fail += 1
        #tc_result_age += 1
        st.report_tc_fail("FtOpSoSwL2MclagFn012", "mac_aging_time_failed_config","test_l2mclag_mac_operations")
        #st.report_fail("mac_aging_time_failed_config")

    #Configure static MACs on Mclag Peers
    api_list = []
    api_list.append([mac.config_mac, dut1, '00:11:80:E1:00:01', 80, dut_tgn_port[(dut1,1)]])
    api_list.append([mac.config_mac, dut2, '00:21:80:E2:00:01', 80, dut_tgn_port[(dut2, 1)]])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([mac.config_mac, dut1, '00:31:80:E1:00:01', 80, 'PortChannel3'])
    api_list.append([mac.config_mac, dut2, '00:41:80:E2:00:01', 80, 'PortChannel4'])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([mac.config_mac, dut1, '00:12:83:E1:00:01', 83, dut_tgn_port[(dut1, 2)]])
    api_list.append([mac.config_mac, dut2, '00:22:83:E2:00:01', 83, dut_tgn_port[(dut2, 2)]])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([mac.config_mac, dut1, '00:31:83:E1:00:01', 83, 'PortChannel3'])
    api_list.append([mac.config_mac, dut2, '00:41:83:E2:00:01', 83, 'PortChannel5'])
    utils.exec_all(True, api_list)

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list,[9,9,0,0])
    #clear_mac_verify([dut3, dut4])

    ###Start base streams and static mac streams -
    # single direction drop stream each on TGN11 and TGN22 to verify MAC move prohibted for static MAC
    src_streams = base_src_streams + static_src_streams
    dst_streams = base_dst_streams + static_dst_streams
    start_stop_traffic(src_stream_list=src_streams,dest_stream_list=dst_streams)
    start_time = time.time()
    #start_stop_traffic(src_stream_list=static_neg_streams,direction='single',clear_flag='NO')
    print_log("Display ICCP mac table to help verify local age of MAC.", "MED")
    [local_mac_counts,exceptions]=utils.exec_foreach(True, mclag_peers, mclag.verify_iccp_macs, domain_id=mclag_domain,age_flag='P',type='D',return_type='NUM')
    print_log("Local Dynamic MACs: {} {}".format(local_mac_counts[0],local_mac_counts[1]))
    #Static MAC counts, local+ remote
    static_mac_list = [8, 8, 4, 4]
    expect_mac_tc = [mac_expect_list[i] + static_mac_list[i] for i in range(len(dut_list))]
    tc_total_macs = expect_mac_tc
    if not verify_mac_table_count(dut_list,expect_mac_tc):
        final_result = False
        mac_count_fail += 1
        tc_result_static += 1
        fail_msg_static += "MAC verification Failed:"

    print_log("TC Summary :==> Sub-Test:Verify MACs aged out after sleep for age time in D2", "MED")
    current_time = time.time()
    time_elapsed = current_time - start_time
    st.wait(2*age_time[dut2]-time_elapsed+1)
    ### 12 SA macs + 8 DA macs (1 MAC each in each stream_id(AC,AD,BC,BD) per vlan) + 4 bi-direction MACs (1 MAC each stream_id(CD) per vlan)
    rem_mac_list = [abs(local_mac_counts[1]-1), abs(local_mac_counts[1]-1), 0, 0]
    expect_mac_tc = [tc_total_macs[i] -  rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [25+8, 25+8, 36+4, 36+4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
        tc_result_age += 1
        fail_msg_age += "MAC verification Failed:"

    print_log("TC Summary :==> Sub-Test:Verify MACs aged out after sleep for age time in D1", "MED")
    st.wait(2 * (age_time[dut1] - age_time[dut2]))
    ### 12 SA macs + 10 DA macs
    rem_mac_list = [abs(local_mac_counts[0] - 1), abs(local_mac_counts[0] - 1), 0, 0]
    expect_mac_tc = [expect_mac_tc[i] - rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [1+8, 1+8, 36+4, 36+4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
        tc_result_age += 1
        fail_msg_age += "MAC verification Failed:"

    ### Revert age time
    api_list = []
    api_list.append([mac.config_mac_agetime, dut1, default_macage])
    api_list.append([mac.config_mac_agetime, dut2, default_macage])
    utils.exec_all(True, api_list)
    age_time[dut1] = default_macage
    age_time[dut2] = default_macage
    [actual_age, exceptions] = utils.exec_foreach(True, mclag_peers, mac.get_mac_agetime)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if actual_age[0] != age_time[dut1] or actual_age[1] != age_time[dut2]:
        print_log("Failed to revert Mac aging time.", "ERROR")
        #tc_result_age += 1
        final_result = False
        mac_aging_fail += 1
        st.report_tc_fail("FtOpSoSwL2MclagFn012", "mac_aging_time_failed_config", "test_l2mclag_mac_operations")
        #st.report_fail("mac_aging_time_failed_config")
    age_time_cleanup = 0

    clear_mac_verify([dut3,dut4],[0,0])

    print_log("TC Summary :==> Sub-Test:Verify MAC move with new set of streams", "MED")
    ### Start mac move streams and static MAC streams
    # start_stop_traffic(src_stream_list=static_neg_streams,direction='single',clear_flag='NO')
    src_streams = mac_move_src_streams + static_src_streams
    dst_streams = mac_move_dst_streams + static_dst_streams
    start_stop_traffic(src_stream_list=src_streams, dest_stream_list=dst_streams)
    # Static MAC counts, local+ remote
    expect_mac_tc = tc_total_macs
    #add_mac_list = [8, 8, 4, 4]
    #expect_mac_tc = [mac_expect_list[i] + add_mac_list[i] for i in range(len(dut_list))]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        tc_result_static += 1
        tc_result_mac_move += 1
        mac_count_fail += 1
        fail_msg_static += "MAC verification Failed:"
        fail_msg_mac_move += "MAC verification Failed:"

    print_log("Display ICCP mac table to help verify clear MAC.", "MED")
    [local_mac_counts, exceptions] = utils.exec_foreach(True, mclag_peers, mclag.verify_iccp_macs,
                                                        domain_id=mclag_domain, age_flag='P', type='D',
                                                        return_type='NUM')
    print_log("Local Dynamic MACs after MAC move streams: {} {}".format(local_mac_counts[0], local_mac_counts[1]))
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    #verify_traffic(src_stream_list=mac_move_dst_streams, dest_stream_list=mac_move_src_streams, direction='single')
    print_log("TC Summary :==> Sub-Test:Verify MAC move streams Forwarding", "HIGH")
    start_stop_traffic(src_stream_list=mac_move_src_streams, dest_stream_list=mac_move_dst_streams)
    if not verify_traffic(src_stream_list=mac_move_dst_streams, dest_stream_list=mac_move_src_streams, direction='single'):
        final_result = False
        traffic_forward_fail += 1
        tc_result_mac_move += 1
        fail_msg_mac_move += "Traffic Forwarding Failed:"

    print_log("TC Summary :==> Sub-Test:Verify Static MAC streams Forwarding", "HIGH")
    start_stop_traffic(src_stream_list=static_src_streams, dest_stream_list=static_dst_streams)
    if not verify_traffic(src_stream_list=static_dst_streams, dest_stream_list=static_src_streams, direction='single'):
        final_result = False
        traffic_forward_fail += 1
        tc_result_static += 1
        fail_msg_static += "Traffic Forwarding Failed:"

    print_log("TC Summary :==> Sub-Test:Verify MAC table after clear MAC in D1", "MED")
    ### Clear MAC on one peer and verify MAC table --- expect static mac
    mac.clear_mac(dut1)
    ### 12 SA macs + 8 DA macs (1 MAC each in each stream_id(AC,AD,BC,BD) per vlan) + 4 bi-direction MACs (1 MAC each stream_id(CD) per vlan)
    rem_mac_list = [abs(local_mac_counts[0] - 1), abs(local_mac_counts[0] - 1), 0, 0]
    expect_mac_tc = [tc_total_macs[i] - rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [25 + 8, 25 + 8, 36 + 4, 36 + 4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
        tc_result_clear += 1
        fail_msg_clear += "MAC verification Failed:"

    print_log("TC Summary :==> Sub-Test:Verify MAC table after clear MAC in D2", "MED")
    mac.clear_mac(dut2)
    ### 12 SA macs + 10 DA macs
    rem_mac_list = [abs(local_mac_counts[1] - 1), abs(local_mac_counts[1] - 1), 0, 0]
    expect_mac_tc = [expect_mac_tc[i] - rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [1 + 8, 1 + 8, 36 + 4, 36 + 4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
        tc_result_clear += 1
        fail_msg_clear += "MAC verification Failed:"

    print_log("TC Summary :==> Sub-Test:Verify MAC table after unconfig few static MACs from both MCLAG peers", "MED")
    ### Unconfig  one static MAC on one peer and another static MAC on other peer check MAC table
    api_list = []
    api_list.append([mac.delete_mac, dut1, '00:11:80:E1:00:01', 80])
    api_list.append([mac.delete_mac, dut2, '00:21:80:E2:00:01', 80])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([mac.delete_mac, dut1, '00:31:80:E1:00:01', 80])
    api_list.append([mac.delete_mac, dut2, '00:41:80:E2:00:01', 80])
    utils.exec_all(True, api_list)
    rem_mac_list = [4, 4, 0, 0]
    expect_mac_tc = [expect_mac_tc[i] - rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [1 + 4, 1 + 4, 36 + 4, 36 + 4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
        tc_result_static += 1
        fail_msg_static += "MAC verification Failed:"
    ### unconfig rest of the static MAC
    api_list = []
    api_list.append([mac.delete_mac, dut1, '00:12:83:E1:00:01', 83])
    api_list.append([mac.delete_mac, dut2, '00:22:83:E2:00:01', 83])
    utils.exec_all(True, api_list)
    api_list = []
    api_list.append([mac.delete_mac, dut1, '00:31:83:E1:00:01', 83])
    api_list.append([mac.delete_mac, dut2, '00:41:83:E2:00:01', 83])
    utils.exec_all(True, api_list)
    static_mac_cleanup = 0
    rem_mac_list = [4, 4, 0, 0]
    expect_mac_tc = [expect_mac_tc[i] - rem_mac_list[i] for i in range(len(dut_list))]
    #expect_mac_tc = [1, 1, 36 + 4, 36 + 4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
        tc_result_static += 1
        fail_msg_static += "MAC verification Failed:"

    ### Report TC wise PASS/FAIL
    if tc_result_age > 0:
        st.report_tc_fail("FtOpSoSwL2MclagFn012", "test_case_failure_message",
                          "Verify MAC aging works fine with non-default age-time=>{}".format(fail_msg_age.strip(':')))
    else:
        st.report_tc_pass('FtOpSoSwL2MclagFn012', "test_case_passed")

    if tc_result_clear > 0:
        st.report_tc_fail("FtOpSoSwL2MclagFn013", "test_case_failure_message",
                          "Verify clear MAC on MCLAG peer=>{}".format(fail_msg_clear.strip(':')))
    else:
        st.report_tc_pass('FtOpSoSwL2MclagFn013', "test_case_passed")

    if tc_result_static > 0:
        st.report_tc_fail("FtOpSoSwL2MclagFn014", "test_case_failure_message",
                          "Verify static MAC over MCLAG=>{}".format(fail_msg_static.strip(':')))
    else:
        st.report_tc_pass('FtOpSoSwL2MclagFn014', "test_case_passed")

    if tc_result_mac_move > 0:
        st.report_tc_fail("FtOpSoSwL2MclagFn015", "test_case_failure_message",
                          "Verify MAC move between orphan ports and mclag interfaces=>{}".format(fail_msg_mac_move.strip(':')))
    else:
        st.report_tc_pass('FtOpSoSwL2MclagFn015', "test_case_passed")

    post_result_handler()


def test_l2mclag_bum_traffic(lag_function_fixture):
    '''
        Verify MCLAG bring up with PortChannel Interfaces
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, bum_traffic_fail
    tc_list = ['FtOpSoSwL2MclagFn019']
    print_log("START of TC:test_l2mclag_bum_traffic ==>Sub-Test:Verify MCLAG functionality with BUM streams\n TCs:<{}>".format(tc_list), "HIGH")
    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)
    #utils.exec_all(True, [[mac.get_mac, dut] for dut in dut_list])
    start_stop_traffic(src_stream_list=bum_src_streams,direction='single',action_ctrl='START')
    expect_mac_tc = [5, 5, 4, 4]
    if not verify_mac_table_count(dut_list,expect_mac_tc):
        final_result = False
        mac_count_fail += 1
    #verify_traffic_path()
    rx_ports=[dut_tgn_port[(dut1,2)],dut_tgn_port[(dut2,2)],dut_tgn_port[(dut3,1)],dut_tgn_port[(dut4,1)]]
    expect_rate_list =[9000,9000,9000,9000]
    threshold_list = [900, 900, 900, 900]
    #threshold_list = [250, 250, 250, 250]
    if not verify_traffic_rate(dut_list, rx_ports, expect_rate_list, threshold_list):
        final_result = False
        bum_traffic_fail += 1
        print_log("BUM traffic verification FAILED, expect ~9000pkt/sec on TGEN ports",'ERROR')
        debug_traffic_fail()
    else:
        print_log("BUM traffic verification PASSED",'MED')

    ### Disable local Mclag nodes to check traffic gets flooded via peer
    print_log("TC Summary :==> Sub-Test:Verify BUM flooding with local Mclag interface shut", "MED")
    port_list = {}
    port_list[dut1] = 'PortChannel3'
    port_list[dut2] = 'PortChannel5'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in mclag_peers])
    po_state = {}
    po_state.update({(dut1, "PortChannel3"): 'down'})
    po_state.update({(dut2, "PortChannel3"): 'up'})
    po_state.update({(dut3, "PortChannel3"): 'up'})
    po_state.update({(dut1, "PortChannel4"): 'up'})
    po_state.update({(dut2, "PortChannel4"): 'up'})
    po_state.update({(dut4, "PortChannel4"): 'up'})
    po_state.update({(dut1, "PortChannel5"): 'up'})
    po_state.update({(dut2, "PortChannel5"): 'down'})
    po_state.update({(dut4, "PortChannel5"): 'up'})
    itr_counter = 0
    po_up_flag = False
    while (itr_counter < 1):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        loop_result = True
        for po_name in mclag_interfaces:
            api_list = []
            api_list.append([po.verify_portchannel_state, dut1, po_name, po_state[(dut1, po_name)]])
            api_list.append([po.verify_portchannel_state, dut2, po_name, po_state[(dut2, po_name)]])
            if po_name == "PortChannel3":
                api_list.append([po.verify_portchannel_state, dut3, po_name, po_state[(dut3, po_name)]])
            elif po_name == "PortChannel4" or po_name == "PortChannel5":
                api_list.append([po.verify_portchannel_state, dut4, po_name, po_state[(dut4, po_name)]])
            [result, exceptions] = utils.exec_all(True, api_list)
            if not all(i is None for i in exceptions):
                print_log(exceptions)
            if False in result:
                loop_result = False
        if not loop_result:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(5)
        else:
            po_up_flag = True
            break
    if not po_up_flag:
        ### Commenting for now to collect logs on regression TB
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

    utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    #utils.exec_all(True, [[mac.get_mac, dut] for dut in dut_list])
    ## Temp delay to rule out delay issue
    #st.wait(2)
    expect_mac_tc = [5, 5, 4, 4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1

    #verify_traffic_path()
    rx_ports = [dut_tgn_port[(dut1, 2)], dut_tgn_port[(dut2, 2)], dut_tgn_port[(dut3, 1)], dut_tgn_port[(dut4, 1)]]
    expect_rate_list = [9000, 9000, 9000, 9000]
    threshold_list = [900, 900, 900, 900]
    #threshold_list = [250, 250, 250, 250]
    if not verify_traffic_rate(dut_list, rx_ports, expect_rate_list, threshold_list):
        ### Commenting for now to collect logs on regression TB
        final_result = False
        bum_traffic_fail += 1
        print_log("BUM traffic verification FAILED, expect ~9000pkt/sec on TGEN ports", 'ERROR')
        debug_traffic_fail()
    else:
        print_log("BUM traffic verification PASSED", 'MED')

    port_list = {}
    port_list[dut1] = 'PortChannel3'
    port_list[dut2] = 'PortChannel5'
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in mclag_peers])
    start_stop_traffic(src_stream_list=bum_src_streams,direction='single',action_ctrl='STOP')
    post_result_handler()


@pytest.fixture(scope="function")
def config_deconfig_same_iccp_peer_links():
    ###Unconfigure mclag domain
    ## Configure IP on PO2 on vlan 1
    ## Configure mclag domain with local & peer ip as that of PO2
    ## Configure Mclag interfaces

    ### UnConfigure Mclag domain and interfaces
    '''dict1 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut1]['local_ip'],
             'peer_ip': mclag_data[dut1]['peer_ip'], 'peer_interface': mclag_data[dut1]['peer_link_inf'],
             'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut2]['local_ip'],
             'peer_ip': mclag_data[dut2]['peer_ip'], 'peer_interface': mclag_data[dut2]['peer_link_inf'],
             'config': 'del'}'''
    dict1 = {'domain_id': mclag_domain, 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'config': 'del'}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])
    ### Disable PO1 to avoid sys MAC learned on vlan 100
    port_list = {}
    port_list[dut1] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut1]])

    dict1 = {'domain_id': mclag_domain, 'local_ip': peer_link_ip_1, 'peer_ip': peer_link_ip_2,
             'peer_interface': 'PortChannel2'}
    dict2 = {'domain_id': mclag_domain, 'local_ip': peer_link_ip_2, 'peer_ip': peer_link_ip_1,
             'peer_interface': 'PortChannel2'}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    utils.exec_all(True, [[mclag.config_interfaces, dut, mclag_domain, mclag_interfaces]
                          for dut in mclag_peers])
    ### Updating Mclag DS
    mclag_data[dut1]['local_ip'] = peer_link_ip_1
    mclag_data[dut1]['peer_ip'] = peer_link_ip_2
    mclag_data[dut1]['peer_link_inf'] = 'PortChannel2'
    mclag_data[dut2]['peer_link_inf'] = 'PortChannel2'
    mclag_data[dut2]['local_ip'] = peer_link_ip_2
    mclag_data[dut2]['peer_ip'] = peer_link_ip_1

    ### Configure new control vlan and add it to PO2
    utils.exec_all(True, [[vlan.create_vlan, dut, mclag_vlan_peer] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.add_vlan_member, dut, mclag_vlan_peer, 'PortChannel2',True] for dut in mclag_peers])

    ### Configure IP on peer link
    utils.exec_foreach(True, mclag_peers, mclag.config_uniqueip,op_type='add', vlan='Vlan' + str(mclag_vlan_peer))

    api_list = []
    api_list.append([ip.config_ip_addr_interface, dut1, 'Vlan' + str(mclag_vlan_peer), peer_link_ip_1, ip_mask])
    api_list.append([ip.config_ip_addr_interface, dut2, 'Vlan' + str(mclag_vlan_peer), peer_link_ip_2, ip_mask])
    utils.exec_all(True, api_list)

    yield

    ### Unconfigure mclag domain with same link
    ## Unconfigure new vlan created
    ## Unconfigure IP on PO2
    ## Cofigure back the original mclag domain with PO1 as control link
    ### Enable PO1 back
    port_list = {}
    port_list[dut1] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut1]])
    ### Remove IP from eth interfaces
    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(mclag_vlan_peer), peer_link_ip_1, ip_mask])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(mclag_vlan_peer), peer_link_ip_2, ip_mask])
    utils.exec_all(True, api_list)

    utils.exec_foreach(True, mclag_peers, mclag.config_uniqueip, op_type='del', vlan='Vlan' + str(mclag_vlan_peer))
    # utils.exec_all(True, [[mclag.config_uniqueip, dut, 'del', 'Vlan' + str(mclag_vlan_peer)] for dut in mclag_peers])

    ### UnConfigure new control vlan from PO2 and delete it
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, mclag_vlan_peer, 'PortChannel2', True] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.delete_vlan, dut, mclag_vlan_peer] for dut in mclag_peers])

    ### Delete mclag domain with PO2 as ICCP
    '''dict1 = {'domain_id': mclag_domain, 'local_ip': peer_link_ip_1, 'peer_ip': peer_link_ip_2,
             'peer_interface': 'PortChannel2', 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'local_ip': peer_link_ip_2, 'peer_ip': peer_link_ip_1,
             'peer_interface': 'PortChannel2', 'config': 'del'}'''
    dict1 = {'domain_id': mclag_domain, 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'config': 'del'}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    ### Updating Mclag DS
    mclag_data[dut1]['local_ip'] = peer1_ip
    mclag_data[dut1]['peer_ip'] = peer2_ip
    mclag_data[dut1]['peer_link_inf'] = 'PortChannel2'
    mclag_data[dut2]['peer_link_inf'] = 'PortChannel2'
    mclag_data[dut2]['local_ip'] = peer2_ip
    mclag_data[dut2]['peer_ip'] = peer1_ip
    #Configure back mclag with PO
    dict1 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut1]['local_ip'],
             'peer_ip': mclag_data[dut1]['peer_ip'], 'peer_interface': mclag_data[dut1]['peer_link_inf']}
    dict2 = {'domain_id': mclag_domain, 'local_ip': mclag_data[dut2]['local_ip'],
             'peer_ip': mclag_data[dut2]['peer_ip'], 'peer_interface': mclag_data[dut2]['peer_link_inf']}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    utils.exec_all(True, [[mclag.config_interfaces, dut, mclag_domain, mclag_interfaces]
                          for dut in mclag_peers])
    mclag_basic_validations()



def test_l2mclag_same_iccp_peer_links(config_deconfig_same_iccp_peer_links):
    '''
        Verify MCLAG bring up with ICCP keep-alive link and peer-link as same PO.
    '''
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail
    tc_list = ['FtOpSoSwL2MclagFn003']
    print_log(
        "START of TC:test_l2mclag_same_iccp_peer_links ==>Sub-Test:Verify MCLAG configured with same PO as ICCP control link and peer-link\n TCs:<{}>".format(
            tc_list), "HIGH")

    ### Display IP interfaces
    utils.exec_all(True, [[ip.get_interface_ip_address, dut] for dut in mclag_peers])
    ### Verify L3 reachability is fine
    print_log("Verify L3 reachability is fine across Mclag peers", 'MED')
    if check_ping(dut1, peer_link_ip_2):
        print_log("L3 reachabilty between Mclag Peers PASSED", "HIGH")
    else:
        print_log("L3 reachabilty between Mclag Peers FAILED", "HIGH")
        st.report_fail("test_case_failure_message", "Ping between MCLAG peers Fail")

    # Sleep for keep-alive time for config change to reflect.
    st.wait(2)
    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification with same ICCP and Peer Link PO PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification with same ICCP and Peer Link PO FAILED", "HIGH")
        mclag_state_fail += 1
        final_result = False

    #CHANGE
    ### Verify MCLAG PortChannel is UP.
    po_up_flag = False
    itr_counter = 0
    while (itr_counter < itr_ctr_limit):
        print_log("Iteration:{}".format(itr_counter + 1), 'MED')
        if verify_po_state(['PortChannel3', 'PortChannel4', 'PortChannel5'], state='up'):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            if itr_counter < itr_ctr_limit:
                st.wait(5)
    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")

   # Sleep for sometime for mclag interface to come up.
    if itr_counter < 2:
        st.wait(5)
    if verify_mclag_intf_state(mclag_intf_data):
        print_log("MCLAG Interfaces State verification with same ICCP and Peer Link PO PASSED", "HIGH")
    else:
        print_log("MCLAG Interfaces State verification with same ICCP and Peer Link PO FAILED", "HIGH")
        mclag_intf_fail += 1
        final_result = False

    ### Send traffic and verify packet count received
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list, [1, 1, 0, 0])

    start_stop_traffic()
    ### System MAC will not be learned on control link PO2  as it is peer-link in which MAC learning disabled
    #rem_mac_list = [1, 1, 0, 0]
    #expect_mac_tc = [mac_expect_list[i] - rem_mac_list[i] for i in range(len(dut_list))]
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    # verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams, direction='single'):
        final_result = False
        traffic_forward_fail += 1

    post_result_handler()



def test_l2mclag_save_reload():
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, intf_fail
    tc_list = ['FtOpSoSwL2MclagPe001']
    print_log("START of TC:test_l2mclag_save_reload:Verify MCLAG functionality after config save and reload\n TCs:<{}>".format(tc_list),
              "HIGH")
    utils.exec_all(True, [[boot.config_save_reload, dut] for dut in mclag_peers])

    print_log("Verify all ports UP after config save reload", "MED")
    [results, exceptions] = utils.exec_foreach(True, mclag_peers, port.get_interfaces_all)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if any(port is None for port in results):
        final_result = False
        intf_fail += 1

    print_log("TC Summary :==> Sub-Test:Verify MCLAG functionality after config save and reload", "MED")
    mclag_basic_validations()

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)

    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1

    post_result_handler()

def test_l2mclag_fast_reboot():
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, intf_fail
    tc_list = ['FtOpSoSwL2MclagPe002']
    print_log("START of TC:test_l2mclag_fast_reboot:Verify MCLAG functionality after fast reboot\n TCs:<{}>".format(tc_list),
              "HIGH")
    utils.exec_all(True, [[boot.config_save, dut] for dut in mclag_peers])
    utils.exec_foreach(True, mclag_peers, st.reboot, "fast")

    print_log("Verify all ports UP after fast reboot", "MED")
    [results, exceptions] = utils.exec_foreach(True, mclag_peers, port.get_interfaces_all)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if any(port is None for port in results):
        final_result = False
        intf_fail += 1
    print_log("TC Summary :==> Sub-Test:Verify MCLAG functionality after fast reboot", "MED")
    mclag_basic_validations()
    print_log(" Clear fdb entries and start traffic streams.", "MED")
    #utils.exec_all(True, [[mac.clear_mac, dut] for dut in dut_list])
    clear_mac_verify(dut_list)

    start_stop_traffic()
    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    #verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,direction='single'):
        final_result = False
        traffic_forward_fail += 1
    post_result_handler()


def test_l2mclag_docker_restart():
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, intf_fail
    tc_list = ['FtOpSoSwL2MclagPe004']
    print_log("START of TC:test_l2mclag_docker_restart:Verify MCLAG functionality after docker restarts\n TCs:<{}>".format(tc_list),
              "HIGH")
    utils.exec_all(True, [[boot.config_save, dut] for dut in mclag_peers])
    utils.exec_all(True,[[basic.service_operations_by_systemctl, dut, "iccpd", "restart"] for dut in mclag_peers])
    #st.wait(30)
    utils.exec_all(True, [[basic.service_operations_by_systemctl, dut, "swss", "restart"] for dut in mclag_peers])
    #st.wait(30)
    result = retry_parallel(basic.get_system_status, dict_list=[None,None], dut_list=mclag_peers, retry_count=7, delay=5)
    if not result:
        fail_msg = 'System not UP after docker restart'
        st.report_fail('test_case_failure_message', fail_msg)

    print_log("Verify all ports UP after iccpd and swss docker restarts", "MED")
    [results, exceptions] = utils.exec_foreach(True, mclag_peers, port.get_interfaces_all)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if any(port is None for port in results):
        final_result = False
        intf_fail += 1

    print_log("TC Summary :==> Sub-Test:Verify MCLAG functionality after docker restarts", "MED")
    mclag_basic_validations()

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)
    start_stop_traffic()

    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    # verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams, direction='single'):
        final_result = False
        traffic_forward_fail += 1

    post_result_handler()


def test_l2mclag_warm_reboot():
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, intf_fail
    tc_list = ['FtOpSoSwL2MclagPe003']
    print_log("START of TC:test_l2mclag_warm_reboot:Verify MCLAG functionality after warm reboot \n TCs:<{}>".format(tc_list),
              "HIGH")
    #utils.exec_all(True, [[boot.config_save, dut] for dut in mclag_peers])
    #utils.exec_foreach(True, mclag_peers, boot.config_warm_restart, oper="enable", tasks=["system", "teamd",'swss'])
    utils.exec_all(True, [[boot.config_save, dut] for dut in [dut2]])
    utils.exec_foreach(True, [dut2], boot.config_warm_restart, oper="enable", tasks=["system"])
    utils.exec_all(True, [[st.reboot, dut, "warm"] for dut in [dut2]])
    ### Sleep for 30 sec for vlan & intf daemons to reconcile.
    st.wait(30)
    ### System status already being checked by warm-reboot api.
    #result = retry_parallel(basic.get_system_status, dict_list=None, dut_list=[dut2], retry_count=7,delay=5)
    #if not result:
    #    fail_msg = 'System not UP after warm-reboot'
    #    st.report_fail('test_case_failure_message', fail_msg)

    print_log("Verify all ports UP after warm reboot", "MED")
    [results, exceptions] = utils.exec_foreach(True, [dut2], port.get_interfaces_all)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if any(port is None for port in results):
        final_result = False
        intf_fail += 1

    print_log("TC Summary :==> Sub-Test:Verify MCLAG functionality after warm reboot", "MED")
    mclag_basic_validations()

    print_log(" Clear fdb entries and start traffic streams.", "MED")
    clear_mac_verify(dut_list)
    start_stop_traffic()

    if not verify_mac_table_count(dut_list, mac_expect_list):
        final_result = False
        mac_count_fail += 1
    # verify_traffic(src_stream_list=base_src_streams, dest_stream_list=base_dst_streams)
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams, direction='single'):
        final_result = False
        traffic_forward_fail += 1

    utils.exec_foreach(True, [dut2], boot.config_warm_restart, oper="disable", tasks=["system"])
    #utils.exec_all(True, [[boot.config_save, dut] for dut in mclag_peers])

    post_result_handler()
