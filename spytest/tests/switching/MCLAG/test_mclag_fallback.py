##########################################################################################
# Title: MCLAG LACP Fallback script
# Author: Sneha Ann Mathew <sneha.mathew@broadcom.com>
##########################################################################################

import pytest

from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan
import apis.routing.ip as ip
import apis.switching.mac as mac
import apis.system.interface as intf
import apis.system.port as port
import apis.system.reboot as boot
import apis.switching.portchannel as po
import apis.switching.mclag as mclag
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
    delay = kwargs.get("delay", 3)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if kwargs.keys() == []:
            if func():
                return True
        else:
            if func(**kwargs):
                return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


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
    global mclag_clients
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
    mclag_clients = [dut3, dut4]
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
    remove_client_configs()
    yield
    enable_client_configs()
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
        if po_id in ['PortChannel3','PortChannel4','PortChannel5']:
            utils.exec_all(True, [[po.create_portchannel, dut, po_id, True] for dut in mclag_peers])
            utils.exec_all(True, [[po.create_portchannel, dut, po_id, False] for dut in mclag_clients])
        else:
            utils.exec_all(True, [[po.create_portchannel, dut, po_id, False] for dut in po_data[po_id]['duts']])
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
    #st.set_device_alias(dut1, "MclagPeer1")
    '''api_list = []
    api_list.append([st.set_device_alias, dut1, "MclagPeer1"])
    api_list.append([st.set_device_alias, dut2, "MclagPeer2"])
    api_list.append([st.set_device_alias, dut3, "MclagClient1"])
    api_list.append([st.set_device_alias, dut4, "MclagClient2"])
    utils.exec_all(True, api_list)'''

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

def remove_client_configs():
    ###Remove PO member ports
    print_log("Remove PortChannel Member ports from PO on  Client Nodes",'MED')
    api_list = []
    api_list.append([po.delete_portchannel_member, dut3, "PortChannel3", po_data['PortChannel3']['po_members'][dut3]])
    api_list.append([po.delete_portchannel_member, dut4, "PortChannel5", po_data['PortChannel5']['po_members'][dut4]])
    utils.exec_all(True, api_list)

    ###Disable client ports
    print_log("Shut unconfigured PortChannel Member ports on  Client Nodes", 'MED')
    api_list = []
    api_list.append([intf.interface_operation, dut3, po_data['PortChannel3']['po_members'][dut3], 'shutdown', False])
    api_list.append([intf.interface_operation, dut4, po_data['PortChannel5']['po_members'][dut4], 'shutdown', False])
    utils.exec_all(True, api_list)

    ###Configure trunk  vlans on client member ports.
    print_log("Configure member vlans on PortChannel Member ports on  Client Nodes", 'MED')
    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    member_port_list = {}
    member_port_list[dut3] = po_data['PortChannel3']['po_members'][dut3]
    member_port_list[dut4] = po_data['PortChannel5']['po_members'][dut4]
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, member_port_list[dut]] for dut in
                          [dut3, dut4]])
    utils.exec_all(True,[[vlan.add_vlan_member, dut, access_vlan, member_port_list[dut3], True] for dut in [dut3]])



def enable_client_configs():
    ###UnConfigure trunk  vlans on client member ports.
    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    member_port_list = {}
    member_port_list[dut3] = po_data['PortChannel3']['po_members'][dut3]
    member_port_list[dut4] = po_data['PortChannel5']['po_members'][dut4]
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, member_port_list[dut],'del'] for dut in
                          [dut3, dut4]])
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, access_vlan, member_port_list[dut3],True] for dut in [dut3]])

    ### Add PO member ports
    api_list = []
    api_list.append([po.add_portchannel_member, dut3, "PortChannel3", po_data['PortChannel3']['po_members'][dut3]])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", po_data['PortChannel5']['po_members'][dut4]])
    utils.exec_all(True, api_list)

    ###Enaable client ports
    api_list = []
    api_list.append([intf.interface_operation, dut3, [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2], 'startup', False])
    api_list.append([intf.interface_operation, dut4, [vars.D4D2P3, vars.D4D2P4, vars.D4D1P3, vars.D4D1P4], 'startup', False])
    utils.exec_all(True, api_list)

def mclag_module_unconfig():
    print_log("Starting MCLAG Base UnConfigurations...", "HIGH")
    utils.exec_foreach(True, mclag_peers, mclag.config_interfaces,  mclag_domain, mclag_interfaces, config='del')

    ### UnConfigure Mclag domain and interfaces
    dict1 = {'domain_id': mclag_domain, 'config': 'del'}
    dict2 = {'domain_id': mclag_domain, 'config': 'del'}
    pll.exec_parallel(True, mclag_peers, mclag.config_domain, [dict1, dict2])

    ### UnConfigure IP on PO-1 for L3 reachability between peers
    api_list = []
    api_list.append([ip.delete_ip_interface, dut1, 'Vlan' + str(mclag_vlan), peer1_ip, ip_mask])
    api_list.append([ip.delete_ip_interface, dut2, 'Vlan' + str(mclag_vlan), peer2_ip, ip_mask])
    utils.exec_all(True, api_list)

    ### UnConfigure Mclag vlan on PO-1
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, mclag_vlan, 'PortChannel1',True] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.delete_vlan, dut, mclag_vlan] for dut in mclag_peers])

    ### UnConfigure vlans on all PortChannels
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel2',True] for dut in mclag_peers])
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel3',True] for dut in [dut1, dut2, dut3]])
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, 'PortChannel4'] for dut in [dut1, dut2, dut4]])

    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel2', 'del'] for dut in mclag_peers])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel3', 'del'] for dut in [dut1, dut2, dut3]])
    utils.exec_all(True, [[vlan.config_vlan_range_members, dut, trunk_vlan_range, 'PortChannel5', 'del'] for dut in [dut1, dut2, dut4]])

    # UnConfigure access vlan on first TGEN ports of Mclag Peers as untagged
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, access_vlan, dut_tgn_port[(dut, 1)]] for dut in mclag_peers])
    # UnConfigure access vlan on first TGEN ports of Mclag clients as tagged
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, access_vlan, dut_tgn_port[(dut, 1)],True] for dut in [dut3, dut4]])
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
                                             mac_dst_mode="increment",
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph_dst)
            stream3 = tg_h.tg_traffic_config(mode='create', port_handle= tg_ph_src,rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment",
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count = stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1',port_handle2=tg_ph_dst)
        elif stdata['vlan_mode']['src'] == 'U':
            stream1 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_src, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment",
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_dst)
            stream3 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_src, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment",
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
                                             mac_dst_mode="increment",
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph_src)
            stream4 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment",
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan',
                                             vlan_id=stdata['vlan'], vlan_id_count=stdata['vlan_count'], vlan="enable",
                                             vlan_id_mode="increment", vlan_id_step='1', port_handle2=tg_ph_src)
        elif stdata['vlan_mode']['dst'] == 'U':
            stream2 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['dst_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['src_mac'],
                                             mac_dst_mode="increment",
                                             mac_dst_count=stdata['mac_count'], mac_dst_step="00:00:00:00:00:01",
                                             l2_encap='ethernet_ii_vlan', vlan="disable", port_handle2=tg_ph_src)
            stream4 = tg_h.tg_traffic_config(mode='create', port_handle=tg_ph_dst, rate_pps=tgen_rate_pps,
                                             mac_src=stdata['src_mac'], mac_src_mode="increment",
                                             mac_src_count=stdata['mac_count'], transmit_mode="continuous",
                                             mac_src_step="00:00:00:00:00:01", mac_dst=stdata['dst_mac'],
                                             mac_dst_mode="increment",
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
    #config_static_mac_streams()
    config_BUM_streams()


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
            tg_h.tg_traffic_control(action='run', handle=dest_stream_list)

    if action_ctrl == 'both':
        st.wait(duration)

    if action_ctrl == 'STOP' or  action_ctrl == 'both':
        stream_list = src_stream_list
        if direction == 'both':
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


def verify_traffic_rate(duts,port_list,expect_rate_list,threshold_list,comparison_flag='EQUAL'):
    '''
        Verify given list of ports is forwarding traffic with tx_rate within threshold
        :param duts:
        :param port_list:
        :param expect_rate_list:
        :param threshold_list:
        :return: False:, If given port is transmitting less than expect_rate
        :return: True:, If given port is transmitting more than expect_rate
        '''
    # Getting interfaces counter values on DUT

    print_log("Clear Interface counters", 'MED')
    utils.exec_all(True, [[port.clear_interface_counters, dut] for dut in dut_list])
    if len(expect_rate_list) != len(threshold_list):
        print_log('expect_rate_list & threshold_list should have same length.', 'ERROR')
        return False
    expect_rate_min_list = [expect_rate_list[x] - threshold_list[x] for x in range(len(expect_rate_list))]
    expect_rate_max_list = [expect_rate_list[x] + threshold_list[x] for x in range(len(expect_rate_list))]
    for port_num,expect_rate_min,expect_rate_max,dut in zip(port_list,expect_rate_min_list,expect_rate_max_list,duts):
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
                print_log("port:{}, tx_value:{}, i:{}".format(port_num, DUT_tx_value, i), 'MED')
                p_txmt = i['tx_pps']
                if p_txmt == 'N/A' or p_txmt is None: return False
                p_txmt = p_txmt.replace(",", "")
                p_txmt = p_txmt.strip('/s')
                if int(float(p_txmt)) < expect_rate_min and comparison_flag != 'MAX':
                    #ver_flag = False
                    print_log(
                        "Iteration:-{} FAIL: Expect tx_rate {} > {} for port:{} in DUT:{}".format(ver_loop_ctr + 1,
                                                                                                  DUT_tx_value,
                                                                                                  expect_rate_min, port_num,
                                                                                                  dut), 'ERROR')
                elif int(float(p_txmt)) > expect_rate_max and comparison_flag != 'MIN':
                    #ver_flag = False
                    print_log(
                        "Iteration:-{} FAIL: Expect tx_rate {} < {} for port:{} in DUT:{}".format(ver_loop_ctr + 1,
                                                                                                  DUT_tx_value,
                                                                                                  expect_rate_max, port_num,
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
    if src_stream_list =='ALL':
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
            dest_stream_list = ['ANY'] * len(src_stream_list)

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
            asicapi.dump_l2(dut)
            ### Collect ICCP FDB table
            if dut == dut1 or dut == dut2:
                mclag.verify_iccp_macs(dut, domain_id=mclag_domain, return_type='NULL')
            mclag.show_stateDB_macs(dut)
            mclag.show_appDB_macs(dut)
            mclag.show_asicDB_macs(dut)
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
            asicapi.dump_l2(dut)
            ### Collect ICCP FDB table
            if dut == dut1 or dut == dut2:
                mclag.verify_iccp_macs(dut, domain_id=mclag_domain, return_type='NULL')
            mclag.show_stateDB_macs(dut)
            mclag.show_appDB_macs(dut)
            mclag.show_asicDB_macs(dut)
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
            asicapi.dump_l2(dut)
            ### Collect ICCP FDB table
            if dut == dut1 or dut == dut2:
                mclag.verify_iccp_macs(dut, domain_id=mclag_domain, return_type='NULL')
            mclag.show_stateDB_macs(dut)
            mclag.show_appDB_macs(dut)
            mclag.show_asicDB_macs(dut)
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


def verify_mac_table(dut_list,expect_mac_list,vlan=None,port=None,type=None,mac_search=None,comp_flag='equal'):
    '''
    Verify MAC table entries in given list of duts is as in expect_mac_list
    It can compare the values are equal or not-equal based on comp_flag
    Count will be verified after the provided filters vlan/port/type applied
    '''
    print_log("Verifying MAC Table DUTs:{}, MACs:{} with filter vlan={} port={} type={}".format(dut_list,expect_mac_list,vlan, port, type),'MED')

    dut_list = dut_list if isinstance(dut_list, list) else [dut_list]
    expect_mac_list = expect_mac_list if isinstance(expect_mac_list, list) else [expect_mac_list]
    [result, exceptions] = utils.exec_all(True, [[show_verify_mac_table, dut, expected_mac, vlan, port, type, mac_search, comp_flag] \
                                                 for dut, expected_mac in zip(dut_list,expect_mac_list)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Table verification FAILED", "HIGH")
        return False
    else:
        print_log("MAC Table verification PASSED", "HIGH")
        return True

def check_mac_count(dut,expect_mac,comp_flag='equal'):
    mac_count = mac.get_mac_count(dut)
    if comp_flag == 'equal':
        if mac_count != expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} = Got: {}".format(dut,expect_mac,mac_count),'ERROR')
            show_verify_mac_table(dut,expect_mac,comp_flag=comp_flag)
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True
    elif comp_flag == 'minimum':
        if mac_count < expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} <= Got: {}".format(dut,expect_mac,mac_count),'ERROR')
            show_verify_mac_table(dut,expect_mac,comp_flag=comp_flag)
            return False
        else:
            print_log(
                "PASS:Verify MAC count on {} passed, Expect: {} <= Got: {}".format(dut, expect_mac, mac_count), 'MED')
            return True
    elif comp_flag == 'not-equal':
        if mac_count == expect_mac:
            print_log(
                "FAIL:Verify MAC count on {} failed, Expect: {} = Got: {}".format(dut, expect_mac, mac_count), 'ERROR')
            show_verify_mac_table(dut,expect_mac,comp_flag=comp_flag)
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
    [result, exceptions] = utils.exec_all(True, [[check_mac_count, dut, expected_mac, comp_flag] \
                                                 for dut, expected_mac in zip(dut_list,expect_mac_list)])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log("MAC Count verification FAILED", "HIGH")
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
        dict2 = {'domain_id': mclag_domain, 'mclag_intf': po,\
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

    print_log("Verify the LAGs configured in the topology is up", 'MED')

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

    ### Verify L3 reachability is fine
    print_log("Verify L3 reachability across Mclag peers", 'MED')
    if check_ping(dut1,peer2_ip):
        print_log("L3 reachabilty between Mclag Peers PASSED", "HIGH")
    else:
        print_log("L3 reachabilty between Mclag Peers FAILED", "HIGH")
        ping_fail += 1
        final_result = False

    ### Verify MCLAG domain and attributes
    if verify_mclag_state(mclag_data):
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
    global fb_fail
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
    fb_fail = 0

def post_result_handler():
    global final_result, clear_mac_fail, traffic_forward_fail, flooding_fail, mac_count_fail, bum_traffic_fail, \
        mac_aging_fail, mclag_state_fail, mclag_intf_fail, po_fail, intf_fail, fb_fail
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
        if fb_fail > 0:
            fail_msg += 'Fallback state Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))

def clear_mac_verify(duts,mac_count_list=[1,1,0,0]):
    global clear_mac_fail, final_result

    utils.exec_all(True, [[mac.clear_mac, dut] for dut in duts])
    dict_list = []
    for i in range(len(mac_count_list)):
        dict_list += [{'expect_mac': mac_count_list[i]}]
    if not retry_parallel(check_mac_count, dict_list=dict_list, dut_list=duts, retry_count=5, delay=2):
        print_log("MAC on all Duts in Failed state")
        utils.exec_all(True, [[mac.get_mac, dut] for dut in dut_list])
        final_result = False
        clear_mac_fail += 1


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


@pytest.fixture(scope="function")
def enable_client_ports():
    ###Enaable client ports
    api_list = []
    api_list.append([intf.interface_operation, dut3, [vars.D3D1P1, vars.D3D1P2, vars.D3D2P1, vars.D3D2P2], 'startup', False])
    api_list.append([intf.interface_operation, dut4, [vars.D4D2P3, vars.D4D2P4, vars.D4D1P3, vars.D4D1P4], 'startup', False])
    utils.exec_all(True, api_list)
    yield


def verify_mclag_fallback_state(po_name):
    '''
    This verification to be used only when fallback is operational.
    FB Op state cannot be enable-enable or Disable-Disable for a PO.
    If FB Op state is Disabled Disabled return False.
    If not find which mclag peer has active port (Op State=Enable) from "show interfaces portchannel PO3 fallback" output.
    For that peer check PO status is UP. and other peer has PO status Dw.
    :param po_name:
    :return:
    '''
    print_log("Check MCLAG Fallback Operational state ", 'HIGH')

    if verify_mclag_fallback(po_name, ["Enabled", "Enabled"], ["Enabled", "Disabled"]):
        active_port_node = dut1
        print_log("Fallback state is operational on active Mclag Peer:{} for:{}".format(active_port_node, po_name),
                  'MED')
    elif verify_mclag_fallback(po_name, ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
        active_port_node = dut2
        print_log("Fallback state is operational on standby Mclag Peer:{} for:{}".format(active_port_node, po_name),
                  'MED')
    elif verify_mclag_fallback(po_name,["Enabled","Enabled"],["Enabled","Enabled"],'NO',False):
        print_log("FAIL: Fallback operational state is Enabled on both node for:{}".format(po_name),'ERROR')
        return False,None
    elif verify_mclag_fallback(po_name,["Enabled","Enabled"],["Disabled","Disabled"],'NO',False):
        print_log("FAIL: Fallback operational state is Disabled on both node for:{}".format(po_name), 'ERROR')
        return False,None
    else:
        ###When Command output is empty set active node to be None
        return False, None

    ver_flag = True
    print_log("Verify PortChannel State ", 'HIGH')
    if active_port_node == dut1:
        if not retry_func(verify_fallback_po_state, po_name=po_name, po_states=['up', 'down']):
            ver_flag = False
            print_log("FAIL: Fallback PO state is incorrect. Expect: UP in {} and DOWN in {}".format(dut1,dut2),\
                      'ERROR')
        else:
            print_log("PASS: Fallback PO state is correct. Got: UP in {} and DOWN in {}".format(dut1, dut2),
                      'ERROR')
    elif active_port_node == dut2:
        if not retry_func(verify_fallback_po_state, po_name=po_name, po_states=['down', 'up']):
            ver_flag = False
            print_log("FAIL: Fallback PO state is incorrect. Expect: UP in {} and DOWN in {}".format(dut2, dut1), \
                      'ERROR')
        else:
            print_log("PASS: Fallback PO state is correct. Got: UP in {} and DOWN in {}".format(dut2, dut1),
                      'ERROR')

    return ver_flag,active_port_node


def verify_mclag_fallback(po_name,fb_cfg_states,fb_op_states,report_failure='YES',comparison_flag=True):
    ver_flag = True
    if comparison_flag == True:
        print_log("Check If Operational state for the PO:{} is {}-{}".format(po_name,fb_op_states[0],fb_op_states[1]), 'MED')
    else:
        print_log("Check If Operational state for the PO:{} is NOT {}-{}".format(po_name, fb_op_states[0], fb_op_states[1]),
                  'MED')
    dict1 = {'port_channel_name': po_name, 'fallback_config': fb_cfg_states[0], 'fallback_oper_status':fb_op_states[0]}
    dict2 = {'port_channel_name': po_name, 'fallback_config': fb_cfg_states[1], 'fallback_oper_status':fb_op_states[1]}
    [result, exceptions] = pll.exec_parallel(True, mclag_peers, po.verify_lacp_fallback, [dict1, dict2])
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        if report_failure == 'YES':
            print_log('Portchannel-{} fallback state not as expected'.format(po_name), 'ERROR')
        ver_flag = False
    return ver_flag

def verify_client_lacp_state(dut, po_name, po_state):
    ver_flag = True
    api_list = []
    api_list.append([po.verify_portchannel_state, dut, po_name, po_state])
    #api_list.append([po.verify_portchannel_state, dut4, po_name, po_states[1]])
    [result, exceptions] = utils.exec_all(True, api_list)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log(
            'Portchannel-{} state not {} in client:{}'.format(po_name,po_state,dut), 'ERROR')
        ver_flag = False
    return ver_flag


def verify_fallback_po_state(po_name,po_states):
    ver_flag = True
    api_list = []
    api_list.append([po.verify_portchannel_state, dut1, po_name, po_states[0]])
    api_list.append([po.verify_portchannel_state, dut2, po_name, po_states[1]])
    [result, exceptions] = utils.exec_all(True, api_list)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log(
            'Portchannel-{} state not as expected'.format(po_name), 'ERROR')
        ver_flag = False
    return ver_flag


def add_rem_vlans_tagged(dut,vlan_list, port, oper_flag='ADD'):
    if oper_flag == 'ADD':
        if len(vlan_list) > 1:
            trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
            vlan.config_vlan_range_members(dut, trunk_vlan_range, port)
        else:
            vlan.add_vlan_member(dut, access_vlan, port,True)
    else:
        if len(vlan_list) > 1:
            trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
            vlan.config_vlan_range_members(dut, trunk_vlan_range, port,'del')
        else:
            vlan.delete_vlan_member(dut, access_vlan, port,True)


def test_mclag_fallback_functionality():
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, fb_fail, bum_traffic_fail
    tc1_result = 0
    tc2_result = 0
    tc3_result = 0
    tc_list = ['FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic','FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic','FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby']
    print_log(
        "START test_mclag_fallback_functionality==>Sub-Test:Verify MCLAG Fallback with 1 member link each\n TCs:<{}>".format(
            tc_list),
        "HIGH")
    ##For PO3, Make active port in active mclag
    ##For PO5,Make active port in standby mclag
    api_list = []
    api_list.append([intf.interface_operation, dut3, vars.D3D1P1, 'startup', False])
    api_list.append([intf.interface_operation, dut4, vars.D4D2P3, 'startup', False])
    utils.exec_all(True, api_list)

    #Verify PO state in both peers
    if not retry_func(verify_fallback_po_state,po_name="PortChannel3",po_states=['up','down']):
        po_fail += 1
        tc1_result += 1
        print_log("PortChannel3 state FAILED, Expect UP in {} and DOWN in {}".format(dut1,dut2),'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message", "PO3 state failed")
    if not retry_func(verify_fallback_po_state,po_name="PortChannel5",po_states=['down','up']):
        po_fail +=1
        tc1_result += 1
        print_log("PortChannel5 state FAILED, Expect DOWN in {} and UP in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message", "PO5 state failed")

    #Verify expected member port is up -- no need to veriy port
    if not verify_mclag_fallback("PortChannel3",["Enabled","Enabled"],["Enabled","Disabled"]):
        fb_fail += 1
        tc1_result += 1
        print_log("PortChannel3 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message", "PO3 fallback state failed")

    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
        fb_fail += 1
        tc1_result += 1
        print_log("PortChannel5 Fallback state FAILED, Expect Disabled in {} and Enabled in {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message", "PO5 fallback state failed")
    ###Verify Mclag Interface state

    ##For PO3, enable one port towards standby Mclag
    ##For PO5, enable one port towards active Mclag
    ###Verify active port remains same
    api_list = []
    api_list.append([intf.interface_operation, dut3, vars.D3D2P1, 'startup', False])
    api_list.append([intf.interface_operation, dut4, vars.D4D1P3, 'startup', False])
    utils.exec_all(True, api_list)

    # Verify PO state in both peers
    if not verify_fallback_po_state('PortChannel3', ['up', 'down']):
        po_fail += 1
        tc1_result += 1
        print_log("PortChannel3 state FAILED, Expect UP in {} and DOWN in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message", "PO3 state failed")
    if not verify_fallback_po_state('PortChannel5', ['down', 'up']):
        po_fail += 1
        tc1_result += 1
        print_log("PortChannel5 state FAILED, Expect DOWN in {} and UP in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message", "PO5 state failed")

    if not verify_mclag_fallback("PortChannel3", ["Enabled", "Enabled"], ["Enabled", "Disabled"]):
        fb_fail += 1
        tc1_result += 1
        print_log("PortChannel3 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message",
                          "PO3 fallback state failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
        fb_fail += 1
        tc1_result += 1
        print_log("PortChannel5 Fallback state FAILED, Expect Disabled in {} and Enabled in {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message",
                          "PO5 fallback state failed")

    clear_mac_verify(dut_list)

    st_key=str(trunk_base_vlan)+":CD"
    client_traffic_src = stream_data[st_key]['streamXY']
    client_traffic_dest = stream_data[st_key]['streamYX']
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="START")
    if not verify_traffic(src_stream_list=client_traffic_dest, dest_stream_list=client_traffic_src,comp_type='packet_rate', direction='both'):
        traffic_forward_fail += 1
        tc1_result += 1
        print_log("FAIL: One member port PO: Traffic Forwarding in Fallback state failed",'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message", "Traffic Forwarding in Fallback state failed")
    ### Verify Tx rate on each PO member expected port
    devices = [dut3,dut4,dut3,dut4]
    rx_ports = [vars.D3D1P1, vars.D4D2P3, vars.D3D2P1, vars.D4D1P3]
    expect_rate_list = [1000, 1000, 0, 0]
    threshold_list = [100, 100, 100, 100]
    # threshold_list = [250, 250, 250, 250]
    if not verify_traffic_rate(devices, rx_ports, expect_rate_list, threshold_list, 'MIN'):
        final_result = False
        traffic_forward_fail += 1
        tc1_result += 1
        print_log("FAIL: One member port PO: Traffic Forwarding port in Fallback state failed",'HIGH')
        debug_traffic_fail()
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic", "test_case_failure_message",
                          "Traffic Forwarding Port in Fallback state failed")
    else:
        print_log("PASS: One member port PO: Traffic Forwarding port in Fallback state passed",'HIGH')

    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="STOP")
    if tc1_result == 0:
        st.report_tc_pass('FtOpSoSwMclagFallbackOneMemberLinkVerifyTraffic', "test_case_passed")

    ##For PO3 Add client member port towards standby to PO (Remove vlan configs first)
    ##For PO5 Add client member port towards active to PO
    ###Verify LACP side comes up

    tc_list = ['FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby']
    print_log(
        "START test_mclag_fallback_functionality==>Sub-Test:Verify MCLAG Fallback with LACP on 1 member link\n TCs:<{}>".format(
            tc_list),
        "HIGH")
    ###Remove vlan configs from PO member
    add_rem_vlans_tagged(dut3,[80], vars.D3D2P1, oper_flag='DEL')
    add_rem_vlans_tagged(dut3, [81, 82, 83], vars.D3D2P1, oper_flag='DEL')
    add_rem_vlans_tagged(dut4, [81, 82, 83], vars.D4D1P3, oper_flag='DEL')

    api_list = []
    api_list.append([po.add_portchannel_member, dut3, "PortChannel3", vars.D3D2P1])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", vars.D4D1P3])
    utils.exec_all(True, api_list)

    api_list = []
    api_list.append([verify_client_lacp_state, dut3, "PortChannel3", 'up'])
    api_list.append([verify_client_lacp_state, dut4, "PortChannel5", 'up'])
    [result, exceptions] = utils.exec_all(True, api_list)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('FAIL: LACP did not come UP in client', 'HIGH')
        po_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby", "test_case_failure_message",
                          "Client LACP state failed")
    else:
        print_log('PASS: LACP has come UP in client', 'HIGH')

    tc_list = ['FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby']
    print_log(
        "START test_mclag_fallback_functionality==>Sub-Test:Verify MCLAG Fallback with 2 member link each in POs\n TCs:<{}>".format(
            tc_list),
        "HIGH")
    api_list = []
    api_list.append([intf.interface_operation, dut3, vars.D3D1P2, 'startup', False])
    api_list.append([intf.interface_operation, dut4, vars.D4D2P4, 'startup', False])
    utils.exec_all(True, api_list)

    if not verify_fallback_po_state('PortChannel3', ['down','up']):
        po_fail += 1
        tc2_result += 1
        print_log("PortChannel5 state FAILED, Expect DOWN in {} and UP in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby", "test_case_failure_message", "PO3 state failed")
    if not verify_fallback_po_state('PortChannel5', ['up', 'down']):
        po_fail += 1
        tc2_result += 1
        print_log("PortChannel5 state FAILED, Expect UP in {} and DOWN in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby", "test_case_failure_message", "PO5 state failed")


    if not verify_mclag_fallback("PortChannel3", ["Enabled", "Enabled"], ["Disabled", "Disabled"]):
        fb_fail += 1
        tc2_result += 1
        print_log("PortChannel3 Fallback state FAILED, Expect Disabled in {} and Disabled in {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby", "test_case_failure_message",
                          "PO3 fallback state failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Disabled"]):
        fb_fail += 1
        tc2_result += 1
        print_log("PortChannel5 Fallback state FAILED, Expect Disabled in {} and Disabled in {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby", "test_case_failure_message",
                          "PO5 fallback state failed")

    if tc2_result == 0:
        st.report_tc_pass('FtOpSoSwMclagFallbackOneMemberLinkLACPonStandby', "test_case_passed")
    #Disable LACP and add 4th port to each nodes
    api_list = []
    api_list.append([po.delete_portchannel_member, dut3, "PortChannel3", vars.D3D2P1])
    api_list.append([po.delete_portchannel_member, dut4, "PortChannel5", vars.D4D1P3])
    utils.exec_all(True, api_list)

    ###Remove vlan configs from PO member
    add_rem_vlans_tagged(dut3, [80], vars.D3D2P1, oper_flag='ADD')
    add_rem_vlans_tagged(dut3, [81, 82, 83], vars.D3D2P1, oper_flag='ADD')
    add_rem_vlans_tagged(dut4, [81, 82, 83], vars.D4D1P3, oper_flag='ADD')

    api_list = []
    api_list.append([intf.interface_operation, dut3, vars.D3D2P2, 'startup', False])
    api_list.append([intf.interface_operation, dut4, vars.D4D1P4, 'startup', False])
    utils.exec_all(True, api_list)

    print_log("Wait for LACP timer for LACP ports to be down")
    st.wait(90)
    ### Expect LACP to go down after timer 90 sec and which port will come up ? same or last added port in sam node ?
    ## Ans - any one port just PO to be UP
    [result_po3,active_node_po3] = verify_mclag_fallback_state('PortChannel3')
    if not result_po3:
        fb_fail += 1
        tc3_result += 1
        print_log("PortChannel3 Fallback state FAILED, Expect Fallback to be enabled on either one of {} and {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message", "Fallback state of PO3 failed")
    else:
        ## Shut both member ports in active_port_node returned above and check other node takes over.
        if active_node_po3 == dut1:
            api_list = []
            api_list.append([intf.interface_operation, dut3, [vars.D3D1P1, vars.D3D1P2], 'shutdown', False])
            # api_list.append([intf.interface_operation, dut4, vars.D4D1P4, 'startup', False])
            utils.exec_all(True, api_list)

            if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['down', 'up']):
                po_fail += 1
                tc3_result += 1
                print_log("PortChannel3 state FAILED, Expect DOWN in {} and UP in {}".format(dut1, dut2), 'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message",
                                  "PO3 state failed")

            if not verify_mclag_fallback("PortChannel3", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
                fb_fail += 1
                tc3_result += 1
                print_log(
                    "PortChannel3 Fallback state FAILED, Expect Disabled in {} and Enabled in {}".format(dut1, dut2),
                    'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message",
                                  "PO3 fallback state failed")
        elif active_node_po3 == dut2:
            api_list = []
            api_list.append([intf.interface_operation, dut3, [vars.D3D2P1, vars.D3D2P2], 'shutdown', False])
            # api_list.append([intf.interface_operation, dut4, vars.D4D1P4, 'startup', False])
            utils.exec_all(True, api_list)

            if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['up', 'down']):
                po_fail += 1
                tc3_result += 1
                print_log("PortChannel3 state FAILED, Expect UP in {} and DOWN in {}".format(dut1, dut2), 'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message",
                                  "PO3 state failed")

            if not verify_mclag_fallback("PortChannel3", ["Enabled", "Enabled"], ["Enabled", "Disabled"]):
                fb_fail += 1
                tc3_result += 1
                print_log(
                    "PortChannel3 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2),
                    'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message",
                                  "PO3 fallback state failed")

    [result_po5, active_node_po5] = verify_mclag_fallback_state('PortChannel5')
    if not result_po5:
        fb_fail += 1
        tc3_result += 1
        print_log(
            "PortChannel5 Fallback state FAILED, Expect Fallback to be enabled on either one of {} and {}".format(dut1,
                                                                                                                  dut2),
            'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message", "Fallback state of PO5 failed")
    else:
        ## Shut both member ports in active_port_node returned above and check other node takes over.
        if active_node_po5 ==dut1:
            api_list = []
            api_list.append([intf.interface_operation, dut4, [vars.D4D1P3,vars.D4D1P4], 'shutdown', False])
            #api_list.append([intf.interface_operation, dut4, vars.D4D1P4, 'startup', False])
            utils.exec_all(True, api_list)

            if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['down', 'up']):
                po_fail += 1
                tc3_result += 1
                print_log("PortChannel5 state FAILED, Expect DOWN in {} and UP in {}".format(dut1, dut2), 'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message", "PO5 state failed")

            if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
                fb_fail += 1
                tc3_result += 1
                print_log("PortChannel5 Fallback state FAILED, Expect Disabled in {} and Enabled in {}".format(dut1, dut2),
                          'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message", "PO5 fallback state failed")

        elif active_node_po5 ==dut2:
            api_list = []
            api_list.append([intf.interface_operation, dut4, [vars.D4D2P3,vars.D4D2P4], 'shutdown', False])
            #api_list.append([intf.interface_operation, dut4, vars.D4D1P4, 'startup', False])
            utils.exec_all(True, api_list)

            if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['up', 'down']):
                po_fail += 1
                tc3_result += 1
                print_log("PortChannel5 state FAILED, Expect UP in {} and DOWN in {}".format(dut1, dut2), 'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message", "PO5 state failed")

            if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Enabled", "Disabled"]):
                fb_fail += 1
                tc3_result += 1
                print_log("PortChannel5 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2),
                          'HIGH')
                st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message", "PO5 fallback state failed")

    ## Send BUM traffic & verify
    clear_mac_verify(dut_list)
    start_stop_traffic(src_stream_list=bum_src_streams, direction='single', action_ctrl='START')

    expect_mac_tc = [5, 5, 4, 4]
    if not verify_mac_table_count(dut_list, expect_mac_tc):
        final_result = False
        mac_count_fail += 1
    # verify_traffic_path()
    rx_ports = [dut_tgn_port[(dut1, 2)], dut_tgn_port[(dut2, 2)], dut_tgn_port[(dut3, 1)], dut_tgn_port[(dut4, 1)]]
    expect_rate_list = [9000, 9000, 9000, 9000]
    threshold_list = [900, 900, 900, 900]
    # threshold_list = [250, 250, 250, 250]
    if not verify_traffic_rate(dut_list, rx_ports, expect_rate_list, threshold_list, 'MIN'):
        final_result = False
        bum_traffic_fail += 1
        tc3_result += 1
        print_log("2 member link fallback:BUM traffic verification FAILED, expect ~9000pkt/sec on TGEN ports", 'ERROR')
        debug_traffic_fail()
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic", "test_case_failure_message",
                          "BUM Traffic Forwarding in Fallback state failed")
    else:
        print_log("2 member link fallback:BUM traffic verification PASSED", 'MED')

    start_stop_traffic(src_stream_list=bum_src_streams, direction='single', action_ctrl='STOP')

    if tc3_result == 0:
        st.report_tc_pass('FtOpSoSwMclagFallbackTwoMemberLinkVerifyTraffic', "test_case_passed")

    if po_fail > 0 or fb_fail > 0 or traffic_forward_fail > 0 or mac_count_fail > 0 or bum_traffic_fail >0 :
        final_result = False
    post_result_handler()


def test_mclag_fallback_lacp_formation(enable_client_ports):
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, fb_fail
    tc1_result = 0
    tc2_result = 0
    tc3_result = 0
    tc_list = ['FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP',
               'FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP','FtOpSoSwMclagFallbackClientReloadNoLACP']
    print_log(
        "START test_mclag_fallback_lacp_formation==>Sub-Test:Verify MCLAG Fallback with sequence of LACP configurations\n TCs:<{}>".format(
            tc_list),
        "HIGH")
    #Save config on Clients with client ports enabled
    utils.exec_all(True, [[boot.config_save, dut] for dut in mclag_clients])

    # Add client ports as PO members
    ##- enable  one lacp client port towards same active fallback node active & different active fallback node
    ###Remove vlan configs from PO member
    add_rem_vlans_tagged(dut3, [80], vars.D3D1P2, oper_flag='DEL')
    add_rem_vlans_tagged(dut3, [81, 82, 83], vars.D3D1P2, oper_flag='DEL')
    add_rem_vlans_tagged(dut4, [81, 82, 83], vars.D4D1P3, oper_flag='DEL')

    api_list = []
    api_list.append([po.add_portchannel_member, dut3, "PortChannel3", vars.D3D1P2])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", vars.D4D1P3])
    utils.exec_all(True, api_list)

    api_list = []
    api_list.append([verify_client_lacp_state, dut3, "PortChannel3", 'up'])
    api_list.append([verify_client_lacp_state, dut4, "PortChannel5", 'up'])
    [result, exceptions] = utils.exec_all(True, api_list)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('FAIL: LACP did not come UP in client', 'ERROR')
        po_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message",
                          "Client LACP state failed")
    else:
        print_log('PASS: LACP has come UP in client', 'MED')

    if not retry_func(verify_fallback_po_state,po_name="PortChannel3",po_states=['up','down']):
        po_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message", "PO3 state failed")
    if not retry_func(verify_fallback_po_state,po_name="PortChannel5",po_states=['up','down']):
        po_fail +=1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message", "PO5 state failed")

    print_log("Verify fallback operation state is disabled on both Mclag Peers",'MED')
    #Verify expected member port is up -- no need to veriy port
    if not verify_mclag_fallback("PortChannel3",["Enabled","Enabled"],["Disabled","Disabled"]):
        fb_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message", "PO3 fallback state failed")
    #st.report_tc_fail("ID", "test_case_failure_message", "Fallback state of PO3 failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Disabled"]):
        fb_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message", "PO5 fallback state failed")

    clear_mac_verify(dut_list)

    st_key = str(trunk_base_vlan) + ":CD"
    client_traffic_src = stream_data[st_key]['streamXY']
    client_traffic_dest = stream_data[st_key]['streamYX']
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="START")
    if not verify_traffic(src_stream_list=client_traffic_dest, dest_stream_list=client_traffic_src,
                          comp_type='packet_rate', direction='both'):
        traffic_forward_fail += 1
        tc1_result += 1
        print_log("One member port PO: Traffic Forwarding with LACP configs failed", 'MED')
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message",
                          "Traffic Forwarding one member LACP link failed")
    ### Verify Tx rate on each PO member expected port
    devices = [dut3, dut4, dut3, dut4]
    rx_ports = [vars.D3D1P2, vars.D4D1P3, vars.D3D1P1, vars.D4D2P3]
    expect_rate_list = [1000, 1000, 0, 0]
    threshold_list = [100, 100, 100, 100]
    # threshold_list = [250, 250, 250, 250]
    if not verify_traffic_rate(devices, rx_ports, expect_rate_list, threshold_list, 'MIN'):
        final_result = False
        traffic_forward_fail += 1
        tc1_result += 1
        print_log("Traffic forwarding port FAILED", 'ERROR')
        debug_traffic_fail()
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message",
                          "Traffic Forwarding Port with LACP failed")
    else:
        print_log("Traffic forwarding port PASSED", 'MED')

    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="STOP")

    ##- Complete 2nd link for above case
    print_log("Trigger:===> Add 2nd LACP link to POs on client nodes",'MED')
    ###Remove vlan configs from PO member
    add_rem_vlans_tagged(dut3, [80], vars.D3D1P1, oper_flag='DEL')
    add_rem_vlans_tagged(dut3, [81, 82, 83], vars.D3D1P1, oper_flag='DEL')
    add_rem_vlans_tagged(dut4, [81, 82, 83], vars.D4D2P4, oper_flag='DEL')

    api_list = []
    api_list.append([po.add_portchannel_member, dut3, "PortChannel3", vars.D3D1P1])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", vars.D4D2P4])
    utils.exec_all(True, api_list)

    api_list = []
    api_list.append([verify_client_lacp_state, dut3, "PortChannel3", 'up'])
    api_list.append([verify_client_lacp_state, dut4, "PortChannel5", 'up'])
    [result, exceptions] = utils.exec_all(True, api_list)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('FAIL: LACP did not come UP in client', 'ERROR')
        po_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message",
                          "Client LACP state failed")
    else:
        print_log('PASS: LACP has come UP in client', 'MED')

    if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['up', 'down']):
        po_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message", "PO3 state failed")
    if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['up', 'up']):
        po_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP", "test_case_failure_message", "PO5 state failed")

    if tc1_result == 0:
        st.report_tc_pass('FtOpSoSwMclagFallbackTwoMemberLinkVerifyLACP', "test_case_passed")

    ##- Shut lacp ports and check fallback to other node
    print_log("Trigger:===> Shut LACP ports on client node for PortChannel3 to verify fallback on other node", 'MED')
    api_list = []
    api_list.append([intf.interface_operation, dut3, [vars.D3D1P1, vars.D3D1P2], 'shutdown', False])
    #api_list.append([intf.interface_operation, dut4, [vars.D4D1P, vars.D4D2P4], 'shutdown', False])
    utils.exec_all(True, api_list)
    st.wait(90)
    api_list = []
    api_list.append([verify_client_lacp_state, dut3, "PortChannel3", 'down'])
    api_list.append([verify_client_lacp_state, dut4, "PortChannel5", 'up'])
    [result, exceptions] = utils.exec_all(True, api_list)
    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('FAIL: LACP did not come UP in client', 'ERROR')
        po_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message",
                          "Client LACP state failed")
    else:
        print_log('PASS: LACP has come UP in client', 'MED')

    if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['down', 'up']):
        po_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message", "PO3 state failed")
    if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['up', 'up']):
        po_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message", "PO5 state failed")

    if not verify_mclag_fallback("PortChannel3",["Enabled","Enabled"],["Disabled","Enabled"]):
        fb_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message", "PO3 fallback state failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Disabled"]):
        fb_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message",
                          "PO5 fallback state failed")

    ##- Enable LACP on  both ports the other node & enable back lacp ports
    print_log("Trigger:===> Enable back LACP ports of PortChannel3 and add remaining links to LACP for both POs", 'MED')
    api_list = []
    api_list.append([intf.interface_operation, dut3, [vars.D3D1P1, vars.D3D1P2], 'startup', False])
    # api_list.append([intf.interface_operation, dut4, [vars.D4D1P, vars.D4D2P4], 'shutdown', False])
    utils.exec_all(True, api_list)

    ###Remove vlan configs from PO member
    add_rem_vlans_tagged(dut3, [80], vars.D3D2P1, oper_flag='DEL')
    add_rem_vlans_tagged(dut3, [81, 82, 83], vars.D3D2P1, oper_flag='DEL')
    add_rem_vlans_tagged(dut4, [81, 82, 83], vars.D4D1P4, oper_flag='DEL')

    add_rem_vlans_tagged(dut3, [80], vars.D3D2P2, oper_flag='DEL')
    add_rem_vlans_tagged(dut3, [81, 82, 83], vars.D3D2P2, oper_flag='DEL')
    add_rem_vlans_tagged(dut4, [81, 82, 83], vars.D4D2P3, oper_flag='DEL')

    api_list = []
    api_list.append([po.add_portchannel_member, dut3, "PortChannel3", [vars.D3D2P1, vars.D3D2P2]])
    api_list.append([po.add_portchannel_member, dut4, "PortChannel5", [vars.D4D2P3, vars.D4D1P4]])
    utils.exec_all(True, api_list)
    ###Verify Mclag Interface state

    if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['up', 'up']):
        po_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message", "PO3 state failed")
    if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['up', 'up']):
        po_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message", "PO5 state failed")

    if not verify_mclag_fallback("PortChannel3",["Enabled","Enabled"],["Disabled","Disabled"]):
        fb_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message", "PO3 fallback state failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Disabled"]):
        fb_fail += 1
        tc2_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message",
                          "PO5 fallback state failed")

    clear_mac_verify(dut_list)

    start_stop_traffic(action_ctrl="START")
    if not verify_traffic(src_stream_list=base_dst_streams, dest_stream_list=base_src_streams,
                          comp_type='packet_rate', direction='both'):
        traffic_forward_fail += 1
        tc2_result += 1
        print_log("All ports LACP configured: Traffic Forwarding with LACP configs failed", 'MED')
        st.report_tc_fail("FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP", "test_case_failure_message",
                          "Traffic Forwarding with LACP added to all client ports failed")
    start_stop_traffic(action_ctrl="STOP")
    ###Wait added for run on ixia to stop traffic
    st.wait(1)
    if tc2_result == 0:
        st.report_tc_pass('FtOpSoSwMclagFallbackTwoMemberLinkShutTwoLinksVerifyLACP', "test_case_passed")

    #Reload client and verify fallback enabled as lacp configs lost on cient
    print_log("Trigger:===> Reboot client nodes so that LACP configs lost and verify fallback is Enabled", 'MED')
    utils.exec_foreach(True, mclag_clients, st.reboot)
    ###Verify Mclag Interface state
    result_po3 = verify_mclag_fallback_state('PortChannel3')[0]
    if not result_po3:
        fb_fail += 1
        tc3_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackClientReloadNoLACP", "test_case_failure_message", "Fallback state of PO3 failed")
    result_po5 = verify_mclag_fallback_state('PortChannel5')[0]
    if not result_po5:
        fb_fail += 1
        tc3_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackClientReloadNoLACP", "test_case_failure_message", "Fallback state of PO5 failed")

    clear_mac_verify(dut_list)

    st_key = str(trunk_base_vlan) + ":CD"
    client_traffic_src = stream_data[st_key]['streamXY']
    client_traffic_dest = stream_data[st_key]['streamYX']
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="START")
    if not verify_traffic(src_stream_list=client_traffic_dest, dest_stream_list=client_traffic_src,
                          comp_type='packet_rate', direction='both'):
        traffic_forward_fail += 1
        tc3_result += 1
        print_log("Client Reboots: Traffic Forwarding in Fallback state failed", 'MED')
        st.report_tc_fail("FtOpSoSwMclagFallbackClientReloadNoLACP", "test_case_failure_message",
                          "Traffic Forwarding in Fallback state failed after client reboot")
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="STOP")

    if tc3_result == 0:
        st.report_tc_pass('FtOpSoSwMclagFallbackClientReloadNoLACP', "test_case_passed")

    if po_fail > 0 or fb_fail > 0 or traffic_forward_fail > 0 :
        final_result = False
    post_result_handler()


def test_mclag_fallback_ICL_shut(enable_client_ports):
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, fb_fail
    tc1_result = 0
    tc_list = ['FtOpSoSwMclagFallbackShutICL']
    print_log(
        "START test_mclag_fallback_ICL_shut==>Sub-Test:Verify MCLAG Fallback with ICL link shut\n TCs:<{}>".format(
            tc_list),
        "HIGH")

    result_po3 = verify_mclag_fallback_state('PortChannel3')[0]
    if not result_po3:
        fb_fail += 1
        tc1_result += 1
        print_log(
            "PortChannel3 Fallback state FAILED, Expect Fallback to be enabled on either one of {} and {}".format(dut1,
                                                                                                                  dut2),
            'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message",
                          "Fallback state of PO3 failed")
    result_po5 = verify_mclag_fallback_state('PortChannel5')[0]
    if not result_po5:
        fb_fail += 1
        tc1_result += 1
        print_log(
            "PortChannel5 Fallback state FAILED, Expect Fallback to be enabled on either one of {} and {}".format(dut1,
                                                                                                                  dut2),
            'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message",
                          "Fallback state of PO5 failed")

    ### Disable the ICCP link
    port_list = {}
    port_list[dut2] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_shutdown, dut, port_list[dut]] for dut in [dut2]])
    ### Verify MCLAG domain and attributes after waiting for session_timeout timer + 2 sec delay
    session_wait_time = session_def_time + 2
    print_log("Wait for session timeout timer:{}".format(session_wait_time))
    st.wait(session_wait_time)
    mclag_data[dut1]['session_status'] = 'ERROR'
    mclag_data[dut2]['session_status'] = 'ERROR'
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification with ICCP link down PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification with ICCP link down FAILED", "HIGH")
        mclag_state_fail += 1
        tc1_result += 1
        final_result = False
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message",
                      "Mclag session not down")

    if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['up', 'down']):
        po_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message", "PO3 state failed")
    if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['up', 'down']):
        po_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message", "PO5 state failed")


    if not verify_mclag_fallback("PortChannel3",["Enabled","Enabled"],["Enabled","Disabled"]):
        fb_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message", "PO3 fallback state failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Enabled", "Disabled"]):
        fb_fail += 1
        tc1_result += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message", "PO5 fallback state failed")


    ### Enable back the ICCP link
    port_list = {}
    port_list[dut2] = 'PortChannel1'
    utils.exec_all(True, [[intf.interface_noshutdown, dut, port_list[dut]] for dut in [dut2]])
    ### Verify MCLAG domain and attributes after waiting for session_timeout timer + 2 sec delay
    session_wait_time = 2
    print_log("Wait for session timeout timer:{}".format(session_wait_time))
    st.wait(session_wait_time)
    mclag_data[dut1]['session_status'] = 'OK'
    mclag_data[dut2]['session_status'] = 'OK'
    if verify_mclag_state(mclag_data):
        print_log("MCLAG Domain State verification with ICCP link up PASSED", "HIGH")
    else:
        print_log("MCLAG Domain State verification with ICCP link up FAILED", "HIGH")
        mclag_state_fail += 1
        tc1_result += 1
        final_result = False
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message",
                          "Mclag session not established")
    result_po3 = verify_mclag_fallback_state('PortChannel3')[0]
    if not result_po3:
        fb_fail += 1
        tc1_result += 1
        print_log(
            "PortChannel3 Fallback state FAILED, Expect Fallback to be enabled on either one of {} and {}".format(dut1,
                                                                                                                  dut2),
            'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message",
                          "Fallback state of PO3 failed")
    result_po5 = verify_mclag_fallback_state('PortChannel5')[0]
    if not result_po5:
        fb_fail += 1
        tc1_result += 1
        print_log(
            "PortChannel5 Fallback state FAILED, Expect Fallback to be enabled on either one of {} and {}".format(dut1,
                                                                                                                  dut2),
            'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackShutICL", "test_case_failure_message",
                          "Fallback state of PO5 failed")

    if tc1_result == 0:
        st.report_tc_pass('FtOpSoSwMclagFallbackShutICL', "test_case_passed")

    if po_fail > 0 or fb_fail > 0 or traffic_forward_fail > 0 or mclag_state_fail >0:
        final_result = False
    post_result_handler()

def test_mclag_fallback_active_standby_coldboot(enable_client_ports):
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, fb_fail
    tc_list = ['FtOpSoSwMclagFallbackActiveStandbyReboot']
    print_log(
        "START test_mclag_fallback_active_standby_coldboot==>Sub-Test:Verify MCLAG Fallback with active and standby node reboot\n TCs:<{}>".format(
            tc_list),
        "HIGH")
    ###Verify Mclag Interface state
    utils.exec_all(True, [[boot.config_save, dut] for dut in mclag_peers])
    utils.exec_foreach(True, mclag_peers, st.reboot)

    result_po3 = verify_mclag_fallback_state('PortChannel3')[0]
    if not result_po3:
        fb_fail += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "Fallback state of PO3 failed")
    result_po5 = verify_mclag_fallback_state('PortChannel5')[0]
    if not result_po5:
        fb_fail += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "Fallback state of PO5 failed")

    clear_mac_verify(dut_list)

    st_key = str(trunk_base_vlan) + ":CD"
    client_traffic_src = stream_data[st_key]['streamXY']
    client_traffic_dest = stream_data[st_key]['streamYX']
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="START")
    if not verify_traffic(src_stream_list=client_traffic_dest, dest_stream_list=client_traffic_src,
                          comp_type='packet_rate', direction='both'):
        traffic_forward_fail += 1
        print_log("Active Standby Config Reload: Traffic Forwarding in Fallback state failed", 'MED')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "Traffic Forwarding in Fallback state failed with active standby config reload")
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="STOP")

    if po_fail > 0 or fb_fail > 0 or traffic_forward_fail > 0:
        final_result = False
    post_result_handler()

def del_test_mclag_fallback_active_standby_coldboot(enable_client_ports):
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, fb_fail
    tc1_result = 0
    tc_list = ['FtOpSoSwMclagFallbackActiveStandbyReboot']
    print_log(
        "START test_mclag_fallback_active_standby_coldboot==>Sub-Test:Verify MCLAG Fallback with active and standby node reboot\n TCs:<{}>".format(
            tc_list),
        "HIGH")
    ###Verify Mclag Interface state
    print_log("Trigger:-> Reboot Standby Mclag Node",'MED')
    utils.exec_all(True, [[boot.config_save, dut] for dut in [dut2]])
    utils.exec_foreach(True, [dut2], st.reboot)

    if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['up', 'down']):
        po_fail += 1
        tc1_result += 1
        print_log("PortChannel3 state FAILED, Expect UP in {} and DOWN in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO3 state failed")
    if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['up', 'down']):
        po_fail += 1
        tc1_result += 1
        print_log("PortChannel5 state FAILED, Expect UP in {} and DOWN in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO5 state failed")

    # Verify expected member port is up -- no need to veriy port
    if not verify_mclag_fallback("PortChannel3", ["Enabled", "Enabled"], ["Enabled", "Disabled"]):
        fb_fail += 1
        print_log("PortChannel3 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO3 fallback state failed")
    # st.report_tc_fail("ID", "test_case_failure_message", "Fallback state of PO3 failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Enabled", "Disabled"]):
        fb_fail += 1
        print_log("PortChannel5 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut1, dut2),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO5 fallback state failed")

    print_log("Trigger:-> Reboot Active Mclag Node", 'MED')
    utils.exec_all(True, [[boot.config_save, dut] for dut in [dut1]])
    utils.exec_foreach(True, [dut1], st.reboot)

    if not retry_func(verify_fallback_po_state, po_name="PortChannel3", po_states=['down', 'up']):
        po_fail += 1
        tc1_result += 1
        print_log("PortChannel3 state FAILED, Expect DOWN in {} and UP in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO3 state failed")
    if not retry_func(verify_fallback_po_state, po_name="PortChannel5", po_states=['down', 'up']):
        po_fail += 1
        tc1_result += 1
        print_log("PortChannel5 state FAILED, Expect DOWN in {} and UP in {}".format(dut1, dut2), 'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO5 state failed")

    # Verify expected member port is up -- no need to veriy port
    if not verify_mclag_fallback("PortChannel3", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
        fb_fail += 1
        print_log("PortChannel3 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut2, dut1),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO3 fallback state failed")
    # st.report_tc_fail("ID", "test_case_failure_message", "Fallback state of PO3 failed")
    if not verify_mclag_fallback("PortChannel5", ["Enabled", "Enabled"], ["Disabled", "Enabled"]):
        fb_fail += 1
        print_log("PortChannel5 Fallback state FAILED, Expect Enabled in {} and Disabled in {}".format(dut2, dut1),
                  'HIGH')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "PO5 fallback state failed")

    clear_mac_verify(dut_list)

    st_key = str(trunk_base_vlan) + ":CD"
    client_traffic_src = stream_data[st_key]['streamXY']
    client_traffic_dest = stream_data[st_key]['streamYX']
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="START")
    if not verify_traffic(src_stream_list=client_traffic_dest, dest_stream_list=client_traffic_src,
                          comp_type='packet_rate', direction='both'):
        traffic_forward_fail += 1
        print_log("Active Standby Reboot: Traffic Forwarding in Fallback state failed", 'MED')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyReboot", "test_case_failure_message",
                          "Traffic Forwarding in Fallback state failed with active standby reboot")
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="STOP")
    if po_fail > 0 or fb_fail > 0 or traffic_forward_fail > 0:
        final_result = False
    post_result_handler()

def test_mclag_fallback_active_standby_reload(enable_client_ports):
    pre_result_handler()
    global final_result, traffic_forward_fail, mac_count_fail, mclag_state_fail, mclag_intf_fail, po_fail, fb_fail
    tc_list = ['FtOpSoSwMclagFallbackActiveStandbyConfigReload']
    print_log(
        "START test_mclag_fallback_active_standby_reload==>Sub-Test:Verify MCLAG Fallback active and standby config reload\n TCs:<{}>".format(
            tc_list),
        "HIGH")
    ###Verify Mclag Interface state
    utils.exec_all(True, [[boot.config_save_reload, dut] for dut in mclag_peers])

    result_po3 = verify_mclag_fallback_state('PortChannel3')[0]
    if not result_po3:
        fb_fail += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyConfigReload", "test_case_failure_message", "Fallback state of PO3 failed")
    result_po5 = verify_mclag_fallback_state('PortChannel5')[0]
    if not result_po5:
        fb_fail += 1
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyConfigReload", "test_case_failure_message", "Fallback state of PO5 failed")

    clear_mac_verify(dut_list)

    st_key = str(trunk_base_vlan) + ":CD"
    client_traffic_src = stream_data[st_key]['streamXY']
    client_traffic_dest = stream_data[st_key]['streamYX']
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="START")
    if not verify_traffic(src_stream_list=client_traffic_dest, dest_stream_list=client_traffic_src,
                          comp_type='packet_rate', direction='both'):
        traffic_forward_fail += 1
        print_log("Active Standby Config Reload: Traffic Forwarding in Fallback state failed", 'MED')
        st.report_tc_fail("FtOpSoSwMclagFallbackActiveStandbyConfigReload", "test_case_failure_message",
                          "Traffic Forwarding in Fallback state failed with active standby config reload")
    start_stop_traffic(src_stream_list=client_traffic_src, dest_stream_list=client_traffic_dest, action_ctrl="STOP")

    if po_fail > 0 or fb_fail > 0 or traffic_forward_fail > 0:
        final_result = False
    post_result_handler()







