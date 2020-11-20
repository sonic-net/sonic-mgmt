##########################################################################################
# Title: UDLD Script with PVST
# Author: Chandra Sekhar Reddy <Chandra.vedanaparthi@broadcom.com>
##########################################################################################

import pytest

from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vlan
import apis.system.interface as intf
import apis.switching.portchannel as po
import apis.switching.udld as udld
import apis.switching.pvst as pvst
import utilities.parallel as pll
import apis.system.basic as basic_api
import apis.system.reboot as reboot_api
import apis.routing.bgp as bgp_api
from udld_vars import *

import utilities.common as utils

data = SpyTestDict()

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
    global po_data
    global dut_list
    global dut1
    global dut2
    global dut3
    global dut_list_tg
    global dut_reload
    global dut_tgn_port
    global udld_global
    global udld_timers
    global udld_neighbor
    global udld_int
    global vars
    po_data = {}
    ### Verify Minimum topology requirement is met
    vars = st.ensure_min_topology("D1D2:3", "D1D3:3", "D2D3:3", "D1T1:2", "D2T1:2", "D3T1:2")

    print_log("Start Test with topology D1D2:3,D1D3:3,D2D3:3,D1T1:2,D2T1:2,D3T1:2",'HIGH')

    print_log(
        "Test Topology Description\n==============================\n\
        - Test script uses UDLD topology with D1,D2 and D3.\n\
        - Between each pair of DUTs, 3 links will be there and 2 TGEN ports per dut.\n\
        - Trunk Vlan 10 between DUT1,DUT2 and DUT3 and enable PVST and.\n\
        - Trunk PO-1(DUT1<->DUT2),PO-2(DUT2<->DUT3),and PO-3(DUT1<->DUT3)with 3 links and enable PVST, UDLD.\n\
        - Mclag interfaces PO-3 will be configured between D1,D2 and D3.\n\
        - Mclag interfaces PO-4 and PO-5 will be configured between D1,D2 and D4.\n\
        - Traffic streams used follow below MAC pattern.\n\
        \t\tStream1 between DUT1 first TG port <-> DUT3 First TG port with tagged 10 traffic\n\
        \t\tStream2 between DUT1 second TG port <-> DUT3 Second TG port with tagged 20 traffic\n\
        In addition, each test case will have trigger configs/unconfigs and corresponding streams used",'HIGH')


    ### Initialize DUT variables and ports
    dut_list = st.get_dut_names()
    dut1 = dut_list[0]
    dut2 = dut_list[1]
    dut3 = dut_list[2]
    dut_list_tg = [dut_list[0],dut_list[2]]
    dut_reload = [dut_list[2]]

    ### Initialize TGEN connected DUT ports
    dut_tgn_port = {}
    for dut in dut_list_tg:
        # first tgen port
        dut_tgn_port.update({(dut,1): st.get_tg_links(dut)[0][0]})
        # second tgen port
        dut_tgn_port.update({(dut,2): st.get_tg_links(dut)[1][0]})

    ### Initialize TGEN side ports and handles
    get_tgen_handles()

    udld_global = {}
    udld_global.update({
        dut1: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_mode_agg': 'Aggressive',
            'udld_message_time': 1,
            'udld_multiplier': 3,
            'udld_recover': 'enable',
            'module': 'udld',
            'udld_recover_timer': 30
        }
    })
    udld_global.update({
        dut2: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_mode_agg': 'Aggressive',
            'udld_message_time': 1,
            'udld_multiplier': 3
        }
    })
    udld_global.update({
        dut3: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_mode_agg': 'Aggressive',
            'udld_message_time': 1,
            'udld_multiplier': 3
        }
    })
    udld_timers = {}
    udld_timers.update({
        dut1: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_message_time': 3,
            'udld_multiplier': 9
        }
    })
    udld_timers.update({
        dut2: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_message_time': 3,
            'udld_multiplier': 9
        }
    })
    udld_timers.update({
        dut3: {
            'config': 'yes',
            'udld_enable': 'yes',
            'udld_admin_state': 'Enabled',
            'udld_mode': 'Normal',
            'udld_message_time': 3,
            'udld_multiplier': 9
        }
    })

    udld_neighbor = {}
    udld_neighbor.update({
        dut1: {
            'local_port': [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D3P1,vars.D1D3P2,vars.D1D3P3],
            'device_name': ['sonic','sonic','sonic','sonic','sonic','sonic'],
            'remote_port': [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D3D1P1,vars.D3D1P2,vars.D3D1P3],
            'neighbor_state': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_norm': ['Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_agg': ['Bidirectional','Bidirectional','Bidirectional'],
            'local_port_na': [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3],
            'device_name_na': ['sonic','sonic','sonic'],
            'remote_port_na': [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3]
        }
    })
    udld_neighbor.update({
        dut2: {
            'local_port': [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D3P1,vars.D2D3P2,vars.D2D3P3],
            'device_name': ['sonic','sonic','sonic','sonic','sonic','sonic'],
            'remote_port': [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D3D2P1,vars.D3D2P2,vars.D3D2P3],
            'neighbor_state': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_norm': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_agg': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional']
        }
    })
    udld_neighbor.update({
        dut3: {
            'local_port': [vars.D3D2P1,vars.D3D2P2,vars.D3D2P3,vars.D3D1P1,vars.D3D1P2,vars.D3D1P3],
            'device_name': ['sonic','sonic','sonic','sonic','sonic','sonic'],
            'remote_port': [vars.D2D3P1,vars.D2D3P2,vars.D2D3P3,vars.D1D3P1,vars.D1D3P2,vars.D1D3P3],
            'neighbor_state': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_norm': ['Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_agg': ['Bidirectional','Bidirectional','Bidirectional'],
            'local_port_na': [vars.D3D2P1,vars.D3D2P2,vars.D3D2P3],
            'device_name_na': ['sonic','sonic','sonic'],
            'remote_port_na': [vars.D2D3P1,vars.D2D3P2,vars.D2D3P3]
        }
    })
    udld_int = {}
    udld_int.update({
        dut1: {
            'udld_int': [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3,vars.D1D3P1,vars.D1D3P2,vars.D1D3P3],
            'udld_enable': 'yes',
            'config': 'yes',
            'udld_int_block': [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3],
            'udld_int_block_stp': [vars.D1D2P1,vars.D1D2P2,vars.D1D2P3],
            'neighbor_state': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_norm': ['Bidirectional','Bidirectional','Bidirectional','Undetermined','Undetermined','Undetermined'],
            'neighbor_state_agg': ['Bidirectional','Bidirectional','Bidirectional','Shutdown','Shutdown','Shutdown']
        }
    })
    udld_int.update({
        dut2: {
            'udld_int': [vars.D2D1P1,vars.D2D1P2,vars.D2D1P3,vars.D2D3P1,vars.D2D3P2,vars.D2D3P3],
            'udld_enable': 'yes',
            'config': 'yes',
            'neighbor_state': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_norm': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_agg': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional']
        }
    })
    udld_int.update({
        dut3: {
            'udld_int': [vars.D3D1P1,vars.D3D1P2,vars.D3D1P3,vars.D3D2P1,vars.D3D2P2,vars.D3D2P3],
            'udld_enable': 'yes',
            'config': 'yes',
            'neighbor_state': ['Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_norm': ['Shutdown','Shutdown','Shutdown','Bidirectional','Bidirectional','Bidirectional'],
            'neighbor_state_agg': ['Undetermined','Undetermined','Undetermined','Bidirectional','Bidirectional','Bidirectional']
        }
    })


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
    api_list.append([udld_traffic_config])
    api_list.append([udld_module_config])
    utils.exec_all(True, api_list, True)
    udld_basic_validations()
    yield
    api_list = []
    api_list.append([udld_module_unconfig])
    utils.exec_all(True, api_list, True)


#Configure Port Channel
#Check Once the port chaneel config
def configure_portchannel(po_data):
    '''
    Sample po_data structure
    po_data['PortChannel1'] = {'duts': [dut1, dut2],
                                 'po_members': {dut1: [vars.D1D2P2, vars.D1D2P3]
                                                dut2: [vars.D2D1P2, vars.D2D1P3]}}
    '''
    for po_id in po_data.keys():
        utils.exec_all(True, [[po.create_portchannel, dut, po_id] for dut in po_data[po_id]['duts']])
        utils.exec_all(True, [[po.add_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in po_data[po_id]['duts']])



def unconfigure_portchannel(po_data):
    '''
    Sample po_data structure
    Sample po_data structure
    po_data['PortChannel2'] = {'duts': [dut1, dut2],
                                 'po_members': {dut1: [vars.D1D2P2, vars.D1D2P3]
                                                dut2: [vars.D2D1P2, vars.D2D1P3]}}
    '''
    for po_id in po_data.keys():
        utils.exec_all(True, [[po.delete_portchannel_member, dut, po_id, po_data[po_id]['po_members'][dut]] for dut in po_data[po_id]['duts']])
        utils.exec_all(True, [[po.delete_portchannel, dut, po_id] for dut in po_data[po_id]['duts']])




def udld_module_config():
    '''
    - Configure vlans 10 and 11 and enable PVST
    - Configure PVST priority to take fwd path DUT1<->DUT2<->DUT3
    - Configure PO and add members
    - Configure UDLD global and interface

    '''
    print_log("Starting UDLD Module Configurations...\n\
    STEPS:\n\
    - Configure vlans 10 and 11 and add TG ports \n\
    - Enable PVST priority to take fwd path DUT1<->DUT2<->DUT3\n\
    - Configure PO and add members\n\
    - Configure UDLD global and interface.", "HIGH")

    ### Create trunk VLANs on all DUTs using range command
    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    utils.exec_all(True,[[vlan.config_vlan_range, dut, trunk_vlan_range] for dut in dut_list])
    #Configure trunk vlans on first TGEN ports of UDLD nodes of DUT1 and DUT3
    utils.exec_all(True, [[vlan.add_vlan_member, dut, trunk_base_vlan, dut_tgn_port[(dut,1)], True] for dut in [dut1,dut3] ])
    #Configure trunk vlans on second TGEN ports of UDLD nodes of DUT1 and DUT3
    utils.exec_all(True, [[vlan.add_vlan_member, dut, trunk_base_vlan+1, dut_tgn_port[(dut,2)], True] for dut in [dut1,dut3] ])

    ### Enable PVST global
    utils.exec_all(True,[[pvst.config_spanning_tree, dut, "pvst", "enable"] for dut in dut_list])

    ### Enable DUT1 as Root Bridge in vlan 10 and 11
    stp_data = {dut1: {"vlan": trunk_base_vlan, "priority": 0}}
    pvst.config_stp_root_bridge_by_vlan(stp_data)
    stp_data = {dut1: {"vlan": trunk_base_vlan+1, "priority": 0}}
    pvst.config_stp_root_bridge_by_vlan(stp_data)

    ### Configure port channel between DUT1<->DUT2<->DUT3<->DUT1
    po_data.update({'PortChannel1': {'duts' : [dut1, dut2] ,
                                 'po_members' : { dut1:[vars.D1D2P2,vars.D1D2P3] ,
                                                  dut2:[vars.D2D1P2,vars.D2D1P3]}}})
    po_data.update({'PortChannel2': {'duts': [dut1, dut3],
                                       'po_members': {dut1: [vars.D1D3P2, vars.D1D3P3],
                                                      dut3: [vars.D3D1P2, vars.D3D1P3]}}})
    po_data.update({'PortChannel3': {'duts': [dut2, dut3],
                                 'po_members': {dut2: [vars.D2D3P2, vars.D2D3P3],
                                                dut3: [vars.D3D2P2, vars.D3D2P3]}}})

    configure_portchannel(po_data)

    ### Add trunk ports between DUT1<->DUT2<->DUT3<->DUT1 in vlan 10
    api_list = []
    api_list.append([vlan.add_vlan_member, dut1, trunk_base_vlan, [vars.D1D2P1,vars.D1D3P1], True])
    api_list.append([vlan.add_vlan_member, dut2, trunk_base_vlan, [vars.D2D1P1,vars.D2D3P1], True])
    api_list.append([vlan.add_vlan_member, dut3, trunk_base_vlan, [vars.D3D2P1,vars.D3D1P1], True])
    utils.exec_all(True, api_list)

    ### Add port channels between DUT1<->DUT2<->DUT3<->DUT1 in vlan 11
    utils.exec_all(True,[[vlan.add_vlan_member, dut, trunk_base_vlan+1, 'PortChannel1', True] for dut in [dut1,dut2]])
    utils.exec_all(True,[[vlan.add_vlan_member, dut, trunk_base_vlan+1, 'PortChannel2', True] for dut in [dut1,dut3]])
    utils.exec_all(True,[[vlan.add_vlan_member, dut, trunk_base_vlan+1, 'PortChannel3', True] for dut in [dut2,dut3]])

    ### Configure lower port cost on access links and trunk PO so that it is selected path D1<->D2<->D3 by default
    api_list = []
    api_list.append([pvst.config_stp_vlan_interface, dut1, trunk_base_vlan, vars.D1D2P1, 1, 'cost'])
    api_list.append([pvst.config_stp_vlan_interface, dut2, trunk_base_vlan, vars.D2D1P1, 1, 'cost'])
    api_list.append([pvst.config_stp_vlan_interface, dut2, trunk_base_vlan, vars.D2D3P1, 1, 'cost'])
    api_list.append([pvst.config_stp_vlan_interface, dut3, trunk_base_vlan, vars.D3D2P1, 1, 'cost'])
    utils.exec_all(False, api_list) #TODO: ENABLE PARALLEL CALLS AFTER FIXING SAME DUT CALLS ABOVE
    utils.exec_foreach(True, [dut1, dut2], pvst.config_stp_vlan_interface, trunk_base_vlan+1, 'PortChannel1', 1, mode='cost')
    utils.exec_foreach(True, [dut2, dut3], pvst.config_stp_vlan_interface, trunk_base_vlan+1, 'PortChannel3', 1, mode='cost')

    ###Enable UDLD global
    dict1 = {'udld_enable': udld_global[dut1]['udld_enable'], 'config': udld_global[dut1]['config']}
    dict2 = {'udld_enable': udld_global[dut2]['udld_enable'], 'config': udld_global[dut2]['config']}
    dict3 = {'udld_enable': udld_global[dut3]['udld_enable'], 'config': udld_global[dut3]['config']}
    pll.exec_parallel(True,dut_list,udld.config_udld_global, [dict1, dict2, dict3])


    ###Enable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': udld_int[dut1]['udld_enable'], 'config': udld_int[dut1]['config']}
    dict2 = {'intf': udld_int[dut2]['udld_int'],'udld_enable': udld_int[dut2]['udld_enable'], 'config': udld_int[dut2]['config']}
    dict3 = {'intf': udld_int[dut3]['udld_int'],'udld_enable': udld_int[dut3]['udld_enable'], 'config': udld_int[dut3]['config']}
    pll.exec_parallel(True,dut_list,udld.config_intf_udld, [dict1, dict2, dict3])



def udld_module_unconfig():
    print_log("Starting UDLD Module UnConfigurations...", "HIGH")

    ###Disable UDLD on Interfaces
    dict1 = {'intf': udld_int[dut1]['udld_int'],'udld_enable': 'no', 'config': 'no'}
    dict2 = {'intf': udld_int[dut2]['udld_int'],'udld_enable': 'no', 'config': 'no'}
    dict3 = {'intf': udld_int[dut3]['udld_int'],'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,dut_list,udld.config_intf_udld, [dict1, dict2, dict3])

    ###Disable UDLD global
    dict1 = {'udld_enable': 'no', 'config': 'no'}
    dict2 = {'udld_enable': 'no', 'config': 'no'}
    dict3 = {'udld_enable': 'no', 'config': 'no'}
    pll.exec_parallel(True,dut_list,udld.config_udld_global, [dict1, dict2, dict3])

    ### Remove the port channels between DUT1<->DUT2<->DUT3<->DUT1 in vlan 11
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, trunk_base_vlan+1, 'PortChannel1'] for dut in [dut1,dut2]])
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, trunk_base_vlan+1, 'PortChannel2'] for dut in [dut1,dut3]])
    utils.exec_all(True,[[vlan.delete_vlan_member, dut, trunk_base_vlan+1, 'PortChannel3'] for dut in [dut2,dut3]])

    ### Remove the trunk ports between DUT1<->DUT2<->DUT3<->DUT1 in vlan 10
    api_list = []
    api_list.append([vlan.delete_vlan_member, dut1, trunk_base_vlan, [vars.D1D2P1,vars.D1D3P1]])
    api_list.append([vlan.delete_vlan_member, dut2, trunk_base_vlan, [vars.D2D1P1,vars.D2D3P1]])
    api_list.append([vlan.delete_vlan_member, dut3, trunk_base_vlan, [vars.D3D2P1,vars.D3D1P1]])
    utils.exec_all(True, api_list)

    ###Unconfigure trunk vlans on first TGEN ports of UDLD nodes of DUT1 and DUT3
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, trunk_base_vlan, dut_tgn_port[(dut,1)]] for dut in [dut1,dut3] ])
    #Unconfigure trunk vlans on second TGEN ports of UDLD nodes of DUT1 and DUT3
    utils.exec_all(True, [[vlan.delete_vlan_member, dut, trunk_base_vlan+1, dut_tgn_port[(dut,2)]] for dut in [dut1,dut3] ])

    ###Unconfigure the port channel on all DUTs
    unconfigure_portchannel(po_data)

    ###Remove the vlans 10 and 11 from all DUTs
    trunk_vlan_range = str(trunk_base_vlan) + " " + str(trunk_base_vlan + trunk_vlan_count - 1)
    utils.exec_all(True,[[vlan.config_vlan_range, dut, trunk_vlan_range, 'del'] for dut in dut_list])

    ### Disable PVST global
    utils.exec_all(True,[[pvst.config_spanning_tree, dut, "pvst", "disable"] for dut in dut_list])

def udld_traffic_config():

    ###Creating the Bi-directional traffic between DUT1 TG1 <-> DUT3 TG1 and DUT1 TG2 <-> DUT3 TG2
    data['stream11'] = tg_h.tg_traffic_config(mac_src=src_mac11, mac_dst=dst_mac31, vlan="enable",
                                    rate_pps=tgen_rate_pps, mode='create', port_handle=tgn_handle[(dut1, 1)], l2_encap='ethernet_ii_vlan',
                                    vlan_id=trunk_base_vlan,transmit_mode='continuous')
    data['stream31'] = tg_h.tg_traffic_config(mac_src=dst_mac31, mac_dst=src_mac11, vlan="enable",
                                    rate_pps=tgen_rate_pps, mode='create', port_handle=tgn_handle[(dut3, 1)], l2_encap='ethernet_ii_vlan',
                                    vlan_id=trunk_base_vlan,transmit_mode='continuous')
    data['stream12'] = tg_h.tg_traffic_config(mac_src=src_mac12, mac_dst=dst_mac32, vlan="enable",
                                    rate_pps=tgen_rate_pps, mode='create', port_handle=tgn_handle[(dut1, 2)], l2_encap='ethernet_ii_vlan',
                                    vlan_id=trunk_base_vlan+1,transmit_mode='continuous')
    data['stream32'] = tg_h.tg_traffic_config(mac_src=dst_mac32, mac_dst=src_mac12, vlan="enable",
                                    rate_pps=tgen_rate_pps, mode='create', port_handle=tgn_handle[(dut3, 2)], l2_encap='ethernet_ii_vlan',
                                    vlan_id=trunk_base_vlan+1,transmit_mode='continuous')



def start_traffic():
    ### Clear stats on all reserved ports
    for dut in dut_list_tg:
        tg_h.tg_traffic_control(action="clear_stats", port_handle=tgn_handle[(dut, 1)])
        if dut == dut1 or dut == dut3:
            tg_h.tg_traffic_control(action="clear_stats", port_handle=tgn_handle[(dut, 2)])

    ###Start Traffic
    stream_list = [data['stream11']['stream_id'],data['stream31']['stream_id'],data['stream12']['stream_id'],data['stream32']['stream_id']]
    tg_h.tg_traffic_control(action="run", handle=stream_list)
    st.wait(5)


def verify_traffic():
    ver_flag = True
    tg_src_port_list = [tgn_port[(dut1, 1)], tgn_port[(dut1, 2)], tgn_port[(dut3, 1)], tgn_port[(dut3, 2)]]
    tg_dst_port_list = [tgn_port[(dut3, 1)], tgn_port[(dut3, 2)], tgn_port[(dut1, 1)], tgn_port[(dut1, 2)]]

    for tg_src_port, tg_dst_port in zip(tg_src_port_list, tg_dst_port_list):
        traffic_data = {
            '1': {
                'tx_ports': [tg_src_port],
                'tx_obj': [tg_h],
                'exp_ratio': [1],
                'rx_ports': [tg_dst_port],
                'rx_obj': [tg_h],
            },
        }
        # verify traffic mode aggregate level
        streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode="aggregate", comp_type="packet_rate")
        if streamResult:
            print_log(
                'Traffic verification PASSED for mode aggregate {} <---> {}'.format(tg_src_port,tg_dst_port),'MED')
        else:
            ver_flag = False
            print_log(
                'Traffic verification FAILED for mode aggregate {} <---> {}'.format(tg_src_port,tg_dst_port),'ERROR')
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


def verify_udld_global(udld_global):
    '''
    Verify UDLD state and other attributes
    :param udld_global: dictionary  of UDLD global attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD state and other attributes", 'MED')
    dict1 = {'udld_admin_state': udld_global[dut1]['udld_admin_state'], 'udld_mode': udld_global[dut1]['udld_mode'],\
             'udld_message_time': udld_global[dut1]['udld_message_time'], 'udld_multiplier': udld_global[dut1]['udld_multiplier']}
    dict2 = {'udld_admin_state': udld_global[dut2]['udld_admin_state'], 'udld_mode': udld_global[dut2]['udld_mode'],\
             'udld_message_time': udld_global[dut2]['udld_message_time'], 'udld_multiplier': udld_global[dut2]['udld_multiplier']}
    dict3 = {'udld_admin_state': udld_global[dut3]['udld_admin_state'], 'udld_mode': udld_global[dut3]['udld_mode'],\
             'udld_message_time': udld_global[dut3]['udld_message_time'], 'udld_multiplier': udld_global[dut3]['udld_multiplier']}
    [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_global, [dict1, dict2, dict3])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD state and other attributes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_mode(udld_mode_def ='Normal'):
    '''
    Verify UDLD mode and other attributes
    :param udld_global: dictionary  of UDLD global attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD modes", 'MED')
    dict1 = {'udld_mode': udld_mode_def}
    dict2 = {'udld_mode': udld_mode_def}
    dict3 = {'udld_mode': udld_mode_def}
    [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_global, [dict1, dict2, dict3])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD modes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_neighbor(udld_neighbor):
    '''
    Verify UDLD neighbor state and other attributes
    :param udld_neighbor: dictionary  of UDLD neighbor attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD neighbor state and other attributes", 'MED')
    dict1 = {'local_port': udld_neighbor[dut1]['local_port'], 'device_name': udld_neighbor[dut1]['device_name'],\
             'remote_port': udld_neighbor[dut1]['remote_port'], 'neighbor_state': udld_neighbor[dut1]['neighbor_state']}

    dict2 = {'local_port': udld_neighbor[dut2]['local_port'], 'device_name': udld_neighbor[dut2]['device_name'],\
             'remote_port': udld_neighbor[dut2]['remote_port'], 'neighbor_state': udld_neighbor[dut2]['neighbor_state']}

    dict3 = {'local_port': udld_neighbor[dut3]['local_port'], 'device_name': udld_neighbor[dut3]['device_name'],\
             'remote_port': udld_neighbor[dut3]['remote_port'], 'neighbor_state': udld_neighbor[dut3]['neighbor_state']}

    [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_neighbors, [dict1, dict2, dict3])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD neighbor state and other attributes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_neighbor_agg(udld_neighbor):
    '''
    Verify UDLD neighbor mode
    :param udld_neighbor: dictionary  of UDLD neighbor attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD neighbor state and other attributes", 'MED')
    dict1 = {'local_port': udld_neighbor[dut1]['local_port_na'], 'device_name': udld_neighbor[dut1]['device_name_na'],\
             'remote_port': udld_neighbor[dut1]['remote_port_na'], 'neighbor_state': udld_neighbor[dut1]['neighbor_state_agg']}
    dict2 = {'local_port': udld_neighbor[dut2]['local_port'], 'device_name': udld_neighbor[dut2]['device_name'],\
             'remote_port': udld_neighbor[dut2]['remote_port'], 'neighbor_state': udld_neighbor[dut2]['neighbor_state_agg']}

    dict3 = {'local_port': udld_neighbor[dut3]['local_port_na'], 'device_name': udld_neighbor[dut3]['device_name_na'],\
             'remote_port': udld_neighbor[dut3]['remote_port_na'], 'neighbor_state': udld_neighbor[dut3]['neighbor_state_agg']}

    [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_neighbors, [dict1, dict2, dict3])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD neighbor state and other attributes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_neighbor_norm(udld_neighbor):
    '''
    Verify UDLD neighbor mode
    :param udld_neighbor: dictionary  of UDLD neighbor attributes to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD neighbor state and other attributes", 'MED')
    dict1 = {'local_port': udld_neighbor[dut1]['local_port_na'], 'device_name': udld_neighbor[dut1]['device_name_na'],\
             'remote_port': udld_neighbor[dut1]['remote_port_na'], 'neighbor_state': udld_neighbor[dut1]['neighbor_state_norm']}
    dict2 = {'local_port': udld_neighbor[dut2]['local_port'], 'device_name': udld_neighbor[dut2]['device_name'],\
             'remote_port': udld_neighbor[dut2]['remote_port'], 'neighbor_state': udld_neighbor[dut2]['neighbor_state_norm']}

    dict3 = {'local_port': udld_neighbor[dut3]['local_port_na'], 'device_name': udld_neighbor[dut3]['device_name_na'],\
             'remote_port': udld_neighbor[dut3]['remote_port_na'], 'neighbor_state': udld_neighbor[dut3]['neighbor_state_norm']}

    [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_neighbors, [dict1, dict2, dict3])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD neighbor state and other attributes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_timers(udld_timers):
    '''
    Verify UDLD timers
    :param udld_timers: dictionary  of UDLD timers to be verified
    :return:
    '''
    ver_flag = True
    print_log("Verify the UDLD timers", 'MED')
    dict1 = {'udld_message_time': udld_timers[dut1]['udld_message_time'], 'udld_multiplier': udld_timers[dut1]['udld_multiplier']}
    dict2 = {'udld_message_time': udld_timers[dut2]['udld_message_time'], 'udld_multiplier': udld_timers[dut2]['udld_multiplier']}
    dict3 = {'udld_message_time': udld_timers[dut3]['udld_message_time'], 'udld_multiplier': udld_timers[dut3]['udld_multiplier']}
    [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_global, [dict1, dict2, dict3])

    if not all(i is None for i in exceptions):
        print_log(exceptions)
    if False in result:
        print_log('UDLD state and other attributes verification FAILED','ERROR')
        ver_flag = False
    return ver_flag

def verify_udld_port_status(udld_ports,dut,status='up'):
    '''
    Verify UDLD port status
    :param udld_ports: list of ports
    :param status: up/down
    :return:
    '''
    ver_flag = True
    if status == "up":
        for interface in udld_ports:
            if not intf.poll_for_interface_status(dut, [interface], "oper", "up", iteration=1, delay=1):
                st.error("The interface {} is down  on the DUT {}".format(interface,dut))
                ver_flag = False
    else:
        for interface in udld_ports:
            if not intf.poll_for_interface_status(dut, [interface], "oper", "down", iteration=1, delay=1):
                st.error("The interface {} is up on the DUT {}".format(interface,dut))
                ver_flag = False
    return ver_flag

def verify_udld_interface(udld_int,mode):
    '''
    Verify UDLD interface local port state
    :param udld_int: dictionary  of UDLD global attributes to be verified
    :param mode: normal/aggressive/normal_udld_block/aggressive_udld_block
    :return:
    '''
    ver_flag = True
    int_local_list1 =  udld_int[dut1]['udld_int']
    int_local_list2 =  udld_int[dut2]['udld_int']
    int_local_list3 =  udld_int[dut3]['udld_int']
    if mode == "normal" or mode == "aggressive":
        st.log("mode inside {}".format(mode))
        int_mode_list1 =  udld_int[dut1]['neighbor_state']
        int_mode_list2 =  udld_int[dut2]['neighbor_state']
        int_mode_list3 =  udld_int[dut3]['neighbor_state']
    elif mode == "udldblocknormal":
        st.log("mode inside {}".format(mode))
        int_mode_list1 =  udld_int[dut1]['neighbor_state_norm']
        int_mode_list2 =  udld_int[dut2]['neighbor_state_norm']
        int_mode_list3 =  udld_int[dut3]['neighbor_state_norm']
    elif mode == "udldblockaggressive":
        int_mode_list1 =  udld_int[dut1]['neighbor_state_agg']
        int_mode_list2 =  udld_int[dut2]['neighbor_state_agg']
        int_mode_list3 =  udld_int[dut3]['neighbor_state_agg']
    for int_local1, int_local2, int_local3,int_mode1, int_mode2, int_mode3 in \
       zip(int_local_list1,int_local_list2,int_local_list3,int_mode_list1,int_mode_list2,int_mode_list3):
        dict1 = {'udld_intf': int_local1, 'udld_status': int_mode1}
        dict2 = {'udld_intf': int_local2, 'udld_status': int_mode2}
        dict3 = {'udld_intf': int_local3, 'udld_status': int_mode3}
        [result, exceptions] = pll.exec_parallel(True, dut_list, udld.verify_udld_interface, [dict1, dict2, dict3])
        if not all(i is None for i in exceptions):
            print_log(exceptions)
        if False in result:
            print_log('UDLD Local port states FAILED','ERROR')
            ver_flag = False
    return ver_flag

def udld_basic_validations():
    '''
    1. Verify PO summary.
    2. Display pvst states.
    3. Verify udld global state
    4. Verify udld neighbors

    '''
    ### Verify all the LAGs configured in the topology is up
    st.wait(60)
    print_log("Verify all the LAGs configured in the topology is up",'MED')
    final_result = True

    po_fail = 0
    udld_global_fail = 0
    udld_neighbor_fail = 0
    tx_rx_fail = 0

    po_up_flag = False
    itr_counter = 0
    while(itr_counter < 3):
        print_log("Iteration:{}".format(itr_counter+1),'MED')
        verify_po_state(po_data.keys(), state='up')
        verify_po_state(['PortChannel1', 'PortChannel3'], state='up')
        if verify_po_state(po_data.keys(), state='up'):
            po_up_flag = True
            break
        else:
            itr_counter += 1
            st.wait(5)

    if not po_up_flag:
        final_result = False
        po_fail += 1
        print_log("PortChannel State verification FAILED", "HIGH")
    else:
        print_log("PortChannel State verification PASSED", "HIGH")
    print_log("Display the PVST states on DUT1,DUT2 and DUT3", "MED")
    pvst.show_stp_in_parallel(dut_list)


    ### Verify UDLD global state and attributes
    if verify_udld_global(udld_global):
        print_log("UDLD Global verification PASSED", "HIGH")
    else:
        print_log("UDLD Global verification FAILED", "HIGH")
        udld_global_fail += 1
        final_result = False

    ### Verify UDLD neighbor state and attributes
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor verification FAILED", "HIGH")
        udld_neighbor_fail += 1
        final_result = False

    if not final_result:
        fail_msg = ''
        if po_fail > 0:
            fail_msg += 'PortChannel not UP:'
        if udld_global_fail > 0:
            fail_msg += 'UDLD Global state Failed:'
        if udld_neighbor_fail > 0:
            fail_msg += 'UDLD neighbor state Failed:'
        st.report_fail("test_case_failure_message", fail_msg.strip(':'))


def test_pvst_udld_normal_aggressive():
    '''
        Verify UDLD with various values of message-time and multipliers in normal mode with PVST
        Verify UDLD with various values of message-time and multipliers in Aggressive mode with PVST
        Verify UDLD operation with one end in normal mode and other end in aggressive mode with PVST
        Verify the PVST convergence with UDLD with Default values of message-time and multipliers in Aggressive mode
        verify Save and Config reload with normal mode with PVST
        verify Save and Config reload with Aggressive mode with PVST
        verify Fast reboot with normal mode with PVST
        verify Fast reboot with Aggressive mode with PVST
        verify Cold reboot with normal mode with PVST
        verify Cold reboot with Aggressive mode with PVST
        verify UDLD docker restartwith normal mode with PVST
        verify UDLD docker restart with Aggressive mode with PVST
    '''
    tc_list = ['FtOpSoSwpvstudld001', 'FtOpSoSwpvstudld002','FtOpSoSwpvstudld003','FtOpSoSwpvstudld004',\
              'FtOpSoSwpvstudldConfReload001', 'FtOpSoSwpvstudldConfReload002',\
              'FtOpSoSwpvstudldFastReboot001','FtOpSoSwpvstudldFastReboot002',\
              'FtOpSoSwpvstudldColdReboot001','FtOpSoSwpvstudldColdReboot002',\
              'FtOpSoSwpvstudldDockerRestart001', 'FtOpSoSwpvstudldDockerRestart002']
    print_log("START of TC:test_pvst_udld_normal_aggressive ==>Sub-Test:Verify UDLD functionality with PVST\n TCs:<{}>".format(tc_list), "HIGH")
    final_result = True
    tc_result1 = 0
    tc_result2 = 0
    tc_result3 = 0
    tc_result4 = 0
    tc_result5 = 0
    tc_result6 = 0
    tc_result7 = 0
    tc_result8 = 0
    tc_result9 = 0
    tc_result10 = 0
    tc_result11 = 0
    tc_result12 = 0
    tx_rx_fail = 0
    udld_neighbor_fail = 0
    udld_timers_fail = 0
    udld_global_fail = 0
    udld_mode_fail = 0
    udld_neighbor_agg_fail = 0
    udld_neighbor_block_fail = 0
    udld_neighbor_unblock_fail = 0
    tx_rx_agg_fail = 0
    udld_interface_normal_block_fail = 0
    udld_interface_normal_unblock_fail = 0
    udld_interface_aggressive_block_fail = 0
    udld_interface_aggressive_unblock_fail = 0
    udld_neighbor_config_reload_norm_fail = 0
    udld_neighbor_fast_reboot_norm_fail = 0
    udld_neighbor_cold_reboot_norm_fail = 0
    udld_neighbor_docker_restart_norm_fail = 0
    udld_neighbor_config_reload_agg_fail = 0
    udld_neighbor_fast_reboot_agg_fail = 0
    udld_neighbor_cold_reboot_agg_fail = 0
    udld_neighbor_docker_restart_agg_fail = 0
    udld_local_state_normal_fail = 0
    udld_local_state_normal_block_fail = 0
    udld_block_local_state_config_reload_norm_fail = 0
    udld__block_local_state_fast_reboot_norm_fail = 0
    udld__block_local_state_cold_reboot_norm_fail = 0
    udld__block_local_state_docker_restart_norm_fail = 0
    udld_local_state_aggressive_fail = 0
    udld_local_state_aggressive_block_fail = 0
    udld_block_local_state_config_reload_agg_fail = 0
    udld__block_local_state_fast_reboot_agg_fail = 0
    udld__block_local_state_cold_reboot_agg_fail = 0
    udld__block_local_state_docker_restart_agg_fail = 0
    udld_neighbor_agg_norm_fail = 0
    udld_local_state_aggressive_normal_fail = 0
    udld_neighbor_agg_norm_block_fail = 0
    udld_local_state_aggressive_normal_block_fail = 0
    udld_interface_aggressive_normal_block_fail = 0
    udld_neighbor_unblock_agg_norm_fail = 0
    udld_interface_aggressive_normal_unblock_fail = 0
    udld_rstp_convergence_normal_blk_v10_fail = 0
    udld_rstp_convergence_normal_blk_v11_fail = 0
    udld_rstp_convergence_normal_fwd_v10_fail = 0
    udld_rstp_convergence_normal_fwd_v11_fail = 0
    ##########################################NORMAL MODE TESTS START#######################################
    ### Send traffic and verify packet count received
    print_log(" Clear the port counters and start traffic streams.", "MED")
    start_traffic()
    if verify_traffic():
        print_log("Traffic verification in Normal mode PASSED", "HIGH")
    else:
        print_log("Traffic verification in Normal mode FAILED", "HIGH")
        tx_rx_fail += 1
        tc_result1 += 1
        final_result = False
    print_log("Verify the UDLD local states in Normal Mode...",'MED')
    mode = "normal"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Local states in normal mode verification PASSED", "HIGH")
    else:
        print_log("UDLD Local states in normal mode verification FAILED", "HIGH")
        udld_local_state_normal_fail += 1
        tc_result1 += 1
        final_result = False
    dict1 = {'udld_message_time': udld_timers[dut1]['udld_message_time'], 'config': udld_timers[dut1]['config']}
    dict2 = {'udld_message_time': udld_timers[dut2]['udld_message_time'], 'config': udld_timers[dut2]['config']}
    dict3 = {'udld_message_time': udld_timers[dut3]['udld_message_time'], 'config': udld_timers[dut3]['config']}
    pll.exec_parallel(True,dut_list,udld.config_udld_message_time, [dict1, dict2, dict3])
    dict1 = {'udld_multiplier': udld_timers[dut1]['udld_multiplier'], 'config': udld_timers[dut1]['config']}
    dict2 = {'udld_multiplier': udld_timers[dut2]['udld_multiplier'], 'config': udld_timers[dut2]['config']}
    dict3 = {'udld_multiplier': udld_timers[dut3]['udld_multiplier'], 'config': udld_timers[dut3]['config']}
    pll.exec_parallel(True,dut_list,udld.config_udld_multiplier, [dict1, dict2, dict3])

    if verify_udld_timers(udld_timers):
        print_log("UDLD timers verification PASSED", "HIGH")
    else:
        print_log("UDLD timers verification FAILED", "HIGH")
        udld_timers_fail += 1
        tc_result1 += 1
        final_result = False


    print_log("Configure back the Message timer and Multiplier 1 and 3..",'MED')
    dict1 = {'udld_message_time': udld_global[dut1]['udld_message_time'], 'config': udld_global[dut1]['config']}
    dict2 = {'udld_message_time': udld_global[dut2]['udld_message_time'], 'config': udld_global[dut2]['config']}
    dict3 = {'udld_message_time': udld_global[dut3]['udld_message_time'], 'config': udld_global[dut3]['config']}
    pll.exec_parallel(True,dut_list,udld.config_udld_message_time, [dict1, dict2, dict3])
    dict1 = {'udld_multiplier': udld_global[dut1]['udld_multiplier'], 'config': udld_global[dut1]['config']}
    dict2 = {'udld_multiplier': udld_global[dut2]['udld_multiplier'], 'config': udld_global[dut2]['config']}
    dict3 = {'udld_multiplier': udld_global[dut3]['udld_multiplier'], 'config': udld_global[dut3]['config']}
    pll.exec_parallel(True,dut_list,udld.config_udld_multiplier, [dict1, dict2, dict3])

    ### Verify UDLD global state and attributes
    if verify_udld_global(udld_global):
        print_log("UDLD Global verification PASSED", "HIGH")
    else:
        print_log("UDLD Global verification FAILED", "HIGH")
        udld_global_fail += 1
        tc_result1 += 1
        final_result = False

    ####################PDB will REMOVE after suite completion
    #import pdb;pdb.set_trace()
    print_log("Blocking the UDLD packets in direction DUT3 to DUT1 in Normal Mode...",'MED')
    dict1 = {'intf': udld_int[dut1]['udld_int_block'], 'config': udld_int[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.udld_block, [dict1])
    print_log("Sleep for default multiplier 5 Sec the state in Bi-directional in normal mode...",'MED')
    st.wait(5)
    if verify_udld_neighbor_norm(udld_neighbor):
        print_log("UDLD neighbor in normal mode verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in normal mode verification FAILED", "HIGH")
        udld_neighbor_fail += 1
        tc_result1 += 1
        final_result = False

    print_log("Verify the UDLD Block local states in Normal Mode...",'MED')
    mode = "udldblocknormal"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in normal mode verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in normal mode verification FAILED", "HIGH")
        udld_local_state_normal_block_fail += 1
        tc_result1 += 1
        final_result = False

    print_log("Verify that the ports from DUT3 to DUT1 should go down in Normal Mode...",'MED')
    udld_interfaces = [vars.D3D1P1,vars.D3D1P2,vars.D3D1P3]
    state = 'down'
    if verify_udld_port_status(udld_interfaces,dut3,state):
        print_log("The ports from DUT3 to DUT1 is going to down state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT3 to DUT1 is not going to down state verification FAILED", "HIGH")
        udld_interface_normal_block_fail += 1
        tc_result1 += 1
        final_result = False
    if tc_result1 > 0:
       st.report_tc_fail("FtOpSoSwpvstudld001", "UDLD_PVST_Normal_message_and_multiplier_timers_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudld001", "UDLD_PVST_Normal _message_and_multiplier_timers_Passed", "test_pvst_udld_normal_aggressive")
    ###############REBOOT/DOCKER RESTART TESTS NORMAL MODE######################################
    print_log("Enable docker routing mode and save on All DUTs...", 'MED')
    utils.exec_foreach(True, dut_list, bgp_api.enable_docker_routing_config_mode)
    utils.exec_foreach(True, dut_list, reboot_api.config_save)

    print_log("Do Config Reload in Normal Mode...", 'MED')
    reboot_api.config_reload(dut3)
    udld.check_udld_status_after_restart(dut3)
    st.wait(15)
    if verify_udld_neighbor_norm(udld_neighbor):
        print_log("UDLD neighbor in normal mode after config reload verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in normal mode after config reload verification FAILED", "HIGH")
        udld_neighbor_config_reload_norm_fail += 1
        tc_result5 += 1
        final_result = False

    mode = "udldblocknormal"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in normal mode after config reload verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in normal mode after config reload verification FAILED", "HIGH")
        udld_block_local_state_config_reload_norm_fail += 1
        tc_result5 += 1
        final_result = False

    if tc_result5 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldConfReload001", "UDLD_PVST_Normal_Config_Reload_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldConfReload001", "UDLD_PVST_Normal_Config_Reload_Passed", "test_pvst_udld_normal_aggressive")

    print_log("Do Fast Reboot in Normal Mode...", 'MED')
    st.reboot(dut3,"fast")
    udld.check_udld_status_after_restart(dut3)

    st.wait(15)
    if verify_udld_neighbor_norm(udld_neighbor):
        print_log("UDLD neighbor in normal mode after fast reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in normal mode after fast reboot verification FAILED", "HIGH")
        udld_neighbor_fast_reboot_norm_fail += 1
        tc_result7 += 1
        final_result = False

    mode = "udldblocknormal"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in normal mode after fast reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in normal mode after fast reboot verification FAILED", "HIGH")
        udld__block_local_state_fast_reboot_norm_fail += 1
        tc_result7 += 1
        final_result = False

    if tc_result7 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldFastReboot001", "UDLD_PVST_Normal_Fast_Reboot_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldFastReboot001", "UDLD_PVST_Normal_Fast_Reboot_Passed", "test_pvst_udld_normal_aggressive")

    print_log("Do Cold Reboot in Normal Mode...", 'MED')
    st.reboot(dut3)
    udld.check_udld_status_after_restart(dut3)
    st.wait(15)
    if verify_udld_neighbor_norm(udld_neighbor):
        print_log("UDLD neighbor in normal mode after cold reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in normal mode after cold reboot verification FAILED", "HIGH")
        udld_neighbor_cold_reboot_norm_fail += 1
        tc_result9 += 1
        final_result = False

    mode = "udldblocknormal"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in normal mode after cold reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in normal mode after cold reboot verification FAILED", "HIGH")
        udld__block_local_state_cold_reboot_norm_fail += 1
        tc_result9 += 1
        final_result = False

    print_log("UnBlocking the UDLD packets in direction DUT3 to DUT1...",'MED')
    dict1 = {'intf': udld_int[dut1]['udld_int_block'], 'config': 'no'}
    pll.exec_parallel(True,[dut1],udld.udld_block, [dict1])
    ###Do  udld reset
    print_log("Reset the UDLD on  DUT3 in Normal mode...",'MED')
    api_list = []
    api_list.append([udld.udld_reset, dut3])
    utils.exec_all(True, api_list)
    st.wait(5)

    print_log("After udld reset, the state should be Bidirectional on DUT1 and DUT3...",'MED')
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in Aggressive mode verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in Aggressive mode verification FAILED", "HIGH")
        udld_neighbor_agg_fail += 1
        tc_result9 += 1
        final_result = False

    print_log("Verify that the ports from DUT3 to DUT1 should up in Normal Mode...",'MED')
    udld_interfaces = [vars.D3D1P1,vars.D3D1P2,vars.D3D1P3]
    state = 'up'
    if verify_udld_port_status(udld_interfaces,dut3,state):
        print_log("The ports from DUT3 to DUT1 is in up state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT3 to DUT1 is not in up state verification FAILED", "HIGH")
        udld_interface_normal_unblock_fail += 1
        tc_result9 += 1
        final_result = False

    if tc_result9 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldColdReboot001", "UDLD_PVST_Normal_Cold_Reboot_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldColdReboot001", "UDLD_PVST_Normal_Cold_Reboot_Passed", "test_pvst_udld_normal_aggressive")

    print_log("Do docker udld restart in Normal Mode...", 'MED')
    basic_api.service_operations_by_systemctl(dut3,"udld","restart")

    st.wait(15)
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in normal mode after docker restart verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in normal mode after docker restart verification FAILED", "HIGH")
        udld_neighbor_docker_restart_norm_fail += 1
        tc_result11 += 1
        final_result = False

    mode = "normal"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Local states in normal mode after docker restart verification PASSED", "HIGH")
    else:
        print_log("UDLD Local states in normal mode after docker restart verification FAILED", "HIGH")
        udld__block_local_state_docker_restart_norm_fail += 1
        tc_result11 += 1
        final_result = False

    if tc_result11 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldDockerRestart001", "UDLD_PVST_Normal_Docker_Restart_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldDockerRestart001", "UDLD_PVST_Normal_Docker_Restart_Passed", "test_pvst_udld_normal_aggressive")

    ##########################################AGGRESSIVE MODE TESTS START#######################################
    ###Enable UDLD mode Aggressive
    print_log("Enable the UDLD Mode Agrgressive on All DUTs...", 'MED')
    dict1 = {'udld_mode': udld_global[dut1]['udld_enable'], 'config': udld_global[dut1]['config']}
    dict2 = {'udld_mode': udld_global[dut2]['udld_enable'], 'config': udld_global[dut2]['config']}
    dict3 = {'udld_mode': udld_global[dut3]['udld_enable'], 'config': udld_global[dut3]['config']}
    pll.exec_parallel(True,dut_list,udld.config_udld_mode, [dict1, dict2, dict3])

    ### Verify UDLD mode
    if verify_udld_mode('Aggressive'):
        print_log("UDLD Mode Aggressive verification PASSED", "HIGH")
    else:
        print_log("UDLD Mode Aggressive verification FAILED", "HIGH")
        udld_mode_fail += 1
        tc_result2 += 1
        final_result = False

    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in Aggressive mode verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in Aggressive mode verification FAILED", "HIGH")
        udld_neighbor_agg_fail += 1
        tc_result2 += 1
        final_result = False

    mode = "aggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Local states in aggressive mode verification PASSED", "HIGH")
    else:
        print_log("UDLD Local states in aggressive mode verification FAILED", "HIGH")
        udld_local_state_aggressive_fail += 1
        tc_result2 += 1
        final_result = False

    print_log("Blocking the UDLD packets in direction DUT3 to DUT1 in Aggressive Mode...",'MED')
    dict1 = {'intf': udld_int[dut1]['udld_int_block'], 'config': udld_int[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.udld_block, [dict1])
    print_log("Sleep for default multiplier 3 Sec the state in Unidirectional in Aggressive mode...",'MED')
    st.wait(5)

    if verify_udld_neighbor_agg(udld_neighbor):
        print_log("UDLD neighbor in Aggressive mode after time out verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in Aggressive mode after time out verification FAILED", "HIGH")
        udld_neighbor_block_fail += 1
        tc_result2 += 1
        final_result = False

    print_log("Verify the UDLD Block local states in Aggresive Mode...",'MED')
    mode = "udldblockaggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in Aggresive mode verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in Aggresive mode verification FAILED", "HIGH")
        udld_local_state_aggressive_block_fail += 1
        tc_result2 += 1
        final_result = False

    print_log("Verify that the ports from DUT1 to DUT3 should go down in Aggressive Mode...",'MED')
    udld_interfaces = [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3]
    state = 'down'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT3 is going to down state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT3 is not going to down state verification FAILED", "HIGH")
        udld_interface_aggressive_block_fail += 1
        tc_result2 += 1
        final_result = False

    if tc_result2 > 0:
       st.report_tc_fail("FtOpSoSwpvstudld002", "UDLD_PVST_Aggressive_message_and_multiplier_timers_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudld002", "UDLD_PVST_Aggressive_message_and_multiplier_timers_Passed", "test_pvst_udld_normal_aggressive")

    ###############REBOOT/DOCKER RESTART TESTS AGGRESSIVE MODE######################################
    print_log("Enable docker routing mode and save on DUT...", 'MED')
    utils.exec_foreach(True, dut_list, bgp_api.enable_docker_routing_config_mode)
    utils.exec_foreach(True, dut_list, reboot_api.config_save)

    print_log("Do Config Reload in Aggressive Mode...", 'MED')
    reboot_api.config_reload(dut3)
    udld.check_udld_status_after_restart(dut3)
    st.wait(15)
    if verify_udld_neighbor_norm(udld_neighbor):
        print_log("UDLD neighbor in aggressive mode after config reload verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in aggressive mode after config reload verification FAILED", "HIGH")
        udld_neighbor_config_reload_agg_fail += 1
        tc_result6 += 1
        final_result = False

    mode = "udldblockaggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in aggressive mode after config reload verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in aggressive mode after config reload verification FAILED", "HIGH")
        udld_block_local_state_config_reload_agg_fail += 1
        tc_result6 += 1
        final_result = False

    if tc_result6 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldConfReload002", "UDLD_PVST_Aggressive_Config_Reload_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldConfReload002", "UDLD_PVST_Aggressive_Config_Reload_Passed", "test_pvst_udld_normal_aggressive")

    print_log("Do Fast Reboot in Aggressive Mode...", 'MED')
    st.reboot(dut3,"fast")
    udld.check_udld_status_after_restart(dut3)
    st.wait(15)
    if verify_udld_neighbor_norm(udld_neighbor):
        print_log("UDLD neighbor in aggressive mode after fast reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in aggressive mode after fast reboot verification FAILED", "HIGH")
        udld_neighbor_fast_reboot_agg_fail += 1
        tc_result8 += 1
        final_result = False

    mode = "udldblockaggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in aggressive mode after fast reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in aggressive mode after fast reboot verification FAILED", "HIGH")
        udld__block_local_state_fast_reboot_agg_fail += 1
        tc_result8 += 1
        final_result = False

    if tc_result8 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldFastReboot002", "UUDLD_PVST_Aggressive_Fast_Reboot_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldFastReboot002", "UDLD_PVST_Aggressive_Fast_Reboot_Passed", "test_pvst_udld_normal_aggressive")

    print_log("Do Cold Reboot in Aggressive Mode...", 'MED')
    st.reboot(dut3)
    udld.check_udld_status_after_restart(dut3)
    st.wait(15)
    if verify_udld_neighbor_norm(udld_neighbor):
        print_log("UDLD neighbor in aggressive mode after cold reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in aggressive mode after cold reboot verification FAILED", "HIGH")
        udld_neighbor_cold_reboot_agg_fail += 1
        tc_result10 += 1
        final_result = False

    mode = "udldblockaggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in Aggressive mode after cold reboot verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in Aggressive mode after cold reboot verification FAILED", "HIGH")
        udld__block_local_state_cold_reboot_agg_fail += 1
        tc_result10 += 1
        final_result = False

    ###unblock the udld packets
    print_log("UnBlocking the UDLD packets in direction DUT3 to DUT1 in Aggressive mode...",'MED')
    dict1 = {'intf': udld_int[dut1]['udld_int_block'], 'config': 'no'}
    pll.exec_parallel(True,[dut1],udld.udld_block, [dict1])

    ###Do  udld reset
    print_log("Reset the UDLD on DUT1 in Aggressive mode...",'MED')
    api_list = []
    api_list.append([udld.udld_reset, dut1])
    utils.exec_all(True, api_list)
    st.wait(5)

    print_log("Verify the UDLD neighbor state in Bidirectional after udld reset in Aggressive mode...",'MED')
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in Aggressive mode verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in Aggressive mode verification FAILED", "HIGH")
        udld_neighbor_unblock_fail += 1
        tc_result10 += 1
        final_result = False

    print_log("Verify that the ports from DUT1 to DUT3 should come up in Aggressive Mode...",'MED')
    udld_interfaces = [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3]
    state = 'up'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT3 is going to up state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT3 is not going to up state verification FAILED", "HIGH")
        udld_interface_aggressive_unblock_fail += 1
        tc_result10 += 1
        final_result = False

    if tc_result10 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldColdReboot002", "UDLD_PVST_Aggressive_Cold_Reboot_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldColdReboot002", "UDLD_PVST_Aggressive_Cold_Reboot_Passed", "test_pvst_udld_normal_aggressive")

    print_log("Do docker udld restart in Aggressive Mode...", 'MED')
    basic_api.service_operations_by_systemctl(dut3,"udld","restart")
    st.wait(15)
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in aggressive mode after docker restart verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in aggressive mode after docker restart verification FAILED", "HIGH")
        udld_neighbor_docker_restart_agg_fail += 1
        tc_result12 += 1
        final_result = False

    mode = "aggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD  Local states in aggressive mode after docker restart verification PASSED", "HIGH")
    else:
        print_log("UDLD Local states in aggressive mode after docker restart verification FAILED", "HIGH")
        udld__block_local_state_docker_restart_agg_fail += 1
        tc_result12 += 1
        final_result = False

    ###Verify the traffic in Aggressive Mode
    if verify_traffic():
        print_log("Traffic verification in Aggressive mode PASSED", "HIGH")
    else:
        print_log("Traffic verificationin Aggressive mode FAILED", "HIGH")
        tx_rx_agg_fail += 1
        tc_result12 += 1
        final_result = False
    if tc_result12 > 0:
       st.report_tc_fail("FtOpSoSwpvstudldDockerRestart002", "UDLD_PVST_Aggressive_Docker_Restart_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudldDockerRestart002", "UDLD_PVST_Aggressive_Docker_Restart_Failed", "test_pvst_udld_normal_aggressive")

    #######################DUT1 Agressive and DUT3 Normal Mode########################################
    print_log("Enable Aggressive Mode On DUT1 and DUT2 and Normal Mode on DUT3", "HIGH")
    dict1 = {'udld_mode':'yes', 'config':'yes'}
    dict2 = {'udld_mode':'yes', 'config':'yes'}
    dict3 = {'udld_mode':'no', 'config':'no'}
    pll.exec_parallel(True,dut_list,udld.config_udld_mode, [dict1, dict2, dict3])


    print_log("Verify the UDLD neighbors on all DUTS...",'MED')
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in Aggressive and Normal mode verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in Aggressive and Normal verification FAILED", "HIGH")
        udld_neighbor_agg_norm_fail += 1
        tc_result3 += 1
        final_result = False

    print_log("Verify the UDLD Local states on all DUTS...",'MED')
    mode = "aggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Local states in aggressive and normal mode verification PASSED", "HIGH")
    else:
        print_log("UDLD Local states in aggressive and normal mode verification FAILED", "HIGH")
        udld_local_state_aggressive_normal_fail += 1
        tc_result3 += 1
        final_result = False

    print_log("Blocking the UDLD packets in direction DUT3 to DUT1 in Normal Mode...",'MED')
    dict1 = {'intf': udld_int[dut1]['udld_int_block'], 'config': udld_int[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.udld_block, [dict1])
    print_log("Sleep for default multiplier 5 Sec the state in Bi-directional in normal mode...",'MED')
    st.wait(5)

    print_log("Verify the UDLD Neighbors after Block in Aggresive and Normal Mode...",'MED')
    if verify_udld_neighbor_agg(udld_neighbor):
        print_log("UDLD neighbor in Aggressive and Local mode after time out verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in Aggressive and Local mode after time out verification FAILED", "HIGH")
        udld_neighbor_agg_norm_block_fail += 1
        tc_result3 += 1
        final_result = False

    print_log("Verify the UDLD Block local states in Aggresive and Normal Mode...",'MED')
    mode = "udldblockaggressive"
    if verify_udld_interface(udld_int,mode):
        print_log("UDLD Block Local states in Aggresive and Normal mode verification PASSED", "HIGH")
    else:
        print_log("UDLD Block Local states in Aggresive and Normal mode verification FAILED", "HIGH")
        udld_local_state_aggressive_normal_block_fail += 1
        tc_result3 += 1
        final_result = False

    print_log("Verify that the ports from DUT1 to DUT3 should go down in Aggressive and Normal Mode...",'MED')
    udld_interfaces = [vars.D1D3P1,vars.D1D3P2,vars.D1D3P3]
    state = 'down'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT3 is going to down state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT3 is not going to down state verification FAILED", "HIGH")
        udld_interface_aggressive_normal_block_fail += 1
        tc_result3 += 1
        final_result = False

    print_log("Enable the errordisable recovery global...",'MED')
    dict1 = {'udld_recover': udld_global[dut1]['udld_recover'], 'module': udld_global[dut1]['module']}
    pll.exec_parallel(True,[dut1],udld.config_udld_recover, [dict1])

    print_log("Configure the errordisable recovery timer to 30 sec...",'MED')
    dict1 = {'udld_recover_timer': udld_global[dut1]['udld_recover_timer']}
    pll.exec_parallel(True,[dut1],udld.config_udld_recover_timer, [dict1])

    print_log("UnBlocking the UDLD packets in direction DUT3 to DUT1 in Aggressive and Normal mode...",'MED')
    dict1 = {'intf': udld_int[dut1]['udld_int_block'], 'config': 'no'}
    pll.exec_parallel(True,[dut1],udld.udld_block, [dict1])
    st.wait(35)

    print_log("Verify the UDLD neighbor state in Bidirectional after ports shut/no shut in Aggressive and normal mode...",'MED')
    if verify_udld_neighbor(udld_neighbor):
        print_log("UDLD neighbor in Aggressive and Normal mode verification PASSED", "HIGH")
    else:
        print_log("UDLD neighbor in Aggressive and Normal mode verification FAILED", "HIGH")
        udld_neighbor_unblock_agg_norm_fail += 1
        tc_result3 += 1
        final_result = False

    print_log("Verify that the ports from DUT1 to DUT3 should come up in Aggressive and Normal Mode...",'MED')
    state = 'up'
    if verify_udld_port_status(udld_interfaces,dut1,state):
        print_log("The ports from DUT1 to DUT3 is going to up state verification PASSED", "HIGH")
    else:
        print_log("The ports from DUT1 to DUT3 is not going to up state verification FAILED", "HIGH")
        udld_interface_aggressive_normal_unblock_fail += 1
        tc_result3 += 1
        final_result = False

    print_log("Configure the errordisable recovery timer to default 300 sec...",'MED')
    dict1 = {'udld_recover_timer': 300}
    pll.exec_parallel(True,[dut1],udld.config_udld_recover_timer, [dict1])

    print_log("Disable the errordisable recovery global...",'MED')
    dict1 = {'udld_recover': 'disable', 'module': udld_global[dut1]['module']}
    pll.exec_parallel(True,[dut1],udld.config_udld_recover, [dict1])

    if tc_result3 > 0:
       st.report_tc_fail("FtOpSoSwpvstudld003", "UDLD_PVST_Aggressive_and_Normal_mode_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudld003", "UDLD_PVST_Aggressive_and_Normal_mode_Passed", "test_pvst_udld_normal_aggressive")

    #######################PVST Convergence########################################
    print_log("PVST Path convergence from DUT1->DUT2->DUT3 to DUT1->DUT3->DUT2 when block the UDLD on DUT1->DUT2 ports", "HIGH")
    print_log("Verify that the PVST Path convergence in direction DUT1->DUT2->DUT3 in Aggressive Mode...",'MED')
    port_list_vlan10 = [vars.D3D1P1]
    port_list_vlan11 = ['PortChannel2']
    if pvst.verify_stp_ports_by_state(dut3, trunk_base_vlan, "BLOCKING", port_list_vlan10):
        print_log("The ports DUT3 to DUT1 in vlan 10 BLOCKING state verification PASSED", "HIGH")
    else:
        print_log("The ports DUT3 to DUT1 in vlan 10 BLOCKING state verification FAILED", "HIGH")
        udld_rstp_convergence_normal_blk_v10_fail += 1
        tc_result4 += 1
        final_result = False

    if pvst.verify_stp_ports_by_state(dut3, trunk_base_vlan+1, "BLOCKING", port_list_vlan11):
        print_log("The ports DUT3 to DUT1 in vlan 11 BLOCKING state verification PASSED", "HIGH")
    else:
        print_log("The ports DUT3 to DUT1 in vlan 11 BLOCKING state verification FAILED", "HIGH")
        udld_rstp_convergence_normal_blk_v11_fail += 1
        tc_result4 += 1
        final_result = False

    print_log("Blocking the UDLD packets in direction DUT2 to DUT1 in Aggressive Mode...",'MED')
    dict1 = {'intf': udld_int[dut1]['udld_int_block_stp'], 'config': udld_int[dut1]['config']}
    pll.exec_parallel(True,[dut1],udld.udld_block, [dict1])
    st.wait(60)
    if pvst.verify_stp_ports_by_state(dut3, trunk_base_vlan, "FORWARDING", port_list_vlan10):
        print_log("The ports DUT3 to DUT1 in vlan 10 FORWARDING state verification PASSED", "HIGH")
    else:
        print_log("The ports DUT3 to DUT1 in vlan 10 FORWARDING state verification FAILED", "HIGH")
        udld_rstp_convergence_normal_fwd_v10_fail += 1
        tc_result4 += 1
        final_result = False

    if pvst.verify_stp_ports_by_state(dut3, trunk_base_vlan+1, "FORWARDING", port_list_vlan11):
        print_log("The ports DUT3 to DUT1 in vlan 11 FORWARDING state verification PASSED", "HIGH")
    else:
        print_log("The ports DUT3 to DUT1 in vlan 11 FORWARDING state verification FAILED", "HIGH")
        udld_rstp_convergence_normal_fwd_v11_fail += 1
        tc_result4 += 1
        final_result = False

    if tc_result4 > 0:
       st.report_tc_fail("FtOpSoSwpvstudld004", "UDLD_PVST_Convergence_Failed", "test_pvst_udld_normal_aggressive")
    else:
       st.report_tc_pass("FtOpSoSwpvstudld004", "UDLD_PVST_Convergence_Passed", "test_pvst_udld_normal_aggressive")

    ###Move UDLD mode Normal
    print_log("Enable the UDLD Mode Back to Default Normal on All DUTs...", 'MED')
    dict1 = {'udld_mode':'no', 'config':'no'}
    dict2 = {'udld_mode':'no', 'config':'no'}
    dict3 = {'udld_mode':'no', 'config':'no'}
    pll.exec_parallel(True,dut_list,udld.config_udld_mode, [dict1, dict2, dict3])


    if final_result:
        st.report_pass("test_case_passed")
    else:
        fail_msg = []
        #########Normal
        if tx_rx_fail > 0:
            fail_msg.append('UDLD rx Failed in Normal mode:')
        if udld_local_state_normal_fail > 0:
            fail_msg.append('UDLD Local states Failed in Normal mode:')
        if udld_neighbor_fail > 0:
            fail_msg.append('UDLD neighbor state Failed:')
        if udld_interface_normal_block_fail > 0:
            fail_msg.append('UDLD ports not down Failed in Normal mode:')
        if udld_local_state_normal_block_fail > 0:
            fail_msg.append('UDLD Block Local states Failed in Normal mode:')
        if udld_neighbor_config_reload_norm_fail > 0:
            fail_msg.append('UDLD Neighbor config Reload Failed in Normal mode:')
        if udld_block_local_state_config_reload_norm_fail > 0:
            fail_msg.append('UDLD Interface config Reload Failed in Normal mode:')
        if udld_neighbor_fast_reboot_norm_fail > 0:
            fail_msg.append('UDLD Neighbor fast Reboot Failed in Normal mode:')
        if udld__block_local_state_fast_reboot_norm_fail > 0:
            fail_msg.append('UDLD Interface fast Reboot Failed in Normal mode:')
        if udld_neighbor_cold_reboot_norm_fail > 0:
            fail_msg.append('UDLD Neighbor cold Reboot Failed in Normal mode:')
        if udld__block_local_state_cold_reboot_norm_fail > 0:
            fail_msg.append('UDLD Interface cold fast Reboot Failed in Normal mode:')
        if udld_neighbor_docker_restart_norm_fail > 0:
            fail_msg.append('UDLD Neighbor cold docker Restart in Normal mode:')
        if udld__block_local_state_docker_restart_norm_fail > 0:
            fail_msg.append('UDLD Interface cold docker restart Failed in Normal mode:')
        if udld_interface_normal_unblock_fail > 0:
            fail_msg.append('UDLD ports not down Failed in Aggressive mode:')
        if udld_timers_fail > 0:
            fail_msg.append('UDLD timers configuration in normal Failed:')
        if udld_global_fail > 0:
            fail_msg.append('UDLD timers back to default configuration in normal Failed:')

        #########Aggressive
        if udld_mode_fail > 0:
            fail_msg.append('UDLD mode Aggressive configuration Failed:')
        if udld_neighbor_agg_fail > 0:
            fail_msg.append('UDLD neighbor in Aggressive configuration Failed:')
        if udld_local_state_aggressive_fail > 0:
            fail_msg.append('UDLD Local states Failed in aggressive mode:')
        if udld_neighbor_block_fail > 0:
            fail_msg.append('UDLD Block neighbor state in Aggressive  Failed :')
        if udld_local_state_aggressive_block_fail > 0:
            fail_msg.append('UDLD Block Local states Failed in Aggressive mode:')
        if udld_interface_aggressive_unblock_fail > 0:
            fail_msg.append('UDLD ports not up Failed in Aggressive mode:')
        if udld_neighbor_config_reload_agg_fail > 0:
            fail_msg.append('UDLD config Reload Failed in Aggressive mode:')
        if udld_block_local_state_config_reload_agg_fail > 0:
            fail_msg.append('UDLD Interface config Reload Failed in Aggressive mode:')
        if udld_neighbor_fast_reboot_agg_fail > 0:
            fail_msg.append('UDLD fast Reboot Failed in Aggressive mode:')
        if udld__block_local_state_fast_reboot_agg_fail > 0:
            fail_msg.append('UDLD Interface fast Reboot Failed in Aggressive mode:')
        if udld_neighbor_cold_reboot_agg_fail > 0:
            fail_msg.append('UDLD cold Reboot Failed in Aggressive mode:')
        if udld__block_local_state_cold_reboot_agg_fail > 0:
            fail_msg.append('UDLD Interface cold fast Reboot Failed in Aggressive mode:')
        if udld_neighbor_docker_restart_agg_fail > 0:
            fail_msg.append('UDLD cold docker Restart in Aggressive mode:')
        if udld__block_local_state_docker_restart_agg_fail > 0:
            fail_msg.append('UDLD Interface docker restart Failed in Aggressive mode:')
        if udld_neighbor_unblock_fail > 0:
            fail_msg.append('UDLD Unblock neighbor state in Aggressive  Failed :')
        if tx_rx_agg_fail > 0:
            fail_msg.append('UDLD rx Failed in Aggressive mode:')
        if udld_neighbor_agg_norm_fail > 0:
            fail_msg.append('UDLD Neighbor Block Failed in Aggressive and Normal mode:')
        if udld_local_state_aggressive_normal_fail > 0:
            fail_msg.append('UDLD Local states Failed in Aggressive and Normal mode:')
        if udld_neighbor_agg_norm_block_fail > 0:
            fail_msg.append('UDLD Neighbor Block Failed in Aggressive and Normal mode:')
        if udld_local_state_aggressive_normal_block_fail > 0:
            fail_msg.append('UDLD Local states in neighbor Block Failed in Aggressive and Normal mode:')
        if udld_neighbor_unblock_agg_norm_fail > 0:
            fail_msg.append('UDLD Neighbor UnBlock Failed in Aggressive and Normal mode:')
        if udld_interface_aggressive_normal_unblock_fail > 0:
            fail_msg.append('UDLD ports not came up when unBlock neighbor Failed in Aggressive and Normal mode:')
        if udld_rstp_convergence_normal_blk_v10_fail  > 0:
            fail_msg.append('UDLD PVST Convergence BLOCKING in vlan 10 Failed in Aggressive mode:')
        if udld_rstp_convergence_normal_blk_v11_fail  > 0:
            fail_msg.append('UDLD PVST Convergence BLOCKING in vlan 11 Failed in Aggressive mode:')
        if udld_rstp_convergence_normal_fwd_v10_fail  > 0:
            fail_msg.append('UDLD PVST Convergence FORWARDING in vlan 10 Failed in Aggressive mode:')
        if udld_rstp_convergence_normal_fwd_v11_fail  > 0:
            fail_msg.append('UDLD PVST Convergence FORWARDING in vlan 11 Failed in Aggressive mode:')
        st.report_fail("test_case_failure_message", " ".join(fail_msg).strip(':'))


