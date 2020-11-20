#   OSPF functional test cases
#   Author:Sesha Reddy Koilkonda (seshareddy.koilkonda@broadcom.com)

import pytest
from spytest.utils import random_vlan_list,exec_all
from spytest.tgen.tgen_utils import validate_tgen_traffic, validate_packet_capture
from spytest.tgen.tg import *
from utilities import parallel
import utilities.utils as utilsapi
import apis.routing.ospf as ospfapi
import apis.routing.ip as ipapi
import apis.routing.bgp as bgpapi
import apis.system.reboot as rebootapi
import apis.switching.vlan as vlanapi
import apis.switching.portchannel as pcapi
import apis.system.interface as intfapi
import apis.system.basic as basicapi
import apis.routing.vrf as vrfapi
import apis.system.snmp as snmp_obj
from apis.system.connection import *
import apis.common.asic_bcm as asicapi


def ospf_initialize_variables():
    """
    This proc is used for declaring the common variables used as part of the scripting.
    :return:
    """
    global data
    data = SpyTestDict()
    data.shell_sonic = "sonic"
    data.shell_vtysh = "vtysh"
    data.vlan_li = random_vlan_list(2)
    data.vlan_in_1 = "Vlan{}".format(str(data.vlan_li[0]))
    data.vlan_in_2 = "Vlan{}".format(str(data.vlan_li[1]))
    data.loopback_addr_l = ["51.1.0.1", "51.1.0.2"]
    data.loopback_network_l = ["51.1.0.0/24"]
    data.tg1_ip4_addr_l = ["21.1.0.1", "22.1.0.1", "23.1.0.1", "24.1.0.1"]
    data.tg2_ip4_addr_l = ["41.1.0.1", "42.1.0.1"]
    data.tg1_ip4_addr_mask_l = ["24", "24", "24", "24"]
    data.tg2_ip4_addr_mask_l = ["24", "24"]
    data.dut1_tg1_ip4_addr_l = ["21.1.0.2", "22.1.0.2", "23.1.0.2", "24.1.0.2"]
    data.dut2_tg2_ip4_addr_l = ["41.1.0.2", "42.1.0.2"]
    data.dut1_dut2_ip4_addr_l = ["31.1.0.1", "32.1.0.1", "33.1.0.1", "34.1.0.1", "35.1.0.1"]
    data.dut2_dut1_ip4_addr_l = ["31.1.0.2", "32.1.0.2", "33.1.0.2", "34.1.0.2", "35.1.0.2"]
    data.dut1_network_l = ["21.1.0.0/24", "22.1.0.0/24", "23.1.0.0/24", "24.1.0.0/24", "31.1.0.0/24", "32.1.0.0/24", "33.1.0.0/24", "34.1.0.0/24", "35.1.0.0/24"]
    data.dut2_network_l = ["41.1.0.0/24", "42.1.0.0/24", "31.1.0.0/24", "32.1.0.0/24", "33.1.0.0/24", "34.1.0.0/24", "35.1.0.0/24" ]
    data.dut1_local_as = "1001"
    data.tg1_local_as = "2001"
    data.dut2_local_as = "3001"
    data.tg2_local_as = "4001"
    data.dut1_rid = "6.6.6.5"
    data.dut2_rid = "5.5.5.4"
    data.wait = 5
    data.vrf_name = ['Vrf-101', 'Vrf-102']
    data.af_ipv4 = 'ipv4'
    data.port_channel = "PortChannel100"
    data.nonDefault_mtu = ['4000', '5000']
    data.default_mtu = intfapi.get_interface_property(vars.D1, vars.D1D2P1, "mtu")[0]
    data.ospfNbrStateChange = "14.16.2.2"
    data.ospfIfStateChange = "14.16.2.16"
    data.bgpEstablishedNotification = "1.15.0.1"
    data.bgpBackwardTransNotification = "1.15.0.2"
    data.max_intra_routes = 5000
    data.max_ext_routes = 40000
    data.ro_community = 'test_123'
    cli_type = st.get_ui_type(cli_type='')
    data.cli_type = 'klish' if cli_type in ["rest-patch", "rest-put"] else cli_type
    data.seq_num = [str(k*10) for k in range(1, 15)]


def get_handles():
    """
    :return:
    """
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg1.get_port_handle(vars.T1D1P2)
    tg_ph_3 = tg1.get_port_handle(vars.T1D1P3)
    tg_ph_4 = tg1.get_port_handle(vars.T1D1P4)
    tg_ph_5 = tg2.get_port_handle(vars.T1D2P1)
    tg_ph_6 = tg2.get_port_handle(vars.T1D2P2)
    return (tg1, tg2, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4, tg_ph_5, tg_ph_6)


def tg_reset():
    """
    This Proc used to reset the TG ports.
    :return:
    """
    for action in ['reset', 'clear_stats']:
        tg1.tg_traffic_control(action=action, port_handle=[tg_ph_1,tg_ph_2,tg_ph_3,tg_ph_4])
        tg2.tg_traffic_control(action=action, port_handle=[tg_ph_5,tg_ph_6])


def tg_clear_stats():
    """
    This Proc used to reset the TG ports.
    :return:
    """
    tg1.tg_traffic_control(action='clear_stats', port_handle=[tg_ph_1,tg_ph_2,tg_ph_3,tg_ph_4])
    tg2.tg_traffic_control(action='clear_stats', port_handle=[tg_ph_5,tg_ph_6])


def ospf_module_preconfig():
    """
    This proc is used to configure the OSPF configurations for non-default/user vrfs on various ports.
    :return:
    """

    st.banner('Creating VRF and binding to interfaces')
    dict1 = {'vrf_name': data.vrf_name[0], 'skip_error': True}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.config_vrf, [dict1, dict1])

    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1T1P3, 'skip_error': True}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2T1P2, 'skip_error': True}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1D2P5, 'skip_error': True}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2D1P5, 'skip_error': True}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    st.banner('Assign the ip addresses on interfaces')
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address' : data.dut1_tg1_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address' : data.dut2_tg2_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1T1P3, 'ip_address' : data.dut1_tg1_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4}
    dict2 = {'interface_name': vars.D2T1P2, 'ip_address' : data.dut2_tg2_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P1, 'ip_address' : data.dut1_dut2_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4}
    dict2 = {'interface_name': vars.D2D1P1, 'ip_address' : data.dut2_dut1_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P5, 'ip_address' : data.dut1_dut2_ip4_addr_l[3], 'subnet' : 24, 'family' : data.af_ipv4}
    dict2 = {'interface_name': vars.D2D1P5, 'ip_address' : data.dut2_dut1_ip4_addr_l[3], 'subnet' : 24, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    #LAG configuration
    st.banner("Port routing configuration on port-channel")
    pcapi.config_portchannel(vars.D1, vars.D2, data.port_channel , [vars.D1D2P3, vars.D1D2P4], [vars.D2D1P3, vars.D2D1P4], config='add', thread=True)

    dict1 = {'interface_name': data.port_channel, 'ip_address' : data.dut1_dut2_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4}
    dict2 = {'interface_name': data.port_channel, 'ip_address' : data.dut2_dut1_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner('Creating Vlans and ports into vlans')
    exec_all(True, [[vlanapi.create_vlan, vars.D1, [data.vlan_li[0], data.vlan_li[1]]], [vlanapi.create_vlan, vars.D2, [data.vlan_li[0], data.vlan_li[1]]]])

    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': data.vlan_in_2, 'skip_error': True}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': data.vlan_in_2, 'skip_error': True}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'port_list': vars.D1D2P2, 'vlan': data.vlan_li[0]}
    dict2 = {'port_list': vars.D2D1P2, 'vlan': data.vlan_li[0]}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vlanapi.add_vlan_member, [dict1, dict2])

    dict1 = {'port_list': vars.D1D2P6, 'vlan': data.vlan_li[1]}
    dict2 = {'port_list': vars.D2D1P6, 'vlan': data.vlan_li[1]}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vlanapi.add_vlan_member, [dict1, dict2])

    dict1 = {'interface_name': data.vlan_in_1, 'ip_address' : data.dut1_dut2_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4}
    dict2 = {'interface_name': data.vlan_in_1, 'ip_address' : data.dut2_dut1_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': data.vlan_in_2, 'ip_address' : data.dut1_dut2_ip4_addr_l[4], 'subnet' : 24, 'family' : data.af_ipv4}
    dict2 = {'interface_name': data.vlan_in_2, 'ip_address' : data.dut2_dut1_ip4_addr_l[4], 'subnet' : 24, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner('Configure ospf Router-id for default and non default vrfs')
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router, [{'vrf': 'default'}, {'vrf': 'default'}])

    dict1 = {'router_id': data.dut1_rid, 'vrf' :'default'}
    dict2 = {'router_id': data.dut2_rid, 'vrf': 'default'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_id, [dict1, dict2])

    st.banner("Configure OSPF peers for the default-vrf domain")
    dict1 = {'networks': data.dut1_network_l[0], 'area' : '0.0.0.1', 'vrf' :'default'}
    dict2 = {'networks': data.dut2_network_l[0], 'area' : '0.0.0.2', 'vrf' :'default'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    dict1 = {'networks': [data.dut1_network_l[4],data.dut1_network_l[5],data.dut1_network_l[6]], 'area' :'0.0.0.0', 'vrf' :'default'}
    dict2 = {'networks': [data.dut2_network_l[2],data.dut2_network_l[3],data.dut2_network_l[4]], 'area': '0.0.0.0', 'vrf' :'default'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    st.banner("Configure OSPF peers for the user-vrf domain")
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router, [{'vrf': data.vrf_name[0]}, {'vrf': data.vrf_name[0]}])

    dict1 = {'router_id': data.dut1_rid, 'vrf': data.vrf_name[0]}
    dict2 = {'router_id': data.dut2_rid, 'vrf': data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_id, [dict1, dict2])

    dict1 = {'networks': data.dut1_network_l[2], 'area' :'0.0.0.1', 'vrf' :data.vrf_name[0]}
    dict2 = {'networks': data.dut2_network_l[1], 'area': '0.0.0.2', 'vrf' :data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    dict1 = {'networks': [data.dut1_network_l[7],data.dut1_network_l[8]], 'area': '0.0.0.0', 'vrf': data.vrf_name[0]}
    dict2 = {'networks': [data.dut2_network_l[5],data.dut2_network_l[6]], 'area': '0.0.0.0', 'vrf': data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])


def ospf_module_unconfig():
    """
    This proc is used to unconfigure the OSPF configurations for non-default/user vrfs on various ports.
    :return:
    """

    st.banner('Remove the ip addresses assigned')
    dict1 = {'interface_name': vars.D1T1P1, 'ip_address' : data.dut1_tg1_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': vars.D2T1P1, 'ip_address' : data.dut2_tg2_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1T1P3, 'ip_address' : data.dut1_tg1_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': vars.D2T1P2, 'ip_address' : data.dut2_tg2_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P1, 'ip_address' : data.dut1_dut2_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': vars.D2D1P1, 'ip_address' : data.dut2_dut1_ip4_addr_l[0], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P5, 'ip_address' : data.dut1_dut2_ip4_addr_l[3], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': vars.D2D1P5, 'ip_address' : data.dut2_dut1_ip4_addr_l[3], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner('LAG un-configuration')
    dict1 = {'interface_name': data.port_channel, 'ip_address' : data.dut1_dut2_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': data.port_channel, 'ip_address' : data.dut2_dut1_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    pcapi.config_portchannel(vars.D1, vars.D2, data.port_channel , [vars.D1D2P3, vars.D1D2P4], [vars.D2D1P3, vars.D2D1P4], config='remove', thread=True)

    dict1 = {'interface_name': data.vlan_in_1, 'ip_address' : data.dut1_dut2_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': data.vlan_in_1, 'ip_address' : data.dut2_dut1_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': data.vlan_in_2, 'ip_address' : data.dut1_dut2_ip4_addr_l[4], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': data.vlan_in_2, 'ip_address' : data.dut2_dut1_ip4_addr_l[4], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Unconfigure OSPF peers for default-vrf domain")
    dict1 = {'networks': data.dut1_network_l[0], 'area' :'0.0.0.1', 'vrf' :'default', 'config' : 'no'}
    dict2 = {'networks': data.dut2_network_l[0], 'area': '0.0.0.2', 'vrf' :'default', 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    dict1 = {'networks': [data.dut1_network_l[4], data.dut1_network_l[5], data.dut1_network_l[6]], 'area' :'0.0.0.0', 'vrf' :'default', 'config' : 'no'}
    dict2 = {'networks': [data.dut2_network_l[2], data.dut2_network_l[3], data.dut2_network_l[4]], 'area': '0.0.0.0', 'vrf' :'default', 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    st.banner('Unbind Vrf-interfaces')
    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1T1P3, 'skip_error': True, 'config': 'no'}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2T1P2, 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1D2P5, 'skip_error': True, 'config': 'no'}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2D1P5, 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': data.vlan_in_2, 'skip_error': True, 'config': 'no'}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': data.vlan_in_2, 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    st.banner("Unconfigure OSPF peers for user-vrf domain")
    dict1 = {'networks': data.dut1_network_l[2], 'area' :'0.0.0.1', 'vrf' :data.vrf_name[0], 'config' : 'no'}
    dict2 = {'networks': data.dut2_network_l[1], 'area': '0.0.0.2', 'vrf' :data.vrf_name[0], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    dict1 = {'networks': [data.dut1_network_l[7],data.dut1_network_l[8]], 'area': '0.0.0.0', 'vrf': data.vrf_name[0], 'config' : 'no'}
    dict2 = {'networks': [data.dut2_network_l[5],data.dut2_network_l[6]], 'area': '0.0.0.0', 'vrf': data.vrf_name[0], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router,[{'vrf' : data.vrf_name[0], 'config' : 'no'}, {'vrf' : data.vrf_name[0], 'config' : 'no'}])

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router, [{'vrf': 'default', 'config': 'no'}, {'vrf': 'default', 'config': 'no'}])

    st.banner('Delete user Vrf')
    dict1 = {'vrf_name': data.vrf_name[0], 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.config_vrf, [dict1, dict1])


def ospf_module_bgp_preconfig():
    """
    This proc is to configure BGP peering b/w DUT1-TG1, DUT2-TG2.
    :return:
    """
    st.banner('Configure BGP peers for default-vrf domain')

    ipapi.config_ip_addr_interface(vars.D1, interface_name=vars.D1T1P2, ip_address=data.dut1_tg1_ip4_addr_l[1], subnet=24, family='ipv4')

    dict1 = {'vrf_name': 'default', 'router_id': data.dut1_rid, 'local_as': data.dut1_local_as, 'addr_family': 'ipv4', 'connect':1,
             'neighbor': data.tg1_ip4_addr_l[1], 'remote_as': data.tg1_local_as, 'config_type_list':['router_id','neighbor', 'connect']}
    parallel.exec_parallel(True, [vars.D1], bgpapi.config_bgp, [dict1])

    st.banner('Configure BGP peers for user-vrf domain')
    vrfapi.bind_vrf_interface(dut=vars.D1, vrf_name=data.vrf_name[0], intf_name=vars.D1T1P4, skip_error=True)
    ipapi.config_ip_addr_interface(vars.D1, interface_name=vars.D1T1P4, ip_address=data.dut1_tg1_ip4_addr_l[3], subnet=24, family='ipv4')
    dict1 = {'vrf_name': data.vrf_name[0], 'router_id': data.dut1_rid, 'local_as': data.dut1_local_as,
             'addr_family': 'ipv4', 'neighbor': data.tg1_ip4_addr_l[3], 'remote_as': data.tg1_local_as,
             'config_type_list': ['router_id', 'neighbor', 'connect'], 'connect':1}
    parallel.exec_parallel(True, [vars.D1], bgpapi.config_bgp, [dict1])


def ospf_module_bgp_unconfig():
    """
    This proc is to Unconfigure BGP peering b/w DUT1-TG1, DUT2-TG2.
    :return:
    """
    st.banner('Unconfigure BGP peers for user-vrf domain')
    dict1 = {'vrf_name': data.vrf_name[0], 'local_as':  data.dut1_local_as, 'config': 'no', 'removeBGP': 'yes', 'config_type_list': ['removeBGP']}
    parallel.exec_parallel(True, [vars.D1], bgpapi.config_bgp, [dict1])

    st.banner('UnConfigure BGP peers for default-vrf domain')
    dict1 = {'vrf_name': 'default', 'local_as':  data.dut1_local_as, 'config': 'no', 'removeBGP': 'yes', 'config_type_list': ['removeBGP']}
    parallel.exec_parallel(True, [vars.D1], bgpapi.config_bgp, [dict1])


def ospf_module_redistribution_config():
    """
    This proc is used to re-distribute the Connected,Static,BGP routes into OSPF domain with Default-Metric
    :return:
    """
    st.banner('Create Static, Default routes for default, non-default vrfs')
    dict1 = {'next_hop': data.tg1_ip4_addr_l[0], 'static_ip' : '192.168.0.0/24'}
    dict2 = {'next_hop': data.tg2_ip4_addr_l[0], 'static_ip' : '193.168.0.0/24'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.create_static_route, [dict1, dict2])

    dict1 = {'next_hop': data.tg1_ip4_addr_l[2], 'static_ip' : '194.168.0.0/24', 'vrf' : data.vrf_name[0]}
    dict2 = {'next_hop': data.tg2_ip4_addr_l[1], 'static_ip' : '195.168.0.0/24', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.create_static_route, [dict1, dict2])

    st.banner('Redistribute the routes into ospf')
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'static'}, {'route_type' : 'static'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'connected'}, {'route_type' : 'connected'}])
    parallel.exec_parallel(True, [vars.D1], ospfapi.redistribute_into_ospf, [{'route_type' : 'bgp'}])

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'static','vrf_name' : data.vrf_name[0]}, {'route_type' : 'static','vrf_name' : data.vrf_name[0]}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'connected','vrf_name' : data.vrf_name[0]}, {'route_type' : 'connected','vrf_name' : data.vrf_name[0]}])
    parallel.exec_parallel(True, [vars.D1], ospfapi.redistribute_into_ospf, [{'route_type' : 'bgp','vrf_name' : data.vrf_name[0]}])


def clear_ip_ospf(vrf='default'):
    result = 0
    if vrf != 'default':
        st.banner("Clear ip ospf configuraion on non-default VRF")
        # Non Default VRF Physical, Vlan interfaces
        dict1 = {'vrf': data.vrf_name[0], 'interfaces': [vars.D1D2P5, data.vlan_in_2]}
        dict2 = {'vrf': data.vrf_name[0], 'interfaces': [vars.D2D1P5, data.vlan_in_2]}

        st.log("Clear ip ospf on non-default vrf: {}-{}, {}-{}".format(vars.D1, dict1, vars.D2, dict2))
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.clear_interface_ip_ospf, [dict1, dict2])

        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
                         states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
            st.error("OSPF neighbourship with the non default vrf is down after clear ip ospf.")
            result += 1
    else:
        st.banner("Clear ip ospf configuraion on default VRF")
        # Default VRF Physical, Vlan and PO interfaces
        dict1 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel]}
        dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel]}

        st.log("Clear ip ospf on default vrf: {}-{}, {}-{}".format(vars.D1, dict1, vars.D2, dict2))
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.clear_interface_ip_ospf, [dict1, dict2])

        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1,
                         ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'],
                         vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship with the default vrf is down after clear ip ospf.")
            result += 1

    return True if result == 0 else False


def ospf_module_redistribution_unconfig():
    """
    This proc is used for unconfiguring the re-distributed route types
    :return:
    """
    st.banner('Unconfiguring static route related config')
    dict1 = {'next_hop': data.tg1_ip4_addr_l[0], 'static_ip' : '192.168.0.0/24'}
    dict2 = {'next_hop': data.tg2_ip4_addr_l[0], 'static_ip' : '193.168.0.0/24'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.delete_static_route, [dict1, dict2])

    dict1 = {'next_hop': data.tg1_ip4_addr_l[2], 'static_ip' : '194.168.0.0/24', 'vrf' : data.vrf_name[0]}
    dict2 = {'next_hop': data.tg2_ip4_addr_l[1], 'static_ip' : '195.168.0.0/24', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.delete_static_route, [dict1, dict2])

    st.banner('Unconfiguring the redistribution related config')
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'static', 'config' : 'no'}, {'route_type' : 'static', 'config' : 'no'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'connected', 'config' : 'no'}, {'route_type' : 'connected', 'config' : 'no'}])
    parallel.exec_parallel(True, [vars.D1], ospfapi.redistribute_into_ospf, [{'route_type' : 'bgp',  'config' : 'no'}])

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'static','vrf_name' : data.vrf_name[0], 'config' : 'no'}, {'route_type' : 'static','vrf_name' : data.vrf_name[0], 'config' : 'no'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'connected','vrf_name' : data.vrf_name[0], 'config' : 'no'}, {'route_type' : 'connected','vrf_name' : data.vrf_name[0], 'config' : 'no'}])
    parallel.exec_parallel(True, [vars.D1], ospfapi.redistribute_into_ospf, [{'route_type' : 'bgp','vrf_name' : data.vrf_name[0], 'config' : 'no'}])


def ospf_module_cost_config(config='yes'):
    """
    This Proc is to configure the uniform cost on all the OSPF interfaces i.e. dynamic cost changes will not impact test cases
    :return:
    """
    st.banner("Configure uniform cost on default OSPF interfaces")
    dict1 = {'interfaces': [vars.D1T1P1, vars.D1D2P1, data.vlan_in_1, data.port_channel], 'cost': '10', 'config' : config}
    dict2 = {'interfaces': [vars.D2T1P1, vars.D2D1P1, data.vlan_in_1, data.port_channel], 'cost': '10', 'config' : config}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])

    st.banner("Configure uniform cost on user OSPF interfaces")
    dict1 = {'interfaces': [vars.D1T1P3, vars.D1D2P5, data.vlan_in_2], 'cost': '10', 'vrf' : data.vrf_name[0], 'config' : config}
    dict2 = {'interfaces': [vars.D2T1P2, vars.D2D1P5, data.vlan_in_2], 'cost': '10', 'vrf' : data.vrf_name[0], 'config' : config}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])


def verify_route_summary(dut, exp_num_of_routes, vrf='default', key='ospf',neg_check='no',route_type='software'):

    if route_type == 'software':
        current_routes = ospfapi.fetch_ip_route_summary(dut, vrf=vrf, key=key)
    else:
        current_routes = asicapi.bcmcmd_route_count_hardware(dut)
    if neg_check != 'no':
        if int(current_routes) < exp_num_of_routes:
            st.log('PASS - Expected number of {} routes present in the hardware'.format(key))
            return True
        st.log('FAIL - Expected number of {} routes not present in the hardware'.format(key))
        return False
    if int(current_routes) >= exp_num_of_routes:
        st.log('PASS - Expected number of {} routes present in the hardware'.format(key))
        return True

    st.log('FAIL - Expected number of {} routes not present in the hardware'.format(key))
    return False


def tg_config():
    """
    Bring up OSPF/BGP sessions b/w DUT1-TG1, DUT2-TG2 for default vrf and user vrf ports
    :return:
    """
    global bgp_rtr1, bgp_rtr2, ospf_rtr1, ospf_rtr2, ospf_rtr3, ospf_rtr4, h1, h2, h3 , h4, h5, h6
    global tg1, tg2, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4, tg_ph_5, tg_ph_6
    tg1, tg2, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4, tg_ph_5, tg_ph_6 = get_handles()

    st.banner('Configuring routing interfaces on TG ports')
    tg_reset()
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.tg1_ip4_addr_l[0], gateway=data.dut1_tg1_ip4_addr_l[0], arp_send_req='1', control_plane_mtu='9100')
    h2 = tg1.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr=data.tg1_ip4_addr_l[2], gateway=data.dut1_tg1_ip4_addr_l[2], arp_send_req='1', control_plane_mtu='9100')
    h3 = tg2.tg_interface_config(port_handle=tg_ph_5, mode='config', intf_ip_addr=data.tg2_ip4_addr_l[0], gateway=data.dut2_tg2_ip4_addr_l[0], arp_send_req='1', control_plane_mtu='9100')
    h4 = tg2.tg_interface_config(port_handle=tg_ph_6, mode='config', intf_ip_addr=data.tg2_ip4_addr_l[1], gateway=data.dut2_tg2_ip4_addr_l[1], arp_send_req='1', control_plane_mtu='9100')
    h5 = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.tg1_ip4_addr_l[1], gateway=data.dut1_tg1_ip4_addr_l[1], arp_send_req='1', control_plane_mtu='9100')
    h6 = tg1.tg_interface_config(port_handle=tg_ph_4, mode='config', intf_ip_addr=data.tg1_ip4_addr_l[3], gateway=data.dut1_tg1_ip4_addr_l[3], arp_send_req='1', control_plane_mtu='9100')

    st.banner('Emulate OSPF devices with TG on DUT1 and DUT2')
    ospf_rtr1 = tg1.tg_emulation_ospf_config(handle=h1['handle'], mode='create', session_type='ospfv2', router_id='4.4.4.3', area_id='0.0.0.1',
                                      gateway_ip_addr=data.dut1_tg1_ip4_addr_l[0], max_mtu='9100', network_type = 'broadcast')
    ospf_rtr2 = tg1.tg_emulation_ospf_config(handle=h2['handle'], mode='create', session_type='ospfv2', router_id='4.4.4.3', area_id='0.0.0.1',
                                      gateway_ip_addr=data.dut1_tg1_ip4_addr_l[2], max_mtu='9100', network_type = 'broadcast')
    ospf_rtr3 = tg2.tg_emulation_ospf_config(handle=h3['handle'], mode='create', session_type='ospfv2', router_id='3.3.3.2', area_id='0.0.0.2',
                                      gateway_ip_addr=data.dut2_tg2_ip4_addr_l[0], max_mtu='9100', network_type = 'broadcast')
    ospf_rtr4 = tg2.tg_emulation_ospf_config(handle=h4['handle'], mode='create', session_type='ospfv2', router_id='3.3.3.2', area_id='0.0.0.2',
                                      gateway_ip_addr=data.dut2_tg2_ip4_addr_l[1], max_mtu='9100',network_type = 'broadcast')

    st.banner('Emulating BGP neighors with TG on DUT1')
    bgp_rtr1 = tg1.tg_emulation_bgp_config(handle=h5['handle'], mode='enable', active_connect_enable='1', local_as=data.tg1_local_as, remote_as=data.dut1_local_as,
                                           remote_ip_addr=data.dut1_tg1_ip4_addr_l[1])
    bgp_rtr2 = tg1.tg_emulation_bgp_config(handle=h6['handle'], mode='enable', active_connect_enable='1', local_as=data.tg1_local_as, remote_as=data.dut1_local_as,
                                           remote_ip_addr=data.dut1_tg1_ip4_addr_l[3])
    st.wait(5)

    st.banner('Starting OSPF protocol on TG ports')
    for tg_ob,ospf_handle in zip([tg1, tg1, tg2, tg2], [ospf_rtr1, ospf_rtr2, ospf_rtr3, ospf_rtr4]):
        tg_ob.tg_emulation_ospf_control(mode='start', handle=ospf_handle['handle'])

    st.banner('Starting BGP protocol on TG ports')
    tg1.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes='2', prefix='121.1.1.0', as_path = 'as_seq:1')
    tg1.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='2', prefix='131.1.1.0', as_path = 'as_seq:1')

    for tg_ob,bgp_handle in zip([tg1, tg1], [bgp_rtr1, bgp_rtr2]):
        tg_ob.tg_emulation_bgp_control(mode='start', handle=bgp_handle['handle'])


def tg_unconfig():
    """
    Tear down OSPF/BGP sessions b/w DUT1-TG1, DUT2-TG2 for default vrf and user vrf ports
    :return:
    """

    st.banner('Unconfiguring OSPF devices on TG ports')
    for tg_ob,ospf_handle in zip([tg1, tg1, tg2, tg2], [ospf_rtr1, ospf_rtr2, ospf_rtr3, ospf_rtr4]):
        tg_ob.tg_emulation_ospf_control(mode='stop', handle=ospf_handle['handle'])
        tg_ob.tg_emulation_ospf_config(handle=ospf_handle['handle'], mode='delete')

    st.banner('Unconfiguring BGP devices on TG ports')
    for tg_ob,bgp_handle in zip([tg1, tg1], [bgp_rtr1, bgp_rtr2]):
        tg_ob.tg_emulation_bgp_control(mode='stop', handle=bgp_handle['handle'])

    st.banner('Unconfiguring routing interfaces on TG ports')
    for tg_ob,port,host_num in zip([tg1,tg1,tg1,tg1,tg2,tg2],[tg_ph_1,tg_ph_2,tg_ph_3,tg_ph_4,tg_ph_5,tg_ph_6],[h1,h2,h3,h4,h5,h6]):
        tg_ob.tg_interface_config(port_handle=port, handle=host_num['handle'], mode='destroy')


def send_and_verify_traffic():

    dut1_mac = basicapi.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    stream_tg1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode="single_burst",
                                       length_mode='fixed', pkts_per_burst=1000, mac_src='00.00.00.11.12.53',
                                       mac_dst=dut1_mac, l3_protocol='ipv4', ip_src_addr=data.tg1_ip4_addr_l[0],
                                       ip_dst_addr=data.tg2_ip4_addr_l[0], port_handle2=tg_ph_5)

    stream_id = stream_tg1['stream_id']
    tg1.tg_traffic_control(action='run', stream_handle=stream_id)
    st.wait(5)
    tg1.tg_traffic_control(action='stop', stream_handle=stream_id)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg2],
            'stream_list': [(stream_id)],
        }
    }

    # verify statistics
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    return aggrResult


def poll_wait(method, timeout, *args, **kwargs):

    delay = kwargs.pop('poll_delay', 5)
    rv = bool(method(*args, **kwargs))
    if rv or st.is_dry_run():
        return rv

    # retry after sleep
    t = time.time() + timeout
    while True:
        st.wait(delay, 'retrying after {} sec'.format(delay))
        if time.time() > t:
            break
        elif method(*args, **kwargs):
            return True
    return False


def verify_ospf_sessions(poll_interval=60, delay=5):
    """
    This proc is used for checking the OSPF session between D1-D2 on portbased, VLAN, LAG interfaces.
    :return:
    """
    result = 0

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, poll_interval , vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf = 'default', addr_family='ipv4', poll_delay=delay):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, poll_interval , vars.D1, ospf_links=[data.vlan_in_1], states=['Full'], vrf = 'default', addr_family='ipv4', poll_delay=delay):
        st.error("OSPF neighbourship with the default vrf on vlan based routing interface is failed.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, poll_interval , vars.D1, ospf_links=[data.port_channel], states=['Full'], vrf = 'default', addr_family='ipv4', poll_delay=delay):
        st.error("OSPF neighbourship with the default vrf on LAG interface is failed.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, poll_interval , vars.D1, ospf_links=[vars.D1D2P5], states=['Full'], vrf = data.vrf_name[0], addr_family='ipv4', poll_delay=delay):
        st.error("OSPF neighbourship with the user vrf configuration on port based routing interface is failed.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, poll_interval , vars.D1, ospf_links=[data.vlan_in_2], states=['Full'], vrf = data.vrf_name[0], addr_family='ipv4', poll_delay=delay):
        st.error("OSPF neighbourship with the user vrf configuration on vlan based routing interface is failed.")
        result += 1

    return result


def show_dut_ospf_cmd_logs(duts='all'):
    """
    Thsi proc is used to dump the various ospf 'show comamnds' in case of failure
    :return:
    """
    st.banner('Debug logs')
    if duts == 'all':
        for dut in st.get_dut_names():
            ospfapi.show_dut_ospf_cmd_logs(dut)
    else :
        ospfapi.show_dut_ospf_cmd_logs(duts)


def snmp_trap_pre_config():
    """
    This proc is used to configure snmp trap server details on DUT.
    :return:
    """
    global capture_file, ip, username, password, path
    ip = utilsapi.ensure_service_params(vars.D1, "snmptrap", "ip")
    username = utilsapi.ensure_service_params(vars.D1, "snmptrap", "username")
    password = utilsapi.ensure_service_params(vars.D1, "snmptrap", "password")
    path = utilsapi.ensure_service_params(vars.D1, "snmptrap", "path")
    capture_file = path
    # enable traps on DUT
    snmp_obj.config_snmp_trap(vars.D1, version=2, ip_addr=ip, community= data.ro_community)
    snmp_obj.config_agentx(vars.D1)


def ospf_module_config():
    """
    This proc will do the module level configuration for OSPF
    :return:
    """
    snmp_trap_pre_config()
    ospf_module_preconfig()
    ospf_module_bgp_preconfig()
    ospf_module_cost_config()
    ospf_module_redistribution_config()


def ospf_module_config_clear():
    """
    This proc will do the module level un-configuration for OSPF
    :return:
    """
    ospf_module_cost_config(config='no')
    ospf_module_bgp_unconfig()
    ospf_module_redistribution_unconfig()
    ospf_module_unconfig()


def ospf_reboot_device(dut_in, action=''):

    dut_list = utils.make_list(dut_in)
    thread = True if len(dut_list) > 1 else False

    save_sonic = []
    save_vtysh = []
    reboot_device = []
    system_status = []
    for dut in dut_list:
        save_sonic.append([rebootapi.config_save, dut, "sonic"])
        save_vtysh.append([rebootapi.config_save, dut, "vtysh"])
        system_status.append([poll_wait, basicapi.get_system_status, 60, dut])
        if action == 'docker':
            reboot_device.append([basicapi.service_operations_by_systemctl, dut, 'bgp', 'restart'])
        elif action in ['warm', 'fast']:
            reboot_device.append([st.reboot, dut, action])
        else:
            reboot_device.append([st.reboot, dut])

    exec_all(thread, save_sonic)
    exec_all(thread, save_vtysh)
    exec_all(thread, reboot_device)
    if action == 'docker':
        [ret_val, _] = exec_all(thread, system_status)
        if False in ret_val:
            st.error('System status is not up after {} reboot')
            return False

    return True


@pytest.fixture(scope="module", autouse=True)
def ospf_module_hooks(request):
    st.banner("OSPF MODULE CONFIG - START")

    global vars
    vars = st.ensure_min_topology("D1D2:6", "D1T1:4", "D2T1:2")
    ospf_initialize_variables()
    api_list = []
    api_list.append([tg_config])
    api_list.append([ospf_module_config])
    exec_all(True, api_list, True)
    st.banner("OSPF MODULE CONFIG - END")

    yield

    st.banner("OSPF MODULE UNCONFIG - START")
    api_list = []
    api_list.append([tg_unconfig])
    api_list.append([ospf_module_config_clear])
    exec_all(True, api_list, True)
    st.banner("OSPF MODULE UNCONFIG - END")


@pytest.fixture(scope="function", autouse=True)
def ospf_func_hooks(request):
    if 'test_ospf_redistribition_nondefault_metric_verify' in request.node.name:
        st.banner('Unconfiguring redistribution parameters configured on module config')
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type': 'connected', 'config': 'no'},
                                {'route_type': 'connected', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type': 'connected', 'vrf_name': data.vrf_name[0],
                                'config': 'no'}, {'route_type': 'connected', 'vrf_name': data.vrf_name[0], 'config': 'no'}])
    if 'test_ospf_redistribition_routemap_verify' in request.node.name:
        ospf_module_redistribution_unconfig()
    if 'test_ospf_reference_bandwidth' in request.node.name:
        ospf_module_redistribution_unconfig()
        st.banner('Unconfiguring non-default cost parameters configured on module config')
        dict1 = {'interfaces': [vars.D1D2P1], 'cost': '10', 'config': 'no'}
        dict2 = {'interfaces': [vars.D2D1P1], 'cost': '10', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])

        dict1 = {'interfaces': [vars.D1D2P5], 'cost': '10', 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'interfaces': [vars.D2D1P5], 'cost': '10', 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])
    if 'test_ospf_stub_functionality' in request.node.name:
        st.banner('Unconfigure the module config, to bringup the stub network')
        dict1 = {'networks': [data.dut1_network_l[4], data.dut1_network_l[5], data.dut1_network_l[6]],
                 'area': '0.0.0.0', 'vrf': 'default', 'config': 'no'}
        dict2 = {'networks': [data.dut2_network_l[2], data.dut2_network_l[3], data.dut2_network_l[4]],
                 'area': '0.0.0.0', 'vrf': 'default', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        dict1 = {'networks': [data.dut1_network_l[7], data.dut1_network_l[8]], 'area': '0.0.0.0',
                 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'networks': [data.dut2_network_l[5], data.dut2_network_l[6]], 'area': '0.0.0.0',
                 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[0], '0.0.0.1', config='no')
        ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[2], '0.0.0.1', vrf=data.vrf_name[0], config='no')
    yield
    if 'test_ospf_loopback_verify' in request.node.name:
        st.banner('Unconfiguring ospf on loopback interfaces')
        dict1 = {'networks': data.loopback_network_l[0], 'area': '0.0.0.0', 'vrf': 'default', 'config': 'no'}
        dict2 = {'networks': data.loopback_network_l[0], 'area': '0.0.0.0', 'vrf': 'default', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        st.banner('Removing Ip Addresses on loopback interfaces')
        dict1 = {'interface_name': 'Loopback1', 'ip_address': data.loopback_addr_l[0], 'subnet': 32, 'family': data.af_ipv4, 'config': 'remove'}
        dict2 = {'interface_name': 'Loopback2', 'ip_address': data.loopback_addr_l[1], 'subnet': 32, 'family': data.af_ipv4, 'config': 'remove'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.configure_loopback, [{'loopback_name': 'Loopback1', 'config': 'no'}, {'loopback_name': 'Loopback2', 'config': 'no'}])
    if 'test_ospf_redistribition_nondefault_metric_verify' in request.node.name:
        st.banner('Unconfiguring redistribution parameters configured on module config')
        default_vrf_cost_l = ['90', '100', '110']
        user_vrf_cost_l = ['120', '130', '140']

        dict1 = {'route_type': 'static', 'metric': default_vrf_cost_l[0], 'metric_type': '1', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

        dict1 = {'route_type': 'connected', 'metric': default_vrf_cost_l[1], 'metric_type': '1', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

        dict1 = {'route_type': 'bgp', 'metric': default_vrf_cost_l[2], 'metric_type': '1', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

        dict1 = {'route_type': 'static', 'metric': user_vrf_cost_l[0], 'vrf_name': data.vrf_name[0], 'metric_type': '1',
                 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

        dict1 = {'route_type': 'connected', 'metric': user_vrf_cost_l[1], 'vrf_name': data.vrf_name[0], 'metric_type': '1',
                 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

        dict1 = {'route_type': 'bgp', 'metric': user_vrf_cost_l[2], 'vrf_name': data.vrf_name[0], 'metric_type': '1',
                 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])
        ospf_module_redistribution_config()
    if 'test_ospf_neighbourship_linkflap_verify' in request.node.name:
        intfapi.interface_operation(vars.D2, vars.D2D1P1, operation="startup", skip_verify=True)
        ospfapi.config_interface_ip_ospf_transmit_delay(vars.D1, vars.D1T1P1, '30', link_ip='', vrf='', config='no')
    if 'test_ospf_reference_bandwidth' in request.node.name:
        st.banner('Configuring non-default cost parameters configured on module config')
        dict1 = {'interfaces': [vars.D1D2P1], 'cost': '10', 'config': 'yes'}
        dict2 = {'interfaces': [vars.D2D1P1], 'cost': '10', 'config': 'yes'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])

        dict1 = {'interfaces': [vars.D1D2P5], 'cost': '10', 'vrf': data.vrf_name[0], 'config': 'yes'}
        dict2 = {'interfaces': [vars.D2D1P5], 'cost': '10', 'vrf': data.vrf_name[0], 'config': 'yes'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])

        dict1 = {'vrf': 'default', 'bandwidth': '10000', 'config': 'no'}
        dict2 = {'vrf': 'default', 'bandwidth': '10000', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_autocost_refbw, [dict1, dict2])

        # Note new cost and redistribute to D2
        dict1 = {'vrf': data.vrf_name[0], 'bandwidth': '10000', 'config': 'no'}
        dict2 = {'vrf': data.vrf_name[0], 'bandwidth': '10000', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_autocost_refbw, [dict1, dict2])

        dict1 = {'route_type': 'static', 'metric': '30', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])
        dict1 = {'route_type': 'static', 'metric': '60', 'vrf_name': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])
        ospf_module_redistribution_config()
    if 'test_ospf_redistribition_routemap_verify' in request.node.name:
        st.banner('Unconfiguring route-map configuration')
        ospfapi.redistribute_into_ospf(vars.D1, 'static', route_map='rmap1', config='no')
        ospfapi.redistribute_into_ospf(vars.D1, 'connected', route_map='rmap2', config='no')
        ospfapi.redistribute_into_ospf(vars.D1, 'bgp', route_map='rmap3', config='no')
        ipapi.config_route_map(vars.D1, 'rmap1', 'no', sequence='5')
        ipapi.config_route_map(vars.D1, 'rmap2', 'no', sequence='5')
        ipapi.config_route_map(vars.D1, 'rmap3', 'no', sequence='5')
        ospf_module_redistribution_config()
    if 'test_ft_ospf_cleartext_authentication' in request.node.name:
        st.banner('Unconfiguring cleartext authentication configuration')
        dict1 = {'interfaces': vars.D1D2P1, 'auth_key': 'CText1', 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P1, 'auth_key': 'CText1', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
        dict1 = {'interfaces': data.vlan_in_1, 'auth_key': 'CText2', 'config': 'no'}
        dict2 = {'interfaces': data.vlan_in_1, 'auth_key': 'CText2', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
        dict1 = {'interfaces': data.port_channel, 'auth_key': 'CText3', 'config': 'no'}
        dict2 = {'interfaces': data.port_channel, 'auth_key': 'CText3', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
        dict1 = {'interfaces': vars.D1D2P5, 'auth_key': 'CText4', 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P5, 'auth_key': 'CText4', 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
        dict1 = {'interfaces': data.vlan_in_2, 'auth_key': 'CText5', 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'interfaces': data.vlan_in_2, 'auth_key': 'CText5', 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    if 'test_ft_ospf_md5_authentication' in request.node.name:
        st.banner('Unconfiguring md5 authentication configuration')
        dict1 = {'interfaces': vars.D1D2P1, 'auth_key': 'MDKey1', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P1, 'auth_key': 'MDKey1', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
        dict1 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
        dict1 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
        dict1 = {'interfaces': vars.D1D2P5, 'auth_key': 'MDKey4', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P5, 'auth_key': 'MDKey4', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,[dict1, dict2])
        dict1 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,[dict1, dict2])
        st.banner('Unconfiguring message-digest authentication on interfaces')
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': vars.D1D2P1, 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': vars.D2D1P1, 'msg_digest': 'message-digest', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': data.vlan_in_1, 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': data.vlan_in_1, 'msg_digest': 'message-digest', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': data.port_channel, 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': data.port_channel, 'msg_digest': 'message-digest', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': vars.D1D2P5, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': vars.D2D1P5, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': data.vlan_in_2, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': data.vlan_in_2, 'vrf': data.vrf_name[0],
                                 'msg_digest': 'message-digest', 'config': 'no'}])

    if 'test_ft_ospf_distance' in request.node.name:
        ospfapi.config_ospf_router_distance(vars.D1, '', distance=255, config='no')
    if 'test_ospf_redistribition_distributionlist_verify' in request.node.name:
        if st.get_ui_type(cli_type='') not in ['klish', "rest-patch", "rest-put"]:
            st.banner('Unconfiguring distributionlist configuration')
            ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_bgp', 'bgp', config='no')
            ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_bgp_uservrf', 'bgp', vrf=data.vrf_name[0], config='no')
            ipapi.config_access_list(vars.D1, 'Dlist_bgp', '121.1.1.0/24', 'permit', config='no', seq_num=data.seq_num[4])
            ipapi.config_access_list(vars.D1, 'Dlist_bgp_uservrf', '131.1.1.0/24', 'permit', config='no', seq_num=data.seq_num[5])

            st.banner('configure the redistributions as per module config')
            ospf_module_redistribution_config()
            ipapi.delete_static_route(vars.D1, data.tg1_ip4_addr_l[0], '198.168.0.0/24')
            ipapi.delete_static_route(vars.D1, data.tg1_ip4_addr_l[2], '199.168.0.0/24', vrf=data.vrf_name[0])
    if 'test_ospf_hello_dead_interval_verify' in request.node.name:
        st.log("Unconfiguring deafult hello and dead interval on interfaces")
        dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'interval': '15',
                 'link_ip': ['', data.dut1_dut2_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'interval': '15',
                 'link_ip': ['', data.dut2_dut1_ip4_addr_l[1], data.dut2_dut1_ip4_addr_l[2]], 'config': 'no'}
        dict3 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'interval': '15',
                 'link_ip': ['', data.dut1_dut2_ip4_addr_l[1], data.dut1_dut2_ip4_addr_l[2]], 'config': 'no'}
        dict4 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'interval': '15',
                 'link_ip': ['', data.dut2_dut1_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'no'}

        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict1, dict2])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict3, dict4])

        dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'interval': '5',
                 'link_ip': ['', data.dut1_dut2_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'interval': '5',
                 'link_ip': ['', data.dut2_dut1_ip4_addr_l[1], data.dut2_dut1_ip4_addr_l[2]], 'config': 'no'}
        dict3 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'interval': '5',
                 'link_ip': ['', data.dut1_dut2_ip4_addr_l[1], data.dut1_dut2_ip4_addr_l[2]], 'config': 'no'}
        dict4 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'interval': '5',
                 'link_ip': ['', data.dut2_dut1_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'no'}

        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_hello_interval,[dict1, dict2])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_hello_interval,[dict3, dict4])

        dict1 = {'ospf_links': [vars.D1D2P5, data.vlan_in_2], 'match': {'hellotmr': '10', 'deadtmr': '40'},'vrf': data.vrf_name[0]}
        dict2 = {'ospf_links': [vars.D2D1P1, data.vlan_in_1, data.port_channel],'match': {'hellotmr': '10', 'deadtmr': '40'}}
        dict3 = {'ospf_links': [vars.D1D2P1, data.vlan_in_1, data.port_channel],'match': {'hellotmr': '10', 'deadtmr': '40'}}
        dict4 = {'ospf_links': [vars.D2D1P5, data.vlan_in_2], 'match': {'hellotmr': '10', 'deadtmr': '40'}, 'vrf': data.vrf_name[0]}
        (res1, execp) = parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.verify_ospf_interface_info,[dict1, dict2])
        (res2, execp) = parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.verify_ospf_interface_info,[dict3, dict4])
        if not all(res1) and not all(res2):
            st.error("OSPF Hello and Dead timers are not updated as expected after clear ip ospf")
    if 'test_ospf_vrf_movement' in request.node.name:
        dict1 = {'interface_name': vars.D1T1P3, 'ip_address': data.dut1_tg1_ip4_addr_l[2], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'remove'}
        dict2 = {'interface_name': vars.D2T1P2, 'ip_address': data.dut2_tg2_ip4_addr_l[1], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'remove'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

        dict1 = {'interface_name': vars.D1D2P5, 'ip_address': data.dut1_dut2_ip4_addr_l[3], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'remove'}
        dict2 = {'interface_name': vars.D2D1P5, 'ip_address': data.dut2_dut1_ip4_addr_l[3], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'remove'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

        st.banner("UnConfigure ospf config on vrf {} interfaces".format(data.vrf_name[1]))
        dict1 = {'interfaces': [vars.D1T1P3, vars.D1D2P5, data.vlan_in_2]}
        dict2 = {'interfaces': [vars.D2T1P2, vars.D2D1P5, data.vlan_in_2]}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_interface, [dict1, dict2])

        st.banner('Unconfig vrf1 on D1, D2 port based links')
        dict1 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D1T1P3, 'skip_error': True, 'config': 'no'}
        dict2 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D2T1P2, 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D1D2P5, 'skip_error': True, 'config': 'no'}
        dict2 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D2D1P5, 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

        dict1 = {'networks': data.dut1_network_l[2], 'area': '0.0.0.1', 'vrf': data.vrf_name[1], 'config': 'no'}
        dict2 = {'networks': data.dut2_network_l[1], 'area': '0.0.0.2', 'vrf': data.vrf_name[1], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        dict1 = {'networks': [data.dut1_network_l[7]], 'area': '0.0.0.0', 'vrf': data.vrf_name[1], 'config': 'no'}
        dict2 = {'networks': [data.dut2_network_l[5]], 'area': '0.0.0.0', 'vrf': data.vrf_name[1], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        dict1 = {'vrf': data.vrf_name[1], 'interfaces': [vars.D1T1P3, vars.D1D2P5]}
        dict2 = {'vrf': data.vrf_name[1], 'interfaces': [vars.D2T1P2, vars.D2D1P5]}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.clear_interface_ip_ospf, [dict1, dict2])

        dict1 = {'router_id': data.dut1_rid, 'vrf': data.vrf_name[1], 'config': 'no'}
        dict2 = {'router_id': data.dut2_rid, 'vrf': data.vrf_name[1], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_id, [dict1, dict2])

        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router,
                               [{'vrf': data.vrf_name[1], 'config': 'no'}, {'vrf': data.vrf_name[1], 'config': 'no'}])

        dict1 = {'vrf_name': data.vrf_name[1], 'skip_error': True, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.config_vrf, [dict1, dict1])

        st.banner('Config vrf1 as per module config')
        dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1T1P3, 'skip_error': True}
        dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2T1P2, 'skip_error': True}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1D2P5, 'skip_error': True}
        dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2D1P5, 'skip_error': True}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

        dict1 = {'interface_name': vars.D1T1P3, 'ip_address': data.dut1_tg1_ip4_addr_l[2], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'add'}
        dict2 = {'interface_name': vars.D2T1P2, 'ip_address': data.dut2_tg2_ip4_addr_l[1], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'add'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

        dict1 = {'interface_name': vars.D1D2P5, 'ip_address': data.dut1_dut2_ip4_addr_l[3], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'add'}
        dict2 = {'interface_name': vars.D2D1P5, 'ip_address': data.dut2_dut1_ip4_addr_l[3], 'subnet': 24,
                 'family': data.af_ipv4, 'config': 'add'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

        st.banner("Configure uniform cost on user OSPF interfaces as per module config")
        dict1 = {'interfaces': [vars.D1T1P3, vars.D1D2P5, data.vlan_in_2], 'cost': '10', 'vrf': data.vrf_name[0]}
        dict2 = {'interfaces': [vars.D2T1P2, vars.D2D1P5, data.vlan_in_2], 'cost': '10', 'vrf': data.vrf_name[0]}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])

        dict1 = {'networks': data.dut1_network_l[2], 'area': '0.0.0.1', 'vrf': data.vrf_name[0]}
        dict2 = {'networks': data.dut2_network_l[1], 'area': '0.0.0.2', 'vrf': data.vrf_name[0]}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        dict1 = {'networks': [data.dut1_network_l[7]], 'area': '0.0.0.0', 'vrf': data.vrf_name[0]}
        dict2 = {'networks': [data.dut2_network_l[5]], 'area': '0.0.0.0', 'vrf': data.vrf_name[0]}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])
        poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5], states=['Full'],vrf=data.vrf_name[0], addr_family='ipv4')
        poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P3], states=['Full'],vrf=data.vrf_name[0], addr_family='ipv4')
    if 'test_ospf_stub_functionality' in request.node.name:
        dict1 = {'area': '0.0.0.4', 'no_summary': 'yes', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])
        dict1 = {'area': '0.0.0.4', 'vrf': data.vrf_name[0], 'no_summary': 'yes', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])

        dict1 = {'area': '0.0.0.4', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])
        dict1 = {'area': '0.0.0.4', 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])

        ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[0], '0.0.0.0', config='no')
        ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[2], '0.0.0.0', vrf=data.vrf_name[0], config='no')

        dict1 = {'interfaces': vars.D1D2P1, 'nw_type': 'point-to-point', 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P1, 'nw_type': 'point-to-point', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_network_type, [dict1, dict2])

        dict1 = {'interfaces': vars.D1D2P5, 'nw_type': 'point-to-point', 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P5, 'nw_type': 'point-to-point', 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_network_type, [dict1, dict2])

        dict1 = {'networks': data.dut1_network_l[4], 'area': '0.0.0.4', 'vrf': 'default', 'config': 'no'}
        dict2 = {'networks': data.dut2_network_l[2], 'area': '0.0.0.4', 'vrf': 'default', 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        dict1 = {'networks': data.dut1_network_l[7], 'area': '0.0.0.4', 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'networks': data.dut2_network_l[5], 'area': '0.0.0.4', 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        dict1 = {'networks': [data.dut1_network_l[4], data.dut1_network_l[5], data.dut1_network_l[6]],
                 'area': '0.0.0.0', 'vrf': 'default', 'config': 'yes'}
        dict2 = {'networks': [data.dut2_network_l[2], data.dut2_network_l[3], data.dut2_network_l[4]],
                 'area': '0.0.0.0', 'vrf': 'default', 'config': 'yes'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        dict1 = {'networks': [data.dut1_network_l[7], data.dut1_network_l[8]], 'area': '0.0.0.0',
                 'vrf': data.vrf_name[0], 'config': 'yes'}
        dict2 = {'networks': [data.dut2_network_l[5], data.dut2_network_l[6]], 'area': '0.0.0.0',
                 'vrf': data.vrf_name[0], 'config': 'yes'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

        ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[0], '0.0.0.1', config='yes')
        ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[2], '0.0.0.1', vrf=data.vrf_name[0], config='yes')

        tg1.tg_emulation_ospf_config(handle=ospf_rtr1['handle'], mode='modify', area_id='0.0.0.1')
        tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])
        tg1.tg_emulation_ospf_config(handle=ospf_rtr2['handle'], mode='modify', area_id='0.0.0.1')
        tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr2['handle'])

        st.log('Verifying the OSPF sesisons as per the module configuration.')
        clear_ip_ospf()
        clear_ip_ospf(vrf=data.vrf_name[0])
    if 'test_ft_ospf_rfc1538compatibility' in request.node.name:
        st.banner('Unconfiguring rfc1538compatibility configuration')
        dict1 = {'interfaces': vars.D1D2P1, 'auth_key': 'MDKey1', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P1, 'auth_key': 'MDKey1', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,[dict1, dict2])
        dict1 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,[dict1, dict2])
        dict1 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,[dict1, dict2])
        dict1 = {'interfaces': vars.D1D2P5, 'auth_key': 'MDKey4', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': vars.D2D1P5, 'auth_key': 'MDKey4', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,[dict1, dict2])
        dict1 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id': 1, 'config': 'no'}
        dict2 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id': 1, 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])

        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_compatibility_rfc,
                               [{'config': 'no'}, {'vrf': data.vrf_name[0], 'config': 'no'}])

        st.banner('Unconfiguring message-digest configuration')
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': vars.D1D2P1, 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': vars.D2D1P1, 'msg_digest': 'message-digest', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': data.vlan_in_1, 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': data.vlan_in_1, 'msg_digest': 'message-digest', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': data.port_channel, 'msg_digest': 'message-digest', 'config': 'no'},
                                {'interfaces': data.port_channel, 'msg_digest': 'message-digest', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': vars.D1D2P5, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest',
                                 'config': 'no'}, {'interfaces': vars.D2D1P5, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest',
                                 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                               [{'interfaces': data.vlan_in_2, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest',
                                 'config': 'no'}, {'interfaces': data.vlan_in_2, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest',
                                 'config': 'no'}])
        verify_ospf_sessions(60)
    if 'test_ospf_bfd_session_flap_verify' in request.node.name:
        st.banner("Unconfiguring BFD on interfaces")
        dict11 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'no'}
        dict12 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'no'}
        dict21 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'config': 'no'}
        dict22 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_bfd, [dict11, dict12])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_bfd, [dict21, dict22])
        verify_ospf_sessions(60)
    if 'test_ospf_retransmit_interval_verify' in request.node.name:
        st.banner("Unconfiguring retransmit interval on interfaces")
        basicapi.service_operations_by_systemctl(vars.D2, 'bgp', 'start')
        if not poll_wait(basicapi.get_system_status, 60, vars.D1):
            st.error('System status is not up after doing BGP docker start.')
        if not poll_wait(basicapi.get_system_status, 60, vars.D2):
            st.error('System status is not up after doing BGP docker start.')
        verify_ospf_sessions(60)
        ospfapi.config_interface_ip_ospf_retransmit_interval(vars.D1, [vars.D1D2P1], '', vrf='', config='no')
        ospfapi.config_interface_ip_ospf_retransmit_interval(vars.D1, [vars.D1D2P5], '', vrf=data.vrf_name[0],
                                                             config='no')

        dict1 = {'interfaces': [vars.D1D2P5], 'interval': '', 'vrf': data.vrf_name[0], 'config': 'no'}
        dict2 = {'interfaces': [vars.D2D1P1], 'interval': '', 'config': 'no'}
        dict3 = {'interfaces': [vars.D1D2P1], 'interval': '', 'config': 'no'}
        dict4 = {'interfaces': [vars.D2D1P5], 'interval': '', 'vrf': data.vrf_name[0], 'config': 'no'}

        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict1, dict2])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict3, dict4])
    if 'test_ospf_max_lsdb_overflow_test' in request.node.name:
        intfapi.interface_operation(vars.D2, [vars.D2D1P2, vars.D2D1P3, vars.D2D1P4], operation="startup", skip_verify=True)
        tg1.tg_emulation_ospf_control(mode='age_out_routes', age_out_percent=100, handle=data.routes_config['ipv4_prefix_interface_handle'])
        tg1.tg_bgp_routes_control(handle=bgp_rtr1['handle'], route_handle=data.bgp_routes['handle'], mode='withdraw')
        st.wait(10)
        tg1.tg_emulation_ospf_route_config(mode='delete', handle=data.routes_config['handle'])
        tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
        verify_ospf_sessions(60)
    if 'test_ospf_max_intra_ext_routes_verify' in request.node.name:
        if data.max_routes_config:
            tg1.tg_emulation_ospf_control(mode='age_out_routes', age_out_percent=100, handle=data.max_routes_config['ipv4_prefix_interface_handle'])
            st.wait(10)
            tg1.tg_emulation_ospf_route_config(mode='delete', handle=data.max_routes_config['handle'])
            verify_ospf_sessions(60)
    if 'test_ospf_routerid_change' in request.node.name:
        verify_ospf_sessions(60)
    if 'test_ospf_max_metric_router_lsa_verify' in request.node.name:
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf,
                               [{'route_type': 'kernel', 'config': 'no'}, {'route_type': 'kernel', 'config': 'no'}])
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [{'route_type' : 'kernel','vrf_name' : data.vrf_name[0], 'config' : 'no'}, {'route_type' : 'kernel','vrf_name' : data.vrf_name[0], 'config' : 'no'}])


@pytest.mark.ospf_regression
def test_ospf_basic_functionality_verify():
    """"
    # ################ Author Details ################
    # Name: Sesha Reddy Koilkonda
    # Email: seshareddy.koilkonda@broadcom.com
    # ################################################
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn003,FtOtSoRtOspfFn009,FtOtSoRtOspfFn012,FtOtSoRtOspfFn028')
    result = 0
    result += verify_ospf_sessions(60)

    if not result:
        st.report_pass("ospf_session_test_pass","with the default/user vrf configuration")
    else:
        st.report_fail("ospf_session_test_fail","with the default/user vrf configuration")


@pytest.mark.ospf_regression
def test_ospf_loopback_verify():
    """
    Verify that OSPF can be enabled on loopback interfaces.
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn005')
    result = 0

    st.banner('Creating loopback interfaces')
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.configure_loopback, [{'loopback_name' : 'Loopback1', 'config' : 'yes'}, {'loopback_name' : 'Loopback2', 'config' : 'yes'}])

    st.banner("Configuring ip address on loopback interfaces")
    dict1 = {'interface_name': 'Loopback1', 'ip_address' : data.loopback_addr_l[0], 'subnet' : 32, 'family' : data.af_ipv4}
    dict2 = {'interface_name': 'Loopback2', 'ip_address' : data.loopback_addr_l[1], 'subnet' : 32, 'family' : data.af_ipv4}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Configuring OSPF on loopback interfaces")
    dict1 = {'networks': data.loopback_network_l[0], 'area' : '0.0.0.0', 'vrf' :'default'}
    dict2 = {'networks': data.loopback_network_l[0], 'area' : '0.0.0.0', 'vrf' :'default'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    st.banner("Checking IPv4 ping between {} and {} over loopbcak routing interface".format(vars.D1, vars.D2))
    if not ipapi.ping(vars.D1, data.loopback_addr_l[1], family=data.af_ipv4, count=2):
        result=+1
        st.error("ping failed from DUT1 to DUT2 over loopback interfaces.")
    if not ipapi.ping(vars.D2, data.loopback_addr_l[0], family=data.af_ipv4, count=2):
        st.error("ping failed from DUT2 to DUT1 over loopback interfaces.")
        result = +1

    if not result:
        st.report_pass("ospf_session_test_pass","with the loopback interfaces")
    else:
        st.report_fail("ping_fail", data.loopback_addr_l[0], data.loopback_addr_l[1])


@pytest.mark.ospf_regression
def test_ospf_redistribition_verify():
    """
    Verify OSPF router redistribute configurations with default metric in default vrf
    Verify OSPF router redistribute configurations with default metric in user vrf
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn021,FtOtSoRtOspfFn030')
    result = 0

    for vrf, ip_addr in zip(['default', data.vrf_name[0]], [data.tg1_ip4_addr_l[1], data.tg1_ip4_addr_l[3]]):
        st.banner('Verifying BGP neighborship with the TG port connected to DUT1 in {}-vrf domain'.format(vrf), 100)
        if not poll_wait(bgpapi.verify_bgp_summary, 20, vars.D1, family='ipv4', vrf=vrf, neighbor=ip_addr, state='Established'):
            st.log("Failed to form BGP Neighbourship with the TG port connected to DUT1 in {}-vrf domain.".format(vrf))
            result += 1

    if result:
        st.report_fail("bgp_neighbor_not_form_error","with the TG")

    for vrf, dut, intf in zip(['default', data.vrf_name[0]]*2, [vars.D1, vars.D1, vars.D2, vars.D2], [vars.D1T1P1, vars.D1T1P3, vars.D2T1P1, vars.D2T1P2]):
        st.banner('Verifying OSPF neighborship with the TG port connected to {} interface {} in {}-vrf domain.'.format(dut, intf, vrf), 120)
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 40, dut, ospf_links=[intf], states=['Full'], vrf=vrf, addr_family='ipv4'):
            st.error("Failed to form OSPF Neighbourship with the TG port connected to {} interface {} in {}-vrf domain.".format(dut, intf, vrf))
            result += 1

    if result:
        st.report_fail("ospf_session_test_fail","with TG")

    [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1D2P1, 'cost', 'default'],
                                          [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2D1P1, 'cost', 'default']])
    st.log(ret_val)
    d1_intf1_cost, d2_intf1_cost = ret_val

    [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1D2P5, 'cost', data.vrf_name[0]],
                                           [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2D1P5, 'cost', data.vrf_name[0]]])
    st.log(ret_val)
    d1_intf1_cost_uservrf, d2_intf1_cost_uservrf = ret_val

    if not d1_intf1_cost or not d2_intf1_cost or not d1_intf1_cost_uservrf or not d2_intf1_cost_uservrf :
        st.report_fail("ospf_session_test_fail","Failed to retrive OSPF cost value from the corresponding interfaces.")

    def_vrf_cost_d2 = str(int(d1_intf1_cost) + int(d2_intf1_cost))
    user_vrf_cost_d2 = str(int(d1_intf1_cost_uservrf) + int(d2_intf1_cost_uservrf))

    for type, ip_list in zip(['static', 'connected', 'BGP'], [["192.168.0.0/24", "194.168.0.0/24"], [data.dut1_network_l[0], data.dut1_network_l[3]], ["121.1.1.0/24", "131.1.1.0/24"]]):
        st.banner('Verification of default metric for redistributed {} routes'.format(type))
        for ip_addr, cost, intf, vrf in zip(ip_list, [def_vrf_cost_d2, user_vrf_cost_d2], [vars.D2D1P1, vars.D2D1P5], ['default', data.vrf_name[0]]):
            if not ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr, cost=cost, interface=intf, vrf=vrf):
                st.error('Failed to redistribute {} routes with default metric'.format(type))
                result += 1

    if not result:
        st.report_pass("ospf_session_test_pass","with the redistribution with default metric.")
    else:
        st.report_fail("ospf_session_test_fail","with the redistribution with default metric.")


@pytest.mark.ospf_regression
def test_ospf_neighbourship_linkflap_verify():
    """
    Verify OSPF functionality with link flap and interface transmit-delay.
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn042, FtOtSoRtOspfFn027')
    result = 0

    for vrf, ip_addr in zip(['default', data.vrf_name[0]], [data.tg1_ip4_addr_l[1], data.tg1_ip4_addr_l[3]]):
        st.banner('Verifying BGP neighborship with the TG port connected to DUT1 in {}-vrf domain.'.format(vrf), 100)
        if not poll_wait(bgpapi.verify_bgp_summary, 20, vars.D1, family='ipv4', vrf=vrf, neighbor=ip_addr, state='Established'):
            st.log("Failed to form BGP Neighbourship with the TG port connected to DUT1 in {}-vrf domain.".format(vrf))
            result += 1

    if result:
        st.report_fail("bgp_neighbor_not_form_error","with the TG")

    st.banner('Verify OSPF neighborship between DUT1 and DUT2')
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 10, vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf='default', addr_family='ipv4', poll_delay=2):
      st.error("OSPF neighbourship with the default vrf on port based routing interface is down.")
      result += 1

    st.banner('Verify the route learned from D2.in the routing table of DUT1')
    if not ospfapi.verify_ospf_route(vars.D1, ip_address="193.168.0.0/24", interface= vars.D1D2P1):
        st.error("OSPF routes are not advertised properly before link flap.")
        result += 1

    st.banner('Configuring and verifying transmit delay on dut {}, interface {}'.format(vars.D1, vars.D1T1P1))
    ospfapi.config_interface_ip_ospf_transmit_delay(vars.D1, vars.D1T1P1, '30', link_ip='', vrf='', config='yes')

    if not ospfapi.verify_ospf_interface_info(vars.D1, vars.D1T1P1, match={'txdelay': '30'}):
        st.error("Transmit delay is not updated with non default value on interface {}.".format(vars.D1T1P1))
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn027')
        st.report_tc_fail("FtOtSoRtOspfFn027", "ospf_session_test_fail", "in Transmit delay is not updated with non default value")

    st.banner('Shutdown the interface {} on dut {}'.format(vars.D2D1P1, vars.D2))
    intfapi.interface_operation(vars.D2, vars.D2D1P1, operation="shutdown", skip_verify=True)

    # Waiting for the default dead timer to expire
    st.wait(40, 'Waiting for the default dead timer to expire')

    intfapi.interface_status_show(vars.D1, vars.D1D2P1)

    if poll_wait(ospfapi.verify_ospf_neighbor_state, 10, vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf='default', addr_family='ipv4', poll_delay=2):
      st.error("OSPF neighbourship with the default vrf on port based routing interface is still Up, after the interface shutdown.")
      result += 1

    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')

    st.banner('No Shutdown the interface {} on dut {}'.format(vars.D2D1P1, vars.D2))
    intfapi.interface_operation(vars.D2, vars.D2D1P1, operation="startup", skip_verify=True)
    st.wait(data.wait)

    st.banner('Capturing the packets to verify configured transmit delay parameters on DUT11', 100)
    tg1.tg_packet_control(port_handle=tg_ph_1, action='stop')

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf='default', addr_family='ipv4'):
      st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
      result += 1

    st.banner('Verifying transmit delay value in captured packets')
    pkts_captured = tg1.tg_packet_stats(port_handle=tg_ph_1, format='var', output_type='hex')

    capture_result = validate_packet_capture(tg_type=tg1.tg_type, pkt_dict=pkts_captured, offset_list=[62], value_list=['001e'])

    if not capture_result:
        st.error("DUT is not send LS update packet with configured Transmit delay value is not updated with non default value on interface {}.".format(vars.D1T1P1))
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn027')
        st.report_tc_fail("FtOtSoRtOspfFn027", "ospf_session_test_fail", "in transmit-delay scenario")
    else:
        st.report_tc_pass("FtOtSoRtOspfFn027", "ospf_session_test_pass", "in transmit-delay scenario")

    st.banner('Verify the route learned from D2, in the routing table of DUT1 after link flap', 100)
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="193.168.0.0/24", interface=vars.D1D2P1):
        st.error("OSPF routes are not advertised properly after link flap")
        result += 1

    if not result:
        st.report_pass("ospf_session_test_pass","in the linkflap scenario.")
    else:
        st.report_fail("ospf_session_test_fail","in the linkflap scenario.")


@pytest.mark.ospf_regression
def test_ospf_redistribition_nondefault_metric_verify():
    """
    Verify OSPF router redistribute configurations with non default metric in default vrf
    Verify OSPF router redistribute configurations with non default metric in user vrf
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn022,FtOtSoRtOspfFn031')
    result = 0
    default_vrf_cost_l = ['30','40','50']
    user_vrf_cost_l = ['60','70','80']

    st.banner('Redistribute the routes with non default metric')
    dict1 = {'route_type': 'static', 'metric' : default_vrf_cost_l[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'connected', 'metric' : default_vrf_cost_l[1]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'bgp', 'metric' : default_vrf_cost_l[2]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'static', 'metric': user_vrf_cost_l[0], 'vrf_name' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'connected', 'metric': user_vrf_cost_l[1], 'vrf_name' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'bgp', 'metric': user_vrf_cost_l[2], 'vrf_name' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    st.wait(10, 'waiting for the route redistributions into the OSPF domain')

    st.banner('Verification of non-deafult metric for redistributed routes in default-vrf domain', 100)
    for ip_addr, cost in zip(["192.168.0.0/24", data.dut1_network_l[1], "121.1.1.0/24"], [default_vrf_cost_l[0], default_vrf_cost_l[1], default_vrf_cost_l[2]]):
        if not poll_wait(ospfapi.verify_ospf_route, 20, vars.D2, ip_address=ip_addr, cost=str(cost), interface=vars.D2D1P1):
            st.error('Failed: Non-deafult metric for redistributed routes {} for cost {} in default-vrf domain'.format(ip_addr, str(cost)))
            result += 1

    st.banner('Verification of non-deafult metric for redistributed routes in user-vrf domain', 100)
    for ip_addr, cost in zip(["194.168.0.0/24", data.dut1_network_l[3], "131.1.1.0/24"],
                             [user_vrf_cost_l[0], user_vrf_cost_l[1], user_vrf_cost_l[2]]):
        if not poll_wait(ospfapi.verify_ospf_route, 20, vars.D2, ip_address=ip_addr, cost=str(cost), interface=vars.D2D1P5, vrf = data.vrf_name[0]):
            st.error('Failed: Non-deafult metric for redistributed routes {} for cost {} in user-vrf domain'.format(ip_addr, str(cost)))
            result += 1

    if result:
        st.log('Generating the tech support for the subtest')
        basicapi.get_techsupport(filename='test_ospf_redistribition_nondefault_metric_verify')

    st.banner('Redistribute the routes with non default metric and metric type as E1')
    dict1 = {'route_type': 'static', 'metric' : default_vrf_cost_l[0], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'connected', 'metric' : default_vrf_cost_l[1], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'bgp', 'metric' : default_vrf_cost_l[2], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'static', 'metric': user_vrf_cost_l[0], 'vrf_name' : data.vrf_name[0], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'connected', 'metric': user_vrf_cost_l[1], 'vrf_name' : data.vrf_name[0], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'bgp', 'metric': user_vrf_cost_l[2], 'vrf_name' : data.vrf_name[0], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])


    default_vrf_cost_l = ['90','100','110']
    user_vrf_cost_l = ['120','130','140']

    dict1 = {'route_type': 'static', 'metric' : default_vrf_cost_l[0], 'metric_type' : '1'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'connected', 'metric' : default_vrf_cost_l[1], 'metric_type' : '1'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'bgp', 'metric' : default_vrf_cost_l[2], 'metric_type' : '1'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'static', 'metric': user_vrf_cost_l[0], 'vrf_name' : data.vrf_name[0], 'metric_type' : '1'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'connected', 'metric': user_vrf_cost_l[1], 'vrf_name' : data.vrf_name[0], 'metric_type' : '1'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'route_type': 'bgp', 'metric': user_vrf_cost_l[2], 'vrf_name' : data.vrf_name[0], 'metric_type' : '1'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    st.wait(10, 'waiting for the route redistributions into the OSPF domain')

    [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1T1P1, 'cost', 'default'],
                                   [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2D1P1, 'cost', 'default']])
    d1_intf1_cost, d2_intf1_cost = ret_val
    [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1T1P3, 'cost', data.vrf_name[0]],
                                   [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2D1P5, 'cost', data.vrf_name[0]]])
    d1_intf2_cost, d2_intf1_cost_uservrf = ret_val

    st.banner('Verify of non default metric for redistributed routes with metric type as E1 in default vrf', 120)
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="192.168.0.0/24", cost=str(int(default_vrf_cost_l[0]) + int(d1_intf1_cost) + int(d2_intf1_cost)), interface=vars.D2D1P1):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut1_network_l[1], cost=str(int(default_vrf_cost_l[1])+ int(d2_intf1_cost)), interface=vars.D2D1P1):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="121.1.1.0/24", cost=str(int(default_vrf_cost_l[2]) + int(d2_intf1_cost)), interface=vars.D2D1P1):
        result += 1

    st.banner('Verify of non default metric for redistributed routes with metric type as E1 in user vrf', 100)
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="194.168.0.0/24", cost=str(int(user_vrf_cost_l[0]) + int(d1_intf2_cost) + int(d2_intf1_cost_uservrf)), interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut1_network_l[3], cost=str(int(user_vrf_cost_l[1]) + int(d2_intf1_cost_uservrf)), interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="131.1.1.0/24",  cost=str(int(user_vrf_cost_l[2]) + int(d2_intf1_cost_uservrf)), interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        result += 1

    if not result:
        st.report_pass("ospf_session_test_pass","with the redistribution with user defined metric.")
    else:
        st.report_fail("ospf_session_test_fail","with the redistribution with user defined metric.")


@pytest.mark.ospf_regression
def test_ospf_ignore_mtu_verify():
    """
    Verify that the OSPF functionality after clear ip ospf and ignore mtu configuration.
    :return:
    """

    utilsapi.banner_log('FtOtSoRtOspfFn016, FtOtSoRtOspfFn043')
    result = 0

    poll_wait(ospfapi.verify_ospf_neighbor_state, 60,vars.D1, ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel],
                                       states=['Full'], vrf='default', addr_family='ipv4')
    poll_wait(ospfapi.verify_ospf_neighbor_state, 60,vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2], states=['Full'],
                                       vrf=data.vrf_name[0], addr_family='ipv4')

    st.banner('Configuring non-default MTU on Non Default VRF')
    dict1 = {'interfaces_list': [vars.D1D2P5, data.vlan_in_2], 'property': 'mtu', 'value': data.nonDefault_mtu[0]}
    dict2 = {'interfaces_list': [vars.D2D1P5, data.vlan_in_2], 'property': 'mtu', 'value': data.nonDefault_mtu[1]}

    st.log("Configuring mtu on non-default vrf: {}-{}, {}-{}".format(vars.D1, dict1['interfaces_list'], vars.D2, dict2['interfaces_list']))
    parallel.exec_parallel(True, [vars.D1, vars.D2], intfapi.interface_properties_set, [dict1, dict2])

    st.banner('Removing the ports from PO before assigning non-default MTU on PO')
    exec_all(True, [[pcapi.add_del_portchannel_member, vars.D1, data.port_channel, [vars.D1D2P3, vars.D1D2P4], 'del'],
                   [pcapi.add_del_portchannel_member, vars.D2, data.port_channel, [vars.D2D1P3, vars.D2D1P4], 'del']])

    st.banner('Configuring non-default MTU on Default VRF')
    dict1 = {'interfaces_list': [vars.D1D2P1, vars.D1D2P3, vars.D1D2P4, data.vlan_in_1, data.port_channel], 'property': 'mtu',
             'value': data.nonDefault_mtu[0]}
    dict2 = {'interfaces_list': [vars.D2D1P1, vars.D2D1P3, vars.D2D1P4, data.vlan_in_1, data.port_channel], 'property': 'mtu',
             'value': data.nonDefault_mtu[1]}

    st.log("Configuring mtu on default vrf: {}-{}, {}-{}".format(vars.D1, dict1['interfaces_list'], vars.D2, dict2['interfaces_list']))
    parallel.exec_parallel(True, [vars.D1, vars.D2], intfapi.interface_properties_set, [dict1, dict2])

    st.banner('Adding ports into PO')
    exec_all(True, [[pcapi.add_del_portchannel_member, vars.D1, data.port_channel, [vars.D1D2P3, vars.D1D2P4], 'add'],
                   [pcapi.add_del_portchannel_member, vars.D2, data.port_channel, [vars.D2D1P3, vars.D2D1P4], 'add']])

    st.wait(20, 'waiting to expire ospf dead timer')

    st.banner('Verify the ospf neighborship on non default VRF of DUT1')
    for interface in [vars.D1D2P5, data.vlan_in_2]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship with interface {} on non default vrf is still Up, after the non default mtu configured on interfaces.".format(interface))
            result += 1

    st.banner('Verify the ospf neighborship on default VRF of DUT1')
    for interface in [vars.D1D2P1, data.vlan_in_1, data.port_channel]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship with interface {} on default vrf is still Up, after the non default mtu configured on interfaces.".format(interface))
            result += 1

    st.banner('Configuring ignore-mtu on Non default VRF')
    dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict2 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'yes'}

    st.log("Configuring mtu-ignore on non-default vrf: {}-{}, {}-{}".format(vars.D1, dict1['interfaces'], vars.D2, dict2['interfaces']))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_mtu_ignore, [dict1, dict2])

    st.banner('Configuring ignore-mtu on default VRF')
    dict1 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'config': 'yes'}
    dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'config': 'yes'}

    st.log("Configuring mtu-ignore on default vrf: {}-{}, {}-{}".format(vars.D1, dict1['interfaces'], vars.D2, dict2['interfaces']))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_mtu_ignore, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2], states=['Full'],
                 vrf=data.vrf_name[0], addr_family='ipv4'):
        st.error("OSPF neighbourship with the non default vrf is not Up, after configuring mtu-ignore.")
        result += 1

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'],
                     vrf='default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf is not Up, after configuring mtu-ignore.")
        result += 1

    st.wait(10)

    # Verify the route learned from D2, in the routing table of DUT1
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="193.168.0.0/24", interface=vars.D1D2P1):
        st.error("OSPF route {} not shown in RTO after clear ip ospf.".format("193.168.0.0/24"))
        result += 1

    # Traffic validation

    st.banner('Configuring default MTU on Non Default VRF interfaces')
    dict1 = {'interfaces_list': [vars.D1D2P5, data.vlan_in_2], 'property': 'mtu', 'value': data.default_mtu}
    dict2 = {'interfaces_list': [vars.D2D1P5, data.vlan_in_2], 'property': 'mtu', 'value': data.default_mtu}

    st.log("Configuring default mtu on non default vrf interfaces: {}-{}, {}-{}".format(vars.D1, dict1['interfaces_list'], vars.D2,
                                                                 dict2['interfaces_list']))
    parallel.exec_parallel(True, [vars.D1, vars.D2], intfapi.interface_properties_set, [dict1, dict2])

    st.banner('Removing the ports from PO before assigning default MTU on PO')
    exec_all(True, [[pcapi.add_del_portchannel_member, vars.D1, data.port_channel, [vars.D1D2P3, vars.D1D2P4], 'del'],
                   [pcapi.add_del_portchannel_member, vars.D2, data.port_channel, [vars.D2D1P3, vars.D2D1P4], 'del']])

    st.banner('Configuring default MTU on Default VRF interfaces')
    dict1 = {'interfaces_list': [vars.D1D2P1, vars.D1D2P3, vars.D1D2P4, data.vlan_in_1, data.port_channel],
             'property': 'mtu', 'value': data.default_mtu}
    dict2 = {'interfaces_list': [vars.D2D1P1, vars.D2D1P3, vars.D2D1P4, data.vlan_in_1, data.port_channel],
             'property': 'mtu', 'value': data.default_mtu}

    st.log("Configuring default mtu on default vrf interfaces: {}-{}, {}-{}".format(vars.D1, dict1['interfaces_list'],
                                                                                    vars.D2, dict2['interfaces_list']))
    parallel.exec_parallel(True, [vars.D1, vars.D2], intfapi.interface_properties_set, [dict1, dict2])

    st.banner('Adding ports into PO after setting default mtu on ports')
    exec_all(True, [[pcapi.add_del_portchannel_member, vars.D1, data.port_channel, [vars.D1D2P3, vars.D1D2P4], 'add'],
                   [pcapi.add_del_portchannel_member, vars.D2, data.port_channel, [vars.D2D1P3, vars.D2D1P4], 'add']])

    st.banner('Unconfiguring ignore-mtu on Non default VRF')
    dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'no'}
    dict2 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'no'}

    st.log("Unconfiguring mtu-ignore on non-default vrf: {}-{}, {}-{}".format(vars.D1, dict1['interfaces'], vars.D2, dict2['interfaces']))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_mtu_ignore, [dict1, dict2])

    st.banner('Unconfiguring ignore-mtu on default VRF')
    dict1 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'config': 'no'}
    dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'config': 'no'}

    st.log("Unconfiguring mtu-ignore on default vrf: {}-{}, {}-{}".format(vars.D1, dict1, vars.D2, dict2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_mtu_ignore, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
                 states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
        st.error("OSPF neighbourship with the non default vrf is not Up, after unconfiguring mtu-ignore.")
        result += 1

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1,
                     ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'], vrf='default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf is not Up, after unconfiguring mtu-ignore.")
        result += 1

    st.wait(10)

    st.banner('Verify the route learned from D2, in the routing table of DUT1')
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="193.168.0.0/24", interface=vars.D1D2P1):
        st.error("OSPF route {} not shown in RTO after clear ip ospf.".format("193.168.0.0/24"))
        result += 1

    if not result:
        st.report_pass("ospf_session_test_pass", "in the mtu-ignore scenario.")
    else:
        st.report_fail("ospf_session_test_fail", "in the mtu-ignore scenario.")


@pytest.mark.ospf_regression
def test_ft_ospf_cleartext_authentication():
    """
    Verify Ospf Clear text Authentication
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn035')
    result = 0

    st.banner('Configuring Clear Text Authentication')
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': vars.D1D2P1}, {'interfaces': vars.D2D1P1}])
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': data.vlan_in_1}, {'interfaces': data.vlan_in_1}])
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': data.port_channel}, {'interfaces': data.port_channel}])
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': vars.D1D2P5, 'vrf' : data.vrf_name[0]}, {'interfaces': vars.D2D1P5, 'vrf' : data.vrf_name[0]}])
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': data.vlan_in_2, 'vrf' : data.vrf_name[0]}, {'interfaces': data.vlan_in_2, 'vrf' : data.vrf_name[0]}])

    st.banner('Configure the different keys on D1,D2 i.e. session should go down')
    dict1 = {'interfaces': vars.D1D2P1, 'auth_key' : 'CText1'}
    dict2 = {'interfaces': vars.D2D1P1, 'auth_key' : 'CText2'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_1, 'auth_key' : 'CText3'}
    dict2 = {'interfaces': data.vlan_in_1, 'auth_key' : 'CText4'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': data.port_channel, 'auth_key' : 'CText5'}
    dict2 = {'interfaces': data.port_channel, 'auth_key' : 'CText6'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': vars.D1D2P5, 'auth_key' : 'CText7', 'vrf' : data.vrf_name[0]}
    dict2 = {'interfaces': vars.D2D1P5, 'auth_key' : 'CText8', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_2, 'auth_key' : 'CText9', 'vrf' : data.vrf_name[0]}
    dict2 = {'interfaces': data.vlan_in_2, 'auth_key' : 'CText10', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])

    #Waiting for the dead timer i.e. sessions should go down
    st.wait(40, 'Waiting for the dead timer to sessions should go down')

    st.banner('Verify the OSPF sessions after CTextText authentication mismatch, ospf sessions will go down', 120)
    result += verify_ospf_sessions(5, delay=2)

    #The OSPF session failure here is expected, so marking the result falg 0 again
    if not result:
        st.error('OSPF sessions are stil up with the ClearText authentication mismatch')
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn035')
    else:
        result = 0

    st.banner('Configuring the same keys on D1,D2 i.e. sessions should come up')
    dict1 = {'interfaces': vars.D1D2P1, 'auth_key' : 'Ctext1'}
    dict2 = {'interfaces': vars.D2D1P1, 'auth_key' : 'Ctext1'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_1, 'auth_key' : 'CText2'}
    dict2 = {'interfaces': data.vlan_in_1, 'auth_key' : 'CText2'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': data.port_channel, 'auth_key' : 'CText3'}
    dict2 = {'interfaces': data.port_channel, 'auth_key' : 'CText3'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': vars.D1D2P5, 'auth_key' : 'CText4', 'vrf' : data.vrf_name[0]}
    dict2 = {'interfaces': vars.D2D1P5, 'auth_key' : 'CText4', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_2, 'auth_key' : 'CText5', 'vrf' : data.vrf_name[0]}
    dict2 = {'interfaces': data.vlan_in_2, 'auth_key' : 'CText5', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ospfapi.config_interface_ip_ospf_authentication_key, [dict1, dict2])

    st.banner('Verify the OSPF sessions after configuring same CTextText authentication key')
    result += verify_ospf_sessions(60)

    if result == 0:
        st.report_pass("ospf_session_test_pass", "in Authentication with Clear text key scenario")
    else:
        st.report_fail("ospf_session_test_fail", "in Authentication with Clear text key scenario")


@pytest.mark.ospf_regression
def test_ft_ospf_md5_authentication():
    """
    Verify that OSPF routers running MD5 authentication will form full adjacency with each other if they are configured with the same Key and KeyID
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn004')
    result = 0

    st.banner('Configuring  message-digest on interfaces')
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': vars.D1D2P1, 'msg_digest' : 'message-digest'}, {'interfaces': vars.D2D1P1, 'msg_digest' : 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': data.vlan_in_1, 'msg_digest' : 'message-digest'}, {'interfaces': data.vlan_in_1, 'msg_digest' : 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': data.port_channel, 'msg_digest' : 'message-digest'}, {'interfaces': data.port_channel, 'msg_digest' : 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': vars.D1D2P5, 'vrf': data.vrf_name[0], 'msg_digest' : 'message-digest'}, {'interfaces': vars.D2D1P5, 'vrf': data.vrf_name[0], 'msg_digest' : 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication, [{'interfaces': data.vlan_in_2, 'vrf' : data.vrf_name[0], 'msg_digest' : 'message-digest'}, {'interfaces': data.vlan_in_2, 'vrf' : data.vrf_name[0], 'msg_digest' : 'message-digest'}])

    st.banner('Configuring the different keys on D1,D2, ospf session should go down', 100)
    dict1 = {'interfaces': vars.D1D2P1, 'auth_key': 'MDKey1', 'key_id' : 1}
    dict2 = {'interfaces': vars.D2D1P1, 'auth_key': 'MDKey2', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,  [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey3', 'key_id' : 1}
    dict2 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey4', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
    dict1 = {'interfaces': data.port_channel, 'auth_key': 'MDKey5', 'key_id' : 1}
    dict2 = {'interfaces': data.port_channel, 'auth_key': 'MDKey6', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,  [dict1, dict2])
    dict1 = {'interfaces': vars.D1D2P5, 'auth_key': 'MDKey7', 'key_id' : 1}
    dict2 = {'interfaces': vars.D2D1P5, 'auth_key': 'MDKey8', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey9', 'key_id' : 1}
    dict2 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey10', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])

    # Waiting for the dead timer i.e. sessions should go down
    st.wait(40, 'Waiting for the dead timer to sessions should go down')

    st.banner('Verify the OSPF sessions after MD5 key authentication mismatch, ospf sessions will go down', 100)
    result += verify_ospf_sessions(5, delay=2)

    #The OSPF session failure here is expected, so marking the result falg 0 again
    if not result:
        st.error('OSPF sessions are still up with the MD5 key authentication mismatch configuration.')
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn004')
    else:
        result = 0

    st.banner('Configuring the same keys on D1,D2, ospf sessions should come up', 100)
    dict1 = {'interfaces': vars.D1D2P1, 'auth_key': 'MDKey1', 'key_id' : 1, 'config' : 'no'}
    dict2 = {'interfaces': vars.D2D1P1, 'auth_key': 'MDKey2', 'key_id' : 1, 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,  [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey3', 'key_id' : 1, 'config' : 'no'}
    dict2 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey4', 'key_id' : 1, 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
    dict1 = {'interfaces': data.port_channel, 'auth_key': 'MDKey5', 'key_id' : 1, 'config' : 'no'}
    dict2 = {'interfaces': data.port_channel, 'auth_key': 'MDKey6', 'key_id' : 1, 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,  [dict1, dict2])
    dict1 = {'interfaces': vars.D1D2P5, 'auth_key': 'MDKey7', 'key_id' : 1, 'config' : 'no'}
    dict2 = {'interfaces': vars.D2D1P5, 'auth_key': 'MDKey8', 'key_id' : 1, 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey9', 'key_id' : 1, 'config' : 'no'}
    dict2 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey10', 'key_id' : 1, 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])

    dict1 = {'interfaces': vars.D1D2P1, 'auth_key': 'MDKey1', 'key_id' : 1}
    dict2 = {'interfaces': vars.D2D1P1, 'auth_key': 'MDKey1', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,  [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id' : 1}
    dict2 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
    dict1 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id' : 1}
    dict2 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,  [dict1, dict2])
    dict1 = {'interfaces': vars.D1D2P5, 'auth_key': 'MDKey4', 'key_id' : 1}
    dict2 = {'interfaces': vars.D2D1P5, 'auth_key': 'MDKey4', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id' : 1}
    dict2 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id' : 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key, [dict1, dict2])

    st.banner('Verify the OSPF sessions after configuring the same MD5 key authentication', 100)
    result += verify_ospf_sessions(60)

    if result == 0:
        st.report_pass("ospf_session_test_pass", "in Authentication with MD5 key scenario")
    else:
        st.report_fail("ospf_session_test_fail", "in Authentication with MD5 key scenario")


@pytest.mark.ospf_regression
def test_ft_ospf_distance():
    """
    Verify OSPF distance setting and its effect on ip routing table
    Verify that a route with preference set with 255 shall never be used for forwarding
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn017,FtOtSoRtOspfFn020')
    result = 0

    st.banner('Configuring non-default disatance in ospf')
    ospfapi.config_ospf_router_distance(vars.D1, '', distance = 50)

    st.banner('Sending external routes from TG')
    tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr1['handle'])
    IA = tg1.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=ospf_rtr1['handle'],
                                            external_number_of_prefix='5', external_prefix_start='201.1.0.0',
                                            external_prefix_length='24', external_prefix_type='1',
                                            router_id='4.4.4.3')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain.")
        result += 1
    st.banner('Verification of distance on DUT1 for the routes sent from TG1')
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="201.1.0.0/24", distance=str(50), interface=vars.D1T1P1):
        st.error("OSPF route {} not shown in RTO.".format("201.1.0.0/24"))
        result += 1

    st.banner('Bound stream traffic configuration')
    tg_clear_stats()
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_5, emulation_src_handle=h3['handle'],
                                emulation_dst_handle=IA['handle'], circuit_endpoint_type='ipv4', duration='5',
                                mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=2000)
    st.log("Bound Stream: " + str(tr1))
    stream_id1 = tr1['stream_id']

    st.banner('send contiuous traffic for 2 seconds with 2k packets per second')
    tg2.tg_traffic_control(action='run', handle=stream_id1, duration='5')
    st.wait(data.wait)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg2],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
            'stream_list': [[stream_id1]],
        },
    }

    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    st.banner('verify traffic mode aggregate')
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    tg1.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle'])
    ospfapi.config_ospf_router_distance(vars.D1, '', distance = 50, config='no')

    if not aggrResult:
        st.report_fail("ospf_traffic_test_fail", "IPv4 traffic is not forwarded based on the routes advertised by the OSPF protocol")

    ospfapi.config_ospf_router_distance(vars.D1, '', distance = 125)
    tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr1['handle'])
    IA = tg1.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=ospf_rtr1['handle'],
                                            external_number_of_prefix='5', external_prefix_start='201.1.0.0',
                                            external_prefix_length='24', external_prefix_type='1',
                                            router_id='4.4.4.3')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="201.1.0.0/24", distance=str(125), interface=vars.D1T1P1):
        st.error("OSPF route {} not shown in RTO.".format("201.1.0.0/24"))
        result += 1

    tg1.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle'])
    ospfapi.config_ospf_router_distance(vars.D1, '', distance = 125, config='no')

    ospfapi.config_ospf_router_distance(vars.D1, '', distance=255)
    tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr1['handle'])
    IA = tg1.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=ospf_rtr1['handle'],
                                            external_number_of_prefix='5', external_prefix_start='201.1.0.0',
                                            external_prefix_length='24', external_prefix_type='1',
                                            router_id='4.4.4.3')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="201.1.0.0/24", distance=str(255), interface=vars.D1T1P1):
        st.error("OSPF route {} not shown in RTO.".format("201.1.0.0/24"))
        result += 1

    tg_clear_stats()
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_5, emulation_src_handle=h3['handle'], duration='2',
                                emulation_dst_handle=IA['handle'], circuit_endpoint_type='ipv4',
                                mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=2000)
    st.log("Bound Stream: " + str(tr1))
    stream_id1 = tr1['stream_id']

    # send contiuous traffic for 2 seconds with 2k packets per second
    tg2.tg_traffic_control(action='run', handle=stream_id1, duration='2')

    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg2],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
            'stream_list': [[stream_id1]],
        },
    }

    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    # verify traffic mode aggregate
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    tg1.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle'])
    if aggrResult:
        st.report_fail("ospf_traffic_test_fail", "IPv4 traffic is forwarded for the route with preference set with 255")

    if result == 0:
        st.report_pass("ospf_session_test_pass", "with the distance configuration")
    else:
        st.report_fail("ospf_session_test_fail", "with the distance configuration")


@pytest.mark.ospf_regression
def test_ospf_passive_interface_verify():
    """
    Verify that the OSPF functionality after enabling/disabling passive mode configuration on interface.
    :return:
    """

    utilsapi.banner_log('FtOtSoRtOspfFn006')
    result = 0

    poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel],
              states=['Full'], vrf='default', addr_family='ipv4')
    poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
              states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4')

    st.banner('Configuring passive-interface with interface')
    dict1 = {'interfaces': [vars.D1D2P5], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict2 = {'interfaces': [vars.D2D1P1], 'config': 'yes'}

    st.log(
        "Configuring passive-interface with interface for non default VRF on {} and default VRF on {}".format(vars.D1,
                                                                                                              vars.D2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    if not ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[data.vlan_in_2], states=['Full'],
                                              vrf=data.vrf_name[0], addr_family='ipv4'):
        st.error(
            "OSPF neighbourship with the non default vrf is not Up, after configuring passive mode on other interface.")
        result += 1

    if not ospfapi.verify_ospf_neighbor_state(vars.D2, ospf_links=[data.vlan_in_1, data.port_channel], states=['Full'],
                                              vrf='default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf is not Up, configuring passive mode on other interface.")
        result += 1

    dict1 = {'interfaces': [data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict2 = {'interfaces': [data.vlan_in_1, data.port_channel], 'config': 'yes'}

    st.log("Configuring passive-interface for non default VRF on {} and default VRF on {}".format(vars.D1, vars.D2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    st.wait(40)
    for interface in [vars.D1D2P5, data.vlan_in_2]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf=data.vrf_name[0],
                                              addr_family='ipv4'):
            st.error(
                "OSPF neighbourship with the non default vrf is Up, after configuring passive mode on interface {}.".format(
                    interface))
            result += 1

    for interface in [vars.D2D1P1, data.vlan_in_1, data.port_channel]:
        if ospfapi.verify_ospf_neighbor_state(vars.D2, ospf_links=[interface], states=['Full'], vrf='default',
                                              addr_family='ipv4'):
            st.error("OSPF neighbourship with the default vrf is Up, configuring passive mode on interface {}.".format(
                interface))
            result += 1

    st.banner('Unconfiguring passive-interface with interface')
    dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'no'}
    dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'config': 'no'}

    st.log(
        "Unconfiguring passive-interface with interface for non default VRF on {} and default VRF on {}".format(vars.D1,
                                                                                                                vars.D2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[data.vlan_in_2], states=['Full'],
                     vrf=data.vrf_name[0], addr_family='ipv4'):
        st.error(
            "OSPF neighbourship with the non default vrf is not Up, after unconfiguring passive mode on interface.")
        result += 1

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D2, ospf_links=[data.vlan_in_1, data.port_channel],
                     states=['Full'], vrf='default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf is not Up, unconfiguring passive mode on interface.")
        result += 1

    st.banner('Configuring passive-interface on interfaces with ip address')
    dict1 = {'interfaces': [vars.D1D2P5], 'vrf': data.vrf_name[0], 'if_ip': data.dut1_dut2_ip4_addr_l[3],
             'config': 'yes'}
    dict2 = {'interfaces': [vars.D2D1P1], 'if_ip': data.dut2_dut1_ip4_addr_l[0], 'config': 'yes'}

    st.log("Configuring passive-interface for non default VRF on {} and default VRF on {}".format(vars.D1, vars.D2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    if not ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[data.vlan_in_2], states=['Full'],
                                              vrf=data.vrf_name[0], addr_family='ipv4'):
        st.error(
            "OSPF neighbourship with the non default vrf is not Up, after configuring passive mode on other interface with ip.")
        result += 1

    if not ospfapi.verify_ospf_neighbor_state(vars.D2, ospf_links=[data.vlan_in_1, data.port_channel], states=['Full'],
                                              vrf='default', addr_family='ipv4'):
        st.error(
            "OSPF neighbourship with the default vrf is not Up, configuring passive mode on other interface with ip.")
        result += 1

    dict1 = {'interfaces': [data.vlan_in_2], 'vrf': data.vrf_name[0], 'if_ip': data.dut1_dut2_ip4_addr_l[4],
             'config': 'yes'}
    dict2 = {'interfaces': [data.vlan_in_1, data.port_channel], 'if_ip': data.dut2_dut1_ip4_addr_l[1:3],
             'config': 'yes'}

    st.log("Configuring passive-interface for non default VRF on {} and default VRF on {}".format(vars.D1, vars.D2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    st.wait(40)

    for interface in [vars.D1D2P5, data.vlan_in_2]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf=data.vrf_name[0],
                                              addr_family='ipv4'):
            st.error(
                "OSPF neighbourship with the non default vrf is Up, after configuring passive mode with ip on interface {}.".format(
                    interface))
            result += 1

    for interface in [vars.D2D1P1, data.vlan_in_1, data.port_channel]:
        if ospfapi.verify_ospf_neighbor_state(vars.D2, ospf_links=[interface], states=['Full'], vrf='default',
                                              addr_family='ipv4'):
            st.error(
                "OSPF neighbourship with the default vrf is Up, after configuring passive mode with ip on interface {}.".format(
                    interface))
            result += 1

    st.banner('Unconfiguring passive-interface on interfaces with ip address')
    dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'vrf': data.vrf_name[0],
             'if_ip': data.dut1_dut2_ip4_addr_l[3:], 'config': 'no'}
    dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'if_ip': data.dut2_dut1_ip4_addr_l[:3],
             'config': 'no'}

    st.log("Unconfiguring passive-interface with ip for non default VRF on {} and default VRF on {}".format(vars.D1,
                                                                                                            vars.D2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2], states=['Full'],
                     vrf=data.vrf_name[0], addr_family='ipv4'):
        st.error(
            "OSPF neighbourship with the non default vrf is not Up, after unconfiguring passive mode on interface with ip.")
        result += 1

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D2, ospf_links=[vars.D2D1P1, data.vlan_in_1, data.port_channel],
                     states=['Full'], vrf='default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf is not Up, unconfiguring passive mode on interface with ip.")
        result += 1

    st.banner('Configuring passive-interface with default')
    dict1 = {'interfaces': '', 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict2 = {'interfaces': '', 'config': 'yes'}

    st.log("Configuring passive-interface with default for non default VRF on {} and default VRF on {}".format(vars.D1,
                                                                                                               vars.D2))
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    st.wait(40, 'waiting to expire dead timer')

    for interface in [vars.D1D2P1, data.vlan_in_2]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf=data.vrf_name[0],
                                              addr_family='ipv4'):
            st.error(
                "OSPF neighbourship with the non default vrf is not Up, after configuring passive mode as default on interface {}.".format(
                    interface))
            result += 1

    for interface in [vars.D2D1P1, data.vlan_in_1, data.port_channel]:
        if ospfapi.verify_ospf_neighbor_state(vars.D2, ospf_links=[interface], states=['Full'], vrf='default',
                                              addr_family='ipv4'):
            st.error(
                "OSPF neighbourship with the default vrf is not Up, after configuring passive mode as default on interface {}.".format(
                    interface))
            result += 1

    st.banner('Unconfiguring passive-interface with default')
    dict1 = {'interfaces': '', 'vrf': data.vrf_name[0], 'config': 'no'}
    dict2 = {'interfaces': '', 'config': 'no'}

    st.log("Unconfiguring passive-interface with default mode")
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_passive_interface, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
                     states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
        st.error(
            "OSPF neighbourship with the non default vrf is not Up, after unconfiguring passive mode on interface with ip.")
        result += 1

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D2,
                     ospf_links=[vars.D2D1P1, data.vlan_in_1, data.port_channel], states=['Full'], vrf='default',
                     addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf is not Up, after unconfiguring passive mode on interface with ip.")
        result += 1

    # Verify the route learned from D2, in the routing table of DUT1
    if not poll_wait(ospfapi.verify_ospf_route, 20, vars.D1, ip_address="193.168.0.0/24", interface=vars.D1D2P1):
        st.error("OSPF route {} not shown in RTO.".format("193.168.0.0/24"))
        result += 1

    if not result:
        st.report_pass("ospf_session_test_pass", "in the passive-interface scenario.")
    else:
        st.report_fail("ospf_session_test_fail", "in the passive-interface scenario.")


@pytest.mark.ospf_regression
def test_ospf_redistribition_distributionlist_verify():
    """
    Verify OSPF router redistribute configurations with default metric in default vrf
    Verify OSPF router redistribute configurations with default metric in user vrf
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn023,FtOtSoRtOspfFn032')
    result = 0

    if st.get_ui_type(cli_type='') in ['klish', "rest-patch", "rest-put"]:
        st.report_unsupported('test_case_unsupported', 'KLISH CLI commands not supported')

    st.banner('unconfigure the redistributions from module config')
    ospf_module_redistribution_unconfig()

    st.banner('Creation and Verification of static routes with the distribute-list')
    ipapi.create_static_route(vars.D1, data.tg1_ip4_addr_l[0], '192.168.0.0/24')
    ipapi.create_static_route(vars.D1, data.tg1_ip4_addr_l[0], '198.168.0.0/24')
    ipapi.config_access_list(vars.D1, 'Dlist_Static', '192.168.0.0/24', 'permit', seq_num=data.seq_num[0])
    ipapi.config_access_list(vars.D1, 'Dlist_Static', '198.168.0.0/24', 'deny', seq_num=data.seq_num[1])
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Static', 'static')
    ospfapi.redistribute_into_ospf(vars.D1, 'static')

    if not ospfapi.verify_ospf_route(vars.D2, ip_address="192.168.0.0/24"):
        result += 1
        st.error('Distribute-list with the static route is not working.')
    for type, ip_addr in zip(['static', 'connected', 'bgp'], ["198.168.0.0/24", data.dut1_network_l[1], "121.1.1.0/24"]):
        if ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr):
            st.error('Distribute-list with the static route is not working, {} route is redistributed instead of static route'.format(type))
            result += 1

    st.banner('Distribute-list verification of static route with the user vrf')
    ipapi.create_static_route(vars.D1, data.tg1_ip4_addr_l[2], '194.168.0.0/24', vrf=data.vrf_name[0])
    ipapi.create_static_route(vars.D1, data.tg1_ip4_addr_l[2], '199.168.0.0/24', vrf=data.vrf_name[0])
    ipapi.config_access_list(vars.D1, 'Dlist_Static_uservrf', '194.168.0.0/24', 'permit', seq_num=data.seq_num[2])
    ipapi.config_access_list(vars.D1, 'Dlist_Static_uservrf', '199.168.0.0/24', 'deny', seq_num=data.seq_num[3])
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Static_uservrf', 'static', vrf=data.vrf_name[0])
    ospfapi.redistribute_into_ospf(vars.D1, 'static', vrf_name=data.vrf_name[0])

    if not ospfapi.verify_ospf_route(vars.D2, ip_address="194.168.0.0/24", vrf=data.vrf_name[0]):
        st.error('Distribute-list with the static route is not working with user-vrf configuration')
        result += 1
    for ip_addr in ["199.168.0.0/24", data.dut1_network_l[3], "131.1.1.0/24"]:
        if ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr, vrf=data.vrf_name[0]):
            st.error('Distribute-list with the static route is not working with user-vrf configuration')
            result += 1
    if result:
        basicapi.get_techsupport(filename='test_ospf_redistribition_distributionlist_verify_1')

    st.banner('Unconfiguring Distribute-list of static route in the default and user vrf', 100)
    ospfapi.redistribute_into_ospf(vars.D1, 'static', config='no')
    ospfapi.redistribute_into_ospf(vars.D1, 'static', vrf_name=data.vrf_name[0], config='no')
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Static', 'static', config='no')
    ipapi.config_access_list(vars.D1, 'Dlist_Static', '192.168.0.0/24', 'permit', config='no', seq_num=data.seq_num[0])
    ipapi.config_access_list(vars.D1, 'Dlist_Static', '198.168.0.0/24', 'deny', config='no', seq_num=data.seq_num[1])
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Static_uservrf', 'static', vrf=data.vrf_name[0], config='no')
    ipapi.config_access_list(vars.D1, 'Dlist_Static_uservrf', '194.168.0.0/24', 'permit', config='no', seq_num=data.seq_num[2])
    ipapi.config_access_list(vars.D1, 'Dlist_Static_uservrf', '199.168.0.0/24', 'deny', config='no', seq_num=data.seq_num[3])

    st.banner('Distribute-list configuration with connected routes')
    ipapi.config_access_list(vars.D1, 'Dlist_Connected', data.dut1_network_l[1], 'permit', seq_num=data.seq_num[0])
    ipapi.config_access_list(vars.D1, 'Dlist_Connected_uservrf', data.dut1_network_l[3], 'permit', seq_num=data.seq_num[1])
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Connected', 'connected')
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Connected_uservrf', 'connected', vrf=data.vrf_name[0])
    ospfapi.redistribute_into_ospf(vars.D1, 'connected')
    ospfapi.redistribute_into_ospf(vars.D1, 'connected', vrf_name=data.vrf_name[0])

    st.banner('Distribute-list verification with connected routes in default-vrf')
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut1_network_l[1]):
        result += 1
        st.error('Distribute-list with the connected route is not working with default-vrf configuration')
    for ip_addr in ["192.168.0.0/24", "121.1.1.0/24"]:
        if ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr):
            st.error('Distribute-list with the connected route is not working with default-vrf configuration')
            result += 1

    st.banner('Distribute-list verification with connected routes in user-vrf')
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut1_network_l[3], vrf=data.vrf_name[0]):
        result += 1
        st.error('Distribute-list with the connected route is not working with user-vrf configuration')
    for ip_addr in ["194.168.0.0/24", "131.1.1.0/24"]:
        if ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr, vrf=data.vrf_name[0]):
            result += 1
            st.error('Distribute-list with the connected route is not working with user-vrf configuration')
    if result:
        basicapi.get_techsupport(filename='test_ospf_redistribition_distributionlist_verify_2')

    st.banner('Unconfiguring Distribute-list of connected route in default and user vrf')
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Connected', 'connected', config='no')
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_Connected_uservrf', 'connected', vrf=data.vrf_name[0], config='no')
    ipapi.config_access_list(vars.D1, 'Dlist_Connected', data.dut1_network_l[1], 'permit', config='no', seq_num=data.seq_num[0])
    ipapi.config_access_list(vars.D1, 'Dlist_Connected_uservrf', data.dut1_network_l[3], 'permit', config='no', seq_num=data.seq_num[1])
    ospfapi.redistribute_into_ospf(vars.D1, 'connected', config='no')
    ospfapi.redistribute_into_ospf(vars.D1, 'connected', vrf_name=data.vrf_name[0], config='no')

    st.banner('Distribute-list configuration with bgp routes')
    ipapi.config_access_list(vars.D1, 'Dlist_bgp', '121.1.1.0/24', 'permit', seq_num=data.seq_num[4])
    ipapi.config_access_list(vars.D1, 'Dlist_bgp_uservrf', '131.1.1.0/24', 'permit', seq_num=data.seq_num[5])
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_bgp', 'bgp')
    ospfapi.config_ospf_router_distribute_list(vars.D1, 'Dlist_bgp_uservrf', 'bgp', vrf=data.vrf_name[0])
    ospfapi.redistribute_into_ospf(vars.D1, 'bgp')
    ospfapi.redistribute_into_ospf(vars.D1, 'bgp', vrf_name=data.vrf_name[0])

    st.banner('Distribute-list verification with bgp routes in default vrf')
    for ip_addr in ["121.1.2.0/24", "192.168.0.0/24", data.dut1_network_l[1]]:
        if ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr):
            result += 1
            st.error('Distribute-list with the bgp route is not working with default-vrf configuration')

    st.banner('Distribute-list verification with bgp routes in user vrf')
    for ip_addr in ["131.1.2.0/24", "194.168.0.0/24", data.dut1_network_l[3]]:
        if ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr, vrf=data.vrf_name[0]):
            result += 1
            st.error('Distribute-list with the bgp route is not working with user-vrf configuration')

    st.banner('Verification of default metric for redistributed BGP routes')
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="121.1.1.0/24"):
        result += 1
        st.error('Distribute-list with the connected route is not working with default-vrf configuration')
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="131.1.1.0/24", vrf=data.vrf_name[0]):
        result += 1
        st.error('Distribute-list with the connected route is not working with user-vrf configuration')

    if not result:
        st.report_pass("ospf_session_test_pass", "with the redistribution with distribution-list.")
    else:
        st.report_fail("ospf_session_test_fail", "with the redistribution with distribution-list.")


@pytest.mark.ospf_regression
def test_ospf_redistribition_routemap_verify():
    """
    Verify redistribution of various route types with various match and set parameters
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn024')
    result = 0

    ipapi.create_static_route(vars.D1, data.tg1_ip4_addr_l[0], '192.168.0.0/24')
    d2_intf1_cost = ospfapi.fetch_ospf_interface_info(vars.D2, vars.D2D1P1, 'cost', 'default')

    st.banner('Redistribustion configuration in OSPF')
    for rmap in ['rmap1', 'rmap2', 'rmap3']:
        ipapi.config_route_map(vars.D1, rmap, 'yes', sequence='5')

    ospfapi.redistribute_into_ospf(vars.D1, 'static', route_map='rmap1')
    ospfapi.redistribute_into_ospf(vars.D1, 'connected', route_map='rmap2')
    ospfapi.redistribute_into_ospf(vars.D1, 'bgp', route_map='rmap3')

    for type, ip_addr in zip(['Static', 'Connected', 'BGP'], ["192.168.0.0/24", data.dut1_network_l[1], "121.1.1.0/24"]):
        if not ospfapi.verify_ospf_route(vars.D2, ip_address=ip_addr):
            st.error('{} route is not redistributed with route-map default metric value'.format(type))
            result += 1

    st.banner('Route-map configuration')
    for metric, rmap in zip([10, 20, 30], ['rmap1', 'rmap2', 'rmap3']):
        ipapi.config_route_map(vars.D1, rmap, 'yes', sequence='5', metric=metric)

    for type, metric, ip_addr in zip(['Static', 'Connected', 'BGP'], [10, 20, 30],
                             ["192.168.0.0/24", data.dut1_network_l[1], "121.1.1.0/24"]):
        if not poll_wait(ospfapi.verify_ospf_route, 10, vars.D2, ip_address=ip_addr, cost=str(metric), poll_delay=2):
            st.error('{} route is not redistributed with the route-map configuration.'.format(type))
            result += 1

    st.banner('Route-map configuration with add-metric')
    for metric, rmap in zip([10, 20, 30], ['rmap1', 'rmap2', 'rmap3']):
        ipapi.config_route_map(vars.D1, rmap, 'yes', sequence='5', metric='+' + str(metric))

    for type, metric, ip_addr in zip(['Static', 'Connected', 'BGP'], [10, 20, 30],
                                     ["192.168.0.0/24", data.dut1_network_l[1], "121.1.1.0/24"]):
        if not poll_wait(ospfapi.verify_ospf_route, 10, vars.D2, ip_address=ip_addr,
                         cost=str(10 + metric + int(d2_intf1_cost)), poll_delay=2):
            st.error('{} route is not redistributed with the route-map add-metric configuration.'.format(type))
            result += 1

    if not result:
        st.report_pass("ospf_session_test_pass", "with redistribution using the route-map.")
    else:
        st.report_fail("ospf_session_test_fail", "with redistribution using the route-map.")


@pytest.mark.ospf_regression
def test_ospf_hello_dead_interval_verify():
    """
    Verify that the OSPF functionality with non default and default hello and dead interval timers on interface.
    :return:
    """

    utilsapi.banner_log('FtOtSoRtOspfFn029')
    result = 0

    st.banner("Configuring non deafult hello interval on interface for non default VRF on {} and default VRF on {}".format(vars.D1, vars.D2), 130)
    dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'interval': 5, 'link_ip': ['', data.dut1_dut2_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'interval': 5, 'link_ip': ['', data.dut2_dut1_ip4_addr_l[1], data.dut2_dut1_ip4_addr_l[2]], 'config': 'yes'}

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_hello_interval, [dict1, dict2])

    st.banner("verfying ospf non default hello and dead intervals on ospf interfaces")
    dict1 = {'ospf_links': [vars.D1D2P5, data.vlan_in_2], 'match': {'hellotmr': '5', 'deadtmr': '40'}, 'vrf': data.vrf_name[0]}
    dict2 = {'ospf_links': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'match': {'hellotmr': '5', 'deadtmr': '40'}}

    (res, execp) = parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.verify_ospf_interface_info, [dict1, dict2])

    if not all(res):
        st.error("OSPF Hello and Dead timers are not updated as expected: {}-{}, {}-{}".format(vars.D1, res[0], vars.D2, res[1]))
        result +=1

    st.wait(40, 'waiting for expire dead timer')

    for interface in [vars.D1D2P5, data.vlan_in_2]:
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 90, vars.D1, ospf_links=[interface], states=[''], vrf=data.vrf_name[0], addr_family='ipv4'):
            st.error("OSPF neighbourship with the non default vrf is Up, after configuring non default timers on interface {}.".format(interface))
            result += 1
    for interface in [vars.D2D1P1, data.vlan_in_1, data.port_channel]:
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 90, vars.D2, ospf_links=[interface], states=[''], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship with the default vrf is Up, after configuring non default timers on interface {}.".format(interface))
            result += 1

    st.banner("Configuring non deafult hello and dead interval on interfaces")
    dict1 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'interval': 15, 'link_ip': ['', data.dut1_dut2_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict2 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'interval': 15, 'link_ip': ['', data.dut2_dut1_ip4_addr_l[1], data.dut2_dut1_ip4_addr_l[2]], 'config': 'yes'}
    dict3 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'interval': 15, 'link_ip': ['', data.dut1_dut2_ip4_addr_l[1], data.dut1_dut2_ip4_addr_l[2]], 'config': 'yes'}
    dict4 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'interval': 15, 'link_ip': ['', data.dut2_dut1_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict5 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'interval': 5, 'link_ip': ['', data.dut1_dut2_ip4_addr_l[1], data.dut1_dut2_ip4_addr_l[2]], 'config': 'yes'}
    dict6 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'interval': 5, 'link_ip': ['', data.dut2_dut1_ip4_addr_l[4]], 'vrf': data.vrf_name[0], 'config': 'yes'}

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict1, dict2])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict3, dict4])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_hello_interval, [dict5, dict6])

    result += verify_ospf_sessions(60)

    intfapi.interface_operation(vars.D2, [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4, vars.D2D1P5, vars.D2D1P6], operation="shutdown", skip_verify=True)

    st.wait(15, 'waiting for expire ospf sessions after shutdown interfaces')

    for interface in [vars.D1D2P5, data.vlan_in_2]:
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 15, vars.D1, ospf_links=[interface], states=[''], vrf=data.vrf_name[0], addr_family='ipv4', poll_delay=3):
            st.error("OSPF neighbourship is Up, after configuring non default timer on interface {}.".format(interface))
            result += 1

    for interface in [vars.D1D2P1, data.vlan_in_1, data.port_channel]:
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 15, vars.D1, ospf_links=[interface], states=[''], vrf='default', addr_family='ipv4', poll_delay=3):
            st.error("OSPF neighbourship is Up, after configuring non default timer on interface {}.".format(interface))
            result += 1

    intfapi.interface_operation(vars.D2, [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4, vars.D2D1P5, vars.D2D1P6], operation="startup", skip_verify=True)

    result += verify_ospf_sessions(60)

    if not result:
        st.report_pass("ospf_session_test_pass", "in the hello and dead interval scenario.")
    else:
        st.report_fail("ospf_session_test_fail", "in the hello and dead interval scenario.")


@pytest.mark.ospf_regression
def test_ospf_vrf_movement():
    """
    Verify that new OSPF neighborship comes-up fine when an OSPF interface is moved to a different VR
    """
    utilsapi.banner_log('FtOtSoRtOspfFn033')
    result = 0

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 5, vars.D1, ospf_links=[vars.D1D2P5], states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4', poll_delay=1):
        st.error("OSPF neighbourship with the user vrf configuration on port based routing interface is failed.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 5, vars.D1, ospf_links=[vars.D1T1P3], states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4', poll_delay=1):
        st.error("OSPF neighbourship with the user vrf configuration on port based routing interface is failed.")
        result += 1

    st.banner('Unconfigure the existing Vrf-1 configurations')
    dict1 = {'interface_name': vars.D1T1P3, 'ip_address' : data.dut1_tg1_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': vars.D2T1P2, 'ip_address' : data.dut2_tg2_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P5, 'ip_address' : data.dut1_dut2_ip4_addr_l[3], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    dict2 = {'interface_name': vars.D2D1P5, 'ip_address' : data.dut2_dut1_ip4_addr_l[3], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'remove'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("UnConfigure uniform cost on user OSPF interfaces")
    dict1 = {'interfaces': [vars.D1T1P3, vars.D1D2P5, data.vlan_in_2], 'cost': '10', 'vrf': data.vrf_name[0],'config': 'no'}
    dict2 = {'interfaces': [vars.D2T1P2, vars.D2D1P5, data.vlan_in_2], 'cost': '10', 'vrf': data.vrf_name[0],'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_cost, [dict1, dict2])

    st.banner("UnConfigure ospf config on vrf {} interfaces".format(data.vrf_name[0]))
    dict1 = {'interfaces': [vars.D1T1P3, vars.D1D2P5, data.vlan_in_2]}
    dict2 = {'interfaces': [vars.D2T1P2, vars.D2D1P5, data.vlan_in_2]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_interface, [dict1, dict2])

    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1T1P3, 'skip_error': True, 'config': 'no'}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2T1P2, 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D1D2P5, 'skip_error': True, 'config': 'no'}
    dict2 = {'vrf_name': data.vrf_name[0], 'intf_name': vars.D2D1P5, 'skip_error': True, 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'vrf': data.vrf_name[0], 'interfaces': [vars.D1T1P3, vars.D1D2P5]}
    dict2 = {'vrf': data.vrf_name[0], 'interfaces': [vars.D2T1P2, vars.D2D1P5]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.clear_interface_ip_ospf, [dict1, dict2])

    st.banner('configure the new vrf i.e. Vrf-102')
    dict1 = {'vrf_name': data.vrf_name[1], 'skip_error': True }
    parallel.exec_parallel(True, [vars.D1,vars.D2], vrfapi.config_vrf, [dict1, dict1])

    dict1 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D1T1P3, 'skip_error': True}
    dict2 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D2T1P2, 'skip_error': True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D1D2P5, 'skip_error': True}
    dict2 = {'vrf_name': data.vrf_name[1], 'intf_name': vars.D2D1P5, 'skip_error': True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrfapi.bind_vrf_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1T1P3, 'ip_address' : data.dut1_tg1_ip4_addr_l[2], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'add'}
    dict2 = {'interface_name': vars.D2T1P2, 'ip_address' : data.dut2_tg2_ip4_addr_l[1], 'subnet' : 24, 'family' : data.af_ipv4, 'config' : 'add'}
    parallel.exec_parallel(True, [vars.D1,vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P5, 'ip_address': data.dut1_dut2_ip4_addr_l[3], 'subnet': 24, 'family': data.af_ipv4, 'config': 'add'}
    dict2 = {'interface_name': vars.D2D1P5, 'ip_address': data.dut2_dut1_ip4_addr_l[3], 'subnet': 24, 'family': data.af_ipv4, 'config': 'add'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.config_ip_addr_interface, [dict1, dict2])

    st.banner("Configure OSPF peers for the new user-vrf domain")
    dict1 = {'router_id': data.dut1_rid, 'vrf': data.vrf_name[1]}
    dict2 = {'router_id': data.dut2_rid, 'vrf': data.vrf_name[1]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_id, [dict1, dict2])

    dict1 = {'networks': data.dut1_network_l[2], 'area' :'0.0.0.1', 'vrf' :data.vrf_name[1]}
    dict2 = {'networks': data.dut2_network_l[1], 'area': '0.0.0.2', 'vrf' :data.vrf_name[1]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    dict1 = {'networks': [data.dut1_network_l[7]], 'area': '0.0.0.0', 'vrf': data.vrf_name[1]}
    dict2 = {'networks': [data.dut2_network_l[5]], 'area': '0.0.0.0', 'vrf': data.vrf_name[1]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5], states=['Full'], vrf=data.vrf_name[1], addr_family='ipv4'):
        st.error("OSPF neighbourship with the new user vrf configuration i.e. Vrf-102 on port based routing interface is failed.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P3], states=['Full'], vrf=data.vrf_name[1], addr_family='ipv4'):
        st.error("OSPF neighbourship with the new user vrf configuration i.e. Vrf-102 on port based routing interface is failed.")
        result += 1

    if not result:
        st.report_pass("ospf_session_test_pass", "in the User-Vrf movement scenario.")
    else:
        st.report_fail("ospf_session_test_fail", "in the User-Vrf movement scenario.")


@pytest.mark.ospf_regression
def test_ospf_reference_bandwidth():
    """
    Verify OSPF reference bandwidth
    """
    utilsapi.banner_log('FtOtSoRtOspfFn034')
    result = 0
    st.banner('Configure the referense b/w')
    dict1 = {'vrf': 'default', 'bandwidth': '10000', 'config': 'yes'}
    dict2 = {'vrf': 'default', 'bandwidth': '10000', 'config': 'yes'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_autocost_refbw, [dict1, dict2])

    st.banner('Getting new cost and redistribute to D2')
    dict1 = {'vrf': data.vrf_name[0], 'bandwidth': '10000', 'config': 'yes'}
    dict2 = {'vrf': data.vrf_name[0], 'bandwidth': '10000', 'config': 'yes'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_autocost_refbw, [dict1, dict2])

    st.banner('Getting initial cost of D1D2P2 and D2D1P1 also BW')
    d1_intf1_cost = ospfapi.fetch_ospf_interface_info(vars.D1, vars.D1T1P1, 'cost', 'default')
    d1_intf1_cost_lat = ospfapi.fetch_ospf_interface_info(vars.D1, vars.D1D2P1, 'cost', 'default')
    d1_intf1_cost_uservrf_lat = ospfapi.fetch_ospf_interface_info(vars.D1, vars.D1D2P5, 'cost', data.vrf_name[0])
    d2_intf1_cost_lat = ospfapi.fetch_ospf_interface_info(vars.D2, vars.D2D1P1, 'cost', 'default')
    d1_intf1_cost_uservrf = ospfapi.fetch_ospf_interface_info(vars.D1, vars.D1T1P3, 'cost', data.vrf_name[0])
    d2_intf1_cost_uservrf_lat = ospfapi.fetch_ospf_interface_info(vars.D2, vars.D2D1P5, 'cost', data.vrf_name[0])

    st.banner('Route-map and redistribution configuration')
    dict1 = {'route_type': 'static', 'metric' : '30'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])
    dict1 = {'route_type': 'static', 'metric': '60', 'vrf_name' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf, [dict1, dict1])

    dict1 = {'next_hop': data.tg1_ip4_addr_l[0], 'static_ip' : '192.168.0.0/24'}
    dict2 = {'next_hop': data.tg2_ip4_addr_l[0], 'static_ip' : '193.168.0.0/24'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.create_static_route, [dict1, dict2])

    dict1 = {'next_hop': data.tg1_ip4_addr_l[2], 'static_ip' : '194.168.0.0/24', 'vrf' : data.vrf_name[0]}
    dict2 = {'next_hop': data.tg2_ip4_addr_l[1], 'static_ip' : '195.168.0.0/24', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ipapi.create_static_route, [dict1, dict2])
    st.wait(data.wait)
    st.banner('Validation of new cost calculations as per the configured reference bandwidth', 100)
    if not ospfapi.verify_ospf_route(vars.D1, ip_address=data.dut1_network_l[4], cost=str(d1_intf1_cost_lat), interface=vars.D1D2P1):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D1, ip_address='193.168.0.0/24', cost=str(30), interface=vars.D1D2P1):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut2_network_l[2], cost=str(d2_intf1_cost_lat), interface=vars.D2D1P1):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address='192.168.0.0/24', cost=str(30), interface=vars.D2D1P1):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut1_network_l[0], cost=str(int(d1_intf1_cost) + int(d2_intf1_cost_lat)), interface=vars.D2D1P1):
        result += 1

    if not ospfapi.verify_ospf_route(vars.D1, ip_address=data.dut1_network_l[7], cost=str(d1_intf1_cost_uservrf_lat), interface=vars.D1D2P5, vrf = data.vrf_name[0]):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D1, ip_address='195.168.0.0/24', cost=str(60), interface=vars.D1D2P5, vrf = data.vrf_name[0]):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut2_network_l[5], cost=str(d2_intf1_cost_uservrf_lat), interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address='194.168.0.0/24', cost=str(60), interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address=data.dut1_network_l[2], cost=str(int(d1_intf1_cost_uservrf) + int(d2_intf1_cost_uservrf_lat)), interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        result += 1

    st.banner('Verifying port speed with Linux ethtool command')
    d1d2_intf1_speed = ospfapi.fetch_ospf_interface_info(vars.D1, vars.D1D2P1, 'bw', 'default')
    kernel_speed = ospfapi.get_ethtool_interface(vars.D1, vars.D1D2P1, key='speed')
    if kernel_speed:
        kernel_speed = kernel_speed.replace('Mb/s', '')
    if kernel_speed != d1d2_intf1_speed:
        st.error('Configured port speed prior to OSPF configuration is not same after OSPF configuration.')
        result +=1

    if not result:
        st.report_pass("ospf_session_test_pass", "with the auto-cost reference bandwidth configuration.")
    else:
        st.report_fail("ospf_session_test_fail", "with the auto-cost reference bandwidth configuration.")


@pytest.mark.snmp_trap
@pytest.mark.ospf_regression
def test_ft_snmp_ospf_bgp_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when ospf and BGP are soft reset.
    """
    #getting variables of snmptrap server

    ssh_conn_obj = connect_to_device(ip, username, password)
    if not ssh_conn_obj:
       st.report_fail("ssh_connection_failed", ip)
    st.banner('check and start the snmptrap on the given server.')
    ps_cmd = "ps -ealf | grep snmptrapd | grep -v grep"
    st.log("Checking for snmptrap process existence with command '{}'".format(ps_cmd))
    output = execute_command(ssh_conn_obj, ps_cmd)
    ps_lines = "\n".join(output.split("\n")[:-1])

    if not "snmptrapd" in ps_lines:
            st.report_fail("snmptrapd_not_running")

    st.banner('Create a trap on DUT')
    bgpapi.clear_ip_bgp(vars.D1)
    ospfapi.clear_interface_ip_ospf(vars.D1,interfaces=vars.D1D2P1)
    result1 = 0
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="193.168.0.0/24", interface=vars.D1D2P1):
        st.error("OSPF route {} not shown in RTO.".format("193.168.0.0/24"))
        result1 += 1

    if result1 != 0:
        st.report_fail("ospf_session_test_fail", "with ospf soft reset")

    # get data from capture
    read_cmd = "cat {}".format(capture_file)
    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]
    st.banner('Verifying trap generation')
    result1 = any('ospfNbrStateChange' in x for x in trap_lines)
    if not result1:
       st.report_tc_fail("SNMPOspfTr001", "snmptrap_not_generated", "ospfNbrStateChange")
    else:
       st.report_tc_pass("SNMPOspfTr001", "snmptrap_generated", "ospfNbrStateChange")

    result2 = any('ospfIfStateChange' in x for x in trap_lines)
    if not result2:
        st.report_tc_fail("SNMPOspfTr002", "snmptrap_not_generated", "ospfIfStateChange")
    else:
        st.report_tc_pass("SNMPOspfTr002", "snmptrap_generated", "ospfIfStateChange")

    result3 = any('15.0.1' in x for x in trap_lines)
    if not result3:
        st.report_tc_fail("SNMPBgpTr001", "snmptrap_not_generated", "bgpEstablishedNotification")
    else:
        st.report_tc_pass("SNMPBgpTr001", "snmptrap_generated", "bgpEstablishedNotification")

    result4 = any('15.0.2' in x for x in trap_lines)
    if not result4:
        st.report_tc_fail("SNMPBgpTr002", "snmptrap_not_generated", "bgpBackwardTransNotification")
    else:
        st.report_tc_pass("SNMPBgpTr002", "snmptrap_generated", "bgpBackwardTransNotification")

    if not (result1 and result2 and result3 and result4):
        st.report_fail('test_case_failed')
    else:
        st.report_pass('test_case_passed')

    st.banner('Trap unconfig and server cleanup')
    snmp_obj.config_snmp_trap(vars.D1, version=2, ip_addr=None, no_form=True)
    read_cmd = "echo "" > {}".format(capture_file)
    output = execute_command(ssh_conn_obj, read_cmd)
    st.vtysh_config(vars.D1, "no agentx")


@pytest.mark.ospf_regression
def test_ospf_intra_inter_area_route_calculations():
    """
    Verify intra area route calculations
    Verify inter area route calculations
    Verify that the OSPF functionality after clear ip ospf configuration
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn039,FtOtSoRtOspfFn40,FtOtSoRtOspfFn044')
    result = 0

    st.banner('Unconfigure inter area ospf and configure intra area ospf config')
    dict1 = {'networks' : data.dut1_network_l[0], 'area' : '0.0.0.1', 'config' : 'no'}
    dict2 = {'networks' : data.dut2_network_l[0], 'area' : '0.0.0.2', 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    dict1 = {'networks' : data.dut1_network_l[0], 'area' : '0.0.0.0', 'config' : 'yes'}
    dict2 = {'networks' : data.dut2_network_l[0], 'area' : '0.0.0.0', 'config' : 'yes'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    tg1.tg_emulation_ospf_config(handle=ospf_rtr1['handle'], mode='modify', area_id='0.0.0.0')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])
    tg2.tg_emulation_ospf_config(handle=ospf_rtr3['handle'], mode='modify', area_id='0.0.0.0')
    tg2.tg_emulation_ospf_control(mode='start', handle=ospf_rtr3['handle'])

    # waiting for the OSPF dead timer to expire
    st.wait(40, 'waiting for the OSPF dead timer to expire')

    st.banner('Verify ospf neighborship established with intra area config')
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf='default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D2, ospf_links=[vars.D2T1P1], states=['Full'], vrf='default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1

    ospf_metric = 100
    routes_config = tg1.tg_emulation_ospf_route_config(router_id='4.4.4.3', ipv4_prefix_network_address='50.1.0.0', handle=ospf_rtr1['handle'],
                                                       ipv4_prefix_length='32', ipv4_prefix_number_of_addresses='10', ipv4_prefix_route_origin='same_area',
                                                       mode='create', type='ipv4-prefix', ipv4_prefix_metric=ospf_metric)

    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])

    st.banner('Verify intra area route cost on D1 and D2')
    [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1T1P1, 'cost', 'default'],
                                   [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2D1P1, 'cost', 'default']])
    d1tg1_intf1_cost, d2d1_intf1_cost = ret_val
    cost_on_dut1 = ospf_metric + int(d1tg1_intf1_cost)
    cost_on_dut2 = ospf_metric + int(d1tg1_intf1_cost) + int(d2d1_intf1_cost)

    for ip_addr in ["50.1.0.0/32", "50.1.0.9/32"]:
        for dut, port, cost in zip([vars.D1, vars.D2], [vars.D1T1P1, vars.D2D1P1], [cost_on_dut1, cost_on_dut2]):
            st.banner('Verifying intra area route {} with cost {} on dut {}'.format(ip_addr, cost, dut))
            if not poll_wait(ospfapi.verify_ospf_route, 10, dut, ip_address=ip_addr, interface=port, cost=str(cost)):
                st.error("Cost is not updated properly for the intra area route {} on the dut {}.".format(ip_addr, dut))
                result += 1

    st.banner('Send the traffic')
    tg_clear_stats()
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_5, emulation_src_handle=h3['handle'], emulation_dst_handle=routes_config['handle'], duration='5',
                                circuit_endpoint_type='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=2000)
    st.log("Bound Stream: " + str(tr1))
    stream_id1 = tr1['stream_id']

    # send contiuous traffic for 5 seconds with 2k packets per second
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg2],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
            'stream_list': [[stream_id1]],
        },
    }
    tg2.tg_traffic_control(action='run', handle=stream_id1, duration='5')
    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    # verify traffic mode aggregate
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    if not aggrResult:
        st.error("IPv4 traffic is not forwarded based on the routes advertised by the OSPF protocol")
        result += 1
    else:
        st.log("IPv4 traffic is forwarded based on the routes advertised by the OSPF protocol")

    st.banner('Advertising the same intra area routes from TG2 to D2 with the lower metric')
    ospf_metric = 70
    routes_config_1 = tg2.tg_emulation_ospf_route_config(router_id='3.3.3.2', ipv4_prefix_network_address='50.1.0.0', handle=ospf_rtr3['handle'],
                                                         ipv4_prefix_length='32', ipv4_prefix_number_of_addresses='10', ipv4_prefix_route_origin='same_area',
                                                         mode='create', type='ipv4-prefix', ipv4_prefix_metric=ospf_metric)

    tg2.tg_emulation_ospf_control(mode='start', handle=ospf_rtr3['handle'])
    st.wait(data.wait)
    [ret_val, _] = exec_all(True,[[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1D2P1, 'cost', 'default'],
                                  [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2T1P1, 'cost', 'default']])
    d1d2_intf1_cost, d2tg2_intf1_cost = ret_val
    cost_on_dut1 = ospf_metric + int(d1d2_intf1_cost) + int(d2tg2_intf1_cost)
    cost_on_dut2 = ospf_metric + int(d2tg2_intf1_cost)

    for ip_addr in ["50.1.0.0/32", "50.1.0.9/32"]:
        for dut, port, cost in zip([vars.D1, vars.D2], [vars.D1D2P1, vars.D2T1P1], [cost_on_dut1, cost_on_dut2]):
            st.banner('Verifying intra area route {} with cost {} on dut {}'.format(ip_addr, cost, dut))
            if not poll_wait(ospfapi.verify_ospf_route, 10, dut, ip_address=ip_addr, interface=port, cost=str(cost)):
                st.error("Cost is not updated properly for the intra area route {} on the {}, after re-sending with the better metric from TG".format(ip_addr, dut))
                result += 1

    if result:
        result = 0
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn039')
        st.report_tc_fail("FtOtSoRtOspfFn039", "ospf_session_test_fail", "Cost is not updated properly for the intra area routes")
    else:
        st.report_tc_pass("FtOtSoRtOspfFn039", "ospf_session_test_pass", "with intra area routes validation.")

    st.banner('Unconfig section for Intra area route calculations')
    tg1.tg_emulation_ospf_route_config(mode='delete', handle=routes_config['handle'])
    tg1.tg_traffic_config(mode='remove', stream_id=tr1['stream_id'])
    tg2.tg_emulation_ospf_route_config(mode='delete', handle=routes_config_1['handle'])
    dict1 = {'networks': data.dut1_network_l[0], 'area': '0.0.0.0', 'vrf': 'default', 'config': 'no'}
    dict2 = {'networks': data.dut2_network_l[0], 'area': '0.0.0.0', 'vrf': 'default', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    st.banner('Config Area1 on DUT1-TG1 and Area2 DUT2-TG2 for Inter area route calculations.')
    exec_all(True, [[ospfapi.config_ospf_network, vars.D1, data.dut1_network_l[0], '0.0.0.1'],
                   [ospfapi.config_ospf_network, vars.D2, data.dut2_network_l[0], '0.0.0.2']])

    tg1.tg_emulation_ospf_config(handle=ospf_rtr1['handle'], mode='modify', area_id='0.0.0.1')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])
    tg2.tg_emulation_ospf_config(handle=ospf_rtr3['handle'], mode='modify', area_id='0.0.0.2')
    tg2.tg_emulation_ospf_control(mode='start', handle=ospf_rtr3['handle'])

    # waiting for the OSPF dead timer to expire
    st.wait(40, 'waiting for the OSPF dead timer to expire')

    ospf_metric = 50
    routes_config = tg1.tg_emulation_ospf_route_config(router_id='4.4.4.3', ipv4_prefix_network_address='50.1.0.0', handle=ospf_rtr1['handle'],
                                                       ipv4_prefix_length='32', ipv4_prefix_number_of_addresses='10', ipv4_prefix_route_origin='same_area',
                                                       mode='create', type='ipv4-prefix', ipv4_prefix_metric=ospf_metric)
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])
    st.wait(data.wait)
    cost_on_dut1 = ospf_metric + int(d1tg1_intf1_cost)
    cost_on_dut2 = ospf_metric + int(d1tg1_intf1_cost) + int(d1d2_intf1_cost)

    for ip_addr in ["50.1.0.0/32", "50.1.0.9/32"]:
        for dut, port, cost in zip([vars.D1, vars.D2], [vars.D1T1P1, vars.D2D1P1], [cost_on_dut1, cost_on_dut2]):
            st.banner('Verifying inter area route {} with cost {} on dut {}'.format(ip_addr, cost, dut))
            if not poll_wait(ospfapi.verify_ospf_route, 10, dut, ip_address=ip_addr, interface=port, cost=str(cost)):
                st.error("Cost is not updated properly for the inter area route {} on the dut {}.".format(ip_addr, dut))
                result += 1

    ospf_metric = 30
    routes_config_1 = tg2.tg_emulation_ospf_route_config(router_id='3.3.3.2', ipv4_prefix_network_address='50.1.0.0', handle=ospf_rtr3['handle'],
                                                         ipv4_prefix_length='32', ipv4_prefix_number_of_addresses='10', ipv4_prefix_route_origin='same_area',
                                                         mode='create', type='ipv4-prefix', ipv4_prefix_metric=ospf_metric)
    tg2.tg_emulation_ospf_control(mode='start', handle=ospf_rtr3['handle'])
    st.wait(data.wait)
    cost_on_dut1 = 50 + int(d1tg1_intf1_cost)
    cost_on_dut2 = ospf_metric + int(d2tg2_intf1_cost)

    for ip_addr in ["50.1.0.0/32", "50.1.0.9/32"]:
        for dut, port, cost in zip([vars.D1, vars.D2], [vars.D1T1P1, vars.D2T1P1], [cost_on_dut1, cost_on_dut2]):
            st.banner('Verifying inter area route {} with cost {} on dut {}'.format(ip_addr, cost, dut))
            if not poll_wait(ospfapi.verify_ospf_route, 10, dut, ip_address=ip_addr, interface=port, cost=str(cost)):
                st.error("Cost is not updated properly for the inter area route {} on the dut {}.".format(ip_addr, dut))
                result += 1

    if result:
        result = 0
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn040')
        st.report_tc_fail("FtOtSoRtOspfFn040", "ospf_session_test_fail", "Cost is not updated properly for the inter area routes")
    else:
        st.report_tc_pass("FtOtSoRtOspfFn040", "ospf_session_test_pass", "with inter area routes validation.")

    res = clear_ip_ospf()
    if not res:
        st.error("OSPF neighbourship with the default vrf is down after clear ip ospf.")
        result += 1
    res = clear_ip_ospf(vrf=data.vrf_name[0])
    if not res:
        st.error("OSPF neighbourship with the non default vrf is down after clear ip ospf.")
        result += 1
    st.banner('Removing OSPF route config on tg PORTS')
    tg1.tg_emulation_ospf_route_config(mode='delete', handle=routes_config['handle'])
    tg2.tg_emulation_ospf_route_config(mode='delete', handle=routes_config_1['handle'])

    if not result:
        st.report_pass("ospf_session_test_pass", "with inter/intra area route updates.")
    else:
        st.report_fail("ospf_session_test_fail", "with inter/intra area route updates.")


@pytest.mark.ospf_regression
def test_ospf_stub_functionality():
    """
    Verify the OSPF neighbourship in various network types(stub, totaly stub area)
    Verify adjacency formation in stub, totaly stub area with non-default vrfs
    Verify redistribution of various route types with various match and set parameters
    Verify that OSPF neighborship is getting formed over virtual link
    Verify that in case of loss of backbone area, DUT is still stable, and OSPF LSA database is correct
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn07,FtOtSoRtOspfFn08,FtOtSoRtOspfFn041,FtOtSoRtOspfFn011,FtOtSoRtOspfFn014')
    result = 0
    ospf_metric_l = ['10', '40', '20']

    tg1.tg_emulation_ospf_config(handle=ospf_rtr1['handle'], mode='modify', area_id='0.0.0.0')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])
    tg1.tg_emulation_ospf_config(handle=ospf_rtr2['handle'], mode='modify', area_id='0.0.0.0')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr2['handle'])

    ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[0], '0.0.0.0')
    ospfapi.config_ospf_network(vars.D1, data.dut1_network_l[2], '0.0.0.0', vrf= data.vrf_name[0])

    dict1 = {'networks' : data.dut1_network_l[4], 'area' : '0.0.0.4', 'vrf' : 'default'}
    dict2 = {'networks' : data.dut2_network_l[2], 'area' : '0.0.0.4', 'vrf' : 'default'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    dict1 = {'networks' : data.dut1_network_l[7], 'area' : '0.0.0.4', 'vrf' : data.vrf_name[0]}
    dict2 = {'networks' : data.dut2_network_l[5], 'area' : '0.0.0.4', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    ospfapi.config_ospf_router_default_information_extended(vars.D1,'always','metric', ospf_metric_l[1])

    tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr1['handle'])
    IA = tg1.tg_emulation_ospf_route_config(mode='create', type='summary_routes', handle=ospf_rtr1['handle'],
                                            summary_number_of_prefix='5', summary_prefix_start='202.1.1.0',
                                            summary_prefix_length='24', summary_prefix_metric=ospf_metric_l[0],
                                            router_id='4.4.4.3')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])

    [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1D2P1, 'cost', 'default'], [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2D1P1, 'cost', 'default']])
    d1_intf1_cost, d2_intf1_cost = ret_val

    cost_on_d2 = int(ospf_metric_l[0]) + int(d1_intf1_cost) + int(d2_intf1_cost)
    cost_on_d2_def_route = ospf_metric_l[1]
    if not poll_wait(ospfapi.verify_ospf_route, 60, vars.D2, ip_address='202.1.1.0/24', cost=str(cost_on_d2), interface=vars.D2D1P1):
        st.error('Route cost is showing wrongly with the configuration default-information originate always, with metric type as E2')
        result += 1
    if not poll_wait(ospfapi.verify_ospf_route, 60, vars.D2, ip_address='0.0.0.0/0', cost=str(cost_on_d2_def_route), interface=vars.D2D1P1):
        st.error('Default route is not generated as per the configuration default-information originate always with metric type as E2')
        result += 1

    ospfapi.config_ospf_router_default_information_extended(vars.D1, 'always', 'metric', ospf_metric_l[1], '1')
    st.wait(data.wait)
    cost_on_d2_def_route = int(ospf_metric_l[1]) + int(d2_intf1_cost)

    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D2, ip_address='202.1.1.0/24', cost=str(cost_on_d2), interface=vars.D2D1P1):
        st.error('Route cost is showing wrongly with the configuration default-information originate always, with metric type as E1')
        result += 1
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D2, ip_address='0.0.0.0/0', cost=str(cost_on_d2_def_route), interface=vars.D2D1P1):
        st.error('Default route is not generated as per the configuration default-information originate always with metric type as E1')
        result += 1

    flag = 0
    if poll_wait(ipapi.verify_ip_route, 5, vars.D1, ip_address='0.0.0.0/0', poll_delay=1):
        flag = 1

    ospfapi.config_ospf_router_default_information_extended(vars.D1, '', 'metric', ospf_metric_l[2])
    st.wait(data.wait)
    if flag:
        if not poll_wait(ospfapi.verify_ospf_route, 10, vars.D2, ip_address='0.0.0.0/0', interface=vars.D2D1P1, poll_delay=2):
            st.error('Default route is not generated with configuration default-information originate, with metric type as E2 when default route is there on DUT1.')
            result += 1
    else:
        if poll_wait(ospfapi.verify_ospf_route, 5, vars.D2, ip_address='0.0.0.0/0', interface=vars.D2D1P1, poll_delay=1):
            st.error('Default route is generated with configuration default-information originate, with metric type as E2 when default route is not there on DUT1')
            result += 1

    ospfapi.config_ospf_router_default_information_extended(vars.D1, '', 'metric', ospf_metric_l[2], '1')
    st.wait(data.wait)
    if flag:
        if not poll_wait(ospfapi.verify_ospf_route,10 , vars.D2, ip_address='0.0.0.0/0', interface=vars.D2D1P1, poll_delay=2):
            st.error('Default route is not generated with configuration default-information originate, with metric type as E1 when default route is there on DUT1.')
            result += 1
    else:
        if poll_wait(ospfapi.verify_ospf_route,10 , vars.D2, ip_address='0.0.0.0/0', interface=vars.D2D1P1, poll_delay=2):
            st.error('Default route is generated with configuration default-information originate, with metric type as E1 when default route is not there on DUT1')
            result += 1
    if result:
        result = 0
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn041')
        st.report_tc_fail("FtOtSoRtOspfFn041", "ospf_session_test_fail", "with redistribution of various route types with various match and set parameters")
    else:
        st.report_tc_pass("FtOtSoRtOspfFn041", "ospf_session_test_pass", "with redistribution of various route types with various match and set parameters")

    st.banner('Verification of OSPF neighbourship with virtual-link in deafult vrf')
    dict1 = {'area' : '0.0.0.4' , 'ip_addr' : '5.5.5.4'}
    dict2 = {'area' : '0.0.0.4' , 'ip_addr' : '6.6.6.5'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_virtual_link, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60 , vars.D2, ospf_links=['VLINK0'], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on virtual link is failed.")
        result += 1
    if not ospfapi.verify_ospf_database(vars.D1, 'router', key_name='state', key_value_list=['ASBR VL-endpoint']):
        st.error("Router LSA not generated for the virtaul-link neighbourship scenario.")
        result += 1
    if result:
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn011')
    intfapi.interface_operation(vars.D2, vars.D2D1P1, operation="shutdown", skip_verify=True)
    st.wait(40, 'waiting to expire ospf dead timer')

    if poll_wait(ospfapi.verify_ospf_neighbor_state, 5 , vars.D2, ospf_links=['VLINK0'], states=['Full'], vrf = 'default', addr_family='ipv4', poll_delay=1):
        st.error("OSPF neighbourship with the default vrf on virtual link is not down, after the link-down event.")
        result += 1

    dict1 = {'area' : '0.0.0.4' , 'ip_addr' : '5.5.5.4', 'vrf' : data.vrf_name[0]}
    dict2 = {'area' : '0.0.0.4' , 'ip_addr' : '6.6.6.5', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_virtual_link, [dict1, dict2])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60 , vars.D2, ospf_links=['VLINK1'], states=['Full'], vrf = data.vrf_name[0], addr_family='ipv4'):
        st.error("OSPF neighbourship with the user vrf on virtual link is failed.")
        result += 1
    if not ospfapi.verify_ospf_database(vars.D1, 'router', key_name='state', key_value_list=['ASBR VL-endpoint'], vrf=data.vrf_name[0]):
        st.error("Router LSA not generated for the virtaul-link neighbourship scenario.")
        result += 1
    if result:
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn011')
    intfapi.interface_operation(vars.D2, vars.D2D1P5, operation="shutdown", skip_verify=True)
    st.wait(40, 'waiting to expire ospf dead timer')
    if poll_wait(ospfapi.verify_ospf_neighbor_state, 5 , vars.D2, ospf_links=['VLINK1'], states=['Full'], vrf = data.vrf_name[0], addr_family='ipv4', poll_delay=2):
        st.error("OSPF neighbourship with the user vrf on virtual link is not down, after the link-down event.")
        result += 1

    st.banner('Unconfigure the virtual link configuration')
    intfapi.interface_operation(vars.D2, vars.D2D1P1, operation="startup", skip_verify=True)
    dict1 = {'area' : '0.0.0.4' , 'ip_addr' : '5.5.5.4', 'config' : 'no'}
    dict2 = {'area' : '0.0.0.4' , 'ip_addr' : '6.6.6.5', 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_virtual_link, [dict1, dict2])
    intfapi.interface_operation(vars.D2, vars.D2D1P5, operation="startup", skip_verify=True)
    dict1 = {'area' : '0.0.0.4' , 'ip_addr' : '5.5.5.4', 'vrf' : data.vrf_name[0], 'config' : 'no'}
    dict2 = {'area' : '0.0.0.4' , 'ip_addr' : '6.6.6.5', 'vrf' : data.vrf_name[0], 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_virtual_link, [dict1, dict2])

    if result:
        result = 0
        st.report_tc_fail("FtOtSoRtOspfFn011", "ospf_session_test_fail", "over the virtual link")
    else:
        st.report_tc_pass("FtOtSoRtOspfFn011", "ospf_session_test_pass", "over the virtual link")

    if not ospfapi.verify_ospf_lsdb_info(vars.D1, 'summary', key_name='linkstateid', key_value_list=['202.1.1.0']):
        st.error("Summary LSA not generated with for the route 202.1.1.0 before link flap.")
        result += 1

    st.banner('Flap the link between D1-TG1 and verify that D1 generates and summary LSA with LS-AGE 3600', 100)
    intfapi.interface_operation(vars.D1, vars.D1T1P1, operation="shutdown", skip_verify=True)
    intfapi.interface_operation(vars.D1, vars.D1T1P1, operation="startup",  skip_verify=True)

    st.banner('Verify that DUT1 generates and LSA with max age')
    if not ospfapi.verify_ospf_lsdb_info(vars.D1, 'summary', key_name='lsage', key_value_list=['3600']):
        st.error("Summary LSA not generated with the LS AGE as 3600.")
        result += 1

    if result:
        result = 0
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn014')
        st.report_tc_fail("FtOtSoRtOspfFn014", "ospf_session_test_fail", "Summary LSA not generated with the LS AGE as 3600 incase of loss to backbone area")
    else:
        st.report_tc_pass("FtOtSoRtOspfFn014", "ospf_session_test_pass", "Summary LSA generated with the LS AGE as 3600 incase of loss to backbone area")

    tg1.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle'])
    ospfapi.config_ospf_router_default_information_extended(vars.D1, '', 'metric', '20',config='no')

    st.banner('Bring up the stub network as TG---Area0-----DUT1---Stub-----DUT2', 100)
    dict1 = {'area': '0.0.0.4'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])
    dict1 = {'area': '0.0.0.4', 'vrf': data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])

    dict1 = {'interfaces': vars.D1D2P1, 'nw_type': 'point-to-point'}
    dict2 = {'interfaces': vars.D2D1P1, 'nw_type': 'point-to-point'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_network_type, [dict1, dict2])

    dict1 = {'interfaces': vars.D1D2P5, 'nw_type': 'point-to-point', 'vrf': data.vrf_name[0]}
    dict2 = {'interfaces': vars.D2D1P5, 'nw_type': 'point-to-point', 'vrf': data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_network_type, [dict1, dict2])

    dict1 = {'networks' : data.dut1_network_l[7], 'area' : '0.0.0.4', 'vrf' : data.vrf_name[0]}
    dict2 = {'networks' : data.dut2_network_l[5], 'area' : '0.0.0.4', 'vrf' : data.vrf_name[0]}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

    # waiting for the OSPF dead timer to expire
    st.wait(40, 'waiting for the OSPF dead timer to expire')

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60 , vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed with the stub area configuration")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60 , vars.D1, ospf_links=[vars.D1D2P5], states=['Full'], vrf = data.vrf_name[0], addr_family='ipv4'):
        st.error("OSPF neighbourship with the user default vrf on port based routing interface is failed with the stub area configuration.")
        result += 1

    if not ospfapi.verify_ospf_route(vars.D2, ip_address="21.1.0.0/24", interface=vars.D2D1P1):
        st.error("DUT1 as ABR, did not sent type-3 LSA with the 21.1.0.0/24 netwrok, into stub area.")
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="0.0.0.0/0", interface=vars.D2D1P1):
        st.error("DUT1 as ABR, did not sent type-3 LSA with the deafult route 0.0.0.0/24 network, into stub area.")
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="23.1.0.0/24", interface=vars.D2D1P5, vrf=data.vrf_name[0]):
        st.error("DUT1 as ABR, did not sent type-3 LSA with the 23.1.0.0/24 netwrok, into stub area with the user-vrf configuration.")
        result += 1
    if not ospfapi.verify_ospf_route(vars.D2, ip_address="0.0.0.0/0", interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        st.error("DUT1 as ABR, did not sent type-3 LSA with the deafult route 0.0.0.0/24 network, into stub area.")
        result += 1

    st.banner('Unconfig the stub network')
    dict1 = {'area': '0.0.0.4', 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])
    dict1 = {'area': '0.0.0.4', 'vrf': data.vrf_name[0], 'config': 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])

    st.banner('Bring up the totally stub network as TG---Area0-----DUT1---Totally Stub-----DUT2', 120)
    dict1 = {'area': '0.0.0.4', 'no_summary': 'yes'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])
    dict1 = {'area': '0.0.0.4', 'vrf': data.vrf_name[0], 'no_summary': 'yes'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_area_stub, [dict1, dict1])

    for ip, vrf, port in zip(["21.1.0.0/24", "23.1.0.0/24"], ['default', data.vrf_name[0]], [vars.D2D1P1, vars.D2D1P5]):
        flag = 1
        for _ in range(6):
            if not ospfapi.verify_ospf_route(vars.D2, ip_address=ip, interface=port, vrf=vrf):
                flag = 0
                break
            st.error("Fail: DUT1 as ABR, sent the type-3 LSA with the {} netwrok, into totally stub area with the {} configuration.".format(ip, vrf))
            st.wait(5)
        if flag: result += 1

    if not poll_wait(ospfapi.verify_ospf_route, 10, vars.D2, ip_address="0.0.0.0/0", interface=vars.D2D1P1):
        st.error("DUT1 as ABR, did not sent type-3 LSA with the deafult route 0.0.0.0/24 network, into totally stub area.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_route, 10, vars.D2, ip_address="0.0.0.0/0", interface=vars.D2D1P5, vrf = data.vrf_name[0]):
        st.error("DUT1 as ABR, did not sent type-3 LSA with the deafult route 0.0.0.0/24 network, into totally stub area with the user-vrf configuration.")
        result += 1

    if result == 0:
        st.report_pass("ospf_session_test_pass", "with the stub area configuration.")
    else:
        st.report_fail("ospf_session_test_fail", "with the stub area configuration.")


@pytest.mark.ospf_regression
def test_ospf_max_intra_ext_routes_verify():
    """
    Verify that the IPv4 traffic is forwarded based on the maximum routes advertised by the OSPF protocol
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn046')
    result = 0
    for route_type in ['intra', 'ext']:
        params = {
            'def_vrf': {'ospf_han': ospf_rtr1, 'interface': vars.D1T1P1, 'port_handle': tg_ph_5, 'tx_port': vars.T1D2P1,
                        'rx_port': vars.T1D1P1, 'router_id': '3.3.3.2', 'src_han': h3, 'vrf': 'default',
                        'prefix': '150.1.0.0', 'src_ip': data.tg2_ip4_addr_l[0]},
            'user_vrf': {'ospf_han': ospf_rtr2, 'interface': vars.D1T1P3, 'port_handle': tg_ph_6,
                         'tx_port': vars.T1D2P2, 'rx_port': vars.T1D1P3, 'router_id': '3.3.3.2', 'src_han': h4,
                         'vrf': data.vrf_name[0], 'prefix': '50.1.0.0', 'src_ip': data.tg2_ip4_addr_l[1]}}
        for vrf_type, val in params.items():
            st.banner('Verifying {} routes in {}'.format(route_type, vrf_type))
            tg1.tg_emulation_ospf_control(mode='stop', handle=val['ospf_han']['handle'])
            num_routes = data.max_ext_routes if route_type == 'ext' else data.max_intra_routes
            if route_type == 'ext':
                data.max_routes_config = tg1.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=val['ospf_han']['handle'],
                                                        external_number_of_prefix=num_routes, external_prefix_start=val['prefix'],
                                                        external_prefix_length='32', external_prefix_type='1',
                                                        router_id=val['router_id'])
            else:
                if tg1.tg_type =='ixia':
                    data.max_routes_config = tg1.tg_emulation_ospf_route_config(router_id=val['router_id'], ipv4_prefix_network_address=val['prefix'],
                                                       handle=val['ospf_han']['handle'], ipv4_prefix_length='32',
                                                       ipv4_prefix_number_of_addresses=num_routes,
                                                       ipv4_prefix_route_origin='same_area', mode='create',
                                                       type='ipv4-prefix')
                else:
                    st.log("HLTAPI support is not provided for intra area routes. Address this section after support added.")
                    continue
            tg1.tg_emulation_ospf_control(mode='start', handle=val['ospf_han']['handle'])
            if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=val['interface'], states=['Full'], vrf=val['vrf'], addr_family='ipv4', cli_type = data.cli_type):
                st.error("OSPF neighbourship with the {} configuration on {} interface is failed after adding maximum routes.".format(vrf_type, val['interface']))
                result += 1
            for type in ['software', 'hardware']:
                if not poll_wait(verify_route_summary, 60, vars.D1, num_routes, vrf=val['vrf'],route_type=type):
                    st.error("Verification of number of IPv4 route entries in {} on {}: Failed".format(vrf_type, type))
                    result +=1
                else:
                    st.log("Verification of number of IPv4 route entries in {} on {}: Passed".format(vrf_type, type))

                if not poll_wait(verify_route_summary, 60, vars.D2, num_routes, key='fib_ospf', vrf=val['vrf'],route_type=type):
                    st.error("Verification of number of IPv4 route entries in {} on {}: Failed".format(vrf_type, type))
                else:
                    st.log("Verification of number of IPv4 route entries in {} on {}: Passed".format(vrf_type, type))
            # Bound stream traffic configuration
            st.banner('Sending traffic from {} TG port {} with src_ip {} to destination prefixes {} on {} TG {}'.format(
                vars.D2, val['tx_port'], val['src_ip'], val['prefix'], vars.D1, val['rx_port']), 150)
            tg_clear_stats()
            exec_all(True, [[intfapi.clear_interface_counters, vars.D1], [intfapi.clear_interface_counters, vars.D2]])
            tr1 = tg2.tg_traffic_config(port_handle=val['port_handle'], emulation_src_handle=val['src_han']['handle'],
                                        emulation_dst_handle=data.max_routes_config['handle'], circuit_endpoint_type='ipv4',
                                        mode='create', length_mode='fixed', rate_pps=2000, duration='5')
            st.log("Bound Stream: " + str(tr1))

            # send contiuous traffic for 2 seconds with 2k packets per second
            tg2.tg_traffic_control(action='run', handle=tr1['stream_id'], duration='5')
            st.wait(data.wait)
            traffic_details = {
                '1': {
                    'tx_ports': [val['tx_port']],
                    'tx_obj': [tg2],
                    'exp_ratio': [1],
                    'rx_ports': [val['rx_port']],
                    'rx_obj': [tg1],
                    'stream_list': [[tr1['stream_id']]],
                },
            }

            tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

            # verify traffic mode aggregate
            aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
            exec_all(True, [[intfapi.show_interface_counters_all, vars.D1], [intfapi.show_interface_counters_all, vars.D2]])

            tg1.tg_emulation_ospf_control(mode='age_out_routes', age_out_percent=100, handle=data.max_routes_config['ipv4_prefix_interface_handle'])
            st.wait(10)
            tg1.tg_emulation_ospf_control(mode='stop', handle=val['ospf_han']['handle'])
            tg1.tg_emulation_ospf_route_config(mode='delete', handle=data.max_routes_config['handle'])
            tg1.tg_traffic_config(mode='remove', stream_id=tr1['stream_id'])
            data.max_routes_config = dict()
            for type, dut in zip(['software', 'software', 'hardware', 'hardware'], [vars.D1, vars.D2]*2):
                if not poll_wait(verify_route_summary, 60, dut, 100, vrf=val['vrf'], neg_check='yes', route_type=type):
                    msg = 'DUT does not removed all the intra routes on {}'.format(type)
                    st.error(msg)
                    st.report_fail("ospf_traffic_test_fail", msg)

            if not aggrResult or result:
                msg = "IPv4 traffic is not forwarded based on the {} routes in {}".format(route_type, vrf_type)
                st.error(msg)
                st.report_fail("ospf_traffic_test_fail", msg)
            else:
                st.log("IPv4 traffic is forwarded based on the {} routes advertised in {}".format(route_type, vrf_type))

    st.report_pass("ospf_session_test_pass", "IPv4 traffic is forwarded based on the maximum intra and external routes advertised by the OSPF protocol")


@pytest.mark.ospf_regression
def test_ft_ospf_rfc1538compatibility():
    """
    Verify that OSPF routers running MD5 authentication will form full adjacency with each other if they are configured with the same Key and KeyID
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn015')
    result = 0

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                           [{'interfaces': vars.D1D2P1, 'msg_digest': 'message-digest'},
                            {'interfaces': vars.D2D1P1, 'msg_digest': 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                           [{'interfaces': data.vlan_in_1, 'msg_digest': 'message-digest'},
                            {'interfaces': data.vlan_in_1, 'msg_digest': 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                           [{'interfaces': data.port_channel, 'msg_digest': 'message-digest'},
                            {'interfaces': data.port_channel, 'msg_digest': 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                           [{'interfaces': vars.D1D2P5, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest'},
                            {'interfaces': vars.D2D1P5, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest'}])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication,
                           [{'interfaces': data.vlan_in_2, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest'},
                            {'interfaces': data.vlan_in_2, 'vrf': data.vrf_name[0], 'msg_digest': 'message-digest'}])

    dict1 = {'interfaces': vars.D1D2P1, 'auth_key': 'MDKey1', 'key_id': 1}
    dict2 = {'interfaces': vars.D2D1P1, 'auth_key': 'MDKey1', 'key_id': 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,
                           [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id': 1}
    dict2 = {'interfaces': data.vlan_in_1, 'auth_key': 'MDKey2', 'key_id': 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,
                           [dict1, dict2])
    dict1 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id': 1}
    dict2 = {'interfaces': data.port_channel, 'auth_key': 'MDKey3', 'key_id': 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,
                           [dict1, dict2])
    dict1 = {'interfaces': vars.D1D2P5, 'auth_key': 'MDKey4', 'key_id': 1}
    dict2 = {'interfaces': vars.D2D1P5, 'auth_key': 'MDKey4', 'key_id': 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,
                           [dict1, dict2])
    dict1 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id': 1}
    dict2 = {'interfaces': data.vlan_in_2, 'auth_key': 'MDKey5', 'key_id': 1}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_authentication_md_key,
                           [dict1, dict2])

    st.banner('Verifying the OSPF sessions after configuring the same MD5 key authentication', 100)
    result += verify_ospf_sessions(60)

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_compatibility_rfc,
                           [{}, {'vrf': data.vrf_name[0]}])
    parallel.exec_parallel(True, [vars.D2, vars.D1], ospfapi.config_ospf_router_compatibility_rfc,
                           [{}, {'vrf': data.vrf_name[0]}])

    result += verify_ospf_sessions(60)

    if result == 0:
        st.report_pass("ospf_session_test_pass", "in rfc1538compatibilty scenario")
    else:
        st.report_fail("ospf_session_test_fail", "in rfc1538compatibilty scenario")


@pytest.mark.ospf_regression
def test_ospf_inter_area_summarization():
    """
    Verify inter-area route summarization
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn037')
    result = 0
    prefix_network = ['111.1.1.0/24', '111.1.11.0/24', '111.1.21.0/24']
    cost_on_tg = ['10', '20', '30']

    params = {'def_vrf': {'ospf_han': ospf_rtr1, 'interface_d1': vars.D1T1P1, 'interface_d2': vars.D2D1P1,
                          'port_handle': tg_ph_5, 'tx_port': vars.T1D2P1, 'rx_port': vars.T1D1P1,
                          'router_id': '3.3.3.2', 'src_han': h3, 'vrf': 'default'},
              'user_vrf': {'ospf_han': ospf_rtr2, 'interface_d1': vars.D1T1P3, 'interface_d2': vars.D2D1P5,
                           'port_handle': tg_ph_6, 'tx_port': vars.T1D2P2, 'rx_port': vars.T1D1P3,
                           'router_id': '3.3.3.2', 'src_han': h4, 'vrf': data.vrf_name[0]}}

    for vrf_type, val in params.items():
        st.banner("Test for {} vrf".format(vrf_type))
        tg1.tg_emulation_ospf_control(mode='stop', handle=val['ospf_han']['handle'])

        routes1 = tg1.tg_emulation_ospf_route_config(router_id=val['router_id'],
                                                     ipv4_prefix_network_address=prefix_network[0].split('/')[0],
                                                     handle=val['ospf_han']['handle'], ipv4_prefix_length='24',
                                                     ipv4_prefix_number_of_addresses='10',
                                                     ipv4_prefix_route_origin='same_area', mode='create',
                                                     type='ipv4-prefix', ipv4_prefix_metric=cost_on_tg[0])
        routes2 = tg1.tg_emulation_ospf_route_config(router_id=val['router_id'],
                                                     ipv4_prefix_network_address=prefix_network[1].split('/')[0],
                                                     handle=val['ospf_han']['handle'], ipv4_prefix_length='24',
                                                     ipv4_prefix_number_of_addresses='10',
                                                     ipv4_prefix_route_origin='same_area', mode='create',
                                                     type='ipv4-prefix', ipv4_prefix_metric=cost_on_tg[1])
        routes3 = tg1.tg_emulation_ospf_route_config(router_id=val['router_id'],
                                                     ipv4_prefix_network_address=prefix_network[2].split('/')[0],
                                                     handle=val['ospf_han']['handle'], ipv4_prefix_length='24',
                                                     ipv4_prefix_number_of_addresses='10',
                                                     ipv4_prefix_route_origin='same_area', mode='create',
                                                     type='ipv4-prefix', ipv4_prefix_metric=cost_on_tg[2])

        tg1.tg_emulation_ospf_control(mode='start', handle=val['ospf_han']['handle'])

        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=val['interface_d1'], states=['Full'], vrf=val['vrf'], addr_family='ipv4'):
            st.error("OSPF neighbourship with the {} configuration on {} interface is failed after adding maximum routes.".format(vrf_type, val['interface_d1']))
            result += 1

        st.banner('Getting cost from ospf enabled interfaces')
        [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, val['interface_d1'], 'cost', val['vrf']],
                                        [ospfapi.fetch_ospf_interface_info, vars.D2, val['interface_d2'], 'cost', val['vrf']]])
        d1_intf1_cost, d2_intf1_cost = ret_val
        if not d1_intf1_cost or not d2_intf1_cost:
            st.error("Failed to retrive OSPF cost value from the corresponding interfaces.")
            result += 1

        for ip_add, cost_tg in zip(prefix_network, cost_on_tg):
            cost_dut = str(int(d1_intf1_cost) + int(cost_tg))
            if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address=ip_add, interface=val['interface_d1'], vrf=val['vrf'], cost=cost_dut):
                st.error("OSPF route {} not shown in routing table.".format(ip_add))
                result += 1
            cost_dut = str(int(d1_intf1_cost) + int(cost_tg) + int(d2_intf1_cost))
            if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D2, ip_address=ip_add, interface=val['interface_d2'], vrf=val['vrf'], cost=cost_dut):
                st.error("OSPF route {} not shown in routing table.".format(ip_add))
                result += 1

        # Bound stream traffic configuration
        tg_clear_stats()
        tr1 = tg2.tg_traffic_config(port_handle=val['port_handle'], emulation_src_handle=val['src_han']['handle'],
                                    emulation_dst_handle=[routes1['handle'], routes2['handle'], routes3['handle']],
                                    circuit_endpoint_type='ipv4', duration = '5',
                                    mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=2000)
        st.log("Bound Stream: " + str(tr1))

        # send contiuous traffic for 2 seconds with 2k packets per second
        tg2.tg_traffic_control(action='run', handle=tr1['stream_id'], duration='5')
        tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

        traffic_details = {
            '1': {
                'tx_ports': [val['tx_port']],
                'tx_obj': [tg2],
                'exp_ratio': [1],
                'rx_ports': [val['rx_port']],
                'rx_obj': [tg1],
                'stream_list': [[tr1['stream_id']]],
            },
        }

        # verify traffic mode aggregate
        aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

        st.log("Configuring area range with summarized network 111.1.0.0/16")
        ospfapi.config_ospf_router_area_range_cost(vars.D1, '0.0.0.1', '111.1.0.0/16', vrf=val['vrf'], config='yes')

        cost_dut = str(int(d1_intf1_cost) + int(cost_on_tg[2]) + int(d2_intf1_cost))
        if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D2, ip_address='111.1.0.0/16', interface=val['interface_d2'], vrf=val['vrf'], cost=cost_dut):
            st.error("OSPF summarized route {} not shown in routing table.".format('111.1.0.0/16'))
            result += 1

        st.log("Configuring area range with summarized network 111.1.0.0/18")
        ospfapi.config_ospf_router_area_range_cost(vars.D1, '0.0.0.1', '111.1.0.0/16', vrf=val['vrf'], config='no')
        ospfapi.config_ospf_router_area_range_cost(vars.D1, '0.0.0.1', '111.1.0.0/18', vrf=val['vrf'], config='yes')

        if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address='111.1.0.0/18', interface="blackhole", vrf=val['vrf'],):
            st.error("OSPF null route {} not shown in routing table.".format('111.1.0.0/18'))
            result += 1

        st.log("Configuring area range with summarized network 111.1.0.0/18")
        cost_dut = str(int(d1_intf1_cost) + 150)
        ospfapi.config_ospf_router_area_range_cost(vars.D1, '0.0.0.1', '111.1.0.0/18', vrf=val['vrf'], config='no')
        ospfapi.config_ospf_router_area_range_cost(vars.D1, '0.0.0.1', '111.1.0.0/18', vrf=val['vrf'], cost ='150', config='yes')

        if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D2, ip_address='111.1.0.0/18', interface=val['interface_d2'], vrf=val['vrf'], cost=cost_dut):
            st.error("OSPF summarized route {} not shown in routing table.".format('111.1.0.0/18'))
            result += 1

        # Bound stream traffic configuration
        tg_clear_stats()
        # send contiuous traffic for 2 seconds with 2k packets per second
        tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
        tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

        # verify traffic mode aggregate
        aggrResult1 = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

        ospfapi.config_ospf_router_area_range_cost(vars.D1, '0.0.0.1', '111.1.0.0/18', vrf=val['vrf'], cost='50', config='no')

        tg1.tg_emulation_ospf_route_config(mode='delete', handle=routes1['handle'])
        tg1.tg_emulation_ospf_route_config(mode='delete', handle=routes2['handle'])
        tg1.tg_emulation_ospf_route_config(mode='delete', handle=routes3['handle'])

        if not aggrResult and not aggrResult1:
            st.error("IPv4 traffic is not forwarded based on the routes advertised by the OSPF protocol")
            result +=1
        else:
            st.log("IPv4 traffic is forwarded based on the routes advertised by the OSPF protocol")

    if not result:
        st.report_pass("ospf_session_test_pass",
                       "IPv4 traffic is forwarded based on the maximum intra and external routes advertised by the OSPF protocol")
    else:
        st.report_fail("ospf_traffic_test_fail")

@pytest.mark.ospf_regression
def test_ospf_bfd_session_flap_verify():
    """
    Verify OSPF-BFD neighbourship flap scenario
    :return:
    """

    utilsapi.banner_log('FtOtSoRtOspfFn025')
    result = 0
    poll_wait(ospfapi.verify_ospf_neighbor_state, 40, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2], states=['Full'], vrf=data.vrf_name[0],
                                       addr_family='ipv4')
    poll_wait(ospfapi.verify_ospf_neighbor_state, 40, vars.D1, ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'], vrf='default',
                                       addr_family='ipv4')

    st.banner("Configuring BFD on interfaces")
    dict11 = {'interfaces': [vars.D1D2P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict12 = {'interfaces': [vars.D2D1P5, data.vlan_in_2], 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict21 = {'interfaces': [vars.D1D2P1, data.vlan_in_1, data.port_channel], 'config': 'yes'}
    dict22 = {'interfaces': [vars.D2D1P1, data.vlan_in_1, data.port_channel], 'config': 'yes'}

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_bfd, [dict11, dict12])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_bfd, [dict21, dict22])

    result += verify_ospf_sessions(60)

    intfapi.interface_operation(vars.D2, [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4, vars.D2D1P5, vars.D2D1P6],
                                operation="shutdown", skip_verify=False)
    st.wait(5)
    for interface in [vars.D1D2P5, data.vlan_in_2]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
            st.error("OSPF neighbourship with the non default vrf is Up, after BFD session flap on interface {}.".format(interface))
            result += 1

    for interface in [vars.D1D2P1, data.vlan_in_1, data.port_channel]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship with the default vrf is Up, after BFD session flap on interface {}.".format(interface))
            result += 1

    if result: basicapi.get_techsupport(filename='FtOtSoRtOspfFn025_flap')

    intfapi.interface_operation(vars.D2, [vars.D2D1P1, vars.D2D1P2, vars.D2D1P3, vars.D2D1P4, vars.D2D1P5, vars.D2D1P6],
                                operation="startup", skip_verify=False)

    result += verify_ospf_sessions(80)

    st.banner("Removing ip addresses on interfaces")
    int_list = [vars.D1D2P1, data.vlan_in_1, data.port_channel, vars.D1D2P5, data.vlan_in_2]
    for interface, ip in zip(int_list, data.dut1_dut2_ip4_addr_l):
        ipapi.config_ip_addr_interface(vars.D1, interface_name=interface, ip_address=ip, subnet=24, family=data.af_ipv4, config='remove')
    st.wait(5)
    for interface in [vars.D1D2P5, data.vlan_in_2]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
            st.error("OSPF neighbourship with the non default vrf is Up, after BFD session flap on interface {}.".format(interface))
            result += 1

    for interface in [vars.D1D2P1, data.vlan_in_1, data.port_channel]:
        if ospfapi.verify_ospf_neighbor_state(vars.D1, ospf_links=[interface], states=['Full'], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship with the default vrf is Up, after BFD session flap on interface {}.".format(interface))
            result += 1

    if result: basicapi.get_techsupport(filename='FtOtSoRtOspfFn025_ip_address')

    st.banner("Assigning ip addresses on interfaces")
    for interface, ip in zip(int_list, data.dut1_dut2_ip4_addr_l):
        ipapi.config_ip_addr_interface(vars.D1, interface_name=interface, ip_address=ip, subnet=24, family=data.af_ipv4)

    result += verify_ospf_sessions(60)

    if not result:
        st.report_pass("ospf_session_test_pass", "in the OSPF-BFD neighbourship flap scenario.")
    else:
        st.report_fail("ospf_session_test_fail", "in the OSPF-BFD neighbourship flap scenario.")


@pytest.mark.ospf_regression
def test_ospf_max_lsdb_overflow_test():
    """
    Verify the DUT behavior with route table maxed out with OSPF routes & local/Static routes
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn018')
    result = 0
    intfapi.interface_operation(vars.D2, [vars.D2D1P2, vars.D2D1P3, vars.D2D1P4], operation="shutdown", skip_verify=True)
    st.log('Displaying the OSPF route summary')
    ospfapi.fetch_ip_route_summary(vars.D1, vrf='default', key='ospf')

    st.banner("Sending 5k intra routes form the TG1 to DUT1 and verify that DUT is stable after the warmreboot, linkflap, reload scenarios", 140)
    tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr1['handle'])
    data.routes_config = tg1.tg_emulation_ospf_route_config(router_id='4.4.4.4', ipv4_prefix_network_address='59.1.0.0', handle=ospf_rtr1['handle'],
                                                         ipv4_prefix_length='24', ipv4_prefix_number_of_addresses='5000',
                                                         ipv4_prefix_route_origin='same_area', mode='create', type='ipv4-prefix')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain after warmboot.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf ='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")

    if not poll_wait(verify_route_summary, 30, vars.D1, data.max_intra_routes):
        st.error('All the intra routes are not learnt by the DUT')
        # tg1.tg_emulation_ospf_route_config(mode='delete', handle=routes_config['handle'])
        st.report_fail("ospf_session_test_fail", "with the maximum intra routes.")

    st.banner('Verifying the 5k intra routes learned after warm reboot')
    st.log("verify warm reboot with 5k internal routes")
    rebootapi.config_warm_restart(vars.D1, oper="enable")
    ospf_reboot_device(vars.D1, 'warm')
    rebootapi.verify_warm_restart(vars.D1, mode='config')
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 120, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain after warmboot.")
        result += 1
    if not poll_wait(verify_route_summary, 30, vars.D1, data.max_intra_routes):
        st.error('All the intra routes not retained by the DUT after warmboot')
        st.report_fail("ospf_session_test_fail", "with the maximum intra routes after warmboot.")

    st.banner('Verifying the 5k intra routes learned after clear ospf.')
    ospfapi.clear_interface_ip_ospf(vars.D1, vars.D1T1P1, vrf='default')
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 120, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain after after clear ospf.")
        result += 1
    if not poll_wait(verify_route_summary, 30, vars.D1, data.max_intra_routes):
        st.error('All the intra routes are not retained by the DUT after link flap scenario.')
        st.report_fail("ospf_session_test_fail", "with the maximum intra routes after clear ospf")

    st.log('Save and reboot with 5k intra routes')
    ospf_reboot_device(vars.D1, '')

    st.banner('Verifying the 5k intra routes learned after reboot.')
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 120, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain after save and reboot.")
        result += 1
    if not poll_wait(verify_route_summary, 30, vars.D1, data.max_intra_routes):
        st.error('All the intra routes are not learnt by the DUT after save and reboot')
        st.report_fail("ospf_session_test_fail", "with the maximum intra routes after save and reboot.")

    st.banner('Sending more than 5k+ intra routes i.e. DUT will enter into overflow state and flushes all the OSPF routes learned', 130)
    tg1.tg_emulation_ospf_route_config(router_id='4.4.4.4', ipv4_prefix_network_address='59.1.0.0',
                                          handle=re.search(r'.*networkGroup:(\d)+', data.routes_config['handle']).group(0),
                                          ipv4_prefix_length='24', ipv4_prefix_number_of_addresses='10000',
                                          ipv4_prefix_route_origin='same_area', mode='modify', type='ipv4-prefix')
    st.wait(data.wait)
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 120, vars.D1, ospf_links=[vars.D1T1P1], states=['Full', 'Loading'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain.")
        result += 1
    st.wait(20)
    ospf_routes_overflow = ospfapi.fetch_ip_route_summary(vars.D1, vrf='default', key='ospf')
    if int(ospf_routes_overflow) > 100:
        st.error('All the intra routes are not flushed when the router reaches overflow state.')
        result += 1

    # tg1.tg_emulation_ospf_route_config(mode='delete', handle=routes_config['handle'])

    st.banner("Sending 40k external BGP routes from TG port connected to DUT1")
    data.bgp_routes = tg1.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes='40000', prefix='122.1.1.0', as_path='as_seq:1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(40)
    bgp_routes_external = ospfapi.fetch_ip_route_summary(vars.D1, vrf='default', key='ebgp')
    ospf_routes_external = ospfapi.fetch_ip_route_summary(vars.D2, vrf='default', key='ospf')
    if int(bgp_routes_external) < data.max_ext_routes:
        st.error('All the external BGP routes are not installed on the DUT1.')
        result +=1
    else:
        if int(ospf_routes_external) < data.max_ext_routes:
           st.error('All the external BGP routes are not redistributed into OSPF domain.')
           ospfapi.fetch_ip_route_summary(vars.D1, vrf='default', key='ospf')
           st.report_fail("ospf_session_test_fail", "with the maximum external routes not learned")

    st.banner("verify warm reboot with more than 40k external routes")
    rebootapi.config_warm_restart(vars.D1, oper="enable")
    ospf_reboot_device(vars.D1, 'warm')
    rebootapi.verify_warm_restart(vars.D1, mode='config')
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 120, vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with DUT2 in default-vrf domain after warmboot.")
        result += 1
    if not poll_wait(bgpapi.verify_bgp_summary, 60, vars.D1, family='ipv4', neighbor=data.tg1_ip4_addr_l[1], state='Established'):
        st.error("Failed to form BGP Neighbourship with the TG port connected to DUT1 in default-vrf domain after warmboot..")
        result += 1
    if not poll_wait(verify_route_summary, 60, vars.D1, data.max_ext_routes, key='ebgp', poll_delay=10):
        st.error('All the external routes are not installed after warm reboot scenario.')
        result += 1
    if not poll_wait(verify_route_summary, 60, vars.D2, data.max_ext_routes, poll_delay=10):
        st.error('All the external routes are not installed after warm reboot scenario.')
        st.report_fail("ospf_session_test_fail", "with the maximum external routes after warm reboot")

    st.banner("verify shutdown/no shutdown with more than 40k external routes")
    intfapi.interface_operation(vars.D1, vars.D1D2P1, operation="shutdown", skip_verify=True)
    st.wait(data.wait)
    intfapi.interface_operation(vars.D1, vars.D1D2P1, operation="startup", skip_verify=True)
    st.wait(data.wait)
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 120, vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with the port based interface between DUT1-DUT2 in default-vrf domain after linkflap.")
        result += 1
    if not poll_wait(verify_route_summary, 60, vars.D1, data.max_ext_routes, key='ebgp', poll_delay=10):
        st.error('All the external routes are not learnt by the DUT after linkflap scenario.')
        result += 1
    if not poll_wait(verify_route_summary, 60, vars.D2, data.max_ext_routes, poll_delay=10):
        st.error('All the external routes are not learnt by the DUT after linkflap scenario.')
        st.report_fail("ospf_session_test_fail", "with the maximum external routes after link flap")

    st.log('Save and reboot with 40k external routes')
    ospf_reboot_device(vars.D1, '')

    st.banner("verify reboot with more than 40k external routes")
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 120, vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf='default', addr_family='ipv4', cli_type = data.cli_type):
        st.error("Failed to form OSPF Neighbourship with DUT2 in default-vrf domain after save and reboot.")
        result += 1
    if not poll_wait(bgpapi.verify_bgp_summary, 60, vars.D1, family='ipv4', neighbor=data.tg1_ip4_addr_l[1], state='Established'):
        st.error("Failed to form BGP Neighbourship with the TG port connected to DUT1 in default-vrf domain after save and reboot.")
        result += 1
    if not poll_wait(verify_route_summary, 60, vars.D1, data.max_ext_routes, key='ebgp', poll_delay=10):
        st.error('All the external routes are not learnt by the DUT after save and reboot scenario.')
        result += 1
    if not poll_wait(verify_route_summary, 60, vars.D2, data.max_ext_routes, poll_delay=10):
        st.error('All the external routes are not learnt by the DUT after save and reboot scenario.')
        st.report_fail("ospf_session_test_fail", "with the maximum external routes after save and reboot")

    if not result:
        st.report_pass("ospf_session_test_pass", "with the maximum intra/external routes.")
    else:
        st.report_fail("ospf_session_test_fail", "with the maximum intra/external routes.")


@pytest.mark.ospf_regression
def test_ospf_traffic_verify():
    """
    Verify that the IPv4 traffic is forwarded based on the routes advertised by the OSPF protocol
    :return:
    """
    result = 1
    utilsapi.banner_log('FtOtSoRtOspfFn010, FtOtSoRtOspfFn050')

    st.banner('sending routes from TG1 for verification')
    tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr1['handle'])
    IA = tg1.tg_emulation_ospf_route_config(router_id='4.4.4.3', ipv4_prefix_network_address='201.1.1.0',
                                            handle=ospf_rtr1['handle'],
                                            ipv4_prefix_length='24', ipv4_prefix_number_of_addresses='5',
                                            ipv4_prefix_route_origin='same_area',
                                            mode='create', type='ipv4-prefix', ipv4_prefix_metric='10')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])

    for port, dut in zip([vars.D1T1P1, vars.D2T1P1], [vars.D1, vars.D2]):
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, dut, ospf_links=[port], states=['Full'], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship is failed with TG interface {} on dut {}".format(port, dut))
            result = 0

    st.banner('Bound stream traffic configuration')
    tg_clear_stats()
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_5, emulation_src_handle=h3['handle'], port_handle2=tg_ph_1,
                                emulation_dst_handle=IA['handle'], circuit_endpoint_type='ipv4',
                                mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=2000)
    st.log("Bound Stream: " + str(tr1))
    stream_id1 = tr1['stream_id']

    # send contiuous traffic for 5 seconds with 2k packets per second
    tg2.tg_traffic_control(action='run', handle=stream_id1)
    st.wait(data.wait)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg2],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
            'stream_list': [[stream_id1]],
        },
    }

    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    st.banner('verify traffic mode aggregate')
    aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    tg_clear_stats()
    tg2.tg_traffic_control(action='run', handle=stream_id1)
    st.wait(data.wait)

    st.banner('Verify traffic scenario with docker restart')
    ospf_reboot_device(vars.D2, 'docker')

    result += verify_ospf_sessions(60)

    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    st.banner('verify traffic mode streamblock')
    streamResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count', tolerance_factor=0)

    if streamResult:
        st.report_tc_pass('FtOtSoRtOspfFn050', 'ospf_session_test_pass', 'IPv4 traffic verification is successful over the docker restart')
    else:
        st.report_tc_fail('FtOtSoRtOspfFn050', 'ospf_session_test_fail', 'IPv4 traffic verification is failed over the docker restart')

    tg1.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle'])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D2, ospf_links=[vars.D2T1P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result = 0

    if aggrResult and result:
        st.report_pass("ospf_session_test_pass", "IPv4 traffic is forwarded based on the routes advertised by the OSPF protocol")
    else:
        st.report_fail("ospf_traffic_test_fail")


@pytest.mark.ospf_regression
def test_ospf_import_export_list():
    """
    Verify multiple areas with two or more node OSPF sessions using import/export list
    :return:
    """
    result = 1
    utilsapi.banner_log('FtOtSoRtOspfFn013')

    if st.get_ui_type(cli_type='') in ['klish', "rest-patch", "rest-put"]:
        st.report_unsupported('test_case_unsupported', 'KLISH CLI commands not supported')

    st.banner('sending routes from TG1 for export-list verification')
    tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr1['handle'])
    IA = tg1.tg_emulation_ospf_route_config(router_id='4.4.4.3', ipv4_prefix_network_address='201.1.1.0',
                                            handle=ospf_rtr1['handle'],
                                            ipv4_prefix_length='24', ipv4_prefix_number_of_addresses='5',
                                            ipv4_prefix_route_origin='same_area',
                                            mode='create', type='ipv4-prefix', ipv4_prefix_metric='10')
    tg1.tg_emulation_ospf_control(mode='start', handle=ospf_rtr1['handle'])

    st.banner('sending routes from TG2 for import-list verification')
    tg2.tg_emulation_ospf_control(mode='stop', handle=ospf_rtr3['handle'])
    IA1 = tg2.tg_emulation_ospf_route_config(router_id='3.3.3.2', ipv4_prefix_network_address='202.1.1.0',
                                             handle=ospf_rtr3['handle'],
                                             ipv4_prefix_length='24', ipv4_prefix_number_of_addresses='5',
                                             ipv4_prefix_route_origin='same_area',
                                             mode='create', type='ipv4-prefix', ipv4_prefix_metric='10')
    tg2.tg_emulation_ospf_control(mode='start', handle=ospf_rtr3['handle'])

    for port, dut in zip([vars.D1T1P1, vars.D2T1P1], [vars.D1, vars.D2]):
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, dut, ospf_links=[port], states=['Full'], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship is failed with TG interface {} on dut {}".format(port, dut))
            result = 0

    cli_type = st.get_ui_type(cli_type='')

    if cli_type not in ['klish', "rest-patch", "rest-put"]:
        st.banner('configure access-lists for import/export list config')
        exec_all(True, [[ipapi.config_access_list, vars.D1, 'export_list', '201.1.1.0/24', 'permit', 'yes', 'ipv4', cli_type, data.seq_num[6]],
                       [ipapi.config_access_list, vars.D2, 'import_list', '202.1.1.0/24', 'permit', 'yes', 'ipv4', cli_type, data.seq_num[6]]])
        exec_all(True, [[ipapi.config_access_list, vars.D1, 'export_list', '201.1.2.0/24', 'permit', 'yes', 'ipv4', cli_type, data.seq_num[7]],
                       [ipapi.config_access_list, vars.D2, 'import_list', '202.1.2.0/24', 'permit', 'yes', 'ipv4', cli_type, data.seq_num[7]]])

    st.banner('configuire import-list on D2 and export-list list on D1')
    exec_all(True, [[ospfapi.config_ospf_router_area_export_list, vars.D1, '0.0.0.1', 'export_list'],
                    [ospfapi.config_ospf_router_area_import_list, vars.D2, '0.0.0.0', 'import_list']])

    for port, dut in zip([vars.D1T1P1, vars.D2T1P1], [vars.D1, vars.D2]):
        if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, dut, ospf_links=[port], states=['Full'], vrf='default', addr_family='ipv4'):
            st.error("OSPF neighbourship is failed with TG interface {} on dut {}".format(port, dut))
            result = 0

    for dut, ip_addr in zip([vars.D1, vars.D1, vars.D2, vars.D2], ["201.1.1.0/24", "201.1.5.0/24", "202.1.1.0/24", "202.1.5.0/24"]):
        st.banner('Verifying routes learned dut {} send from TG for prefixes {}'.format(dut, ip_addr))
        if not poll_wait(ospfapi.verify_ospf_route, 40, dut, ip_address=ip_addr):
            st.error("OSPF route {} not shown in RTO on dut {}.".format(ip_addr, dut))
            result = 0
    for type, dut, ip_addr in zip(['export-list', 'import-list'], [vars.D2, vars.D1], ["201.1.1.0/24", "202.1.1.0/24"]):
        st.banner('Verifying {} functionality for OSPF route {} on dut {}'.format(type, ip_addr, dut))
        if not poll_wait(ospfapi.verify_ospf_route, 10, dut, ip_address=ip_addr):
            st.error("OSPF route {} not shown in RTO on dut {}, {} functionality is not working.".format(ip_addr, dut, type))
            result = 0
    for type, dut, ip_addr in zip(['export-list', 'import-list'], [vars.D2, vars.D1], ["201.1.5.0/24", "202.1.5.0/24"]):
        st.banner('Verifying {} functionality for OSPF route {} on dut {}'.format(type, ip_addr, dut))
        if ospfapi.verify_ospf_route(dut, ip_address=ip_addr):
            st.error("OSPF route {} shown in RTO on dut {}, {} functionality is not working.".format(ip_addr, dut, type))
            result = 0

    st.banner('Unconfiguring export/import lists')
    exec_all(True, [[ospfapi.config_ospf_router_area_export_list, vars.D1, '0.0.0.1', 'export_list', 'default', '', 'no'],
                   [ospfapi.config_ospf_router_area_import_list, vars.D2, '0.0.0.0', 'import_list',  'default', '', 'no']])

    if not poll_wait(ospfapi.verify_ospf_route, 30, vars.D2, ip_address="201.1.5.0/24"):
        st.error("OSPF route {} is not shown in RTO, export-list functionality is not working.".format("201.1.5.0/24"))

    st.banner('Bound stream traffic configuration')
    tg_clear_stats()
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_5, emulation_src_handle=h3['handle'], port_handle2=tg_ph_1,
                                emulation_dst_handle=IA['handle'], circuit_endpoint_type='ipv4',
                                mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=2000)
    st.log("Bound Stream: " + str(tr1))
    stream_id1 = tr1['stream_id']

    # send contiuous traffic for 5 seconds with 2k packets per second
    tg2.tg_traffic_control(action='run', handle=stream_id1)
    st.wait(data.wait)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg2],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
            'stream_list': [[stream_id1]],
        },
    }

    tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])

    st.banner('verify traffic mode streamblock')
    streamResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')

    tg1.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle'])
    tg2.tg_emulation_ospf_route_config(mode='delete', handle=IA1['handle'])

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D2, ospf_links=[vars.D2T1P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result = 0

    if streamResult and result:
        st.report_pass("ospf_session_test_pass", "IPv4 traffic is forwarded based on the import/export list routes advertised by the OSPF protocol")
    else:
        st.report_fail("ospf_traffic_test_fail")


@pytest.mark.ospf_regression
def test_ospf_dr_bdr_election():
    """
    DR/BDR Election
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn002')
    result = 0

    state_d1 = ospfapi.fetch_ospf_interface_info(vars.D1, vars.D1D2P1, 'nbrstate', 'default')
    if state_d1 != 'DR':
        result +=1
        st.error("router with highest router-id is not choosen as the DR when default priority is configured.")

    st.banner('Configure priority on interfaces')
    dict1 = {'interfaces' : vars.D1D2P1, 'priority' : '30'}
    dict2 = {'interfaces' : vars.D2D1P1, 'priority' : '40'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_priority, [dict1, dict2])

    st.banner('Verify the DR/BDR aftre docker restart')
    ospf_reboot_device([vars.D1, vars.D2], 'docker')

    st.banner('Verifying the neighbourship status after BGP docker restart')
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 90 , vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1

    [ret_val, _] = exec_all(True, [[ospfapi.fetch_ospf_interface_info, vars.D1, vars.D1D2P1, 'nbrstate', 'default'],
                                   [ospfapi.fetch_ospf_interface_info, vars.D2, vars.D2D1P1, 'nbrstate', 'default']])
    state_d1, state_d2 = ret_val

    if state_d1 == 'DR' or state_d2 != 'DR':
        result += 1
        basicapi.get_techsupport(filename='FtOtSoRtOspfFn002')
        st.error("router with highest priority is not choosen as the DR..")

    st.banner('Bring back both the DUTS to default priority and verify DR/BDR')
    dict1 = {'interfaces' : vars.D1D2P1, 'priority' : '30', 'config' : 'no'}
    dict2 = {'interfaces' : vars.D2D1P1, 'priority' : '40', 'config' : 'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_priority, [dict1, dict2])

    ospf_reboot_device([vars.D1, vars.D2], 'docker')

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 90 , vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1

    state_d1 = ospfapi.fetch_ospf_interface_info(vars.D1, vars.D1D2P1, 'nbrstate', 'default')

    if state_d1 != 'DR':
        result += 1
        st.error("router with highest router-id is not choosen as the DR when default priority is configured.")

    if result == 0:
        st.report_pass("ospf_session_test_pass", "the DR/BDR eleaction.")
    else:
        st.report_fail("ospf_session_test_fail", "the DR/BDR eleaction..")


@pytest.mark.ospf_regression
def test_ospf_retransmit_interval_verify():
    """
    Verify LSA retransmission timer.
    :return:
    """

    utilsapi.banner_log('FtOtSoRtOspfFn036')
    result = 0
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
              states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase")
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, addr_family='ipv4',
              ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'], vrf='default'):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase.")

    ospfapi.config_interface_ip_ospf_retransmit_interval(vars.D1, [vars.D1D2P1], 20, vrf='', config='yes')
    ospfapi.config_interface_ip_ospf_retransmit_interval(vars.D1, [vars.D1D2P5], 20, vrf=data.vrf_name[0], config='yes')

    st.banner("Configuring non deafult dead interval on interface")
    dict1 = {'interfaces': [vars.D1D2P5], 'interval': 1500, 'vrf': data.vrf_name[0], 'config': 'yes'}
    dict2 = {'interfaces': [vars.D2D1P1], 'interval': 1500, 'config': 'yes'}
    dict3 = {'interfaces': [vars.D1D2P1], 'interval': 1500, 'config': 'yes'}
    dict4 = {'interfaces': [vars.D2D1P5], 'interval': 1500, 'vrf': data.vrf_name[0], 'config': 'yes'}

    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict1, dict2])
    parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_interface_ip_ospf_dead_interval, [dict3, dict4])

    st.wait(40)

    st.banner('Verify OSPF packets transmitting based on configured transmit-interval')
    rebootapi.config_save(vars.D2, "sonic")
    rebootapi.config_save(vars.D2, "vtysh")
    basicapi.service_operations_by_systemctl(vars.D2, 'bgp', 'stop')

    intfapi.interface_operation(vars.D1, [vars.D1T1P1, vars.D1T1P3], operation="shutdown", skip_verify=True)
    st.wait(data.wait)
    intfapi.interface_operation(vars.D1, [vars.D1T1P1, vars.D1T1P3], operation="startup", skip_verify=True)
    st.wait(data.wait)
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in default-vrf domain.")
        result += 1
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1T1P3], states=['Full'], vrf = data.vrf_name[0], addr_family='ipv4'):
        st.error("Failed to form OSPF Neighbourship with the TG port connected to DUT1 in user-vrf domain.")
        result += 1
    res1 = ospfapi.get_ospf_interface_traffic(vars.D1, ospf_links=[vars.D1D2P1], key='lsu_tx', vrf='default')
    res2 = ospfapi.get_ospf_interface_traffic(vars.D1, ospf_links=[vars.D1D2P5], key='lsu_tx', vrf=data.vrf_name[0])
    st.log("Results: {}, {}".format(res1, res2))
    st.wait(25)
    res11 = ospfapi.get_ospf_interface_traffic(vars.D1, ospf_links=[vars.D1D2P1], key='lsu_tx', vrf='default')
    res22 = ospfapi.get_ospf_interface_traffic(vars.D1, ospf_links=[vars.D1D2P5], key='lsu_tx', vrf=data.vrf_name[0])
    st.log("Results: {}, {}".format(res11,res22))

    if (res22[0]-res2[0] in range(1,3)) or (res11[0]-res1[0] in range(1,3)):
        st.log("OSPF LSA packets are forwarding as per the configured retransmit-interval")
    else:
        st.error("OSPF LSA packets are not forwarding as per the configured retransmit-interval")
        result += 1

    if not result:
        st.report_pass("ospf_session_test_pass", "in the retransmit-interval scenario.")
    else:
        st.report_fail("ospf_session_test_fail", "in the retransmit-interval scenario.")


@pytest.mark.ospf_regression
def test_ft_ospf_routing_config_mode():
    """
    Verify OSPF application functionality with Split/Seperated routing config mode
    :return:
    """
    result = 0

    st.banner('FtOtSoRtOspfFn048')
    verify_ospf_sessions(60)
    rebootapi.config_save(vars.D1)
    rebootapi.config_save(vars.D1, shell='vtysh')

    rebootapi.config_warm_restart(vars.D1, oper = "enable")
    protocol = 'ospf' if data.cli_type != 'click' else None
    output = basicapi.get_frr_config(vars.D1, protocol=protocol)

    def_vrf = "network %s area 0.0.0.1\n network %s area 0.0.0.0\n network %s area 0.0.0.0\n network %s area 0.0.0.0\n" % (data.dut1_network_l[0], data.dut1_network_l[4], data.dut1_network_l[5], data.dut1_network_l[6])
    user_vrf = "network %s area 0.0.0.1\n network %s area 0.0.0.0\n network %s area 0.0.0.0\n" % (data.dut1_network_l[2], data.dut1_network_l[7], data.dut1_network_l[8])

    def_vrf_1 = "network %s area 0.0.0.0 \n  network %s area 0.0.0.0 \n  network %s area 0.0.0.0 \n  network %s area 0.0.0.1 \n" % (data.dut1_network_l[4], data.dut1_network_l[5], data.dut1_network_l[6], data.dut1_network_l[0])
    user_vrf_1 = "network %s area 0.0.0.0 \n  network %s area 0.0.0.0 \n  network %s area 0.0.0.1 \n" % (data.dut1_network_l[7], data.dut1_network_l[8], data.dut1_network_l[2])

    if (def_vrf not in output and def_vrf_1 not in output) or (user_vrf not in output and user_vrf_1 not in output):
        st.error("OSPF config is not retained properly in frr.conf file before BGP docker restart")
        st.report_fail("ospf_session_test_fail", "config not retained properly in frr.conf file before BGP docker restart")

    ospf_reboot_device(vars.D1, 'docker')

    st.banner('Verifying the OSPF sessions after docker restart')
    result += verify_ospf_sessions(60)

    output = basicapi.get_frr_config(vars.D1, protocol=protocol)
    if (def_vrf not in output and def_vrf_1 not in output) or (user_vrf not in output and user_vrf_1 not in output):
        st.error("OSPF config is not retained properly in frr.conf file after BGP docker restart")
        st.report_fail("ospf_session_test_fail", "after BGP docker restart, config not retained properly in frr.conf file")

    if not result:
        st.report_pass("ospf_session_test_pass", "config retained properly in frr.conf file")
    else:
        st.report_pass("ospf_session_test_fail", "config not retained properly in frr.conf file")


@pytest.mark.ospf_regression
def test_ft_ospf_warmreboot():
    """
    Verify OSPF application functionality with save and warm-reboot
    Verify OSPF application functionality with save and reboot
    :return:
    """
    result = 0
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 10, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
              states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4', poll_delay=2):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase")
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 10, vars.D1, addr_family='ipv4',
              ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'], vrf='default', poll_delay=2):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase.")

    st.banner('Warm reboot with OSPF-FtOtSoRtOspfFn045')

    # Verify the route learned from D2, in the routing table of DUT1
    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="193.168.0.0/24", interface=vars.D1D2P1):
        st.error("OSPF route {} not shown in RTO.".format("193.168.0.0/24"))
        result += 1

    st.banner('Config reload with OSPF')
    rebootapi.config_save_reload(vars.D1)

    st.banner('Verifying the OSPF sessions after Config reload with OSPF')
    result += verify_ospf_sessions(60)

    rebootapi.config_warm_restart(vars.D1, oper="enable", tasks=["bgp","system","teamd", "swss"])
    rebootapi.verify_warm_restart(vars.D1, mode='config')
    ospf_reboot_device(vars.D1, 'warm')
    st.wait(data.wait)
    rebootapi.verify_warm_restart(vars.D1, mode = 'config')

    st.banner('Verifying the OSPF sessions after Warm reboot')
    result = verify_ospf_sessions(60)

    if not poll_wait(ospfapi.verify_ospf_route, 40, vars.D1, ip_address="193.168.0.0/24", interface=vars.D1D2P1):
        st.error("OSPF route {} not shown in RTO.".format("193.168.0.0/24"))
        result += 1

    if result == 0:
        st.report_pass("ospf_session_test_pass", "with save and reboot and warm reboot")
    else:
        ospfapi.get_ospf_interface_traffic(vars.D1, ospf_links=[vars.D1D2P1], key='lsu_tx')
        st.report_fail("ospf_session_test_fail", "with save and reboot and warm reboot")


@pytest.mark.ospf_regression
def test_ospf_routerid_change():
    """
    Verify OSPF router Id selection
    :return:
    """
    utilsapi.banner_log('FtOtSoRtOspfFn001')

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
              states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase")
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 60, vars.D1, addr_family='ipv4',
              ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'], vrf='default'):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase.")

    result = 0
    lo_ip_list = ['72.72.72.71', '12.12.12.11']

    match = {u'routerid': '6.6.6.5'}
    rid_match = ospfapi.verify_ospf_router_info(vars.D1, 'default', match=match)
    if not rid_match:
        st.error("Configured router-id {} is not choosen as the OSPF router-id.".format("6.6.6.5"))
        st.report_fail("ospf_route_validation_fail", "the changes with the router-id configuration")
        result += 1

    st.banner('Configure the loopback interfaces i.e. loopback interface will have the highest ip address then physical', 130)
    ipapi.configure_loopback(vars.D1, loopback_name='Loopback1')
    ipapi.config_ip_addr_interface(vars.D1, interface_name='Loopback1', ip_address=lo_ip_list[0], subnet='32')
    ipapi.configure_loopback(vars.D1, loopback_name='Loopback2')
    ipapi.config_ip_addr_interface(vars.D1, interface_name='Loopback2', ip_address=lo_ip_list[1], subnet='32')
    ospfapi.config_ospf_network(vars.D1, networks='12.12.12.0/24', vrf='default', area='0.0.0.0')

    rid_match = ospfapi.verify_ospf_router_info(vars.D1, 'default', match=match)
    if not rid_match:
        st.error("Loopback ip is choosen as the OSPF router-id, instead of the configured router-id")
        result += 1

    st.banner('Unconfigure the router-id and do the BGP docker restart')
    ospfapi.config_ospf_router_id(vars.D1, router_id='6.6.6.5', config='no')

    ospf_reboot_device(vars.D1, 'docker')

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 90 , vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1

    match = {u'routerid': lo_ip_list[0]}
    rid_match = ospfapi.verify_ospf_router_info(vars.D1, 'default', match=match)
    if not rid_match:
        st.error("Loopback ip is not choosen as the OSPF router-id when router-id configuration is present,as its higher than physical ip addresses.")
        result += 1

    st.banner('Remove the loopback interfaces')
    ipapi.configure_loopback(vars.D1, loopback_name='Loopback1', config='no')
    ipapi.configure_loopback(vars.D1, loopback_name='Loopback2', config='no')

    ospf_reboot_device(vars.D1, 'docker')

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 90 , vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1

    match = {u'routerid': data.dut1_dut2_ip4_addr_l[2]}
    rid_match = ospfapi.verify_ospf_router_info(vars.D1, 'default', match=match)
    if not rid_match:
        st.error("Highest ip address is not choosen as the OSPF router-id when router-id/loopback ip configuration is not there on the DUT.")
        result += 1

    st.banner('Verify default ospf router-id with docker restart')
    ospfapi.config_ospf_router_id(vars.D1, router_id='6.6.6.5', config='yes')

    ospf_reboot_device(vars.D1, 'docker')

    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 90 , vars.D1, ospf_links=[vars.D1D2P1], states=['Full'], vrf = 'default', addr_family='ipv4'):
        st.error("OSPF neighbourship with the default vrf on port based routing interface is failed.")
        result += 1

    match = {u'routerid': '6.6.6.5'}
    rid_match = ospfapi.verify_ospf_router_info(vars.D1, 'default', match=match)
    if not rid_match:
        st.error("Configured router-id {} is not choosen as the OSPF router-id.".format("6.6.6.5"))
        result += 1

    if result == 0:
        st.report_pass("ospf_session_test_pass", "the changes with the router-id configuration.")
    else:
        st.report_fail("ospf_session_test_fail", "the changes with the router-id configuration")


@pytest.mark.ospf_regression
def test_ospf_max_metric_router_lsa_verify():
    """
    Verify OPSF max-metric router-lsa functionality
    :return:
    """

    utilsapi.banner_log('FtOtSoRtOspfFn026')
    res = 0
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 20, vars.D1, ospf_links=[vars.D1D2P5, data.vlan_in_2],
              states=['Full'], vrf=data.vrf_name[0], addr_family='ipv4'):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase")
    if not poll_wait(ospfapi.verify_ospf_neighbor_state, 20, vars.D1, addr_family='ipv4',
              ospf_links=[vars.D1D2P1, data.vlan_in_1, data.port_channel], states=['Full'], vrf='default'):
        st.report_fail("ospf_session_test_fail", "OSPF sessions not up at start of the testcase.")

    metric_value = {'administrative': '', 'on-startup': '720', 'on-shutdown': '60'}

    data.my_dut_list = [vars.D1, vars.D2]
    for metric_type in ['administrative', 'on-startup', 'on-shutdown']:
        if st.get_ui_type(cli_type='') in ['klish', "rest-patch", "rest-put"] and metric_type == 'on-shutdown':
            st.log('max-metric on-shutdown will not be supported in Klish Mode.')
            continue
        result = 0
        st.banner("Test for max-metric router-lsa {}".format(metric_type))
        dict1 = {'mmetric_type': metric_type, 'mmetric_value': metric_value[metric_type], 'vrf': 'default',
                 'config': 'yes'}
        dict2 = {'mmetric_type': metric_type, 'mmetric_value': metric_value[metric_type], 'vrf': data.vrf_name[0],
                 'config': 'yes'}

        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_max_metric, [dict1, dict2])

        if metric_type == 'on-startup':
            ospf_reboot_device(data.my_dut_list, 'fast')
            result += verify_ospf_sessions(90)

        if metric_type == 'on-shutdown':
            parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router, [{'vrf': 'default', 'config':'no'}, {'vrf': data.vrf_name[0], 'config':'no'}])

        for interface in data.dut1_dut2_ip4_addr_l[:3]:
            if not poll_wait(ospfapi.verify_ospf_database, 10, vars.D2, lsdb_type='router', vrf='default', addr_family='ipv4',key_name='linkdata', key_value_list=[interface], match={'tosmetric': '65535'}, poll_delay=2):
                st.error("OSPF route {} not shown in ospf lsdb.".format(interface))
                result += 1

        for interface in data.dut2_dut1_ip4_addr_l[3:]:
            if not poll_wait(ospfapi.verify_ospf_database, 10, vars.D1, lsdb_type='router', vrf=data.vrf_name[0], addr_family='ipv4',key_name='linkdata', key_value_list=[interface], match={'tosmetric': '65535'}, poll_delay=2):
                st.error("OSPF route {} not shown in ospf lsdb.".format(interface))
                result += 1

        if metric_type == 'on-shutdown':
            st.banner('Configure Router-id for default and non default vrfs')
            dict1 = {'router_id': data.dut1_rid, 'vrf': 'default'}
            dict2 = {'router_id': data.dut2_rid, 'vrf': data.vrf_name[0]}
            parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_id, [dict1, dict2])

            st.banner('Configure the ospf config, to bringup the module config')
            dict1 = {'networks': [data.dut1_network_l[4], data.dut1_network_l[5], data.dut1_network_l[6]],
                     'area': '0.0.0.0', 'vrf': 'default', 'config': 'yes'}
            dict2 = {'networks': [data.dut1_network_l[7], data.dut1_network_l[8]], 'area': '0.0.0.0',
                     'vrf': data.vrf_name[0], 'config': 'yes'}
            parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_network, [dict1, dict2])

            parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf,
                                   [{'route_type': 'static'}, {'route_type': 'static', 'vrf_name': data.vrf_name[0]}])
            parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf,
                                   [{'route_type': 'connected'}, {'route_type': 'connected', 'vrf_name': data.vrf_name[0]}])
            parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf,
                                   [{'route_type': 'kernel'}, {'route_type': 'kernel', 'vrf_name': data.vrf_name[0]}])
            parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.redistribute_into_ospf,
                                   [{'route_type': 'bgp'}, {'route_type': 'bgp', 'vrf_name': data.vrf_name[0]}])
            result += verify_ospf_sessions(40)

        dict1 = {'mmetric_type': metric_type, 'mmetric_value': metric_value[metric_type], 'vrf': 'default', 'config': 'no'}
        dict2 = {'mmetric_type': metric_type, 'mmetric_value': metric_value[metric_type], 'vrf': data.vrf_name[0], 'config': 'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], ospfapi.config_ospf_router_max_metric, [dict1, dict2])

        if result:
            res += 1
            st.banner("Test failed for max-metric router-lsa {}".format(metric_type))
            break

    if not res:
        st.report_pass("ospf_session_test_pass", "in the max-metric router-lsa scenario.")
    else:
        st.report_fail("ospf_session_test_fail", "in the max-metric router-lsa scenario.")

