#################################################################################
#Script Title : VRF Lite
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

#################################################################################

from spytest import st,utils

from vrf_vars import * #all the variables used for vrf testcases
from vrf_vars import data
from utilities import parallel

import apis.switching.portchannel as pc_api
import apis.switching.vlan as vlan_api

import apis.routing.ip as ip_api
import apis.routing.vrf as vrf_api
import apis.routing.bgp as bgp_api

from spytest.tgen.tgen_utils import validate_tgen_traffic, tg_bgp_config


def vrf_base_config():
    vrf_config()
    tg_vrf_bind()
    dut_vrf_bind(phy = '1')
    dut_vrf_bind(ve = '1')
    dut_vrf_bind(pc = '1')
    ip_api.config_route_map_global_nexthop(data.dut1, 'UseGlobal', type = 'next_hop_v6', config = 'yes')
    ip_api.config_route_map_global_nexthop(data.dut2, 'UseGlobal', type = 'next_hop_v6', config = 'yes')
    dut_vrf_bgp(phy = '1')
    dut_vrf_bgp(ve = '1')
    dut_vrf_bgp(pc = '1')
    tg_vrf_bgp(phy = '1')
    tg_vrf_bgp(ve = '1')
    tg_vrf_bgp(pc = '1')
    # import pdb; pdb.set_trace()
    # import code; code.interact(local=globals())
    tg_interfaces(phy = '1')
    tg_interfaces(ve = '1')
    tg_interfaces(pc = '1')
    start_arp_nd()
    pump_bgp_routes(dut = data.dut1, ip = 'ipv4', vlan = dut1_tg1_vlan[0])
    pump_bgp_routes(dut = data.dut1, ip = 'ipv6', vlan = dut1_tg1_vlan[0])
    pump_bgp_routes(dut = data.dut1, ip = 'ipv4', vlan = dut1_tg1_vlan[1])
    pump_bgp_routes(dut = data.dut1, ip = 'ipv6', vlan = dut1_tg1_vlan[1])
    pump_bgp_routes(dut = data.dut1, ip = 'ipv4', vlan = dut1_tg1_vlan[2])
    pump_bgp_routes(dut = data.dut1, ip = 'ipv6', vlan = dut1_tg1_vlan[2])
    create_streams_all_vrf(todut = data.dut1)

def vrf_base_unconfig():
    ip_api.config_route_map_global_nexthop(data.dut1, 'UseGlobal', type = 'next_hop_v6', config = 'no')
    ip_api.config_route_map_global_nexthop(data.dut2, 'UseGlobal', type = 'next_hop_v6', config = 'no')
    dut_vrf_bgp(phy = '1', config = 'no')
    dut_vrf_bgp(ve = '1', config = 'no')
    dut_vrf_bgp(pc = '1', config = 'no')
    dut_vrf_bind(phy = '1', config = 'no')
    dut_vrf_bind(ve = '1', config = 'no')
    dut_vrf_bind(pc = '1', config = 'no')
    tg_vrf_bind(config = 'no')
    vrf_config(config = 'no')

    data.tg1.tg_traffic_control(action = 'reset', port_handle = data.tg_dut1_p1)
    data.tg2.tg_traffic_control(action = 'reset', port_handle = data.tg_dut2_p1)

    data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, handle=data.d1_p1_intf_v4.get('1')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, handle=data.d1_p1_intf_v4.get('2')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, handle=data.d1_p1_intf_v4.get('3')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, handle=data.d1_p1_intf_v6.get('1')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, handle=data.d1_p1_intf_v6.get('2')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, handle=data.d1_p1_intf_v6.get('3')['handle'], mode='destroy')

    data.tg1.tg_interface_config(port_handle = data.tg_dut2_p1, handle=data.d2_p1_intf_v4.get('6')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut2_p1, handle=data.d2_p1_intf_v4.get('7')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut2_p1, handle=data.d2_p1_intf_v4.get('8')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut2_p1, handle=data.d2_p1_intf_v6.get('6')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut2_p1, handle=data.d2_p1_intf_v6.get('7')['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle = data.tg_dut2_p1, handle=data.d2_p1_intf_v6.get('8')['handle'], mode='destroy')

def debug_bgp_vrf():
    st.log("Dubug commands starts!")
    cmd_list = ['show ip route vrf Vrf-101','show ip route vrf Vrf-102','show ip route vrf Vrf-103','show ipv6 route vrf Vrf-101','show ipv6 route vrf Vrf-102','show ipv6 route vrf Vrf-103','show arp','show ndp']
    utils.exec_all(True, [[st.apply_script, data.dut1, cmd_list], [st.apply_script, data.dut2, cmd_list]])
    st.log(" End of Dubug commands")

def vrf_config(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        st.log('######------Configure vrfs ------######')
        for vrf in vrf_name[0:3]:
            dict1 = {'vrf_name':vrf,'skip_error':True}
            parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.config_vrf, [dict1, dict1])
    else:
        st.log('######------Unconfigure vrfs ------######')
        for vrf in vrf_name[0:3]:
            dict1 = {'vrf_name':vrf,'skip_error':True,'config':'no'}
            parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.config_vrf, [dict1, dict1])

def tg_vrf_bind(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        st.log('######------Configure vlans on the PE--CE side -------######')
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, dut1_tg1_vlan[0]], [vlan_api.create_vlan, data.dut2, dut2_tg1_vlan[0]]])
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, dut1_tg1_vlan[1]], [vlan_api.create_vlan, data.dut2, dut2_tg1_vlan[1]]])
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, dut1_tg1_vlan[2]], [vlan_api.create_vlan, data.dut2, dut2_tg1_vlan[2]]])

        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_tg1_vlan[0],data.dut1_tg1_ports[0],True,True], [vlan_api.add_vlan_member,data.dut2,dut2_tg1_vlan[0],data.dut2_tg1_ports[0],True,True]])
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_tg1_vlan[1],data.dut1_tg1_ports[0],True,True], [vlan_api.add_vlan_member,data.dut2,dut2_tg1_vlan[1],data.dut2_tg1_ports[0],True,True]])
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_tg1_vlan[2],data.dut1_tg1_ports[0],True,True], [vlan_api.add_vlan_member,data.dut2,dut2_tg1_vlan[2],data.dut2_tg1_ports[0],True,True]])

        st.log('######------Bind DUT1 <--> tg1 vlans to vrf------######')
        dict1 = {'vrf_name':vrf_name[0], 'intf_name':'Vlan'+dut1_tg1_vlan[0],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[0], 'intf_name':'Vlan'+dut2_tg1_vlan[0],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_tg1_vlan[1],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_tg1_vlan[1],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
        dict1 = {'vrf_name':vrf_name[2], 'intf_name':'Vlan'+dut1_tg1_vlan[2],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[2], 'intf_name':'Vlan'+dut2_tg1_vlan[2],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        st.log('######------Assign v4 addresses to vrf bound tg vlans------######')
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ip[0],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[1],dut1_tg1_vrf_ip[1],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[1], dut2_tg1_vrf_ip[1], dut2_tg1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[2],dut1_tg1_vrf_ip[2],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[2], dut2_tg1_vrf_ip[2], dut2_tg1_vrf_ip_subnet, 'ipv4']])

        st.log('######------Assign v6 addresses to vrf bound tg vlans------######')
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ipv6[0],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[1],dut1_tg1_vrf_ipv6[1],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[1], dut2_tg1_vrf_ipv6[1], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_tg1_vlan[2],dut1_tg1_vrf_ipv6[2],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[2], dut2_tg1_vrf_ipv6[2], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])
    else:
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ip[0],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ip[0], dut2_tg1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[1],dut1_tg1_vrf_ip[1],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[1], dut2_tg1_vrf_ip[1], dut2_tg1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[2],dut1_tg1_vrf_ip[2],dut1_tg1_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[2], dut2_tg1_vrf_ip[2], dut2_tg1_vrf_ip_subnet, 'ipv4']])

        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[0],dut1_tg1_vrf_ipv6[0],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[0], dut2_tg1_vrf_ipv6[0], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[1],dut1_tg1_vrf_ipv6[1],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[1], dut2_tg1_vrf_ipv6[1], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_tg1_vlan[2],dut1_tg1_vrf_ipv6[2],dut1_tg1_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_tg1_vlan[2], dut2_tg1_vrf_ipv6[2], dut2_tg1_vrf_ipv6_subnet, 'ipv6']])

        st.log('######------Bind DUT1 <--> tg1 vlans to vrf------######')
        dict1 = {'vrf_name':vrf_name[0], 'intf_name':'Vlan'+dut1_tg1_vlan[0],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[0], 'intf_name':'Vlan'+dut2_tg1_vlan[0],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_tg1_vlan[1],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_tg1_vlan[1],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])
        dict1 = {'vrf_name':vrf_name[2], 'intf_name':'Vlan'+dut1_tg1_vlan[2],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[2], 'intf_name':'Vlan'+dut2_tg1_vlan[2],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        st.log('######------Unconfigure vlans on the PE--CE side -------######')
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_tg1_vlan[0],data.dut1_tg1_ports[0], True], [vlan_api.delete_vlan_member,data.dut2,dut2_tg1_vlan[0],data.dut2_tg1_ports[0], True]])
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_tg1_vlan[1],data.dut1_tg1_ports[0], True], [vlan_api.delete_vlan_member,data.dut2,dut2_tg1_vlan[1],data.dut2_tg1_ports[0], True]])
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_tg1_vlan[2],data.dut1_tg1_ports[0], True], [vlan_api.delete_vlan_member,data.dut2,dut2_tg1_vlan[2],data.dut2_tg1_ports[0], True]])

        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, dut1_tg1_vlan[0]], [vlan_api.delete_vlan, data.dut2, dut2_tg1_vlan[0]]])
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, dut1_tg1_vlan[1]], [vlan_api.delete_vlan, data.dut2, dut2_tg1_vlan[1]]])
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, dut1_tg1_vlan[2]], [vlan_api.delete_vlan, data.dut2, dut2_tg1_vlan[2]]])

def dut_vrf_bind(**kwargs):
    if 'phy' in kwargs:
        phy = kwargs['phy']
    else:
        phy = ''
    if 've' in kwargs:
        ve = kwargs['ve']
    else:
        ve = ''
    if 'pc' in kwargs:
        pc = kwargs['pc']
    else:
        pc = ''
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if phy != '' and config == '':
        st.log('######------Bind DUT1 <--> DUT2 one physical interface to vrf-101 and config v4 and v6 addresses------######')
        dict1 = {'vrf_name':vrf_name[0], 'intf_name':data.d1_dut_ports[0],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[0], 'intf_name':data.d2_dut_ports[0],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

        st.log('######------Bind loopback101 to vrf------######')
        dict1 = {'vrf_name':vrf_name[0], 'intf_name':dut1_loopback[0],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[0], 'intf_name':dut2_loopback[0],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[0],dut1_loopback_ip[0],dut1_loopback_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[0],dut2_loopback_ip[0],dut2_loopback_ip_subnet,'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[0],dut1_loopback_ipv6[0],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[0],dut2_loopback_ipv6[0],dut2_loopback_ipv6_subnet,'ipv6']])
    elif phy != '' and config == 'no':
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,data.d1_dut_ports[0],dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,data.d2_dut_ports[0], dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[0],dut1_loopback_ip[0],dut1_loopback_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[0],dut2_loopback_ip[0],dut2_loopback_ip_subnet,'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[0],dut1_loopback_ipv6[0],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[0],dut2_loopback_ipv6[0],dut2_loopback_ipv6_subnet,'ipv6']])

        st.log('######------Unbind DUT1 <--> DUT2 one physical interface from vrf-101------######')
        dict1 = {'vrf_name':vrf_name[0], 'intf_name':data.d1_dut_ports[0],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[0], 'intf_name':data.d2_dut_ports[0],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        st.log('######------Unbind loopback101 to vrf------######')
        dict1 = {'vrf_name':vrf_name[0],'intf_name':dut1_loopback[0],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[0],'intf_name':dut2_loopback[0],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

    if ve != ''  and config == '':
        st.log('######------Configure vlans on the PE--PE side - DUT1 -- DUT2------######')
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, dut1_dut2_vlan[0]], [vlan_api.create_vlan, data.dut2, dut2_dut1_vlan[0]]])
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, dut1_dut2_vlan[1]], [vlan_api.create_vlan, data.dut2, dut2_dut1_vlan[1]]])
        utils.exec_all(True, [[vlan_api.create_vlan, data.dut1, dut1_dut2_vlan[2]], [vlan_api.create_vlan, data.dut2, dut2_dut1_vlan[2]]])

        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_dut2_vlan[0],data.d1_dut_ports[1],True,True], [vlan_api.add_vlan_member,data.dut2,dut2_dut1_vlan[0],data.d2_dut_ports[1],True,True]])
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_dut2_vlan[1],data.d1_dut_ports[1],True,True], [vlan_api.add_vlan_member,data.dut2,dut2_dut1_vlan[1],data.d2_dut_ports[1],True,True]])
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_dut2_vlan[2],data.d1_dut_ports[1],True,True], [vlan_api.add_vlan_member,data.dut2,dut2_dut1_vlan[2],data.d2_dut_ports[1],True,True]])

        st.log('######------Bind DUT1 <--> DUT2 vlans to vrf------######')
        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_dut2_vlan[0],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_dut1_vlan[0],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_dut2_vlan[1],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_dut1_vlan[1],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_dut2_vlan[2],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_dut1_vlan[2],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_dut2_vlan[0],dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[0], dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_dut2_vlan[1],dut1_dut2_vrf_ip[1],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[1], dut2_dut1_vrf_ip[1], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_dut2_vlan[2],dut1_dut2_vrf_ip[2],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[2], dut2_dut1_vrf_ip[2], dut2_dut1_vrf_ip_subnet, 'ipv4']])

        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_dut2_vlan[0],dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[0], dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_dut2_vlan[1],dut1_dut2_vrf_ipv6[1],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[1], dut2_dut1_vrf_ipv6[1], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'Vlan'+dut1_dut2_vlan[2],dut1_dut2_vrf_ipv6[2],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[2], dut2_dut1_vrf_ipv6[2], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

        st.log('######------Bind loopback102 to vrf------######')
        dict1 = {'vrf_name':vrf_name[1], 'intf_name':dut1_loopback[1],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':dut2_loopback[1],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[1],dut1_loopback_ip[1],dut1_loopback_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[1],dut2_loopback_ip[1],dut2_loopback_ip_subnet,'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[1],dut1_loopback_ipv6[1],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[1],dut2_loopback_ipv6[1],dut2_loopback_ipv6_subnet,'ipv6']])
    elif ve != '' and config == 'no':
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_dut2_vlan[0],dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[0], dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_dut2_vlan[1],dut1_dut2_vrf_ip[1],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[1], dut2_dut1_vrf_ip[1], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_dut2_vlan[2],dut1_dut2_vrf_ip[2],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[2], dut2_dut1_vrf_ip[2], dut2_dut1_vrf_ip_subnet, 'ipv4']])

        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_dut2_vlan[0],dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[0], dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_dut2_vlan[1],dut1_dut2_vrf_ipv6[1],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[1], dut2_dut1_vrf_ipv6[1], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'Vlan'+dut1_dut2_vlan[2],dut1_dut2_vrf_ipv6[2],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'Vlan'+dut2_dut1_vlan[2], dut2_dut1_vrf_ipv6[2], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[1],dut1_loopback_ip[1],dut1_loopback_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[1],dut2_loopback_ip[1],dut2_loopback_ip_subnet,'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[1],dut1_loopback_ipv6[1],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[1],dut2_loopback_ipv6[1],dut2_loopback_ipv6_subnet,'ipv6']])
        st.log('######------Unbind loopback102 to vrf------######')
        dict1 = {'vrf_name':vrf_name[1],'intf_name':dut1_loopback[1],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[1],'intf_name':dut2_loopback[1],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        st.log('######------Unbind DUT1 <--> DUT2 vlans to vrf, , assign v4 and v6 address------######')
        st.log('######------Bind DUT1 <--> DUT2 vlans to vrf------######')
        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_dut2_vlan[0],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_dut1_vlan[0],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_dut2_vlan[1],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_dut1_vlan[1],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut1_dut2_vlan[2],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[1], 'intf_name':'Vlan'+dut2_dut1_vlan[2],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        st.log('######------Delete vlans on the PE--PE side - DUT1 -- DUT2------######')
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_dut2_vlan[0],data.d1_dut_ports[1], True], [vlan_api.delete_vlan_member,data.dut2,dut2_dut1_vlan[0],data.d2_dut_ports[1], True]])
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_dut2_vlan[1],data.d1_dut_ports[1], True], [vlan_api.delete_vlan_member,data.dut2,dut2_dut1_vlan[1],data.d2_dut_ports[1], True]])
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_dut2_vlan[2],data.d1_dut_ports[1], True], [vlan_api.delete_vlan_member,data.dut2,dut2_dut1_vlan[2],data.d2_dut_ports[1], True]])

        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, dut1_dut2_vlan[0]], [vlan_api.delete_vlan, data.dut2, dut2_dut1_vlan[0]]])
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, dut1_dut2_vlan[1]], [vlan_api.delete_vlan, data.dut2, dut2_dut1_vlan[1]]])
        utils.exec_all(True, [[vlan_api.delete_vlan, data.dut1, dut1_dut2_vlan[2]], [vlan_api.delete_vlan, data.dut2, dut2_dut1_vlan[2]]])

    if pc != '' and config == '':
        st.log('######------Create a port channel on the DUTs and add members------######')
        utils.exec_all(True, [[pc_api.create_portchannel, data.dut1, 'PortChannel10'], [pc_api.create_portchannel, data.dut2, 'PortChannel10']])
        utils.exec_all(True, [[pc_api.add_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[2]], [pc_api.add_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[2]]])
        utils.exec_all(True, [[pc_api.add_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[3]], [pc_api.add_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[3]]])

        st.log('######------Bind DUT1 <--> DUT2 port channel to vrf and config IP addresses------######')
        dict1 = {'vrf_name':vrf_name[2], 'intf_name':'PortChannel10','skip_error':True}
        dict2 = {'vrf_name':vrf_name[2], 'intf_name':'PortChannel10','skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

        st.log('######------Bind loopback103 to vrf------######')
        dict1 = {'vrf_name':vrf_name[2], 'intf_name':dut1_loopback[2],'skip_error':True}
        dict2 = {'vrf_name':vrf_name[2], 'intf_name':dut2_loopback[2],'skip_error':True}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[2],dut1_loopback_ip[2],dut1_loopback_ip_subnet,'ipv4'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[2],dut2_loopback_ip[2],dut2_loopback_ip_subnet,'ipv4']])
        utils.exec_all(True,[[ip_api.config_ip_addr_interface,data.dut1,dut1_loopback[2],dut1_loopback_ipv6[2],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.config_ip_addr_interface,data.dut2,dut2_loopback[2],dut2_loopback_ipv6[2],dut2_loopback_ipv6_subnet,'ipv6']])
    elif pc != '' and config == 'no':
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ip[0],dut1_dut2_vrf_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ip[0], dut2_dut1_vrf_ip_subnet, 'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,'PortChannel10',dut1_dut2_vrf_ipv6[0],dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2, 'PortChannel10', dut2_dut1_vrf_ipv6[0], dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[2],dut1_loopback_ip[2],dut1_loopback_ip_subnet,'ipv4'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[2],dut2_loopback_ip[2],dut2_loopback_ip_subnet,'ipv4']])
        utils.exec_all(True,[[ip_api.delete_ip_interface,data.dut1,dut1_loopback[2],dut1_loopback_ipv6[2],dut1_loopback_ipv6_subnet,'ipv6'], [ip_api.delete_ip_interface,data.dut2,dut2_loopback[2],dut2_loopback_ipv6[2],dut2_loopback_ipv6_subnet,'ipv6']])

        st.log('######------Unbind loopback103 to vrf------######')
        dict1 = {'vrf_name':vrf_name[2],'intf_name':dut1_loopback[2],'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[2],'intf_name':dut2_loopback[2],'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        st.log('######------Unbind DUT1 <--> DUT2 physical interfaces to vrf and config v4 and v6 addresses------######')
        dict1 = {'vrf_name':vrf_name[2], 'intf_name':'PortChannel10','skip_error':True,'config':'no'}
        dict2 = {'vrf_name':vrf_name[2], 'intf_name':'PortChannel10','skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

        st.log('######------Delete the member port and port-channel------######')
        utils.exec_all(True, [[pc_api.add_del_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[2],'del'], [pc_api.add_del_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[2],'del']])
        utils.exec_all(True, [[pc_api.add_del_portchannel_member, data.dut1, 'PortChannel10',data.d1_dut_ports[3],'del'], [pc_api.add_del_portchannel_member, data.dut2, 'PortChannel10',data.d2_dut_ports[3],'del']])
        utils.exec_all(True, [[pc_api.delete_portchannel, data.dut1, 'PortChannel10'], [pc_api.delete_portchannel, data.dut2, 'PortChannel10']])

def verify_vrf_bind(**kwargs):
    if 'phy' in kwargs:
        phy = kwargs['phy']
    else:
        phy = ''
    if 've' in kwargs:
        ve = kwargs['ve']
    else:
        ve = ''
    if 'pc' in kwargs:
        pc = kwargs['pc']
    else:
        pc = ''
    if phy != '':
        result = vrf_api.verify_vrf_verbose(data.dut1, vrfname = vrf_name[0], interface = [data.d1_dut_ports[0],'Vlan1'])
        if result is False:
            st.report_fail('vrf_bind','Vlan1',vrf_name[0])
        result = vrf_api.verify_vrf_verbose(data.dut1, vrfname = vrf_name[0], interface = [data.d1_dut_ports[0]])
        if result is False:
            st.report_fail('vrf_bind',data.d1_dut_ports[0],vrf_name[0])
        result = ip_api.verify_interface_ip_address(data.dut1, data.d1_dut_ports[0],dut1_dut2_vrf_ip[0]+'/24', vrfname = vrf_name[0])
        if result is False:
            st.report_fail('vrf_bind',data.d1_dut_ports[0],vrf_name[0])
        result = ip_api.verify_interface_ip_address(data.dut1, data.d1_dut_ports[0],dut1_dut2_vrf_ipv6[0]+'/64', vrfname = vrf_name[0])
        if result is False:
            st.report_fail('vrf_bind',data.d1_dut_ports[0],vrf_name[0])
        return result
    if pc != '':
        result = vrf_api.verify_vrf_verbose(data.dut1, vrfname = vrf_name[2], interface = ['Vlan3'])
        if result is False:
            st.report_fail('vrf_bind','Vlan3',vrf_name[2])
        result = vrf_api.verify_vrf_verbose(data.dut1, vrfname = vrf_name[2], interface = ['PortChannel10'])
        if result is False:
            st.report_fail('vrf_bind','PortChannel10',vrf_name[2])
        result = ip_api.verify_interface_ip_address(data.dut1, 'PortChannel10',dut1_dut2_vrf_ip[0]+'/24', vrfname = vrf_name[2])
        if result is False:
            st.report_fail('vrf_bind','PortChannel10',vrf_name[2])
        result = ip_api.verify_interface_ip_address(data.dut1, 'PortChannel10',dut1_dut2_vrf_ipv6[0]+'/64', vrfname = vrf_name[2])
        if result is False:
            st.report_fail('vrf_bind','PortChannel10',vrf_name[2])
        return result
    if ve != '':
        result = ip_api.verify_interface_ip_address(data.dut1, 'Vlan2', dut1_tg1_vrf_ipv6[1]+'/64', vrfname = vrf_name[1], family = 'ipv6')
        if result is False:
            st.report_fail('vrf_bind','Vlan2',vrf_name[1])
        result = vrf_api.verify_vrf_verbose(data.dut1, vrfname = vrf_name[1], interface = 'Vlan101')
        if result is False:
            st.report_fail('vrf_bind','Vlan101',vrf_name[1])
        result = ip_api.verify_interface_ip_address(data.dut1, 'Vlan101',dut1_dut2_vrf_ip[0]+'/24', vrfname = vrf_name[1])
        if result is False:
            st.report_fail('vrf_bind','Vlan101',vrf_name[1])
        result = ip_api.verify_interface_ip_address(data.dut1, 'Vlan102',dut1_dut2_vrf_ip[0]+'/24', vrfname = vrf_name[1])
        if result is False:
            st.report_fail('vrf_bind','Vlan102',vrf_name[1])
        return result

def dut_vrf_bgp(**kwargs):
    if 'phy' in kwargs:
        phy = kwargs['phy']
    else:
        phy = ''
    if 've' in kwargs:
        ve = kwargs['ve']
    else:
        ve = ''
    if 'pc' in kwargs:
        pc = kwargs['pc']
    else:
        pc = ''
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if phy != '' and config == '':
        st.log('######------Configure BGP in vrf--######')
        dict1 = {'vrf_name':vrf_name[0],'router_id':dut1_router_id,'local_as':dut1_as[0],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[0],'config_type_list':['neighbor']}
        dict2 = {'vrf_name':vrf_name[0],'router_id':dut2_router_id,'local_as':dut2_as[0],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[0],'config_type_list':['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[0],'local_as':dut1_as[0],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[0],'config_type_list':['activate','nexthop_self']}
        dict2 = {'vrf_name':vrf_name[0],'local_as':dut2_as[0],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[0],'config_type_list':['activate','nexthop_self']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        st.log('######------Configure BGPv4+ in vrf ------######')
        dict1 = {'vrf_name':vrf_name[0],'router_id':dut1_router_id,'local_as':dut1_as[0],'addr_family':'ipv6','neighbor':dut2_dut1_vrf_ipv6[0],'remote_as':dut2_as[0],'config_type_list':['neighbor']}
        dict2 = {'vrf_name':vrf_name[0],'router_id':dut2_router_id,'local_as':dut2_as[0],'addr_family':'ipv6','neighbor':dut1_dut2_vrf_ipv6[0],'remote_as':dut1_as[0],'config_type_list':['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[0],'local_as':dut1_as[0],'addr_family':'ipv6','neighbor':dut2_dut1_vrf_ipv6[0],'remote_as':dut2_as[0],'config_type_list':['activate','nexthop_self']}
        dict2 = {'vrf_name':vrf_name[0],'local_as':dut2_as[0],'addr_family':'ipv6','neighbor':dut1_dut2_vrf_ipv6[0],'remote_as':dut1_as[0],'config_type_list':['activate','nexthop_self']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[0], local_as = dut1_as[0], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    elif phy != '' and config == 'no':
        dict1 = {'vrf_name':vrf_name[0],'local_as':dut1_as[0],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'vrf_name':vrf_name[0],'local_as':dut2_as[0],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    if ve != '' and config == '':
        st.log('######------Configure BGP in vrf--######')
        dict1 = {'vrf_name':vrf_name[1],'router_id':dut1_router_id,'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
        dict2 = {'vrf_name':vrf_name[1],'router_id':dut2_router_id,'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[1],'config_type_list':['activate','nexthop_self']}
        dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[1],'config_type_list':['activate','nexthop_self']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        st.log('######------Configure BGPv4+ in vrf ------######')
        dict1 = {'vrf_name':vrf_name[1],'router_id':dut1_router_id,'local_as':dut1_as[1],'addr_family':'ipv6','neighbor':dut2_dut1_vrf_ipv6[0],'remote_as':dut2_as[1],'config_type_list':['neighbor']}
        dict2 = {'vrf_name':vrf_name[1],'router_id':dut2_router_id,'local_as':dut2_as[1],'addr_family':'ipv6','neighbor':dut1_dut2_vrf_ipv6[0],'remote_as':dut1_as[1],'config_type_list':['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'addr_family':'ipv6','neighbor':dut2_dut1_vrf_ipv6[0],'remote_as':dut2_as[1],'config_type_list':['activate','nexthop_self']}
        dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'addr_family':'ipv6','neighbor':dut1_dut2_vrf_ipv6[0],'remote_as':dut1_as[1],'config_type_list':['activate','nexthop_self']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    elif ve != '' and config == 'no':
        dict1 = {'vrf_name':vrf_name[1],'local_as':dut1_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'vrf_name':vrf_name[1],'local_as':dut2_as[1],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

    if pc != '' and config == '':
        st.log('######------Configure BGP in vrf--######')
        dict1 = {'vrf_name':vrf_name[2],'router_id':dut1_router_id,'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[2],'config_type_list':['neighbor']}
        dict2 = {'vrf_name':vrf_name[2],'router_id':dut2_router_id,'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[2],'config_type_list':['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[2],'local_as':dut1_as[2],'neighbor':dut2_dut1_vrf_ip[0],'remote_as':dut2_as[2],'config_type_list':['activate','nexthop_self']}
        dict2 = {'vrf_name':vrf_name[2],'local_as':dut2_as[2],'neighbor':dut1_dut2_vrf_ip[0],'remote_as':dut1_as[2],'config_type_list':['activate','nexthop_self']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        st.log('######------Configure BGPv4+ in vrf ------######')
        dict1 = {'vrf_name':vrf_name[2],'router_id':dut1_router_id,'local_as':dut1_as[2],'addr_family':'ipv6','neighbor':dut2_dut1_vrf_ipv6[0],'remote_as':dut2_as[2],'config_type_list':['neighbor']}
        dict2 = {'vrf_name':vrf_name[2],'router_id':dut2_router_id,'local_as':dut2_as[2],'addr_family':'ipv6','neighbor':dut1_dut2_vrf_ipv6[0],'remote_as':dut1_as[2],'config_type_list':['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        dict1 = {'vrf_name':vrf_name[2],'local_as':dut1_as[2],'addr_family':'ipv6','neighbor':dut2_dut1_vrf_ipv6[0],'remote_as':dut2_as[2],'config_type_list':['activate','nexthop_self']}
        dict2 = {'vrf_name':vrf_name[2],'local_as':dut2_as[2],'addr_family':'ipv6','neighbor':dut1_dut2_vrf_ipv6[0],'remote_as':dut1_as[2],'config_type_list':['activate','nexthop_self']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        bgp_api.config_bgp(dut = data.dut2, vrf_name = vrf_name[2], local_as = dut1_as[2], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=dut1_dut2_vrf_ipv6[0])
    elif pc != '' and config == 'no':
        dict1 = {'vrf_name':vrf_name[2],'local_as':dut1_as[2],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'vrf_name':vrf_name[2],'local_as':dut2_as[2],'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

def verify_bgp(**kwargs):
    if 'phy' in kwargs:
        phy = kwargs['phy']
    else:
        phy = ''
    if 've' in kwargs:
        ve = kwargs['ve']
    else:
        ve = ''
    if 'pc' in kwargs:
        pc = kwargs['pc']
    else:
        pc = ''
    if 'ip' in kwargs:
        ip = kwargs['ip']

    if ip == 'ipv4':
        if phy != '':
            result = bgp_api.verify_bgp_summary(data.dut1, family='ipv4', neighbor = dut2_dut1_vrf_ip[0], state='Established',vrf = vrf_name[0])
            return result
        if ve != '':
            result = bgp_api.verify_bgp_summary(data.dut1, family='ipv4', neighbor = dut2_dut1_vrf_ip[0], state='Established',vrf = vrf_name[1])
            return result
        if pc != '':
            result = bgp_api.verify_bgp_summary(data.dut1, family='ipv4', neighbor = dut2_dut1_vrf_ip[0], state='Established',vrf = vrf_name[2])
            return result
    else:
        if phy != '':
            result = bgp_api.verify_bgp_summary(data.dut1, family='ipv6', neighbor = dut2_dut1_vrf_ipv6[0], state='Established',vrf = vrf_name[0])
            return result
        if ve != '':
            result = bgp_api.verify_bgp_summary(data.dut1, family='ipv6', neighbor = dut2_dut1_vrf_ipv6[0], state='Established',vrf = vrf_name[1])
            return result
        if pc != '':
            result = bgp_api.verify_bgp_summary(data.dut1, family='ipv6', neighbor = dut2_dut1_vrf_ipv6[0], state='Established',vrf = vrf_name[2])
            return result

def tg_vrf_bgp(**kwargs):
    if 'phy' in kwargs:
        phy = kwargs['phy']
    else:
        phy = ''
    if 've' in kwargs:
        ve = kwargs['ve']
    else:
        ve = ''
    if 'pc' in kwargs:
        pc = kwargs['pc']
    else:
        pc = ''
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if phy != '' and config == '':
        st.log('######------Configure BGP in vrf - 101 for TG interface------######')
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0], router_id = dut1_router_id, local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ip[0], remote_as = dut1_tg_as, config = 'yes', config_type_list =['neighbor','activate'])
        st.log('######------Configure BGPv4+ in vrf - 101 for TG interface ------######')
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0], router_id = dut1_router_id, addr_family ='ipv6', local_as = dut1_as[0], neighbor = tg1_dut1_vrf_ipv6[0], remote_as = dut1_tg_as, config = 'yes', config_type_list =['neighbor', 'activate'])
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[0], local_as = dut1_as[0], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=tg1_dut1_vrf_ipv6[0])
    elif phy != '' and config == 'no':
        bgp_api.config_bgp(dut = data.dut1, local_as = dut1_as[0], vrf_name = vrf_name[0] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])

    if ve != '' and config == '':
        st.log('######------Configure BGP in vrf -102 for TG interface------######')
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[1], router_id = dut1_router_id, local_as = dut1_as[1], neighbor = tg1_dut1_vrf_ip[1], remote_as = dut1_tg_as, config = 'yes', config_type_list =['neighbor','activate'])
        st.log('######------Configure BGPv4+ in vrf-102 for TG interface ------######')
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[1], router_id = dut1_router_id, addr_family ='ipv6', local_as = dut1_as[1], neighbor = tg1_dut1_vrf_ipv6[1], remote_as = dut1_tg_as, config = 'yes', config_type_list =['neighbor','activate'])
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[1], local_as = dut1_as[1], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=tg1_dut1_vrf_ipv6[1])
    elif ve != '' and config == 'no':
        bgp_api.config_bgp(dut = data.dut1, local_as = dut1_as[1], vrf_name = vrf_name[1] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])

    if pc != '' and config == '':
        st.log('######------Configure BGP in vrf - 103 for TG interface------######')
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], router_id = dut1_router_id, local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ip[2], remote_as = dut1_tg_as, config = 'yes', config_type_list =['neighbor','activate'])
        st.log('######------Configure BGPv4+ in vrf - 103 for TG interface ------######')
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], router_id = dut1_router_id, addr_family ='ipv6', local_as = dut1_as[2], neighbor = tg1_dut1_vrf_ipv6[2], remote_as = dut1_tg_as, config = 'yes', config_type_list =['neighbor','activate'])
        bgp_api.config_bgp(dut = data.dut1, vrf_name = vrf_name[2], local_as = dut1_as[2], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=tg1_dut1_vrf_ipv6[2])
    elif pc != '' and config == 'no':
        bgp_api.config_bgp(dut = data.dut1, local_as = dut1_as[2], vrf_name = vrf_name[2] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])

def mutliple_hosts(**kwargs):
    if 'dut' in kwargs:
        dut = kwargs['dut']
    if 'vlan' in kwargs:
        vlan = kwargs['vlan']
    if 'ip' in kwargs:
        ip = kwargs['ip']

    if dut == data.dut1:
        if ip == 'ipv4':
            if vlan == '1':
                intf_ip = tg1_dut1_vrf_ip[0]
                gatway = dut1_tg1_vrf_ip[0]
            if vlan == '2':
                intf_ip = tg1_dut1_vrf_ip[1]
                gatway = dut1_tg1_vrf_ip[1]
            if vlan == '3':
                intf_ip = tg1_dut1_vrf_ip[2]
                gatway = dut1_tg1_vrf_ip[2]
            st.log('######------On DUT1 create ipv4 hosts on vlan '+vlan+' -----######')
            # intf_hand_v4 = data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, mode='config', intf_ip_addr = intf_ip, gateway = gatway, count = dut1_hosts, gateway_step ='0.0.0.0', netmask = '255.255.255.0', vlan = '1', vlan_id = vlan, intf_ip_addr_step = '0.0.0.1', arp_send_req = '1', vlan_id_step='0')
            intf_hand_v4 = data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, mode='config', intf_ip_addr = intf_ip, gateway = gatway, netmask = '255.255.255.0', vlan = '1', vlan_id = vlan, intf_ip_addr_step = '0.0.0.1', arp_send_req = '1')
            data.d1_p1_intf_v4.update({vlan:intf_hand_v4})
        else:
            if vlan == '1':
                intf_ip = tg1_dut1_vrf_ipv6[0]
                gatway = dut1_tg1_vrf_ipv6[0]
            if vlan == '2':
                intf_ip = tg1_dut1_vrf_ipv6[1]
                gatway = dut1_tg1_vrf_ipv6[1]
            if vlan == '3':
                intf_ip = tg1_dut1_vrf_ipv6[2]
                gatway = dut1_tg1_vrf_ipv6[2]
            st.log('######------On DUT1 create ipv6 hosts on vlan '+vlan+' -----######')
            # intf_hand_v6 = data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, mode = 'config', ipv6_intf_addr = intf_ip, ipv6_prefix_length = '64', ipv6_gateway=gatway, arp_send_req='1', vlan = '1', vlan_id = vlan, ipv6_intf_addr_step = '::1', count = dut1_hosts, vlan_id_step='0')
            intf_hand_v6 = data.tg1.tg_interface_config(port_handle = data.tg_dut1_p1, mode = 'config', ipv6_intf_addr = intf_ip, ipv6_prefix_length = '64', ipv6_gateway=gatway, arp_send_req='1', vlan = '1', vlan_id = vlan)
            data.d1_p1_intf_v6.update({vlan:intf_hand_v6})
    else:
        if ip == 'ipv4':
            if vlan == '6':
                intf_ip = tg1_dut2_vrf_ip[0]
                gatway = dut2_tg1_vrf_ip[0]
            if vlan == '7':
                intf_ip = tg1_dut2_vrf_ip[1]
                gatway = dut2_tg1_vrf_ip[1]
            if vlan == '8':
                intf_ip = tg1_dut2_vrf_ip[2]
                gatway = dut2_tg1_vrf_ip[2]
            st.log('######------On DUT2 create ipv4 hosts on vlan '+vlan+' -----######')
            # intf_hand_v4 = data.tg2.tg_interface_config(port_handle = data.tg_dut2_p1, mode='config', intf_ip_addr = intf_ip, gateway = gatway, count = dut2_hosts, gateway_step ='0.0.0.0', netmask = '255.255.255.0', vlan = '1', vlan_id = vlan, intf_ip_addr_step = '0.0.0.1', arp_send_req = '1', vlan_id_step='0')
            intf_hand_v4 = data.tg2.tg_interface_config(port_handle = data.tg_dut2_p1, mode='config', intf_ip_addr = intf_ip, gateway = gatway, netmask = '255.255.255.0', vlan = '1', vlan_id = vlan, arp_send_req = '1')
            data.d2_p1_intf_v4.update({vlan:intf_hand_v4})
        else:
            if vlan == '6':
                intf_ip = tg1_dut2_vrf_ipv6[0]
                gatway = dut2_tg1_vrf_ipv6[0]
            if vlan == '7':
                intf_ip = tg1_dut2_vrf_ipv6[1]
                gatway = dut2_tg1_vrf_ipv6[1]
            if vlan == '8':
                intf_ip = tg1_dut2_vrf_ipv6[2]
                gatway = dut2_tg1_vrf_ipv6[2]
            st.log('######------On DUT2 create ipv6 hosts on vlan '+vlan+' -----######')
            # intf_hand_v6 = data.tg2.tg_interface_config(port_handle = data.tg_dut2_p1, mode = 'config', ipv6_intf_addr = intf_ip, ipv6_prefix_length = '64', ipv6_gateway=gatway, arp_send_req='1', vlan = '1', vlan_id = vlan, ipv6_intf_addr_step = '::1', count = dut2_hosts, vlan_id_step='0')
            intf_hand_v6 = data.tg2.tg_interface_config(port_handle = data.tg_dut2_p1, mode = 'config', ipv6_intf_addr = intf_ip, ipv6_prefix_length = '64', ipv6_gateway=gatway, arp_send_req='1', vlan = '1', vlan_id = vlan)
            data.d2_p1_intf_v6.update({vlan:intf_hand_v6})

def start_arp_nd():
    data.tg1.tg_arp_control(handle=data.d1_p1_intf_v4.get('1')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d1_p1_intf_v4.get('2')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d1_p1_intf_v4.get('3')['handle'], arp_target='all')

    data.tg1.tg_arp_control(handle=data.d1_p1_intf_v6.get('1')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d1_p1_intf_v6.get('2')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d1_p1_intf_v6.get('3')['handle'], arp_target='all')

    data.tg1.tg_arp_control(handle=data.d2_p1_intf_v4.get('6')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d2_p1_intf_v4.get('7')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d2_p1_intf_v4.get('8')['handle'], arp_target='all')

    data.tg1.tg_arp_control(handle=data.d2_p1_intf_v6.get('6')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d2_p1_intf_v6.get('7')['handle'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.d2_p1_intf_v6.get('8')['handle'], arp_target='all')

def pump_bgp_routes(**kwargs):
    if 'dut' in kwargs:
        dut = kwargs['dut']
    if 'ip' in kwargs:
        ip = kwargs['ip']
    if 'vlan' in kwargs:
        vlan = kwargs['vlan']
    if dut == data.dut1:
        if ip == 'ipv4':
            if vlan == '1':
                remote_as = dut1_as[0]
                gatway = dut1_tg1_vrf_ip[0]
            if vlan == '2':
                remote_as = dut1_as[1]
                gatway = dut1_tg1_vrf_ip[1]
            if vlan == '3':
                remote_as = dut1_as[2]
                gatway = dut1_tg1_vrf_ip[2]
            st.log('######------On DUT1 send IPv4 BGP routes from Tgen -----######')
            d1_p1_v4_config = {'mode':'enable', 'active_connect_enable':'1', 'local_as':'300', 'remote_as':remote_as, 'remote_ip_addr':gatway}
            d1_p1_v4_route = {'mode':'add','num_routes':tg_dut1_p1_v4_routes, 'as_path':'as_seq:1', 'prefix':tg_dut1_p1_v4_prefix}
            d1_p1_v4_start = {'mode':'start'}
            intf_handle = data.d1_p1_intf_v4.get(vlan)
            # bgp_router = tg_bgp_config(tg = data.tg1, handle = intf_handle['handle'][0], conf_var  = d1_p1_v4_config, route_var = d1_p1_v4_route, ctrl_var  = d1_p1_v4_start)
            bgp_router = tg_bgp_config(tg = data.tg1, handle = intf_handle['handle'], conf_var  = d1_p1_v4_config, route_var = d1_p1_v4_route, ctrl_var  = d1_p1_v4_start)
            st.log("DUT1 PORT1 BGP_HANDLE: "+str(bgp_router))

            # bgp_router = tg_bgp_config(tg = data.tg1, port_handle = data.tg_dut1_p1, mode = 'enable', ip_version = 4, intf_ip_addr = tg1_dut1_vrf_ip[0],gateway = dut1_tg1_vrf_ip[0], local_as = 300, remote_as = dut1_as[0], next_hop_ip = dut1_tg1_vrf_ip[0])

            data.d1_p1_bgp_v4.update({vlan:bgp_router})
        else:
            if vlan == '1':
                remote_as = dut1_as[0]
                gatway = dut1_tg1_vrf_ipv6[0]
            if vlan == '2':
                remote_as = dut1_as[1]
                gatway = dut1_tg1_vrf_ipv6[1]
            if vlan == '3':
                remote_as = dut1_as[2]
                gatway = dut1_tg1_vrf_ipv6[2]
            st.log('######------On DUT1 send IPv6 BGP routes from Tgen -----######')
            d1_p1_v6_config = {'mode':'enable', 'ip_version':'6', 'active_connect_enable':'1', 'local_as':'300', 'remote_as':remote_as, 'remote_ipv6_addr':gatway}
            d1_p1_v6_route = {'mode':'add', 'ip_version':'6', 'num_routes':tg_dut1_p1_v6_routes, 'as_path':'as_seq:1', 'prefix':tg_dut1_p1_v6_prefix}
            d1_p1_v6_start = {'mode':'start'}
            intf_handle = data.d1_p1_intf_v6.get(vlan)
            #bgp_router = tg_bgp_config(tg = data.tg1, handle = intf_handle['handle'][0], conf_var  = d1_p1_v6_config, route_var = d1_p1_v6_route, ctrl_var  = d1_p1_v6_start)
            bgp_router = tg_bgp_config(tg = data.tg1, handle = intf_handle['handle'], conf_var  = d1_p1_v6_config, route_var = d1_p1_v6_route, ctrl_var  = d1_p1_v6_start)
            data.d1_p1_bgp_v6.update({vlan:bgp_router})

def create_streams_all_vrf(**kwargs):
    if 'todut' in kwargs:
        todut = kwargs['todut']

    if todut == data.dut1:
        intf_handle1 = data.d2_p1_intf_v4.get('6')
        bgp_handle1 = data.d1_p1_bgp_v4.get('1')

        intf_handle2 = data.d2_p1_intf_v4.get('7')
        bgp_handle2 = data.d1_p1_bgp_v4.get('2')

        intf_handle3 = data.d2_p1_intf_v4.get('8')
        bgp_handle3 = data.d1_p1_bgp_v4.get('3')

        # tc1 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, emulation_src_handle = intf_handle1['handle'][0], emulation_dst_handle = bgp_handle1['route'][0]['handle'], circuit_endpoint_type = 'ipv4', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        # data.stream_list.update({'phy_v4_stream':tc1['stream_id']})

        # tc2 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, emulation_src_handle = intf_handle2['handle'][0], emulation_dst_handle = bgp_handle2['route'][0]['handle'], circuit_endpoint_type = 'ipv4', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        # data.stream_list.update({'ve_v4_stream':tc2['stream_id']})

        # tc3 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, emulation_src_handle = intf_handle3['handle'][0], emulation_dst_handle = bgp_handle3['route'][0]['handle'], circuit_endpoint_type = 'ipv4', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        # data.stream_list.update({'pc_v4_stream':tc3['stream_id']})

        tc1 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, duration = '2', emulation_src_handle = intf_handle1['handle'], emulation_dst_handle = bgp_handle1['route'][0]['handle'], circuit_endpoint_type = 'ipv4', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        data.stream_list.update({'phy_v4_stream':tc1['stream_id']})

        tc2 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, duration = '2', emulation_src_handle = intf_handle2['handle'], emulation_dst_handle = bgp_handle2['route'][0]['handle'], circuit_endpoint_type = 'ipv4', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        data.stream_list.update({'ve_v4_stream':tc2['stream_id']})

        tc3 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, duration = '2', emulation_src_handle = intf_handle3['handle'], emulation_dst_handle = bgp_handle3['route'][0]['handle'], circuit_endpoint_type = 'ipv4', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        data.stream_list.update({'pc_v4_stream':tc3['stream_id']})

        intf_handle4 = data.d2_p1_intf_v6.get('6')
        bgp_handle4 = data.d1_p1_bgp_v6.get('1')

        intf_handle5 = data.d2_p1_intf_v6.get('7')
        bgp_handle5 = data.d1_p1_bgp_v6.get('2')

        intf_handle6 = data.d2_p1_intf_v6.get('8')
        bgp_handle6 = data.d1_p1_bgp_v6.get('3')

        # tc4 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, emulation_src_handle = intf_handle4['handle'][0], emulation_dst_handle = bgp_handle4['route'][0]['handle'], circuit_endpoint_type = 'ipv6', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        # data.stream_list.update({'phy_v6_stream':tc4['stream_id']})

        # tc5 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, emulation_src_handle = intf_handle5['handle'][0], emulation_dst_handle = bgp_handle5['route'][0]['handle'], circuit_endpoint_type = 'ipv6', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        # data.stream_list.update({'ve_v6_stream':tc5['stream_id']})

        # tc6 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, emulation_src_handle = intf_handle6['handle'][0], emulation_dst_handle = bgp_handle6['route'][0]['handle'], circuit_endpoint_type = 'ipv6', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        # data.stream_list.update({'pc_v6_stream':tc6['stream_id']})

        tc4 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, duration = '2', emulation_src_handle = intf_handle4['handle'], emulation_dst_handle = bgp_handle4['route'][0]['handle'], circuit_endpoint_type = 'ipv6', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        data.stream_list.update({'phy_v6_stream':tc4['stream_id']})

        tc5 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, duration = '2', emulation_src_handle = intf_handle5['handle'], emulation_dst_handle = bgp_handle5['route'][0]['handle'], circuit_endpoint_type = 'ipv6', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        data.stream_list.update({'ve_v6_stream':tc5['stream_id']})

        tc6 = data.tg2.tg_traffic_config(port_handle = data.tg_dut2_p1, duration = '2', emulation_src_handle = intf_handle6['handle'], emulation_dst_handle = bgp_handle6['route'][0]['handle'], circuit_endpoint_type = 'ipv6', mode = 'create', transmit_mode = 'continuous', length_mode = 'fixed', rate_pps = tg_dut1_rate_pps, port_handle2 = data.tg_dut1_p1)
        data.stream_list.update({'pc_v6_stream':tc6['stream_id']})
        return

def verify_traffic_all_vrfs(**kwargs):
    if 'stream_id' in kwargs:
        stream_id = kwargs['stream_id']
    else:
        stream_id = 'all'

    st.log('######------Clear stats before the start of the traffic -----######')
    #data.tg2.tg_traffic_control(action = 'stop', port_handle = data.tg_dut2_p1)
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.values())
    data.tg1.tg_traffic_control(action = 'clear_stats',port_handle = data.tg_dut1_p1)
    data.tg1.tg_traffic_control(action = 'clear_stats',port_handle = data.tg_dut2_p1)

    #data.tg2.tg_traffic_control(action = 'run', port_handle = data.tg_dut2_p1, duration = '2') #send continuous traffic for 5 seconds
    data.tg2.tg_traffic_control(action = 'run', stream_handle = data.stream_list.values(), duration = '2') #send continuous traffic for 5 seconds
    #data.tg2.tg_traffic_control(action = 'stop', port_handle = data.tg_dut2_p1) # stop the traffic
    data.tg2.tg_traffic_control(action = 'stop', stream_handle = data.stream_list.values()) # stop the traffic

    if stream_id == 'all':
        # traffic_details = {'1': {'tx_ports' : [vars.T1D2P1],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1],'rx_obj' : [data.tg1],'stream_list' : [list(data.stream_list.values())]}}
        traffic_details = {'1': {'tx_ports' : [data.tg_dut2_hw_port],'tx_obj' : [data.tg2],'exp_ratio' : [1],'rx_ports' : [data.tg_dut1_hw_port],'rx_obj' : [data.tg1],'stream_list' : [data.stream_list.values()]}}
        aggrResult = validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
        return aggrResult

def clear_tg(**kwargs):
    data.tg1.tg_traffic_control(action = 'clear_stats',port_handle = data.tg_dut1_p1)
    data.tg1.tg_traffic_control(action = 'clear_stats',port_handle = data.tg_dut2_p1)

def config_route_map(dut,rmap,type='next_hop_v6',config='yes'):
    if config == 'yes':
        st.vtysh_config(dut,"route-map %s permit 10"%rmap)
        if type=='local_pref':
            st.vtysh_config(dut,"set local-preference 40")
        elif type == 'next_hop_v6':
            st.log('######------Configure route-map to prefer global v6 address over link local address as next hop ------######')
            st.vtysh_config(dut, "set ipv6 next-hop prefer-global")
        st.vtysh(dut,'end')
        st.vtysh(dut,'exit')
    else:
        st.vtysh_config(dut,"no route-map %s permit 10"% rmap)
        st.vtysh(dut,'end')
        st.vtysh(dut,'exit')

def retry_api(func,**kwargs):
    retry_count = kwargs.get("retry_count", 10)
    delay = kwargs.get("delay", 3)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if func(**kwargs):
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False

def tg_interfaces(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if 'phy' in kwargs:
        phy = kwargs['phy']
    else:
        phy = ''
    if 've' in kwargs:
        ve = kwargs['ve']
    else:
        ve = ''
    if 'pc' in kwargs:
        pc = kwargs['pc']
    else:
        pc = ''

    if config == '' and phy != '':
        st.log('######------Push multiple hosts on DUT1 on vlan 1 and vlan 6------######')
        mutliple_hosts(dut = data.dut1, vlan = dut1_tg1_vlan[0], ip = 'ipv4')
        mutliple_hosts(dut = data.dut2, vlan = dut2_tg1_vlan[0], ip = 'ipv4')
        mutliple_hosts(dut = data.dut1, vlan = dut1_tg1_vlan[0], ip = 'ipv6')
        mutliple_hosts(dut = data.dut2, vlan = dut2_tg1_vlan[0], ip = 'ipv6')

    if config == '' and ve != '':
        st.log('######------Push multiple hosts on DUT1 on vlan 2 and vlan 7------######')
        mutliple_hosts(dut = data.dut1, vlan = dut1_tg1_vlan[1], ip = 'ipv4')
        mutliple_hosts(dut = data.dut2, vlan = dut2_tg1_vlan[1], ip = 'ipv4')
        mutliple_hosts(dut = data.dut1, vlan = dut1_tg1_vlan[1], ip = 'ipv6')
        mutliple_hosts(dut = data.dut2, vlan = dut2_tg1_vlan[1], ip = 'ipv6')

    if config == '' and pc != '':
        st.log('######------Push multiple hosts on DUT1 on vlan 3 and vlan 8------######')
        mutliple_hosts(dut = data.dut1, vlan = dut1_tg1_vlan[2], ip = 'ipv4')
        mutliple_hosts(dut = data.dut2, vlan = dut2_tg1_vlan[2], ip = 'ipv4')
        mutliple_hosts(dut = data.dut1, vlan = dut1_tg1_vlan[2], ip = 'ipv6')
        mutliple_hosts(dut = data.dut2, vlan = dut2_tg1_vlan[2], ip = 'ipv6')

    if config == 'no' and phy != '':
        st.log('######------Removes all the traffic streams configured on the port.------######')
        data.tg1.tg_traffic_control(action = 'reset', port_handle = data.tg_dut1_p1)
        data.tg2.tg_traffic_control(action = 'reset', port_handle = data.tg_dut2_p1)
