
import time
import datetime

from spytest import st, utils
from spytest.tgen.tg import tgen_obj_dict

import apis.routing.bgp as bgp_obj

import apis.routing.ip as ipfeature
import apis.switching.vlan as vlan_obj

import apis.routing.arp as arp_api

import apis.routing.vrf as vrf_api
import apis.common.asic as asicapi
from utilities import parallel

from L3SclEnhancement_vars import data

vars = dict()

def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n%s\n######################################################################"%msg)

def get_handles():

    global vars
    vars = st.ensure_min_topology("D1T1:1","D2T1:1","D1T1:2","D2T1:2" )
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg3 = tgen_obj_dict[vars['tgen_list'][0]]
    tg4 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg2.get_port_handle(vars.T1D2P1)
    tg_ph_3 = tg3.get_port_handle(vars.T1D1P2)
    tg_ph_4 = tg4.get_port_handle(vars.T1D2P2)

    return (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4)

def verify_arp_count(dut,expected_count=data.max_host_1,**kwargs):

    #n = show_arp_count(dut)
    cli_type = kwargs.pop('cli_type', "")
    n = arp_api.get_arp_count(dut,None,None,cli_type,**kwargs)
    if int(n) >= int(expected_count):
        st.log('PASS - Expected number of ARP entries found in the arp table')
        return True
    else:
        st.log('FAIL - Expected number of ARP entries not found in the arp table.')
        return False

def verify_bgp_nbr_count(dut,expected_count=data.max_ecmp,vrf='default'):

    n = bgp_obj.get_bgp_nbr_count(dut,vrf=vrf)
    if int(n) >= expected_count:
        st.log('PASS - Expected number of BGP neighbors found')
        return True
    else:
        st.log('FAIL - Expected number of BGP neighbors not found')
        return False

def verify_ipv6_bgp_nbr_count(dut,expected_count=data.max_ecmp,vrf='default'):

    n = bgp_obj.get_bgp_nbr_count(dut,family='ipv6',vrf=vrf)
    if int(n) >= expected_count:
        st.log('PASS - Expected number of BGP neighbors found')
        return True
    else:
        st.log('FAIL - Expected number of BGP neighbors not found')
        return False

def verify_ndp_count(dut,expected_count=data.max_host_1,**kwargs):

    #n = show_nd_count(dut)
    cli_type = kwargs.pop('cli_type', "")
    n = arp_api.get_ndp_count(dut,cli_type,**kwargs)
    if int(n) >= int(expected_count):
        st.log('PASS - Expected number of ND entries found in the arp table')
        return True
    else:
        st.log('FAIL - Expected number of ND entries not found in the arp table.')
        return False

def verify_ipv6_route_count_hardware(dut,exp_num_of_routes=data.num_of_routes2):

    n = asicapi.get_ipv6_route_count(dut)
    if int(n) > exp_num_of_routes:
        st.log('PASS - Expected number of IPv6 routes present in the hardware')
        return True
    else:
        st.log('FAIL - Expected number of IPv6 routes not present in the hardware')
        return False

def verify_route_count_hardware(dut,exp_num_of_routes=data.num_of_routes):

    #n = show_route_count_hardware(dut)
    n = asicapi.get_ipv4_route_count(dut)
    if int(n) > exp_num_of_routes:
        st.log('PASS - Expected number of IPv4 routes present in the hardware')
        return True
    else:
        st.log('FAIL - Expected number of IPv4 routes not present in the hardware')
        return False

def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 5)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if func(args,**kwargs):
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retrying again"%delay)
            st.wait(delay)
    return False



def tg_vrf_bind(**kwargs):
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        st.log('######------Configure vlans on the PE--CE side-------######')
        for i in range(3):
            utils.exec_all(True, [[vlan_obj.create_vlan, vars.D1, data.dut1_tg1_vlan[i]], [vlan_obj.create_vlan, vars.D2, data.dut2_tg1_vlan[i]]])
            utils.exec_all(True,[[vlan_obj.add_vlan_member,vars.D1,data.dut1_tg1_vlan[i],vars.D1T1P1,True,True], [vlan_obj.add_vlan_member,vars.D2,data.dut2_tg1_vlan[i],vars.D2T1P1,True,True]])
            '''
            vlan_obj.create_vlan(vars.D1, data.dut1_tg1_vlan[i]) # Vlan-1, VRF-101, port1
            vlan_obj.add_vlan_member(vars.D1, data.dut1_tg1_vlan[i], vars.D1T1P1, True, True)
            vlan_obj.create_vlan(vars.D2, data.dut2_tg1_vlan[i])
            vlan_obj.add_vlan_member(vars.D2, data.dut2_tg1_vlan[i], vars.D2T1P1, True, True)
            '''
        st.log('######------Bind DUT1 <--> tg1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan, ip, ipv6 in zip(data.vrf_name[0:3], data.dut1_tg1_vlan[0:3],data.dut1_tg1_vrf_ip[0:3], data.dut1_tg1_vrf_ipv6[0:3]):
            vrf_api.bind_vrf_interface(dut = vars.D1, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True)
            ipfeature.config_ip_addr_interface(vars.D1, 'Vlan'+vlan, ip, data.dut1_tg1_vrf_ip_subnet, 'ipv4')
            ipfeature.config_ip_addr_interface(vars.D1, 'Vlan'+vlan, ipv6, data.dut1_tg1_vrf_ipv6_subnet, 'ipv6')

        st.log('######------Bind DUT2 <--> tg1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan,ip,ipv6 in zip(data.vrf_name[0:3], data.dut2_tg1_vlan[0:3], data.dut2_tg1_vrf_ip[0:3], data.dut2_tg1_vrf_ipv6[0:3]):
            vrf_api.bind_vrf_interface(dut = vars.D2, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True)
            ipfeature.config_ip_addr_interface(vars.D2, 'Vlan'+vlan, ip, data.dut2_tg1_vrf_ip_subnet, 'ipv4')
            ipfeature.config_ip_addr_interface(vars.D2, 'Vlan'+vlan, ipv6, data.dut2_tg1_vrf_ipv6_subnet, 'ipv6')
    else:
        st.log('######------Unbind DUT1 <--> tg1port1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan, ip, ipv6 in zip(data.vrf_name[0:3], data.dut1_tg1_vlan[0:3],data.dut1_tg1_vrf_ip[0:3], data.dut1_tg1_vrf_ipv6[0:3]):
            ipfeature.delete_ip_interface(dut1, 'Vlan'+vlan, ip, data.dut1_tg1_vrf_ip_subnet, 'ipv4')
            ipfeature.delete_ip_interface(dut1, 'Vlan'+vlan, ipv6, data.dut1_tg1_vrf_ipv6_subnet, 'ipv6')
            vrf_api.bind_vrf_interface(dut = dut1, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True, config = 'no')
        st.log('######------Unbind DUT2 <--> tg1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan,ip,ipv6 in zip(data.vrf_name[0:3], data.dut2_tg1_vlan[0:3], data.dut2_tg1_vrf_ip[0:3], data.dut2_tg1_vrf_ipv6[0:3]):
            ipfeature.delete_ip_interface(dut2, 'Vlan'+vlan, ip, data.dut2_tg1_vrf_ip_subnet, 'ipv4')
            ipfeature.delete_ip_interface(dut2, 'Vlan'+vlan, ipv6, data.dut2_tg1_vrf_ipv6_subnet, 'ipv6')
            vrf_api.bind_vrf_interface(dut = dut2, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True, config = 'no')

        st.log('######------Unconfigure vlans on the PE--CE side -------######')
        for i in range(3):
            vlan_obj.delete_vlan_member(dut1, data.dut1_tg1_vlan[i], vars.D1T1P1, tagging_mode=True)
            vlan_obj.delete_vlan(dut1, data.dut1_tg1_vlan[i]) # Vlan-1, VRF-101, port1
            vlan_obj.delete_vlan_member(dut2, data.dut2_tg1_vlan[i], vars.D2T1P1, tagging_mode=True)
            vlan_obj.delete_vlan(dut2, data.dut2_tg1_vlan[i])

def tg_vrf_bind2(**kwargs):
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        st.log('######------Configure vlans on the PE--CE side-------######')
        for i in range(3):
            utils.exec_all(True, [[vlan_obj.create_vlan, vars.D1, data.dut1_tg1_vlan2[i]], [vlan_obj.create_vlan, vars.D2, data.dut1_tg1_vlan2[i]]])
            utils.exec_all(True,[[vlan_obj.add_vlan_member,vars.D1,data.dut1_tg1_vlan2[i],vars.D1T1P2,True,True], [vlan_obj.add_vlan_member,vars.D2,data.dut1_tg1_vlan2[i],vars.D2T1P2,True,True]])
            '''
            vlan_obj.create_vlan(vars.D1, data.dut1_tg1_vlan2[i]) # Vlan-1, VRF-101, port1
            vlan_obj.add_vlan_member(vars.D1, data.dut1_tg1_vlan2[i], vars.D1T1P2, True, True)
            vlan_obj.create_vlan(vars.D2, data.dut1_tg1_vlan2[i])
            vlan_obj.add_vlan_member(vars.D2, data.dut1_tg1_vlan2[i], vars.D2T1P2, True, True)
            '''

        st.log('######------Bind DUT1 <--> tg1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan, ipv6 in zip(data.vrf_name[0:3], data.dut1_tg1_vlan2[0:3], data.dut1_tg1_vrf_ipv6_2[0:3]):
            vrf_api.bind_vrf_interface(dut = vars.D1, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True)
            ipfeature.config_ip_addr_interface(vars.D1, 'Vlan'+vlan, ipv6, data.dut1_tg1_vrf_ipv6_subnet, 'ipv6')

        st.log('######------Bind DUT2 <--> tg1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan,ipv6 in zip(data.vrf_name[0:3], data.dut1_tg1_vlan2[0:3], data.dut2_tg1_vrf_ipv6_2[0:3]):
            vrf_api.bind_vrf_interface(dut = vars.D2, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True)
            ipfeature.config_ip_addr_interface(vars.D2, 'Vlan'+vlan, ipv6, data.dut2_tg1_vrf_ipv6_subnet, 'ipv6')
    else:
        st.log('######------Unbind DUT1 <--> tg1port1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan, ipv6 in zip(data.vrf_name[0:3], data.dut1_tg1_vlan2[0:3], data.dut1_tg1_vrf_ipv6_2[0:3]):
            vrf_api.bind_vrf_interface(dut = dut1, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True, config = 'no')
            ipfeature.delete_ip_interface(dut1, 'Vlan'+vlan, ipv6, data.dut1_tg1_vrf_ipv6_subnet, 'ipv6')

        st.log('######------Unbind DUT2 <--> tg1 vlans to vrf, assign v4 and v6 address------######')
        for vrf, vlan,ipv6 in zip(data.vrf_name[0:3], data.dut1_tg1_vlan2[0:3],  data.dut2_tg1_vrf_ipv6_2[0:3]):
            vrf_api.bind_vrf_interface(dut = dut2, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True, config = 'no')
            ipfeature.delete_ip_interface(dut2, 'Vlan'+vlan, ipv6, data.dut2_tg1_vrf_ipv6_subnet, 'ipv6')

        st.log('######------Unconfigure vlans on the PE--CE side -------######')
        for i in range(3):
            vlan_obj.delete_vlan_member(dut1, data.dut1_tg1_vlan2[i], vars.D1T1P2, tagging_mode=True)
            vlan_obj.delete_vlan(dut1, data.dut1_tg1_vlan2[i]) # Vlan-1, VRF-101, port1
            vlan_obj.delete_vlan_member(dut2, data.dut1_tg1_vlan2[i], vars.D2T1P2, tagging_mode=True)
            vlan_obj.delete_vlan(dut2, data.dut1_tg1_vlan2[i])


def dut_vrf_bind(**kwargs):
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if  config == '':
        st.log('######------Configure vlans on the PE--PE side - DUT1 -- DUT2------######')
        for vlan in data.dut1_dut2_vlan[0:3]:
            vlan_obj.create_vlan(dut1, vlan)
            vlan_obj.add_vlan_member(dut1, vlan, vars.D1D2P1, True, True)
        for vlan in data.dut2_dut1_vlan[0:3]:
            vlan_obj.create_vlan(dut2, vlan)
            vlan_obj.add_vlan_member(dut2, vlan, vars.D2D1P1, True, True)

        st.log('######------Bind DUT1 <--> DUT2 vlans to vrf, assign v4 and v6 address------######')
        for vlan, ip, ip2, ipv6, ipv6_2, vrf in zip(data.dut1_dut2_vlan[0:3], data.dut1_dut2_vrf_ip[0:3], data.dut2_dut1_vrf_ip[0:3], data.dut1_dut2_vrf_ipv6[0:3], data.dut2_dut1_vrf_ipv6[0:3], data.vrf_name[0:3]):
            dict1 = {'vrf_name':vrf, 'intf_name':'Vlan'+vlan,'skip_error':True}
            dict2 = {'vrf_name':vrf, 'intf_name':'Vlan'+vlan,'skip_error':True}
            parallel.exec_parallel(True, [dut1, dut2], vrf_api.bind_vrf_interface, [dict1, dict2])

            utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,'Vlan'+vlan,ip,data.dut1_dut2_vrf_ip_subnet,'ipv4'], [ipfeature.config_ip_addr_interface,dut2, 'Vlan'+vlan, ip2, data.dut2_dut1_vrf_ip_subnet, 'ipv4']])

            utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,'Vlan'+vlan,ipv6,data.dut1_dut2_vrf_ipv6_subnet,'ipv6'], [ipfeature.config_ip_addr_interface,dut2, 'Vlan'+vlan,ipv6_2, data.dut2_dut1_vrf_ipv6_subnet, 'ipv6']])

            '''
            vrf_api.bind_vrf_interface(dut = dut1, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True)
            ipfeature.config_ip_addr_interface(dut1, 'Vlan'+vlan, ip, data.dut1_dut2_vrf_ip_subnet, 'ipv4')
            ipfeature.config_ip_addr_interface(dut1, 'Vlan'+vlan, ipv6, data.dut1_dut2_vrf_ipv6_subnet, 'ipv6')
            '''
        '''
        st.log('######------Bind DUT2 <--> DUT1 virtual interfaces to vrf and config IP addresses------######')
        for vlan, ip, ipv6, vrf in zip(data.dut2_dut1_vlan[0:3], data.dut2_dut1_vrf_ip[0:3], data.dut2_dut1_vrf_ipv6[0:3],data.vrf_name[0:3]):
            vrf_api.bind_vrf_interface(dut = dut2, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True)
            ipfeature.config_ip_addr_interface(dut2, 'Vlan'+vlan, ip, data.dut2_dut1_vrf_ip_subnet, 'ipv4')
            ipfeature.config_ip_addr_interface(dut2, 'Vlan'+vlan, ipv6, data.dut2_dut1_vrf_ipv6_subnet, 'ipv6')
        '''

    elif config == 'no':
        '''
        st.log('######------Unbind DUT1 <--> DUT2 vlans to vrf, assign v4 and v6 address------######')
        for vlan, ip, ipv6, vrf in zip(data.dut1_dut2_vlan[0:3], data.dut1_dut2_vrf_ip[0:3], data.dut1_dut2_vrf_ipv6[0:3],data.vrf_name[0:3]):
            vrf_api.bind_vrf_interface(dut = dut1, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True, config = 'no')
            ipfeature.delete_ip_interface(dut1, 'Vlan'+vlan, ip, data.dut1_dut2_vrf_ip_subnet, 'ipv4')
            ipfeature.delete_ip_interface(dut1, 'Vlan'+vlan, ipv6, data.dut1_dut2_vrf_ipv6_subnet, 'ipv6')

        st.log('######------Unbind DUT2 <--> DUT1 physical interfaces to vrf and config IP addresses------######')
        for vlan, ip, ipv6, vrf in zip(data.dut2_dut1_vlan[0:3], data.dut2_dut1_vrf_ip[0:3], data.dut2_dut1_vrf_ipv6[0:3],data.vrf_name[0:3]):
            vrf_api.bind_vrf_interface(dut = dut2, vrf_name = vrf, intf_name = 'Vlan'+vlan, skip_error = True, config = 'no')
            ipfeature.delete_ip_interface(dut2, 'Vlan'+vlan, ip, data.dut2_dut1_vrf_ip_subnet, 'ipv4')
            ipfeature.delete_ip_interface(dut2, 'Vlan'+vlan, ipv6, data.dut2_dut1_vrf_ipv6_subnet, 'ipv6')
        '''
        st.log('######------Delete vlans on the PE--PE side - DUT1 -- DUT2------######')
        for vlan in data.dut1_dut2_vlan[0:3]:
            vlan_obj.delete_vlan_member(dut1, vlan, vars.D1D2P1, tagging_mode=True)
            vlan_obj.delete_vlan(dut1, vlan)
        for vlan in data.dut2_dut1_vlan[0:3]:
            vlan_obj.delete_vlan_member(dut2, vlan, vars.D2D1P1, tagging_mode=True)
            vlan_obj.delete_vlan(dut2, vlan)

def dut_vrf_bgp(**kwargs):
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        st.log('######------Configure BGP in vrf for virtual interface ------######')
        for i in range(0,3):
            dict1 = {'vrf_name':data.vrf_name[i],'router_id':data.dut1_router_id,'local_as':data.dut1_as[i],'neighbor':data.dut2_dut1_vrf_ip[i],'remote_as':data.dut2_as[i],'config_type_list':['neighbor']}
            dict2 = {'vrf_name':data.vrf_name[i],'router_id':data.dut2_router_id,'local_as':data.dut2_as[i],'neighbor':data.dut1_dut2_vrf_ip[i],'remote_as':data.dut1_as[i],'config_type_list':['neighbor']}
            parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])

            dict1 = {'vrf_name':data.vrf_name[i],'router_id':data.dut1_router_id,'local_as':data.dut1_as[i],'neighbor':data.dut2_dut1_vrf_ip[i],'remote_as':data.dut2_as[i],'config_type_list':['activate','nexthop_self']}
            dict2 = {'vrf_name':data.vrf_name[i],'router_id':data.dut2_router_id,'local_as':data.dut2_as[i],'neighbor':data.dut1_dut2_vrf_ip[i],'remote_as':data.dut1_as[i],'config_type_list':['activate','nexthop_self']}
            parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])

            st.log('######------Configure BGPv4+ in vrf for virtual interface ------######')
            dict1 = {'vrf_name':data.vrf_name[i],'router_id':data.dut1_router_id,'local_as':data.dut1_as[i],'addr_family':'ipv6','neighbor':data.dut2_dut1_vrf_ipv6[i],'remote_as':data.dut2_as[i],'config_type_list':['neighbor']}
            dict2 = {'vrf_name':data.vrf_name[i],'router_id':data.dut2_router_id,'local_as':data.dut2_as[i],'addr_family':'ipv6','neighbor':data.dut1_dut2_vrf_ipv6[i],'remote_as':data.dut1_as[i],'config_type_list':['neighbor']}
            parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])

            dict1 = {'vrf_name':data.vrf_name[i],'router_id':data.dut1_router_id,'local_as':data.dut1_as[i],'addr_family':'ipv6','neighbor':data.dut2_dut1_vrf_ipv6[i],'remote_as':data.dut2_as[i],'config_type_list':['activate','nexthop_self']}
            dict2 = {'vrf_name':data.vrf_name[i],'router_id':data.dut2_router_id,'local_as':data.dut2_as[i],'addr_family':'ipv6','neighbor':data.dut1_dut2_vrf_ipv6[i],'remote_as':data.dut1_as[i],'config_type_list':['activate','nexthop_self']}
            parallel.exec_parallel(True, [vars.D1, vars.D2], bgp_obj.config_bgp, [dict1, dict2])

            bgp_obj.config_bgp(dut = dut2, vrf_name = data.vrf_name[i], local_as = data.dut2_as[i], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.dut1_dut2_vrf_ipv6[i])
            bgp_obj.config_bgp(dut = dut1, vrf_name = data.vrf_name[i], local_as = data.dut1_as[i], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.dut2_dut1_vrf_ipv6[i])
    elif config == 'no':
        for i in range(0,3):
            bgp_obj.config_bgp(dut = dut1, local_as = data.dut1_as[i], vrf_name = data.vrf_name[i] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])
            bgp_obj.config_bgp(dut = dut2, local_as = data.dut2_as[i], vrf_name = data.vrf_name[i] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])

def tg_vrf_bgp(**kwargs):
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        st.log('######------Configure BGP in vrf -101 for TG interface------######')
        for i in range(0,3):
            bgp_obj.config_bgp(dut = dut1, vrf_name = data.vrf_name[i], router_id = data.dut1_router_id, local_as = data.dut1_as[i], neighbor = data.tg1_dut1_vrf_ip[i], remote_as = data.dut1_tg_as[i], config = 'yes', config_type_list =['neighbor','activate'])
            st.log('######------Configure BGPv4+ in vrf-102 for TG interface ------######')
            bgp_obj.config_bgp(dut = dut1, vrf_name = data.vrf_name[i], router_id = data.dut1_router_id, addr_family ='ipv6', local_as = data.dut1_as[i], neighbor = data.tg1_dut1_vrf_ipv6[i], remote_as = data.dut1_tg_as[i], config = 'yes', config_type_list =['neighbor','activate'])
            bgp_obj.config_bgp(dut = dut1, vrf_name = data.vrf_name[i], local_as = data.dut1_as[i], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.tg1_dut1_vrf_ipv6[i])
            bgp_obj.config_bgp(dut = dut2, vrf_name = data.vrf_name[i], router_id = data.dut2_router_id, local_as = data.dut2_as[i], neighbor = data.tg1_dut2_vrf_ip[i], remote_as = data.dut2_tg_as[i], config = 'yes', config_type_list =['neighbor','activate'])
            bgp_obj.config_bgp(dut = dut2, vrf_name = data.vrf_name[i], router_id = data.dut2_router_id, addr_family ='ipv6', local_as = data.dut2_as[i], neighbor = data.tg1_dut2_vrf_ipv6[i], remote_as = data.dut2_tg_as[i], config = 'yes', config_type_list =['neighbor','activate'])
            bgp_obj.config_bgp(dut = dut2, vrf_name = data.vrf_name[i], local_as = data.dut2_as[i], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.tg1_dut2_vrf_ipv6[i])
        time.sleep(2)
        '''
        for i in range(0,3):
            if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv4',shell="sonic",neighbor=data.tg1_dut1_vrf_ip[i], state='Established', vrf = data.vrf_name[i],delay=5,retry_count=5):
                st.log("FAIL: BGP not up")
            if not retry_api(bgp_obj.verify_bgp_summary,dut2,family='ipv6',shell="sonic",neighbor=data.tg1_dut2_vrf_ipv6[i], state='Established', vrf = data.vrf_name[i],delay=5,retry_count=5):
                st.log("FAIL: BGPv6 not up")
        '''
    elif config == 'no':
        for i in range(0,3):
            bgp_obj.config_bgp(dut = dut1, local_as = data.dut1_as[i], vrf_name = data.vrf_name[i] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])
            bgp_obj.config_bgp(dut = dut2, local_as = data.dut2_as[i], vrf_name = data.vrf_name[i] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])

def tg_vrf_bgp2(**kwargs):
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        st.log('######------Configure BGP in vrf -101 for TG interface------######')
        for i in range(0,3):
            st.log('######------Configure BGPv4+ in vrf-102 for TG interface ------######')
            bgp_obj.config_bgp(dut = dut1, vrf_name = data.vrf_name[i], router_id = data.dut1_router_id, addr_family ='ipv6', local_as = data.dut1_as[i], neighbor = data.tg1_dut1_vrf_ipv6_2[i], remote_as = data.dut1_tg_as[i], config = 'yes', config_type_list =['neighbor','activate'])
            bgp_obj.config_bgp(dut = dut1, vrf_name = data.vrf_name[i], local_as = data.dut1_as[i], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.tg1_dut1_vrf_ipv6_2[i])
            bgp_obj.config_bgp(dut = dut2, vrf_name = data.vrf_name[i], router_id = data.dut2_router_id, addr_family ='ipv6', local_as = data.dut2_as[i], neighbor = data.tg1_dut2_vrf_ipv6_2[i], remote_as = data.dut2_tg_as[i], config = 'yes', config_type_list =['neighbor','activate'])
            bgp_obj.config_bgp(dut = dut2, vrf_name = data.vrf_name[i], local_as = data.dut2_as[i], addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.tg1_dut2_vrf_ipv6_2[i])
        time.sleep(2)
    elif config == 'no':
        for i in range(0,3):
            bgp_obj.config_bgp(dut = dut1, local_as = data.dut1_as[i], vrf_name = data.vrf_name[i] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])
            bgp_obj.config_bgp(dut = dut2, local_as = data.dut2_as[i], vrf_name = data.vrf_name[i] ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])


def ip_incr(ip,octet):
   ip_list = ip.split(".")
   ip_list[octet] = str(int(ip_list[octet]) + 1)
   return '.'.join(ip_list)

#print (ip_incr("8.0.0.1",2))

def ip_range(ip,octet,scl):
    i=0
    j=0
    ip2=ip
    ip_list=[ip]
    while (i<scl):
        if j==255:
            ip = ip_incr(ip,octet-1)
            j=0
            ip2=ip
            ip_list.append(ip2)
        else:
            ip2 = ip_incr(ip2,octet)
            ip_list.append(ip2)
            i += 1
            j += 1
    return ip_list

#print ip_range('8.0.0.1',2,1000)

def ipv6_list(ipv6,count):
    j=0
    i=1
    ipv6_list=[ipv6+str(i)+'::'+'1']
    while j<count:
        i = int(i)+1
        ipv6_new= ipv6+hex(i)[2:]+'::'+'1'
        ipv6_list.append(ipv6_new)
        j=j+1
    return ipv6_list

#x= ipv6_list('1000:',1000)


def measure_nd_learn_time(dut1, default_nd, max_nd):
    st.log("Number of NDP's in the beginning %d" %(default_nd))
    curr_nd = default_nd
    nd_in_this_poll = default_nd
    sleep_time = 10
    record_start_time = 0
    prev_poll_count = 0
    #initialize start time for error cases
    start_time = datetime.datetime.now()

    while(curr_nd < max_nd):
        now = datetime.datetime.now()
        prev_poll_count = nd_in_this_poll
        n = arp_api.get_ndp_count(vars.D1)
        nd_in_this_poll = n - curr_nd

        #no more entries learnt, break!
        if (prev_poll_count == nd_in_this_poll):
          break

        nd_in_this_poll = n - curr_nd
        if nd_in_this_poll > 0 and record_start_time == 0:
            start_time = now
            st.log("Time when the first nd was installed %s " %(str(start_time)))
            sleep_time=10
            record_start_time =1
        #st.log start_time
        curr_nd = curr_nd + nd_in_this_poll
        after = datetime.datetime.now()
        st.log(" [%s]: increment %d curr_nd %d " %(str(after), nd_in_this_poll, curr_nd))
        if curr_nd == max_nd:
            break
        st.wait(sleep_time)

    end_time = datetime.datetime.now()
    st.log("Time when all the NDP's were installed %s" %(str(end_time)))
    #st.log end_time
    diff = (end_time - start_time).total_seconds()
    st.log("total time is %d" %(int(diff)))
    return int(diff)


