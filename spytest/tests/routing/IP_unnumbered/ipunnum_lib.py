################################################################################
#Script Title : IPv4 unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

################################################################################

import pytest

from spytest import st
import utilities.common as utils

from ipunnum_vars import * #all the variables used for the testcase
from ipunnum_vars import data
from utilities import parallel

import apis.switching.mac as mac_obj
import apis.switching.portchannel as pc_obj

import apis.routing.ip as ip_obj
import apis.routing.bgp as bgp_obj
import apis.routing.arp as arp_obj
import apis.routing.ospf as ospf_obj
import apis.routing.bfd as bfd_obj

from spytest.tgen.tgen_utils import validate_tgen_traffic

def debug_failure():
    st.log('Dubug commands starts!')
    cmd_list = ['show arp','show ndp','show ip route','show ipv6 route','show interface counters']
    utils.exec_all(True, [[st.apply_script, data.dut1, cmd_list], [st.apply_script, data.dut2, cmd_list], [st.apply_script, data.dut3, cmd_list]])
    st.log('End of Dubug commands')

def module_config():
    dut_intf_config()
    result = base_interfaces()
    if result is False:
        st.error('Module config Failed - Base interfaces/Loopback configuration failed')
        base_interfaces(config = 'no')
        pytest.skip()
    result = unnumbered_ospf()
    if result is False:
        st.error('Module config Failed - OSPF configuration failed')
        unnumbered_ospf(config = 'no')
        base_interfaces(config = 'no')
        pytest.skip()

def module_config_scale():
    dut_intf_config()
    result = base_interfaces_scale()
    if result is False:
        st.error('Module config Failed - Base interfaces/Loopback configuration failed')
        base_interfaces_scale(config = 'no')
        pytest.skip()
    result = unnumbered_ospf_scale()
    if result is False:
        st.error('Module config Failed - OSPF configuration failed')
        unnumbered_ospf_scale(config = 'no')
        base_interfaces_scale(config = 'no')
        pytest.skip()

def module_unconfig_scale():
    unnumbered_ospf_scale(config = 'no')
    dut_intf_config(config = 'no')
    base_interfaces_scale(config = 'no')

def module_unconfig():
    dict1 ={"interface":'PortChannel1','neighbor_ip':dut2_loopback_ip[0],'config':'no'}
    dict2 ={"interface":'PortChannel1','neighbor_ip':dut1_loopback_ip[0],'config':'no'}
    parallel.exec_parallel(True,[data.dut1,data.dut2],bfd_obj.configure_bfd,[dict1,dict2])
    dict1 ={"interface":data.d2_d3_ports[0],'neighbor_ip':dut3_loopback_ip[0],'config':'no'}
    dict2 ={"interface":data.d3_d2_ports[0],'neighbor_ip':dut2_loopback_ip[0],'config':'no'}
    parallel.exec_parallel(True,[data.dut2,data.dut3],bfd_obj.configure_bfd,[dict1,dict2])
    unnumbered_ospf(config = 'no')
    dut_intf_config(config = 'no')
    utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, 'PortChannel1', dut1_dut2_ipv6[0], 64,'ipv6'],
                         [ip_obj.delete_ip_interface, data.dut2, 'PortChannel1', dut2_dut1_ipv6[0], 64,'ipv6']])
    ipv6_bgp_unconfig()
    base_interfaces(config = 'no')

def base_interfaces_scale(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        result = True
        st.log('Configure loopback interface on all the DUTs')
        dict1 = {'config':'yes','loopback_name':dut1_loopback[0]}
        dict2 = {'config':'yes','loopback_name':dut2_loopback[0]}
        dict3 = {'config':'yes','loopback_name':dut3_loopback[0]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])
        dict1 = {'config':'yes','loopback_name':dut1_loopback[1]}
        dict2 = {'config':'yes','loopback_name':dut2_loopback[1]}
        dict3 = {'config':'yes','loopback_name':dut3_loopback[1]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])

        st.banner('Configure IPv4 addresses on the loopback interfaces')
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, dut1_loopback[0], dut1_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut2, dut2_loopback[0], dut2_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut3, dut3_loopback[0], dut3_loopback_ip[0], ip_loopback_prefix,'ipv4']])
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, dut1_loopback[1], dut1_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut2, dut2_loopback[1], dut2_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut3, dut3_loopback[1], dut3_loopback_ip[1], ip_loopback_prefix,'ipv4']])
        return result
    else:
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, dut1_loopback[0], dut1_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut2, dut2_loopback[0], dut2_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut3, dut3_loopback[0], dut3_loopback_ip[0], ip_loopback_prefix,'ipv4']])
        dict1 = {'config':'no','loopback_name':dut1_loopback[0]}
        dict2 = {'config':'no','loopback_name':dut2_loopback[0]}
        dict3 = {'config':'no','loopback_name':dut3_loopback[0]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, dut1_loopback[1], dut1_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut2, dut2_loopback[1], dut2_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut3, dut3_loopback[1], dut3_loopback_ip[1], ip_loopback_prefix,'ipv4']])
        dict1 = {'config':'no','loopback_name':dut1_loopback[1]}
        dict2 = {'config':'no','loopback_name':dut2_loopback[1]}
        dict3 = {'config':'no','loopback_name':dut3_loopback[1]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])

def unnumbered_ospf_scale(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        result = True
        utils.exec_all(True,[[ospf_obj.config_ospf_router_id, data.dut1, dut1_router_id, 'default', '','yes'],
                             [ospf_obj.config_ospf_router_id, data.dut2, dut2_router_id, 'default', '','yes'],
                             [ospf_obj.config_ospf_router_id, data.dut3, dut3_router_id, 'default', '','yes']])

        utils.exec_all(True,[[ospf_obj.config_ospf_network, data.dut1, dut1_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes'],
                             [ospf_obj.config_ospf_network, data.dut2, dut2_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes'],
                             [ospf_obj.config_ospf_network, data.dut3, dut3_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes']])

        for d12ports, d21ports in zip(data.d1_d2_ports, data.d2_d1_ports): 
            utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, d12ports,'point-to-point','default','yes'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, d21ports,'point-to-point','default','yes']])

        for d23ports, d32ports in zip(data.d2_d3_ports, data.d3_d2_ports): 
            utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut2, d23ports,'point-to-point','default','yes'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut3, d32ports,'point-to-point','default','yes']])

        result = utils.exec_all(True,[[ospf_obj.config_ospf_router_redistribute, data.dut1, 'connected'],
                             [ospf_obj.config_ospf_router_redistribute, data.dut2, 'connected'],
                             [ospf_obj.config_ospf_router_redistribute, data.dut3, 'connected']])
        return result

    else:
        for d12ports, d21ports in zip(data.d1_d2_ports, data.d2_d1_ports): 
            utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, d12ports,'point-to-point','default','no'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, d21ports,'point-to-point','default','no']])

        for d23ports, d32ports in zip(data.d2_d3_ports, data.d3_d2_ports): 
            utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut2, d23ports,'point-to-point','default','no'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut3, d32ports,'point-to-point','default','no']])

        utils.exec_all(True,[[ospf_obj.config_ospf_router, data.dut1, 'default', '','no'],
                             [ospf_obj.config_ospf_router, data.dut2, 'default', '','no'],
                             [ospf_obj.config_ospf_router, data.dut3, 'default', '','no']])

def base_interfaces(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        result = True
        st.log('Configure loopback interface on all the DUTs')
        dict1 = {'config':'yes','loopback_name':dut1_loopback[0]}
        dict2 = {'config':'yes','loopback_name':dut2_loopback[0]}
        dict3 = {'config':'yes','loopback_name':dut3_loopback[0]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])
        dict1 = {'config':'yes','loopback_name':dut1_loopback[1]}
        dict2 = {'config':'yes','loopback_name':dut2_loopback[1]}
        dict3 = {'config':'yes','loopback_name':dut3_loopback[1]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])

        st.banner('Configure IPv4 addresses on the loopback interfaces')
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, dut1_loopback[0], dut1_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut2, dut2_loopback[0], dut2_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut3, dut3_loopback[0], dut3_loopback_ip[0], ip_loopback_prefix,'ipv4']])
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, dut1_loopback[1], dut1_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut2, dut2_loopback[1], dut2_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.config_ip_addr_interface, data.dut3, dut3_loopback[1], dut3_loopback_ip[1], ip_loopback_prefix,'ipv4']])
        st.log('Configure port channel between DUT1 and DUT2')
        utils.exec_all(True, [[pc_obj.create_portchannel, data.dut1, 'PortChannel1'], [pc_obj.create_portchannel, data.dut2, 'PortChannel1']])
        result = utils.exec_all(True, [[pc_obj.add_portchannel_member, data.dut1, 'PortChannel1',[data.d1_d2_ports[0],data.d1_d2_ports[1]]], [pc_obj.add_portchannel_member, data.dut2, 'PortChannel1',[data.d2_d1_ports[0],data.d2_d1_ports[1]]]])
        return result
    else:
        dict2 = {'family':'ipv4', 'action':'del', 'interface':data.d2_d3_ports[0], 'loop_back':dut2_loopback[0]}
        dict3 = {'family':'ipv4', 'action':'del', 'interface':data.d3_d2_ports[0], 'loop_back':dut3_loopback[0]}
        parallel.exec_parallel(True, [data.dut2, data.dut3], ip_obj.config_unnumbered_interface, [dict2, dict3])
        dict1 = {'family':'ipv4', 'action':'del', 'interface':'PortChannel1', 'loop_back':dut1_loopback[0]}
        dict2 = {'family':'ipv4', 'action':'del', 'interface':'PortChannel1', 'loop_back':dut2_loopback[0]}
        parallel.exec_parallel(True, [data.dut1, data.dut2], ip_obj.config_unnumbered_interface, [dict1, dict2])
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, dut1_loopback[0], dut1_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut2, dut2_loopback[0], dut2_loopback_ip[0], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut3, dut3_loopback[0], dut3_loopback_ip[0], ip_loopback_prefix,'ipv4']])
        dict1 = {'config':'no','loopback_name':dut1_loopback[0]}
        dict2 = {'config':'no','loopback_name':dut2_loopback[0]}
        dict3 = {'config':'no','loopback_name':dut3_loopback[0]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, dut1_loopback[1], dut1_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut2, dut2_loopback[1], dut2_loopback_ip[1], ip_loopback_prefix,'ipv4'],
                             [ip_obj.delete_ip_interface, data.dut3, dut3_loopback[1], dut3_loopback_ip[1], ip_loopback_prefix,'ipv4']])
        dict1 = {'config':'no','loopback_name':dut1_loopback[1]}
        dict2 = {'config':'no','loopback_name':dut2_loopback[1]}
        dict3 = {'config':'no','loopback_name':dut3_loopback[1]}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], ip_obj.configure_loopback, [dict1, dict2, dict3])
        st.log('Unconfigure port channel between DUT1 and DUT2 ')
        utils.exec_all(True, [[pc_obj.add_del_portchannel_member, data.dut1, 'PortChannel1',[data.d1_d2_ports[0],data.d1_d2_ports[1]],'del'], [pc_obj.add_del_portchannel_member, data.dut2, 'PortChannel1',[data.d2_d1_ports[0],data.d2_d1_ports[1]],'del']])

        utils.exec_all(True, [[pc_obj.delete_portchannel, data.dut1, 'PortChannel1'], [pc_obj.delete_portchannel, data.dut2, 'PortChannel1']])

def unnumbered_ospf(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        result = True
        utils.exec_all(True,[[ospf_obj.config_ospf_router_id, data.dut1, dut1_router_id, 'default', '','yes'],
                             [ospf_obj.config_ospf_router_id, data.dut2, dut2_router_id, 'default', '','yes'],
                             [ospf_obj.config_ospf_router_id, data.dut3, dut3_router_id, 'default', '','yes']])

        utils.exec_all(True,[[ospf_obj.config_ospf_network, data.dut1, dut1_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes'],
                             [ospf_obj.config_ospf_network, data.dut2, dut2_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes'],
                             [ospf_obj.config_ospf_network, data.dut3, dut3_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','yes']])

        utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, 'PortChannel1','point-to-point','default','yes'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, 'PortChannel1','point-to-point','default','yes'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut3, data.d3_d2_ports[0],'point-to-point','default','yes']])

        ospf_obj.config_interface_ip_ospf_network_type(data.dut2, data.d2_d3_ports[0],'point-to-point','default','yes')

        result = utils.exec_all(True,[[ospf_obj.config_ospf_router_redistribute, data.dut1, 'connected'],
                             [ospf_obj.config_ospf_router_redistribute, data.dut2, 'connected'],
                             [ospf_obj.config_ospf_router_redistribute, data.dut3, 'connected']])
        return result

    else:
        utils.exec_all(True,[[ospf_obj.config_interface_ip_ospf_network_type, data.dut1, 'PortChannel1','point-to-point','default','no'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut2, 'PortChannel1','point-to-point','default','no'],
                             [ospf_obj.config_interface_ip_ospf_network_type, data.dut3, data.d3_d2_ports[0],'point-to-point','default','no']])

        utils.exec_all(True,[[ospf_obj.config_ospf_network, data.dut1, dut1_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','no'],
                             [ospf_obj.config_ospf_network, data.dut2, dut2_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','no'],
                             [ospf_obj.config_ospf_network, data.dut3, dut3_loopback_ip[0]+'/'+ip_loopback_prefix, 0, 'default', '','no']])

        ospf_obj.config_interface_ip_ospf_network_type(data.dut2, data.d2_d3_ports[0],'point-to-point','default','no')

        utils.exec_all(True,[[ospf_obj.config_ospf_router, data.dut1, 'default', '','no'],
                             [ospf_obj.config_ospf_router, data.dut2, 'default', '','no'],
                             [ospf_obj.config_ospf_router, data.dut3, 'default', '','no']])

def bgp_router_id(**kwargs):
        dict1 = {'router_id':dut1_router_id,'local_as':dut1_as,'config_type_list':['router_id']}
        dict2 = {'router_id':dut2_router_id,'local_as':dut2_as,'config_type_list':['router_id']}
        dict3 = {'router_id':dut3_router_id,'local_as':dut3_as,'config_type_list':['router_id']}

        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp, [dict1, dict2, dict3])

def ipv6_bgp(**kwargs):
    if 'type' in kwargs:
        type = kwargs['type']
    else:
        type = 'unnumbered'
    if type == 'unnumbered':
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'enable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'enable']])
        dict1 = {'addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list': ['remote-as','activate'], 'interface': 'PortChannel1','neighbor': 'PortChannel1'}
        dict2 = {'addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list': ['remote-as','activate'], 'interface': 'PortChannel1','neighbor': 'PortChannel1'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    elif type == 'normal':
        dict1 = {'local_as':dut1_as,'addr_family':'ipv6','neighbor':dut2_dut1_ipv6[0],'remote_as':dut2_as,'config_type_list':['neighbor']}
        dict2 = {'local_as':dut2_as,'addr_family':'ipv6','neighbor':dut1_dut2_ipv6[0],'remote_as':dut1_as,'config_type_list':['neighbor']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
        dict1 = {'local_as':dut1_as,'addr_family':'ipv6','neighbor':dut2_dut1_ipv6[0],'remote_as':dut2_as,'config_type_list':['activate']}
        dict2 = {'local_as':dut2_as,'addr_family':'ipv6','neighbor':dut1_dut2_ipv6[0],'remote_as':dut1_as,'config_type_list':['activate']}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])

def bgp_unconfig():
        dict1 = {'config':'no','local_as':dut1_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'config':'no','local_as':dut2_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict3 = {'config':'no','local_as':dut3_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp, [dict1, dict2, dict3])

def ipv6_bgp_unconfig():
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'disable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'disable']])

def dut_intf_config(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':

        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, data.dut1_tg_ports[0], dut1_tg_ipv6[0], dut1_tg_ipv6_subnet,'ipv6'], [ip_obj.config_ip_addr_interface, data.dut3, data.dut3_tg_ports[0], dut3_tg_ipv6[0], dut3_tg_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, data.dut1_tg_ports[0], dut1_tg_ip[0], dut1_tg_ip_subnet,'ipv4'], [ip_obj.config_ip_addr_interface, data.dut3, data.dut3_tg_ports[0], dut3_tg_ip[0], dut3_tg_ip_subnet, 'ipv4']])
        arp_obj.add_static_arp(data.dut3, tg_dut3_ip[0], '00:00:33:33:33:01', data.dut3_tg_ports[0])
        arp_obj.config_static_ndp(data.dut3, tg_dut3_ipv6[0], '00:00:33:33:33:02', data.dut3_tg_ports[0], operation="add")
    else:
        arp_obj.config_static_ndp(data.dut3, tg_dut3_ipv6[0], '00:00:33:33:33:02', data.dut3_tg_ports[0], operation="del")
        arp_obj.delete_static_arp(data.dut3, tg_dut3_ip[0], '00:00:33:33:33:01')
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, data.dut1_tg_ports[0], dut1_tg_ipv6[0], dut1_tg_ipv6_subnet,'ipv6'], [ip_obj.delete_ip_interface, data.dut3, data.dut3_tg_ports[0], dut3_tg_ipv6[0], dut3_tg_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, data.dut1_tg_ports[0], dut1_tg_ip[0], dut1_tg_ip_subnet,'ipv4'], [ip_obj.delete_ip_interface, data.dut3, data.dut3_tg_ports[0], dut3_tg_ip[0], dut3_tg_ip_subnet, 'ipv4']])

def redistribute_routes(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        st.log('Configure redistribute connected on all the DUTs for IPv4 and IPv6 address families')
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv4','unicast','connected','yes'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv4','unicast','connected','yes'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv4','unicast','connected','yes']])
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv6','unicast','connected','yes'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv6','unicast','connected','yes'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv6','unicast','connected','yes']])
    else:
        st.log('Configure redistribute connected on all the DUTs for IPv4 and IPv6 address families')
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv4','unicast','connected','no'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv4','unicast','connected','no'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv4','unicast','connected','no']])
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv6','unicast','connected','yes'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv6','unicast','connected','no'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv6','unicast','connected','no']])

def tg_streams(**kwargs):
    st.banner('Configure IPv4 raw streams on DUT1 and DUT3')
    d1_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut1,'eth0')
    d3_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut3,'eth0')
    st1 = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p1, port_handle2 = data.tg_dut3_p1, duration = 5, mac_src='00:11:01:00:00:01', mac_dst = str(d1_gateway_mac), l2_encap = 'ethernet_ii', ip_src_addr = tg_dut1_ip[0], ip_dst_addr = tg_dut3_ip[0], l3_protocol='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    data.d1_stream_list.update({'stream_v4_d1_p1':st1['stream_id']})

    # st.banner('Configure IPv6 raw stream on DUT1 and DUT3')
    # st3 = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p1, port_handle2 = data.tg_dut3_p1, mac_src = '00:22:02:00:00:02', mac_dst = str(d1_gateway_mac),  l2_encap = 'ethernet_ii', ipv6_src_addr = tg_dut1_ipv6[0], ipv6_dst_addr = tg_dut3_ipv6[0], l3_protocol='ipv6', mode='create',transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    # data.d1_stream_list.update({'stream_v6_d1_p1':st3['stream_id']})

def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 10)
    delay = kwargs.get("delay", 3)
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

def reset_streams(**kwargs):
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut1_p1)
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut3_p1)
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut1_p2)
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut3_p2)

def send_verify_traffic(**kwargs):
    if 'dut' in kwargs:
        dut = kwargs['dut']
    else:
        dut = data.dut1
    if 'type' in kwargs:
        type = kwargs['type']
    else:
        type = 'both'
    if dut == data.dut1:
        st.log('Send and verify IPv4 and IPv6 traffic')
        #data.tg.tg_traffic_control(action = 'run', port_handle = data.tg_dut1_p1, duration = 5)
        data.tg.tg_traffic_control(action = 'run', stream_handle = data.d1_stream_list.values(), duration = 5)
        if type == 'ipv4':
            traffic_details = {'1': {'tx_ports' : [data.tg_dut1_ports[0]],'tx_obj' : [data.tg],'exp_ratio' : [1],'rx_ports' : [data.tg_dut3_ports[0]],'rx_obj' : [data.tg], 'stream_list' : [[data.d1_stream_list.get('stream_v4_d1_p1')]]}}
        elif type == 'ipv6':
            traffic_details = {'1': {'tx_ports' : [data.tg_dut1_ports[0]],'tx_obj' : [data.tg],'exp_ratio' : [1],'rx_ports' : [data.tg_dut3_ports[0]],'rx_obj' : [data.tg], 'stream_list' : [[data.d1_stream_list.get('stream_v6_d1_p1')]]}}
        else:
            traffic_details = {'1': {'tx_ports' : [data.tg_dut1_ports[0]],'tx_obj' : [data.tg],'exp_ratio' : [1,1],'rx_ports' : [data.tg_dut3_ports[0]],'rx_obj' : [data.tg], 'stream_list' : [data.d1_stream_list.values()]}}
        #data.tg.tg_traffic_control(action = 'stop', port_handle = data.tg_dut1_p1)
        data.tg.tg_traffic_control(action = 'stop', stream_handle = data.d1_stream_list.values())
        aggrResult = validate_tgen_traffic(traffic_details = traffic_details, mode = 'streamblock', comp_type = 'packet_count', delay_factor = data.delay_factor)
    return aggrResult
