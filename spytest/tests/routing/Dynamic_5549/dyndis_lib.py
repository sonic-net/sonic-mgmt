#################################################################################
#Script Title : BGP Dynamic Discovery and BGP unnumbered
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

#################################################################################

from spytest import st,utils
import utilities.common as utils
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *

from dyndis_vars import * #all the variables used for the testcase
from dyndis_vars import data
from utilities import parallel


import apis.switching.mac as mac_obj
import apis.switching.portchannel as pc_obj

import apis.switching.vlan as vlan_obj
import apis.system.basic as basic_obj

import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.routing.bgp as bgp_obj
import apis.routing.arp as arp_obj


from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *

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

def debug_failure():
    st.log('Dubug commands starts!')
    # cmd_list = ['show arp','show ndp','show ip route','show ipv6 route','show interface counters']
    # utils.exec_all(True, [[st.apply_script, data.dut1, cmd_list], [st.apply_script, data.dut2, cmd_list], [st.apply_script, data.dut3, cmd_list]])
    # st.log('End of Dubug commands')

def module_config():
    base_interfaces(pc = '1')
    bgp_router_id()
    bgp_unnumbered(pc = '1')
    bgp_dynamic_neigh()
    redistribute_routes()
    dut_intf_config()

def module_unconfig():
    base_interfaces(pc = '1',config = 'no')
    dut_intf_config(config = 'no')
    # bgp_unconfig()

def base_interfaces(**kwargs):
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

    if pc != '' and config == '':
        st.log('Configure port channel between DUT1 and DUT2')
        utils.exec_all(True, [[pc_obj.create_portchannel, data.dut1, 'PortChannel1'], [pc_obj.create_portchannel, data.dut2, 'PortChannel1']])
        utils.exec_all(True, [[pc_obj.add_portchannel_member, data.dut1, 'PortChannel1',[data.d1_d2_ports[0],data.d1_d2_ports[1]]], [pc_obj.add_portchannel_member, data.dut2, 'PortChannel1',[data.d2_d1_ports[0],data.d2_d1_ports[1]]]])

        st.log('Configure a port channel between DUT2 and DUT3 for IPv6 traffic')
        utils.exec_all(True, [[pc_obj.create_portchannel, data.dut2, 'PortChannel2'], [pc_obj.create_portchannel, data.dut3, 'PortChannel2']])
        utils.exec_all(True, [[pc_obj.add_portchannel_member, data.dut2, 'PortChannel2',[data.d2_d3_ports[0]]], [pc_obj.add_portchannel_member, data.dut3, 'PortChannel2',[data.d3_d2_ports[0]]]])

        st.log('Configure a port channel between DUT2 and DUT3 for IPv4 traffic')
        utils.exec_all(True, [[pc_obj.create_portchannel, data.dut2, 'PortChannel3'], [pc_obj.create_portchannel, data.dut3, 'PortChannel3']])
        utils.exec_all(True, [[pc_obj.add_portchannel_member, data.dut2, 'PortChannel3',[data.d2_d3_ports[2]]], [pc_obj.add_portchannel_member, data.dut3, 'PortChannel3',[data.d3_d2_ports[2]]]])

        st.banner('Enable IPv6 link local configuration on PortChannel1 between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'enable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'enable']])

        st.banner('Configure IPv4 and IPv6 addresses on port channel between DUT2 and DUT3')
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut2, 'PortChannel2', dut2_dut3_ipv6[0], dut2_dut3_ipv6_subnet,'ipv6'], [ip_obj.config_ip_addr_interface, data.dut3, 'PortChannel2', dut3_dut2_ipv6[0], dut3_dut2_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut2, 'PortChannel3', dut2_dut3_ip[0], dut2_dut3_ip_subnet,'ipv4'], [ip_obj.config_ip_addr_interface,data.dut3, 'PortChannel3', dut3_dut2_ip[0], dut3_dut2_ip_subnet, 'ipv4']])

    elif pc != '' and config == 'no':
        st.log('Unconfigure IPv4 and IPv6 addresses on port channel between DUT2 and DUT3')
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut2, 'PortChannel2', dut2_dut3_ipv6[0], dut2_dut3_ipv6_subnet,'ipv6'], [ip_obj.delete_ip_interface, data.dut3, 'PortChannel2', dut3_dut2_ipv6[0], dut3_dut2_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut2, 'PortChannel3', dut2_dut3_ip[0], dut2_dut3_ip_subnet,'ipv4'], [ip_obj.delete_ip_interface,data.dut3, 'PortChannel3', dut3_dut2_ip[0], dut3_dut2_ip_subnet, 'ipv4']])

        st.log('Disable IPv6 link local configuration on PortChannel1 between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'PortChannel1', 'disable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'PortChannel1', 'disable']])

        st.log('Unconfigure port channel between DUT1 and DUT2 ')
        utils.exec_all(True, [[pc_obj.add_del_portchannel_member, data.dut1, 'PortChannel1',[data.d1_d2_ports[0],data.d1_d2_ports[1]],'del'], [pc_obj.add_del_portchannel_member, data.dut2, 'PortChannel1',[data.d2_d1_ports[0],data.d2_d1_ports[1]],'del']])

        utils.exec_all(True, [[pc_obj.delete_portchannel, data.dut1, 'PortChannel1'], [pc_obj.delete_portchannel, data.dut2, 'PortChannel1']])

        st.log('Unconfigure port channel between DUT2 and DUT3 for IPv6 traffic ')
        utils.exec_all(True, [[pc_obj.add_del_portchannel_member, data.dut2, 'PortChannel2',[data.d2_d3_ports[0]],'del'], [pc_obj.add_del_portchannel_member, data.dut3, 'PortChannel2',[data.d3_d2_ports[0]],'del']])
        utils.exec_all(True, [[pc_obj.delete_portchannel, data.dut2, 'PortChannel2'], [pc_obj.delete_portchannel, data.dut3, 'PortChannel2']])

        st.log('Unconfigure port channel between DUT2 and DUT3 for IPv4 traffic ')
        utils.exec_all(True, [[pc_obj.add_del_portchannel_member, data.dut2, 'PortChannel3',[data.d2_d3_ports[2]],'del'], [pc_obj.add_del_portchannel_member, data.dut3, 'PortChannel3',[data.d3_d2_ports[2]],'del']])
        utils.exec_all(True, [[pc_obj.delete_portchannel, data.dut2, 'PortChannel3'], [pc_obj.delete_portchannel, data.dut3, 'PortChannel3']])

    if phy != '' and config == '':
        st.banner('Enable IPv6 link local configuration on physical interface between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, data.d1_d2_ports[2], 'enable'],[ip_obj.config_interface_ip6_link_local, data.dut2, data.d2_d1_ports[2], 'enable']])
    elif phy != '' and config == 'no':
        st.log('Disable IPv6 link local configuration on physical interface between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, data.d1_d2_ports[2], 'disable'],[ip_obj.config_interface_ip6_link_local, data.dut2, data.d2_d1_ports[2], 'disable']])

    if ve != '' and config == '':
        st.log('Configure vlan interfaces between DUT1 and DUT2------######')
        utils.exec_all(True, [[vlan_obj.create_vlan, data.dut1, dut1_dut2_vlan], [vlan_obj.create_vlan, data.dut2, dut1_dut2_vlan]])
        utils.exec_all(True,[[vlan_obj.add_vlan_member,data.dut1,dut1_dut2_vlan,data.d1_d2_ports[3],True,True], [vlan_obj.add_vlan_member,data.dut2,dut1_dut2_vlan, data.d2_d1_ports[3],True,True]])
        st.banner('Enable IPv6 link local configuration on vlan between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'Vlan'+dut1_dut2_vlan, 'enable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'Vlan'+dut1_dut2_vlan, 'enable']])

    elif ve != '' and config == 'no':
        st.log('Disable IPv6 link local configuration on vlan between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, 'Vlan'+dut1_dut2_vlan, 'disable'],[ip_obj.config_interface_ip6_link_local, data.dut2, 'Vlan'+dut1_dut2_vlan, 'disable']])
        utils.exec_all(True,[[vlan_obj.delete_vlan_member,data.dut1,dut1_dut2_vlan,data.d1_d2_ports[3], True], [vlan_obj.delete_vlan_member,data.dut2,dut1_dut2_vlan, data.d2_d1_ports[3], True]])
        utils.exec_all(True, [[vlan_obj.delete_vlan, data.dut1, dut1_dut2_vlan], [vlan_obj.delete_vlan, data.dut2, dut1_dut2_vlan]])

def bgp_unnumbered(**kwargs):
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

    if pc != '' and config == '':
        st.banner('Configure BGP Unnumbered peers on port channel')
        dict1 = {'addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list': ['remote-as'], 'interface': 'PortChannel1','neighbor': 'PortChannel1'}
        dict2 = {'addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list': ['remote-as'], 'interface': 'PortChannel1','neighbor': 'PortChannel1'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
        dict1 = {'local_asn':dut1_as,'neighbor_ip': 'PortChannel1','family':'ipv4','config':'yes', 'vrf':'default','remote_asn':dut2_as}
        dict2 = {'local_asn':dut2_as,'neighbor_ip': 'PortChannel1','family':'ipv4','config':'yes', 'vrf':'default','remote_asn':dut1_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
        dict1 = {'local_asn':dut1_as,'neighbor_ip': 'PortChannel1','family':'ipv6','config':'yes', 'vrf':'default','remote_asn':dut2_as}
        dict2 = {'local_asn':dut2_as,'neighbor_ip': 'PortChannel1','family':'ipv6','config':'yes', 'vrf':'default','remote_asn':dut1_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
    elif pc != '' and config == 'no':
        st.banner('Unconfigure BGP Unnumbered peers on port channel')
        dict1 = {'config':'no','addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list': ['neighbor'], 'interface': 'PortChannel1','neighbor': 'PortChannel1'}
        dict2 = {'config':'no','addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list': ['neighbor'], 'interface': 'PortChannel1','neighbor': 'PortChannel1'}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    if ve != '' and config == '':
        st.banner('Configure BGP Unnumbered peers on vlan')
        dict1 = {'addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list':['remote-as'],'interface':'Vlan'+dut1_dut2_vlan,'neighbor':'Vlan'+dut1_dut2_vlan}
        dict2 = {'addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list':['remote-as'],'interface':'Vlan'+dut1_dut2_vlan,'neighbor':'Vlan'+dut1_dut2_vlan}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
        dict1 = {'local_asn':dut1_as,'neighbor_ip': 'Vlan'+dut1_dut2_vlan,'family':'ipv4','config':'yes','vrf':'default','remote_asn':dut2_as}
        dict2 = {'local_asn':dut2_as,'neighbor_ip': 'Vlan'+dut1_dut2_vlan,'family':'ipv4','config':'yes','vrf':'default','remote_asn':dut1_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
        dict1 = {'local_asn':dut1_as,'neighbor_ip': 'Vlan'+dut1_dut2_vlan,'family':'ipv6','config':'yes','vrf':'default','remote_asn':dut2_as}
        dict2 = {'local_asn':dut2_as,'neighbor_ip': 'Vlan'+dut1_dut2_vlan,'family':'ipv6','config':'yes','vrf':'default','remote_asn':dut1_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
    elif ve != '' and config == 'no':
        st.banner('Unconfigure BGP Unnumbered peers on vlan')
        dict1 = {'config':'no','addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list':['neighbor'],'interface':'Vlan'+dut1_dut2_vlan,'neighbor':'Vlan'+dut1_dut2_vlan}
        dict2 = {'config':'no','addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list':['neighbor'],'interface':'Vlan'+dut1_dut2_vlan,'neighbor':'Vlan'+dut1_dut2_vlan}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
    if phy != '' and config == '':
        st.banner('Configure BGP Unnumbered peers on physical interface')
        dict1 = {'addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list':['remote-as'],'interface':data.d1_d2_ports[2],'neighbor':data.d1_d2_ports[2]}
        dict2 = {'addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list':['remote-as'],'interface':data.d2_d1_ports[2],'neighbor':data.d2_d1_ports[2]}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
        dict1 = {'local_asn':dut1_as,'neighbor_ip': data.d1_d2_ports[2],'family':'ipv4','config':'yes','vrf':'default','remote_asn':dut2_as}
        dict2 = {'local_asn':dut2_as,'neighbor_ip': data.d2_d1_ports[2],'family':'ipv4','config':'yes','vrf':'default','remote_asn':dut1_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
        dict1 = {'local_asn':dut1_as,'neighbor_ip': data.d1_d2_ports[2],'family':'ipv6','config':'yes','vrf':'default','remote_asn':dut2_as}
        dict2 = {'local_asn':dut2_as,'neighbor_ip': data.d2_d1_ports[2],'family':'ipv6','config':'yes','vrf':'default','remote_asn':dut1_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
    elif phy != '' and config == 'no':
        st.banner('Unconfigure BGP Unnumbered peers on physical interface')
        dict1 = {'config':'no','addr_family':'ipv6','local_as':dut1_as,'remote_as':dut2_as,'config_type_list':['neighbor'],'interface':data.d1_d2_ports[2],'neighbor':data.d1_d2_ports[2]}
        dict2 = {'config':'no','addr_family':'ipv6','local_as':dut2_as,'remote_as':dut1_as,'config_type_list':['neighbor'],'interface':data.d2_d1_ports[2],'neighbor':data.d2_d1_ports[2]}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])

def bgp_router_id(**kwargs):
    dict1 = {'router_id':dut1_router_id,'local_as':dut1_as,'config_type_list':['router_id']}
    dict2 = {'router_id':dut2_router_id,'local_as':dut2_as,'config_type_list':['router_id']}
    dict3 = {'router_id':dut3_router_id,'local_as':dut3_as,'config_type_list':['router_id']}
    parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp, [dict1, dict2, dict3])

def bgp_dynamic_neigh(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''

    if config == '':
        st.log('Configure peergrougs on DUT2')
        bgp_obj.create_bgp_peergroup(data.dut2, dut2_as,'d2d3_v4_peer',dut3_as,60,180,None,'default','ipv4')
        bgp_obj.create_bgp_peergroup(data.dut2, dut2_as,'d2d3_v6_peer',dut3_as,60,180,None,'default','ipv6')
        bgp_obj.create_bgp_peergroup(data.dut3, dut3_as,'d2d3_v4_peer',dut2_as,60,180,None,'default','ipv4',neighbor_ip = dut2_dut3_ip[0])
        bgp_obj.create_bgp_peergroup(data.dut3, dut3_as,'d2d3_v6_peer',dut2_as,60,180,None,'default','ipv6',neighbor_ip = dut2_dut3_ipv6[0])
        st.banner('Configure BGP listen range on DUT2 for Ipv4 and Ipv6 addresses')
        bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, neighbor_address = '2.0.1.0', subnet = dut3_dut2_ip_subnet, peer_grp_name = 'd2d3_v4_peer', limit = 2, config = 'yes')
        bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as, neighbor_address = '2001::', subnet = dut3_dut2_ipv6_subnet, peer_grp_name = 'd2d3_v6_peer', limit = 2, config = 'yes')
        bgp_obj.activate_bgp_neighbor(data.dut3,dut3_as,dut2_dut3_ip[0],'ipv4',remote_asn = dut2_as)
        bgp_obj.activate_bgp_neighbor(data.dut3,dut3_as,dut2_dut3_ipv6[0],'ipv6',remote_asn = dut2_as)
    else:
        dict1 = {'local_as':dut2_as,'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'local_as':dut3_as,'config':'no','removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut2, data.dut3], bgp_obj.config_bgp, [dict1, dict2])

def bgp_unconfig():
        dict1 = {'config':'no','local_as':dut1_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'config':'no','local_as':dut2_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict3 = {'config':'no','local_as':dut3_as,'removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp, [dict1, dict2, dict3])

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
        st.log('Configure redistribute connected on all the DUTs for IPv4 and IPv6 address families ')
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv4','unicast','connected','yes'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv4','unicast','connected','yes'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv4','unicast','connected','yes']])
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv6','unicast','connected','yes'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv6','unicast','connected','yes'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv6','unicast','connected','yes']])
    else:
        st.log('Unconfigure redistribute connected on all the DUTs for IPv4 and IPv6 address families')
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv4','unicast','connected','no'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv4','unicast','connected','no'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv4','unicast','connected','no']])
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as,'ipv6','unicast','connected','yes'], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as,'ipv6','unicast','connected','no'],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as,'ipv6','unicast','connected','no']])

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
    if dut == data.dut1:
        st.log('Send and verify IPv4 and IPv6 traffic')
        #data.tg.tg_traffic_control(action = 'run', port_handle = data.tg_dut1_p1, duration = 5)
        data.tg.tg_traffic_control(action = 'run', stream_handle = data.d1_stream_list.values(), duration = 5)
        traffic_details = {'1': {'tx_ports' : [data.tg_dut1_ports[0]],'tx_obj' : [data.tg],'exp_ratio' : [1,1],'rx_ports' : [data.tg_dut3_ports[0]],'rx_obj' : [data.tg], 'stream_list' : [data.d1_stream_list.values()]}}
        #data.tg.tg_traffic_control(action = 'stop', port_handle = data.tg_dut1_p1)
        data.tg.tg_traffic_control(action = 'stop', stream_handle = data.d1_stream_list.values())
        aggrResult = validate_tgen_traffic(traffic_details = traffic_details, mode = 'streamblock', comp_type = 'packet_count', delay_factor = data.delay_factor)
    return aggrResult

def config_vrf_base(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        st.log('Configure non default VRFs on all the DUTs')
        dict1 = {'vrf_name': dut1_vrf, 'skip_error': True}
        dict2 = {'vrf_name': dut2_vrf, 'skip_error': True}
        dict3 = {'vrf_name': dut3_vrf, 'skip_error': True}
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], vrf_obj.config_vrf, [dict1, dict2, dict3])

        st.log('Bind DUT interfaces to the VRFs')
        dict1 = {'vrf_name': dut1_vrf, 'intf_name': data.d1_d2_ports[3], 'skip_error': True}
        dict2 = {'vrf_name': dut2_vrf, 'intf_name': data.d2_d1_ports[3], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut1,data.dut2], vrf_obj.bind_vrf_interface, [dict1, dict2])
        dict2 = {'vrf_name': dut2_vrf, 'intf_name': data.d2_d3_ports[1], 'skip_error': True}
        dict3 = {'vrf_name': dut3_vrf, 'intf_name': data.d3_d2_ports[1], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut2,data.dut3], vrf_obj.bind_vrf_interface, [dict2, dict3])
        dict2 = {'vrf_name': dut2_vrf, 'intf_name': data.d2_d3_ports[3], 'skip_error': True}
        dict3 = {'vrf_name': dut3_vrf, 'intf_name': data.d3_d2_ports[3], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut2,data.dut3], vrf_obj.bind_vrf_interface, [dict2, dict3])

        st.log('Bind TG interfaces to the VRFs')
        dict1 = {'vrf_name': dut1_vrf, 'intf_name': data.dut1_tg_ports[1], 'skip_error': True}
        dict3 = {'vrf_name': dut3_vrf, 'intf_name': data.dut3_tg_ports[1], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut1,data.dut3], vrf_obj.bind_vrf_interface, [dict1, dict3])

        # st.log('Configure IPv4 and IPv6 addresses on the VRF interfaces between DUT1 and DUT2')
        # utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, d1_d2_ports[3], dut1_dut2_ipv6[3], dut1_dut2_ipv6_subnet,'ipv6'], [ip_obj.config_ip_addr_interface, data.dut2, d2_d1_ports[3], dut2_dut1_ipv6[0], dut2_dut1_ipv6_subnet, 'ipv6']])
        # utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, d1_d2_ports[3], dut1_dut2_ip[3], dut1_dut2_ip_subnet,'ipv4'], [ip_obj.config_ip_addr_interface, data.dut2, d2_d1_ports[3], dut2_dut1_ip[0], dut2_dut1_ip_subnet, 'ipv4']])

        st.log('Configure IPv4 and IPv6 addresses on the VRF interfaces between DUT2 and DUT3')
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut2, data.d2_d3_ports[1], dut2_dut3_ipv6[0], dut2_dut3_ipv6_subnet,'ipv6'], [ip_obj.config_ip_addr_interface, data.dut3, data.d3_d2_ports[1], dut3_dut2_ipv6[0], dut3_dut2_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut2, data.d2_d3_ports[3], dut2_dut3_ip[0], dut2_dut3_ip_subnet,'ipv4'], [ip_obj.config_ip_addr_interface, data.dut3, data.d3_d2_ports[3], dut3_dut2_ip[0], dut3_dut2_ip_subnet, 'ipv4']])
    else:
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut2, data.d2_d3_ports[1], dut2_dut3_ipv6[0], dut2_dut3_ipv6_subnet,'ipv6'], [ip_obj.delete_ip_interface, data.dut3, data.d3_d2_ports[1], dut3_dut2_ipv6[0], dut3_dut2_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut2, data.d2_d3_ports[3], dut2_dut3_ip[0], dut2_dut3_ip_subnet,'ipv4'], [ip_obj.delete_ip_interface, data.dut3, data.d3_d2_ports[3], dut3_dut2_ip[0], dut3_dut2_ip_subnet, 'ipv4']])

        st.log('Unbind DUT interfaces from the VRFs')
        dict1 = {'config':'no','vrf_name': dut1_vrf, 'intf_name': data.d1_d2_ports[3], 'skip_error': True}
        dict2 = {'config':'no','vrf_name': dut2_vrf, 'intf_name': data.d2_d1_ports[3], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut1,data.dut2], vrf_obj.bind_vrf_interface, [dict1, dict2])
        dict2 = {'config':'no','vrf_name': dut2_vrf, 'intf_name': data.d2_d3_ports[1], 'skip_error': True}
        dict3 = {'config':'no','vrf_name': dut3_vrf, 'intf_name': data.d3_d2_ports[1], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut2,data.dut3], vrf_obj.bind_vrf_interface, [dict2, dict3])
        dict2 = {'config':'no','vrf_name': dut2_vrf, 'intf_name': data.d2_d3_ports[3], 'skip_error': True}
        dict3 = {'config':'no','vrf_name': dut3_vrf, 'intf_name': data.d3_d2_ports[3], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut2,data.dut3], vrf_obj.bind_vrf_interface, [dict2, dict3])

        st.log('Unbind TG interfaces from the VRFs')
        dict1 = {'config':'no','vrf_name': dut1_vrf, 'intf_name': data.dut1_tg_ports[1], 'skip_error': True}
        dict3 = {'config':'no','vrf_name': dut3_vrf, 'intf_name': data.dut3_tg_ports[1], 'skip_error': True}
        parallel.exec_parallel(True, [data.dut1,data.dut3], vrf_obj.bind_vrf_interface, [dict1, dict3])

        st.log('Unconfigure non default VRFs on all the DUTs')
        dict1 = {'config':'no','vrf_name': dut1_vrf, 'skip_error': True}
        dict2 = {'config':'no','vrf_name': dut2_vrf, 'skip_error': True}
        dict3 = {'config':'no','vrf_name': dut3_vrf, 'skip_error': True}
        parallel.exec_parallel(True, [data.dut1,data.dut2,data.dut3], vrf_obj.config_vrf, [dict1, dict2, dict3])

def vrf_bgp_unnumbered(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        dict1 = {'vrf_name':dut1_vrf,'router_id':dut1_router_id_vrf,'local_as':dut1_as_vrf,'config_type_list':['router_id']}
        dict2 = {'vrf_name':dut2_vrf,'router_id':dut2_router_id_vrf,'local_as':dut2_as_vrf,'config_type_list':['router_id']}
        dict3 = {'vrf_name':dut3_vrf,'router_id':dut3_router_id_vrf,'local_as':dut3_as_vrf,'config_type_list':['router_id']}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp, [dict1, dict2, dict3])

        st.log('Enable IPv6 link local configuration on VRFs between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, data.d1_d2_ports[3], 'enable'],[ip_obj.config_interface_ip6_link_local, data.dut2, data.d2_d1_ports[3], 'enable']])

        st.log('Configure BGP Unnumbered peers on VRFs')
        dict1 = {'vrf_name':dut1_vrf,'addr_family':'ipv6','local_as':dut1_as_vrf,'remote_as':dut2_as_vrf,'config_type_list':['remote-as'],'interface':data.d1_d2_ports[3],'neighbor':data.d1_d2_ports[3]}
        dict2 = {'vrf_name':dut2_vrf,'addr_family':'ipv6','local_as':dut2_as_vrf,'remote_as':dut1_as_vrf,'config_type_list':['remote-as'],'interface':data.d2_d1_ports[3],'neighbor':data.d2_d1_ports[3]}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.config_bgp, [dict1, dict2])
        dict1 = {'local_asn':dut1_as_vrf,'neighbor_ip': data.d1_d2_ports[3],'family':'ipv4','config':'yes','vrf':dut1_vrf,'remote_asn':dut2_as_vrf}
        dict2 = {'local_asn':dut2_as_vrf,'neighbor_ip': data.d2_d1_ports[3],'family':'ipv4','config':'yes','vrf':dut2_vrf,'remote_asn':dut1_as_vrf}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
        dict1 = {'local_asn':dut1_as_vrf,'neighbor_ip': data.d1_d2_ports[3],'family':'ipv6','config':'yes','vrf':dut1_vrf,'remote_asn':dut2_as_vrf}
        dict2 = {'local_asn':dut2_as_vrf,'neighbor_ip': data.d2_d1_ports[3],'family':'ipv6','config':'yes','vrf':dut2_vrf,'remote_asn':dut1_as_vrf}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_obj.activate_bgp_neighbor, [dict1, dict2])
    else:
        st.log('Disable IPv6 link local configuration on VRFs between DUT1 and DUT2')
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, data.dut1, data.d1_d2_ports[3], 'disable'],[ip_obj.config_interface_ip6_link_local, data.dut2, data.d2_d1_ports[3], 'disable']])

def vrf_bgp_dynamic_neigh(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        st.log('Configure peergrougs on VRF blue and VRF green')
        bgp_obj.create_bgp_peergroup(data.dut2, dut2_as_vrf,'d2d3_v4_peer_vrf',dut3_as_vrf,60,180,None,dut2_vrf,'ipv4')
        bgp_obj.create_bgp_peergroup(data.dut2, dut2_as_vrf,'d2d3_v6_peer_vrf',dut3_as_vrf,60,180,None,dut2_vrf,'ipv6')
        bgp_obj.create_bgp_peergroup(data.dut3, dut3_as_vrf,'d2d3_v4_peer_vrf',dut2_as_vrf,60,180,None,dut3_vrf,'ipv4',neighbor_ip = dut2_dut3_ip[0])
        bgp_obj.create_bgp_peergroup(data.dut3, dut3_as_vrf,'d2d3_v6_peer_vrf',dut2_as_vrf,60,180,None,dut3_vrf,'ipv6',neighbor_ip = dut2_dut3_ipv6[0])
        st.log('Configure BGP listen range on VRF blue for Ipv4 and Ipv6 addresses')
        bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as_vrf, neighbor_address = '2.0.1.0', subnet = dut3_dut2_ip_subnet, peer_grp_name = 'd2d3_v4_peer_vrf', limit = 2, config = 'yes', vrf = dut2_vrf)
        bgp_obj.config_bgp_listen_range(dut = data.dut2, local_asn = dut2_as_vrf, neighbor_address = '2001::', subnet = dut3_dut2_ipv6_subnet, peer_grp_name = 'd2d3_v6_peer_vrf', limit = 2, config = 'yes', vrf = dut2_vrf)
        bgp_obj.activate_bgp_neighbor(data.dut3,dut3_as_vrf,dut2_dut3_ip[0],'ipv4','yes',dut3_vrf,remote_asn = dut2_as_vrf)
        bgp_obj.activate_bgp_neighbor(data.dut3,dut3_as_vrf,dut2_dut3_ipv6[0],'ipv6','yes',dut3_vrf,remote_asn = dut2_as_vrf)

        st.log('Configure redistribute connected on all the VRFs for IPv4 and IPv6 address families')
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as_vrf,'ipv4','unicast','connected','yes',dut1_vrf], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as_vrf,'ipv4','unicast','connected','yes',dut2_vrf],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as_vrf,'ipv4','unicast','connected','yes',dut3_vrf]])
        utils.exec_all(True,[[bgp_obj.config_address_family_redistribute,data.dut1, dut1_as_vrf,'ipv6','unicast','connected','yes',dut1_vrf], [bgp_obj.config_address_family_redistribute,data.dut2, dut2_as_vrf,'ipv6','unicast','connected','yes',dut2_vrf],[bgp_obj.config_address_family_redistribute,data.dut3, dut3_as_vrf,'ipv6','unicast','connected','yes',dut3_vrf]])
    else:
        dict1 = {'config':'no','vrf_name':dut1_vrf,'local_as':dut1_as_vrf,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict2 = {'config':'no','vrf_name':dut2_vrf,'local_as':dut2_as_vrf,'removeBGP':'yes','config_type_list':['removeBGP']}
        dict3 = {'config':'no','vrf_name':dut3_vrf,'local_as':dut3_as_vrf,'removeBGP':'yes','config_type_list':['removeBGP']}
        parallel.exec_parallel(True, [data.dut1, data.dut2, data.dut3], bgp_obj.config_bgp, [dict1, dict2, dict3])

def vrf_tg_interfaces(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        st.log('Configure IPv4 and IPv6 addresses on the VRF interfaces towards TG')
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, data.dut1_tg_ports[1], dut1_tg_ipv6[1], dut1_tg_ipv6_subnet,'ipv6'], [ip_obj.config_ip_addr_interface, data.dut3, data.dut3_tg_ports[1], dut3_tg_ipv6[1], dut3_tg_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.config_ip_addr_interface, data.dut1, data.dut1_tg_ports[1], dut1_tg_ip[1], dut1_tg_ip_subnet,'ipv4'], [ip_obj.config_ip_addr_interface, data.dut3, data.dut3_tg_ports[1], dut3_tg_ip[1], dut3_tg_ip_subnet, 'ipv4']])
        arp_obj.add_static_arp(data.dut3, tg_dut3_ip[1], '00:00:44:44:44:01', data.dut3_tg_ports[1])
        arp_obj.config_static_ndp(data.dut3, tg_dut3_ipv6[1], '00:00:44:44:44:02', data.dut3_tg_ports[1], operation="add")
    else:
        arp_obj.config_static_ndp(data.dut3, tg_dut3_ipv6[1], '00:00:44:44:44:02', data.dut3_tg_ports[1], operation="del")
        arp_obj.delete_static_arp(data.dut3, tg_dut3_ip[1], '00:00:44:44:44:01')
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, data.dut1_tg_ports[1], dut1_tg_ipv6[1], dut1_tg_ipv6_subnet,'ipv6'], [ip_obj.delete_ip_interface, data.dut3, data.dut3_tg_ports[1], dut3_tg_ipv6[1], dut3_tg_ipv6_subnet, 'ipv6']])
        utils.exec_all(True,[[ip_obj.delete_ip_interface, data.dut1, data.dut1_tg_ports[1], dut1_tg_ip[1], dut1_tg_ip_subnet,'ipv4'], [ip_obj.delete_ip_interface, data.dut3, data.dut3_tg_ports[1], dut3_tg_ip[1], dut3_tg_ip_subnet, 'ipv4']])

def tg_streams_vrf(**kwargs):

    st.log('Configure IPv4 and IPv6 raw streams on DUT1 and DUT3 for non default vrfs')

    d1_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut1,'eth0')
    d3_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut3,'eth0')

    st1_vrf = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p2, port_handle2 = data.tg_dut3_p2, duration = 5, mac_src='00:33:03:00:00:03', mac_dst = str(d1_gateway_mac), l2_encap = 'ethernet_ii', ip_src_addr = tg_dut1_ip[1], ip_dst_addr = tg_dut3_ip[1], l3_protocol='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    data.d1_stream_list_vrf.update({'stream_v4_d1_p2':st1_vrf['stream_id']})

    st3_vrf = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p2, port_handle2 = data.tg_dut3_p2, duration = 5, mac_src = '00:44:04:00:00:04', mac_dst = str(d1_gateway_mac),  l2_encap = 'ethernet_ii', ipv6_src_addr = tg_dut1_ipv6[1], ipv6_dst_addr = tg_dut3_ipv6[1], l3_protocol='ipv6', mode='create',transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    data.d1_stream_list_vrf.update({'stream_v6_d1_p2':st3_vrf['stream_id']})

def send_verify_traffic_vrf(**kwargs):
    if 'dut' in kwargs:
        dut = kwargs['dut']
    else:
        dut = data.dut1
    if dut == data.dut1:
        st.log('Send and verify IPv4 and IPv6 traffic on non default VRFs')
        #data.tg.tg_traffic_control(action = 'run', port_handle = data.tg_dut1_p2, duration = 5)
        data.tg.tg_traffic_control(action = 'run', stream_handle = data.d1_stream_list_vrf.values(), duration = 5)
        traffic_details = {'1': {'tx_ports' : [data.tg_dut1_ports[1]],'tx_obj' : [data.tg],'exp_ratio' : [1,1],'rx_ports' : [data.tg_dut3_ports[1]],'rx_obj' : [data.tg], 'stream_list' : [data.d1_stream_list_vrf.values()]}}
        #data.tg.tg_traffic_control(action = 'stop', port_handle = data.tg_dut1_p2)
        data.tg.tg_traffic_control(action = 'stop', stream_handle = data.d1_stream_list_vrf.values())
        aggrResult = validate_tgen_traffic(traffic_details = traffic_details, mode = 'streamblock', comp_type = 'packet_count', delay_factor = data.delay_factor)
    return aggrResult

def ip_incr(ip,octet):
   ip_list = ip.split(".")
   ip_list[octet] = str(int(ip_list[octet]) + 1)
   return '.'.join(ip_list)

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

def tg_streams(**kwargs):
    st.banner('Configure raw streams on DUT1 and DUT3')

    d1_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut1,'eth0')
    d3_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut3,'eth0')

    st1 = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p1, port_handle2 = data.tg_dut3_p1, duration = 5, mac_src='00:11:01:00:00:01', mac_dst = str(d1_gateway_mac), l2_encap = 'ethernet_ii', ip_src_addr = tg_dut1_ip[0], ip_dst_addr = tg_dut3_ip[0], l3_protocol='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    data.d1_stream_list.update({'stream_v4_d1_p1':st1['stream_id']})

    st3 = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p1, port_handle2 = data.tg_dut3_p1, duration = 5, mac_src = '00:22:02:00:00:02', mac_dst = str(d1_gateway_mac),  l2_encap = 'ethernet_ii', ipv6_src_addr = tg_dut1_ipv6[0], ipv6_dst_addr = tg_dut3_ipv6[0], l3_protocol='ipv6', mode='create',transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    data.d1_stream_list.update({'stream_v6_d1_p1':st3['stream_id']})

def module_config_scale():
    st.log('###### ----- Taking backup for unconfig ------######')
    src_path = "/etc/sonic/config_db.json"
    dst_path = "/etc/sonic/default.json"
    #cmd = 'cp /etc/sonic/config_db.json /etc/sonic/default.json'
    utils.exec_all(True,[[basic_obj.copy_file_to_local_path,data.dut1,src_path,dst_path], [basic_obj.copy_file_to_local_path,data.dut2, src_path, dst_path], [basic_obj.copy_file_to_local_path,data.dut3, src_path, dst_path]])
    st.log('######------Configure vlans and add members------######')
    utils.exec_all(True,[[vlan_obj.config_vlan_range,data.dut1,'1 100','add'], [vlan_obj.config_vlan_range,data.dut2,'1 100','add']])
    utils.exec_all(True,[[vlan_obj.config_vlan_range,data.dut2,'101 200','add'], [vlan_obj.config_vlan_range,data.dut3,'101 200','add']])
    utils.exec_all(True,[[vlan_obj.config_vlan_range_members,data.dut1,'1 100',data.d1_d2_ports[0],'add'], [vlan_obj.config_vlan_range_members,data.dut2,'1 100',data.d2_d1_ports[0],'add']])
    utils.exec_all(True,[[vlan_obj.config_vlan_range_members,data.dut2,'101 200',data.d2_d3_ports[0],'add'], [vlan_obj.config_vlan_range_members,data.dut3,'101 200',data.d3_d2_ports[0],'add']])
    st.log('###### ----- Loading json file with vlans, IP addresses and BGP unnumbered configuration config ------######')
    curr_path = os.getcwd()
    json_file_dut1 = curr_path+"/routing/Dynamic_5549/dut1.json"
    json_file_dut2 = curr_path+"/routing/Dynamic_5549/dut2.json"
    json_file_dut3 = curr_path+"/routing/Dynamic_5549/dut3.json"
    utils.exec_all(True,[[st.apply_files,data.dut1,[json_file_dut1]], [st.apply_files,data.dut2,[json_file_dut2]], [st.apply_files,data.dut3,[json_file_dut3]]])

    dut_intf_config()
    tg_streams_scale()

def module_unconfig_scale():
    bgp_unconfig()
    # st.log('###### ----- Loading json file for unconfig ------######3')
    # curr_path = os.getcwd()
    # json_file_dut1_unconfig = curr_path+"/routing/Dynamic_5549/dut1_unconfig.json"
    # json_file_dut2_unconfig = curr_path+"/routing/Dynamic_5549/dut2_unconfig.json"
    # json_file_dut3_unconfig = curr_path+"/routing/Dynamic_5549/dut3_unconfig.json"
    # utils.exec_all(True,[[st.apply_files,data.dut1,[json_file_dut1_unconfig]], [st.apply_files,data.dut2,[json_file_dut2_unconfig]], [st.apply_files,data.dut3,[json_file_dut3_unconfig]]])
    # st.log('######------Unonfigure vlans and add members------######')
    # utils.exec_all(True,[[vlan_obj.config_vlan_range_members,data.dut1,'1 100',data.d1_d2_ports[0],'del'], [vlan_obj.config_vlan_range_members,data.dut2,'1 100',data.d2_d1_ports[0],'del']])
    # utils.exec_all(True,[[vlan_obj.config_vlan_range_members,data.dut2,'101 200',data.d2_d3_ports[0],'del'], [vlan_obj.config_vlan_range_members,data.dut3,'101 200',data.d3_d2_ports[0],'del']])
    # utils.exec_all(True,[[vlan_obj.config_vlan_range,data.dut1,'1 100','del'], [vlan_obj.config_vlan_range,data.dut2,'1 100','del']])
    # utils.exec_all(True,[[vlan_obj.config_vlan_range,data.dut2,'101 200','del'], [vlan_obj.config_vlan_range,data.dut3,'101 200','del']])

    st.log('###### ----- Laoding back the config_db file ------######')
    src_path = "/etc/sonic/default.json"
    dst_path = "/etc/sonic/config_db.json"
    #cmd = 'cp /etc/sonic/default.json /etc/sonic/config_db.json'
    utils.exec_all(True,[[basic_obj.copy_file_to_local_path,data.dut1, src_path, dst_path], [basic_obj.copy_file_to_local_path,data.dut2, src_path, dst_path], [basic_obj.copy_file_to_local_path,data.dut3, src_path, dst_path]])
    utils.exec_all(True,[[st.reboot,data.dut1,'fast'], [st.reboot,data.dut2,'fast'], [st.reboot,data.dut3,'fast']])
    # dutlist = [data.dut1, data.dut2, data.dut3]
    # reboot_obj.config_reload(dutlist)


def tg_streams_scale(**kwargs):
    st.banner('Configure raw streams on DUT1 and DUT3')
    d1_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut1,'eth0')
    d3_gateway_mac = mac_obj.get_sbin_intf_mac(data.dut3,'eth0')

    st1 = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p1, port_handle2 = data.tg_dut3_p1, duration = 5, mac_src='00:11:01:00:00:01', mac_dst = str(d1_gateway_mac), l2_encap = 'ethernet_ii', ip_src_addr = tg_dut1_ip[0], ip_dst_addr = tg_dut3_ip[0], l3_protocol='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    data.d1_stream_list.update({'stream_v4_d1_p1':st1['stream_id']})

    ###############################################################################################################################
