###############################################################################

#Script Title : IP unnumbered over non-default vrf vrf and vlan
#Author       : Manisha Joshi
#Mail-id      : manisha.joshi@broadcom.com

###############################################################################

import pytest
from spytest import st
from unnumbered_vrf_vars import data
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.routing.arp as arp_obj
import apis.routing.ospf as ospf_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import utilities.common as utils
from utilities.utils import retry_api
from spytest.tgen.tgen_utils import validate_tgen_traffic

def module_config():
    result = True
    result = utils.exec_all(True, [[dut1_config],[dut2_config]])
    if result is False:
        st.error("Module config Failed - IP address/Portchannel/Vlan configuration failed")
        pytest.skip()

def module_unconfig():
    st.exec_all(True, [[dut1_unconfig],[dut2_unconfig]])

def tg_streams():

    st1 = data.tg.tg_traffic_config(port_handle = data.tg_dut1_p1, port_handle2 = data.tg_dut2_p1, duration = 5, mac_src='00:11:01:00:00:01', mac_dst = str(data.d1_gateway_mac), l2_encap = 'ethernet_ii', ip_src_addr = data.tg_dut1_ip[0], ip_dst_addr = data.tg_dut2_ip[0], l3_protocol='ipv4', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps = 2000)
    data.d1_stream_list['stream_v4_d1_p1'] = st1['stream_id']

def dut1_config():

    result = True
    st.log('On DUT1 configure vrfs and loopbacks')
    result = vrf_obj.config_vrf(dut = data.dut1, vrf_name = data.dut1_vrf[0], config = 'yes')
    result = ip_obj.configure_loopback(data.dut1, config = 'yes', loopback_name = [data.dut1_loopback[0],data.dut1_loopback[1],data.dut1_loopback[2]])

    st.log('On DUT1 configure vlan')
    result = vlan_obj.create_vlan(data.dut1, data.dut1_dut2_vlan[0])
    result = vlan_obj.add_vlan_member(data.dut1,data.dut1_dut2_vlan[0],data.d1_d2_ports[1],True,True)

    st.log('On DUT1 configure portchannel')
    result = pc_obj.create_portchannel(data.dut1, data.portchannel)
    result = pc_obj.add_portchannel_member(data.dut1, data.portchannel,[data.d1_d2_ports[2],data.d1_d2_ports[3]])

    st.log('On DUT1 bind all the loopbacks, physical, vlan and portchannel interfaces between the DUTs to the VRF')
    result = vrf_obj.bind_vrf_interface(dut = data.dut1, vrf_name = [data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0],data.dut1_vrf[0]], intf_name = [data.dut1_tg_ports[0], data.dut1_loopback[0], data.dut1_loopback[1], data.dut1_loopback[2], data.d1_d2_ports[0], 'Vlan'+data.dut1_dut2_vlan[0], data.portchannel], config = 'yes')

    st.banner('On DUT1 verify vrf bindings for all the interfaces')
    output = vrf_obj.get_vrf_verbose(dut = data.dut1,vrfname = data.dut1_vrf[0])
    if data.dut1_vrf[0] in output['vrfname']:
        st.log('VRF configured on DUT1 is as expected',data.dut1_vrf[0])
    else:
        st.error('VRF name configured on DUT1 is as not expected',data.dut1_vrf[0])
        result = False
    for value in output['interfaces']:
        if data.dut1_tg_ports[0] or data.dut1_loopback[0] or data.dut1_loopback[1] or data.dut1_loopback[2] or data.d1_d2_ports[0] or 'Vlan'+data.dut1_dut2_vlan[0] or data.portchannel == value:
            st.log('Bind to VRF is as expected',value)
        else:
            st.error('Bind to VRF is not as expected',value)
            result = False

    st.log('On DUT1 configure OSPF router ID, ospf networks and add all the ospf interfaces')
    result = ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[0], data.dut1_loopback_ipv6[0], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[0], data.dut1_loopback_ip[0], data.ip_loopback_prefix,'ipv4')
    result = ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[1], data.dut1_loopback_ipv6[1], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[1], data.dut1_loopback_ip[1], data.ip_loopback_prefix,'ipv4')
    result = ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[2], data.dut1_loopback_ipv6[2], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut1, data.dut1_loopback[2], data.dut1_loopback_ip[2], data.ip_loopback_prefix,'ipv4')

    st.log('On DUT1 configure OSPF router ID, ospf networks and add all the ospf interfaces')
    result = ospf_obj.config_ospf_router_id(data.dut1, data.dut1_ospf_router_id, data.dut1_vrf[0], '','yes')
    result = ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[0]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','yes')
    result = ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[1]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','yes')
    result = ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[2]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','yes')
    result = ospf_obj.config_ospf_network(data.dut1, data.dut1_tg1_network_v4, 0, data.dut1_vrf[0], '','yes')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.d1_d2_ports[0],'point-to-point',data.dut1_vrf[0],'yes')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut1, 'Vlan'+data.dut1_dut2_vlan[0],'point-to-point',data.dut1_vrf[0],'yes')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.portchannel,'point-to-point',data.dut1_vrf[0],'yes')

    st.log('On DUT1 configure IP addresses on DUT - TG interfaces')
    ip_obj.config_ip_addr_interface(data.dut1, data.dut1_tg_ports[0], data.dut1_tg_ipv6[0], data.tg_ipv6_subnet,'ipv6')
    ip_obj.config_ip_addr_interface(data.dut1, data.dut1_tg_ports[0], data.dut1_tg_ip[0], data.tg_ip_subnet,'ipv4')
    return result

def dut1_unconfig():

    result = 0
    st.log('On DUT1 unconfigure IP addresses on DUT - TG interfaces')
    ip_obj.delete_ip_interface(data.dut1, data.dut1_tg_ports[0], data.dut1_tg_ipv6[0], data.tg_ipv6_subnet,'ipv6')
    ip_obj.delete_ip_interface(data.dut1, data.dut1_tg_ports[0], data.dut1_tg_ip[0], data.tg_ip_subnet,'ipv4')

    st.log('On DUT1 Unonfigure OSPF router ID, ospf network and add all the ospf interfaces')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.d1_d2_ports[0],'point-to-point',data.dut1_vrf[0],'no')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut1, 'Vlan'+data.dut1_dut2_vlan[0],'point-to-point',data.dut1_vrf[0],'no')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut1, data.portchannel,'point-to-point',data.dut1_vrf[0],'no')
    result = ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[0]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','no')
    result = ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[1]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','no')
    result = ospf_obj.config_ospf_network(data.dut1, data.dut1_loopback_ip[2]+'/'+data.ip_loopback_prefix, 0, data.dut1_vrf[0], '','no')
    result = ospf_obj.config_ospf_router_id(data.dut1, data.dut1_ospf_router_id, data.dut1_vrf[0], '','no')

    st.banner('Unconfigure IPv4 and IPv6 addresses on the loopback interfaces')
    result = ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[0], data.dut1_loopback_ipv6[0], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[0], data.dut1_loopback_ip[0], data.ip_loopback_prefix,'ipv4')
    result = ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[1], data.dut1_loopback_ipv6[1], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[1], data.dut1_loopback_ip[1], data.ip_loopback_prefix,'ipv4')
    result = ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[2], data.dut1_loopback_ipv6[2], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut1, data.dut1_loopback[2], data.dut1_loopback_ip[2], data.ip_loopback_prefix,'ipv4')

    st.log('On DUT1 unbind all the loopbacks, physical, vlan and portchannel interfaces to the VRF')
    result = vrf_obj.bind_vrf_interface(dut = data.dut1, vrf_name = data.dut1_vrf[0], intf_name = [data.dut1_loopback[0], data.dut1_loopback[1], data.dut1_loopback[2], data.d1_d2_ports[0], 'Vlan'+data.dut1_dut2_vlan[0], data.portchannel], config = 'no')

    st.log('On DUT1 unconfigure vlan')
    result = vlan_obj.delete_vlan_member(data.dut1_client,data.dut1_dut2_vlan[0],data.d1_d2_ports[1],True)
    result = vlan_obj.create_vlan(data.dut1_client, data.dut1_dut2_vlan[0])

    st.banner('Unconfigure portchannel on DUT1')
    result = pc_obj.add_del_portchannel_member(data.dut1_client, data.portchannel,[data.d1_d2_ports[2],data.d1_d2_ports[3]],'del')
    result = pc_obj.delete_portchannel(data.dut1_client, data.portchannel)

    st.log('On DUT1 unconfigure vrfs and loopbacks')
    result = ip_obj.configure_loopback(data.dut1, config = 'no', loopback_name = [data.dut1_loopback[0],data.dut1_loopback[1],data.dut1_loopback[2]])
    result = vrf_obj.config_vrf(dut = data.dut3_client, vrf_name = data.dut1_vrf[0], config = 'no')

    return result

def dut2_config():

    result = True
    st.log('On DUT2 configure loopback')
    result = ip_obj.configure_loopback(data.dut2, config = 'yes', loopback_name = [data.dut2_loopback[0],data.dut2_loopback[1],data.dut2_loopback[2]])

    st.log('On DUT2 configure vlan')
    result = vlan_obj.create_vlan(data.dut2, data.dut1_dut2_vlan[0])
    result = vlan_obj.add_vlan_member(data.dut2,data.dut1_dut2_vlan[0], data.d2_d1_ports[1],True,True)

    st.log('On DUT2 configure portchannel')
    result = pc_obj.create_portchannel(data.dut2, data.portchannel)
    result = pc_obj.add_portchannel_member(data.dut2, data.portchannel,[data.d2_d1_ports[2],data.d2_d1_ports[3]])

    st.log('On DUT2 configure OSPF router ID, ospf networks and add all the ospf interfaces')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_loopback[0], data.dut2_loopback_ipv6[0], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_loopback[0], data.dut2_loopback_ip[0], data.ip_loopback_prefix,'ipv4')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_loopback[1], data.dut2_loopback_ipv6[1], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_loopback[1], data.dut2_loopback_ip[1], data.ip_loopback_prefix,'ipv4')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_loopback[2], data.dut2_loopback_ipv6[2], data.ipv6_loopback_prefix,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_loopback[2], data.dut2_loopback_ip[2], data.ip_loopback_prefix,'ipv4')

    st.log('On DUT2 configure OSPF router ID, ospf networks and add all the ospf interfaces')
    result = ospf_obj.config_ospf_router_id(data.dut2, data.dut2_ospf_router_id, 'default', '','yes')
    result = ospf_obj.config_ospf_network(data.dut2, data.dut2_loopback_ip[0]+'/'+data.ip_loopback_prefix, 0, 'default', '','yes')
    result = ospf_obj.config_ospf_network(data.dut2, data.dut2_loopback_ip[1]+'/'+data.ip_loopback_prefix, 0, 'default', '','yes')
    result = ospf_obj.config_ospf_network(data.dut2, data.dut2_loopback_ip[2]+'/'+data.ip_loopback_prefix, 0, 'default', '','yes')
    result = ospf_obj.config_ospf_network(data.dut2, data.dut2_tg1_network_v4, 0, 'default', '','yes')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut2, data.d2_d1_ports[0],'point-to-point','default','yes')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut2, 'Vlan'+data.dut1_dut2_vlan[0],'point-to-point','default','yes')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut2, data.portchannel,'point-to-point','default','yes')

    st.log('On DUT2 configure IP addresses on DUT2 - TG interfaces')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_tg_ports[0], data.dut2_tg_ipv6[0], data.tg_ipv6_subnet,'ipv6')
    result = ip_obj.config_ip_addr_interface(data.dut2, data.dut2_tg_ports[0], data.dut2_tg_ip[0], data.tg_ip_subnet,'ipv4')
    result = arp_obj.add_static_arp(data.dut2, data.tg_dut2_ip[0], '00:00:33:33:33:01', data.dut2_tg_ports[0])

    return result

def dut2_unconfig():

    result = 0
    st.log('On Configure IP addresses on DUT2 - TG interfaces')
    result = ip_obj.delete_ip_interface(data.dut2, data.dut2_tg_ports[0], data.dut2_tg_ipv6[0], data.tg_ipv6_subnet,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2, data.dut2_tg_ports[0], data.dut2_tg_ip[0], data.tg_ip_subnet,'ipv4')
    result = arp_obj.config_static_ndp(data.dut2, data.tg_dut2_ipv6[0], '00:00:33:33:33:02', data.dut2_tg_ports[0], operation="del")
    result = arp_obj.delete_static_arp(data.dut2, data.tg_dut2_ip[0], '00:00:33:33:33:01')

    st.log('On DUT2 unconfigure OSPF router ID, ospf networks and add all the ospf interfaces')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut2, data.d2_d1_ports[0],'point-to-point','default','no')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut2, 'Vlan'+data.dut1_dut2_vlan[0],'point-to-point','default','no')
    result = ospf_obj.config_interface_ip_ospf_network_type(data.dut2, data.portchannel,'point-to-point','default','no')
    result = ospf_obj.config_ospf_network(data.dut2, data.dut2_loopback_ip[0]+'/'+data.ip_loopback_prefix, 0, 'default', '','no')
    result = ospf_obj.config_ospf_router_id(data.dut2, data.dut2_ospf_router_id, 'default', '','no')

    st.log('On DUT2 unconfigure loopback and remove IPv4 and IPv6 addresses on it')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.dut2_loopback[0], data.dut2_loopback_ipv6[0], data.dut2_loopback_ipv6_subnet,'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.dut2_loopback[0], data.dut2_loopback_ip[0], data.dut2_loopback_ip_subnet,'ipv4')
    result = ip_obj.configure_loopback(data.dut2_server, config = 'no', loopback_name = data.dut2_loopback[0])

    st.log('On DUT2 unconfigure portchannel and remove IPv4 and IPv6 addresses on it')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.portchannel, data.dut2_dut1_ipv6[2], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2_server, data.portchannel, data.dut2_dut1_ip[2], data.dut2_dut1_ip_subnet, 'ipv4')
    result = pc_obj.add_del_portchannel_member(data.dut2_server, data.portchannel,[data.d2_d1_ports[2],data.d2_d1_ports[3]],'del')
    result = pc_obj.delete_portchannel(data.dut2_server, data.portchannel)

    st.log('On DUT2 unconfigure vlan and remove IPv4 and IPv6 addresses on it')
    result = ip_obj.delete_ip_interface(data.dut2, 'Vlan'+data.dut1_dut2_vlan[0], data.dut2_dut1_ipv6[1], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2, 'Vlan'+data.dut1_dut2_vlan[0], data.dut2_dut1_ip[1], data.dut2_dut1_ip_subnet, 'ipv4')
    result = vlan_obj.delete_vlan_member(data.dut2,data.dut1_dut2_vlan[0], data.d2_d1_ports[1],True)
    result = vlan_obj.delete_vlan(data.dut2, data.dut1_dut2_vlan[0])

    st.log('On DUT2 remove IPv4 and IPv6 addresses on physical interface')
    result = ip_obj.delete_ip_interface(data.dut2, data.d2_d1_ports[0], data.dut2_dut1_ipv6[0], data.dut2_dut1_ipv6_subnet, 'ipv6')
    result = ip_obj.delete_ip_interface(data.dut2, data.d2_d1_ports[0], data.dut2_dut1_ip[0], data.dut2_dut1_ip_subnet, 'ipv4')

    return result

def dut1_config_unnumbered(type, config):

    result = True
    if config == '':
        if type == 'phy':
            st.log('On DUT1 Configure IP unnumbered for Physical interface')
            result = ip_obj.config_unnumbered_interface(dut = data.dut1, family = 'ipv4', action = 'add', interface = data.d1_d2_ports[0], loop_back = data.dut1_loopback[0])
        if type == 'vlan':
            st.log('On DUT1 Configure IP unnumbered for vlan')
            result = ip_obj.config_unnumbered_interface(dut = data.dut1, family = 'ipv4', action = 'add', interface = 'Vlan'+data.dut1_dut2_vlan[0], loop_back = data.dut1_loopback[1])
        if type == 'pc':
            st.log('On DUT1 Configure IP unnumbered for portchannel')
            result = ip_obj.config_unnumbered_interface(dut = data.dut1, family = 'ipv4', action = 'add', interface = data.portchannel, loop_back = data.dut1_loopback[2])
    else:
        if type == 'phy':
            st.log('On DUT1 unconfigure IP unnumbered for Physical interface')
            result = ip_obj.config_unnumbered_interface(dut = data.dut1, family = 'ipv4', action = 'del', interface = data.d1_d2_ports[0], loop_back = data.dut1_loopback[0])
        if type == 'vlan':
            st.log('On DUT1 unconfigure IP unnumbered for vlan')
            result = ip_obj.config_unnumbered_interface(dut = data.dut1, family = 'ipv4', action = 'del', interface = 'Vlan'+data.dut1_dut2_vlan[0], loop_back = data.dut1_loopback[1])
        if type == 'pc':
            st.log('On DUT1 unconfigure IP unnumbered for portchannel')
            result = ip_obj.config_unnumbered_interface(dut = data.dut1, family = 'ipv4', action = 'del', interface = data.portchannel, loop_back = data.dut1_loopback[2])
    return result

def dut2_config_unnumbered(type, config):

    result = True
    if config == '':
        if type == 'phy':
            st.log('On DUT2 Configure IP unnumbered for Physical interface')
            result = ip_obj.config_unnumbered_interface(dut = data.dut2, family = 'ipv4', action = 'add', interface = data.d2_d1_ports[0], loop_back = data.dut2_loopback[0])
        if type == 'vlan':
            st.log('On DUT2 Configure IP unnumbered for vlan')
            result = ip_obj.config_unnumbered_interface(dut = data.dut2, family = 'ipv4', action = 'add', interface = 'Vlan'+data.dut1_dut2_vlan[0], loop_back = data.dut2_loopback[1])
        if type == 'pc':
            st.log('On DUT2 Configure IP unnumbered for portchannel')
            result = ip_obj.config_unnumbered_interface(dut = data.dut2, family = 'ipv4', action = 'add', interface = data.portchannel, loop_back = data.dut2_loopback[2])
    else:
        if type == 'phy':
            st.log('On DUT2 unconfigure IP unnumbered for Physical interface')
            result = ip_obj.config_unnumbered_interface(dut = data.dut2, family = 'ipv4', action = 'del', interface = data.d2_d1_ports[0], loop_back = data.dut2_loopback[0])
        if type == 'vlan':
            st.log('On DUT2 unconfigure IP unnumbered for vlan')
            result = ip_obj.config_unnumbered_interface(dut = data.dut2, family = 'ipv4', action = 'del', interface = 'Vlan'+data.dut1_dut2_vlan[0], loop_back = data.dut2_loopback[1])
        if type == 'pc':
            st.log('On DUT2 unconfigure IP unnumbered for portchannel')
            result = ip_obj.config_unnumbered_interface(dut = data.dut2, family = 'ipv4', action = 'del', interface = data.portchannel, loop_back = data.dut2_loopback[2])
    return result

def dut1_verify_unnumbered(type):

    result = True
    if type == 'phy':
        st.log('On DUT1 verify IP unnumbered for Physical interface')
        if not ip_obj.verify_interface_ip_address(data.dut1, data.d1_d2_ports[0], data.dut1_loopback_ip[0]+'/'+data.ip_loopback_prefix, 'ipv4',data.dut1_vrf[0],'U'):
            result = False
    if type == 'vlan':
        st.log('On DUT1 verify IP unnumbered for vlan')
        if not ip_obj.verify_interface_ip_address(data.dut1, 'Vlan'+data.dut1_dut2_vlan[0], data.dut1_loopback_ip[1]+'/'+data.ip_loopback_prefix, 'ipv4',data.dut1_vrf[0],'U'):
            result = False
    if type == 'pc':
        st.log('On DUT1 verify IP unnumbered for portchannel')
        if not ip_obj.verify_interface_ip_address(data.dut1, data.portchannel, data.dut1_loopback_ip[2]+'/'+data.ip_loopback_prefix, 'ipv4',data.dut1_vrf[0],'U'):
            result = False
    return result

def dut2_verify_unnumbered(type):

    result = True
    if type == 'phy':
        st.log('On DUT2 verify IP unnumbered for Physical interface')
        if not ip_obj.verify_interface_ip_address(data.dut2, data.d2_d1_ports[0], data.dut2_loopback_ip[0]+'/'+data.ip_loopback_prefix, 'ipv4','','U'):
            result = False
    if type == 'vlan':
        st.log('On DUT2 verify IP unnumbered for vlan')
        if not ip_obj.verify_interface_ip_address(data.dut2, 'Vlan'+data.dut1_dut2_vlan[0], data.dut2_loopback_ip[1]+'/'+data.ip_loopback_prefix, 'ipv4','','U'):
            result = False
    if type == 'pc':
        st.log('On DUT2 verify IP unnumbered for portchannel')
        if not ip_obj.verify_interface_ip_address(data.dut2, data.portchannel, data.dut2_loopback_ip[2]+'/'+data.ip_loopback_prefix, 'ipv4','','U'):
            result = False
    return result

def reset_streams(**kwargs):
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut1_p1)
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut2_p1)
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut1_p2)
    data.tg.tg_traffic_control(action='reset', port_handle = data.tg_dut2_p2)

def send_verify_traffic(**kwargs):
    st.log('Send and verify IPv4 and IPv6 traffic')
    data.tg.tg_traffic_control(action = 'run', stream_handle = data.d1_stream_list.values(), duration = 5)
    traffic_details = {'1': {'tx_ports' : [data.tg_dut1_ports[0]],'tx_obj' : [data.tg],'exp_ratio' : [1],'rx_ports' : [data.tg_dut2_ports[0]],'rx_obj' : [data.tg], 'stream_list' : [[data.d1_stream_list.get('stream_v4_d1_p1')]]}}
    data.tg.tg_traffic_control(action = 'stop', stream_handle = data.d1_stream_list.values())
    aggrResult = validate_tgen_traffic(traffic_details = traffic_details, mode = 'streamblock', comp_type = 'packet_count', delay_factor = data.delay_factor)

    return aggrResult

def verify_ospf(**kwargs):

    result = True

    st.log('On DUT1 verify OSPF on non default vrf and on DUT2 verify OSPF on default vrf')
    result = retry_api(ospf_obj.verify_ospf_neighbor_state,data.dut1,[data.d1_d2_ports[0],data.portchannel,'Vlan'+data.dut1_dut2_vlan[0]],['Full','Full','Full'], data.dut1_vrf[0], retry_count= 3, delay= 10)

    st.log('On DUT1 verify OSPF on non default vrf')
    result = retry_api(ospf_obj.verify_ospf_neighbor_state,data.dut2,[data.d2_d1_ports[0],data.portchannel,'Vlan'+data.dut1_dut2_vlan[0]],['Full','Full','Full'], 'default', retry_count= 3, delay= 10)
    return result
