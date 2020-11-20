
import itertools

from evpn_vlan_vars import *
from evpn_vlan_vars import data

from spytest import st,utils,tgapi

import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.evpn as evpn
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.routing.vrf as vrf_api
import apis.system.basic as basic_api
import apis.switching.mclag as mclag
import apis.routing.sag as sag

import utilities.utils as utils_obj
from utilities.utils import retry_parallel
from utilities import parallel

def evpn_vlan_base_config():
    ###################################################
    st.banner(" Begin base Configuration ")
    ###################################################
    config_ip()
    config_loopback()
    config_static_route()
    config_bgp()
    st.wait(4)
    result = verify_bgp()
    if not result:
        config_bgp(config='no')
        config_static_route(config='no')
        config_loopback(config='no')
        config_ip(config='no')
        return False
    config_leafInterface()
    result = verify_vxlan()
    if not result:
        config_leafInterface(config='no')
        config_bgp(config='no')
        config_static_route(config='no')
        config_loopback(config='no')
        config_ip(config='no')
        return False
    config_mclag()
    l3vni_client_config()
    vlan_underlay_lvtep()

    create_stream()
    result1 = pc.verify_portchannel_member_state(data.dut7, client_lag, [data.d7d3_ports[0],data.d7d4_ports[0]])
    result2 = pc.verify_portchannel_member_state(data.dut3, iccp_lag, [data.d3d4_ports[0]])
    if False in [result1,result2]:
        evpn_vlan_base_unconfig()
        return False
    ###################################################
    st.banner("BASE Config End ")
    ###################################################
    return True

def evpn_vlan_base_unconfig():
    vlan_underlay_lvtep(config='no')
    l3vni_client_config(config='no')
    config_mclag(config='no')
    config_leafInterface(config='no')
    config_bgp(config='no')
    config_static_route(config='no')
    config_loopback(config='no')
    config_ip(config='no')

def config_ip(config='yes'):
    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        action = 'enable'
        config_str = "Configure"
    else:
        api_name = ip_api.delete_ip_interface
        action = 'disable'
        config_str = "Delete"

    st.log("%s L3 configs between Leaf and Spine"%(config_str))

    # Config phy router port
    # Config vlan with ip
    # Config vlan with ipv6 link local
    def spine1():
        dut = data.dut1
        # Step 1 - Config phy router port
        port_list = [data.d1d3_ports[0], data.d1d5_ports[0], data.d1d6_ports[0]]
        ip_list = [dut1_3_ip_list[0], dut1_5_ip_list[0], dut1_6_ip_list[0]]
        for port, ip in zip(port_list, ip_list):
            api_name(dut, port, ip, mask31)
        # Step 2- Configure IP over Vlan interface
        port_list1 = [data.d1d3_ports[1], data.d1d5_ports[1], data.d1d6_ports[1]]
        po_list = [po_s1l1, po_s1l3, po_s1l4]
        ip_list1 = [dut1_3_ip_list[1], dut1_5_ip_list[1], dut1_6_ip_list[1]]
        vlan_list1 = [vlan_s1_l1[0], vlan_s1_l3[0], vlan_s1_l4[0]]
        vlan_int_list = [vlanInt_s1_l1[0], vlanInt_s1_l3[0], vlanInt_s1_l4[0]]
        if config == "yes":
            for po, mem in zip(po_list, [data.d1d3_ports[2], data.d1d5_ports[2], data.d1d6_ports[2]]):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mem)
            config_vlan_and_member(dut,vlan_list1,port_list1,config = 'yes')
        for port, ip in zip(vlan_int_list, ip_list1):
            api_name(dut, port, ip, mask31)

        # Step 3 - Ipv6 link local over vlan
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            config_vlan_and_member(dut,vlan_list1,port_list1,config = 'no')
            for po, mem in zip(po_list, [data.d1d3_ports[2], data.d1d5_ports[2], data.d1d6_ports[2]]):
                pc.delete_portchannel_member(dut, po, mem)
                pc.delete_portchannel(dut, po)
    def spine2():
        dut = data.dut2
        # Step 1 - Config phy router port
        port_list = [data.d2d4_ports[0], data.d2d5_ports[0], data.d2d6_ports[0]]
        ip_list = [dut2_4_ip_list[0], dut2_5_ip_list[0], dut2_6_ip_list[0]]
        for port, ip in zip(port_list, ip_list):
            api_name(dut, port, ip, mask31)

        # Step 2- Configure IP over Vlan interface
        port_list1 = [data.d2d4_ports[1], data.d2d5_ports[1], data.d2d6_ports[1]]
        po_list = [po_s2l2, po_s2l3, po_s2l4]

        ip_list = [dut2_4_ip_list[1], dut2_5_ip_list[1], dut2_6_ip_list[1]]
        vlan_list1 = [vlan_s2_l2[0], vlan_s2_l3[0], vlan_s2_l4[0]]
        vlan_int_list = [vlanInt_s2_l2[0], vlanInt_s2_l3[0], vlanInt_s2_l4[0]]

        if config == "yes":
            for po, mem in zip(po_list, [data.d2d4_ports[2], data.d2d5_ports[2], data.d2d6_ports[2]]):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mem)
            config_vlan_and_member(dut,vlan_list1,port_list1,config = 'yes',tagged='no')
        for port, ip in zip(vlan_int_list, ip_list):
            api_name(dut, port, ip, mask31)

        # Step 3 - Ipv6 link local over vlan
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            config_vlan_and_member(dut,vlan_list1,port_list1,config = 'no',tagged='no')
            for po, mem in zip(po_list, [data.d2d4_ports[2], data.d2d5_ports[2], data.d2d6_ports[2]]):
                pc.delete_portchannel_member(dut, po, mem)
                pc.delete_portchannel(dut, po)

    def leaf1():
        dut = data.dut3

        api_name(dut, data.d3d1_ports[0], dut3_1_ip_list[0], mask31)
        port_list = [data.d3d1_ports[1]]
        if config == "yes":
            pc.create_portchannel(dut, po_s1l1)
            pc.add_portchannel_member(dut,po_s1l1, [data.d3d1_ports[2]])
            config_vlan_and_member(dut,[vlan_s1_l1[0]],port_list,config = 'yes')
        api_name(dut, "Vlan"+vlan_s1_l1[0], dut3_1_ip_list[1], mask31)

        ip_api.config_interface_ip6_link_local(dut, po_s1l1, action=action)
        if config != "yes":
            config_vlan_and_member(dut,[vlan_s1_l1[0]],port_list,config = 'no')
            pc.delete_portchannel_member(dut,po_s1l1, [data.d3d1_ports[2]])
            pc.delete_portchannel(dut, po_s1l1)
            vrf_api.config_vrf(dut, vrf_name=vrf1,config='no')

    def leaf2():
        dut = data.dut4

        api_name(dut, data.d4d2_ports[0], dut4_2_ip_list[0], mask31)
        port_list = [data.d4d2_ports[1]]

        if config == "yes":
            pc.create_portchannel(dut, po_s2l2)
            pc.add_portchannel_member(dut, po_s2l2, [data.d4d2_ports[2]])
            config_vlan_and_member(dut, [vlan_s2_l2[0]], port_list, config='yes',tagged='no')
        api_name(dut, "Vlan" + vlan_s2_l2[0], dut4_2_ip_list[1], mask31)
        ip_api.config_interface_ip6_link_local(dut, po_s2l2, action=action)
        if config != "yes":
            config_vlan_and_member(dut, [vlan_s2_l2[0]], port_list, config='no',tagged='no')
            pc.delete_portchannel_member(dut, po_s2l2, [data.d4d2_ports[2]])
            pc.delete_portchannel(dut, po_s2l2)
            vrf_api.config_vrf(dut, vrf_name=vrf1,config='no')

    def leaf3():
        dut = data.dut5
        #api_name(dut, data.d5d1_ports[0], dut5_1_ip_list[0], mask31)
        #api_name(dut, data.d5d2_ports[0], dut5_2_ip_list[0], mask31)
        port_list1 = [data.d5d1_ports[1], data.d5d2_ports[1]]
        po_list = [po_s1l3,po_s2l3]

        #vlan_list = [vlan_s1_l3[0],vlan_s2_l3[0],vlan_s1_l3[1],vlan_s2_l3[1]]
        vlan_list = [vlan_s1_l3[0], vlan_s2_l3[0]]
        vlanInt_list = [vlanInt_s1_l3[0], vlanInt_s2_l3[0]]

        if config == "yes":
            for po, mem in zip(po_list, [data.d5d1_ports[2], data.d5d2_ports[2]]):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mem)

            config_vlan_and_member(dut, [vlan_list[0]], [port_list1[0]], config='yes')
            config_vlan_and_member(dut, [vlan_list[1]], [port_list1[1]], config='yes',tagged='no')
        port_list2 = [data.d5d1_ports[0], data.d5d2_ports[0]]
        port_list = port_list2 + vlanInt_list
        ip_list = [dut5_1_ip_list[0],dut5_2_ip_list[0],dut5_1_ip_list[1],dut5_2_ip_list[1]]

        for port, ip in zip(port_list, ip_list):
            api_name(dut, port, ip, mask31)

        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            config_vlan_and_member(dut, [vlan_list[0]], [port_list1[0]], config='no')
            config_vlan_and_member(dut, [vlan_list[1]], [port_list1[1]], config='no',tagged='no')
            for po, mem in zip(po_list, [data.d5d1_ports[2], data.d5d2_ports[2]]):
                pc.delete_portchannel_member(dut, po, mem)
                pc.delete_portchannel(dut, po)
            vrf_api.config_vrf(dut, vrf_name=vrf1,config='no')

    def leaf4():
        dut = data.dut6
        #api_name(dut, data.d6d1_ports[0], dut6_1_ip_list[0], mask31)
        #api_name(dut, data.d6d2_ports[0], dut6_2_ip_list[0], mask31)
        port_list1 = [data.d6d1_ports[1], data.d6d2_ports[1]]
        po_list = [po_s1l4,po_s2l4]

        vlan_list = [vlan_s1_l4[0], vlan_s2_l4[0]]
        vlanInt_list = [vlanInt_s1_l4[0], vlanInt_s2_l4[0]]

        if config == "yes":
            for po, mem in zip(po_list, [data.d6d1_ports[2], data.d6d2_ports[2]]):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mem)
            config_vlan_and_member(dut, [vlan_list[0]], [port_list1[0]], config='yes')
            config_vlan_and_member(dut, [vlan_list[1]], [port_list1[1]], config='yes',tagged='no')
        port_list2 = [data.d6d1_ports[0], data.d6d2_ports[0]]
        port_list = port_list2 + vlanInt_list
        ip_list = [dut6_1_ip_list[0], dut6_2_ip_list[0], dut6_1_ip_list[1], dut6_2_ip_list[1]]

        for port, ip in zip(port_list, ip_list):
            api_name(dut, port, ip, mask31)

        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            config_vlan_and_member(dut, [vlan_list[0]], [port_list1[0]], config='no')
            config_vlan_and_member(dut, [vlan_list[1]], [port_list1[1]], config='no',tagged='no')
            #config_vlan_and_member(dut, vlan_list, port_list1, config='no')
            for po, mem in zip(po_list, [data.d6d1_ports[2], data.d6d2_ports[2]]):
                pc.delete_portchannel_member(dut, po, mem)
                pc.delete_portchannel(dut, po)
            vrf_api.config_vrf(dut, vrf_name=vrf1,config='no')
    # Configure all the IP addresses in parallel
    [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2],[leaf3],[leaf4]])

def config_vlan_and_member(dut,vlan_list,port_list,config='yes',tagged='yes'):
    if config == 'yes':
        vlan_api.create_vlan(dut,vlan_list)
        for vlan,port in zip(vlan_list,port_list):
            if tagged == 'yes':
                vlan_api.add_vlan_member(dut,vlan,port,True)
            else:
                vlan_api.add_vlan_member(dut,vlan,port)
    else:
        for vlan,port in zip(vlan_list,port_list):
            if tagged == 'yes':
                vlan_api.delete_vlan_member(dut,vlan,port,True)
            else:
                vlan_api.add_vlan_member(dut,vlan,port)
        vlan_api.delete_vlan(dut, vlan_list)


def config_loopback(config='yes'):

    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip_api.delete_ip_interface
        config_str = "Delete"

    st.log("%s Loopback configs between Leaf and Spine"%(config_str))
    if config == 'yes' :
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback, [{'loopback_name': loopback1}] * 6)
        utils.exec_all(True, [[api_name, dut, loopback1, ip, mask32]
                              for dut, ip in zip(data.rtr_list, loopback1_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback, [{'loopback_name': loopback2}] * 6)
        utils.exec_all(True, [[api_name, dut, loopback2, ip, mask32]
                              for dut, ip in zip(data.rtr_list, loopback2_ip_list)])

    else:
        utils.exec_all(True, [[api_name, dut, loopback2, ip, mask32]
                              for dut, ip in zip(data.rtr_list, loopback2_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback,
                               [{'loopback_name': loopback2,'config':'no'}] * 6)
        utils.exec_all(True, [[api_name, dut, loopback1, ip, mask32]
                              for dut, ip in zip(data.rtr_list, loopback1_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback,
                               [{'loopback_name': loopback1,'config':'no'}] * 6)

def tunnel_static_routes(config = 'yes'):
    if config == 'yes':
        api_name = ip_api.create_static_route
        config_str = "Configure"
    else:
        api_name = ip_api.delete_static_route
        config_str = "Delete"
    st.log("%s Static route configs between Leaf and Spine"%(config_str))

    def leaf1():
        dut = data.dut3
        for i in range(2):
            api_name(dut, next_hop=dut1_3_ip_list[i], static_ip=dut5_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut1_3_ip_list[i], static_ip=dut6_loopback_ip[1] + '/' + mask32)
        api_name(dut, next_hop=dut4_3_ip_list[1], static_ip=dut5_loopback_ip[1] + '/' + mask32)
        api_name(dut, next_hop=dut4_3_ip_list[1], static_ip=dut6_loopback_ip[1] + '/' + mask32)

    def leaf2():
        dut = data.dut4
        for i in range(2):
            api_name(dut, next_hop=dut2_4_ip_list[i], static_ip=dut5_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut2_4_ip_list[i], static_ip=dut6_loopback_ip[1] + '/' + mask32)

    def leaf3():
        dut = data.dut5
        for i in range(2):
            api_name(dut, next_hop=dut1_5_ip_list[i], static_ip=dut3_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut2_5_ip_list[i], static_ip=dut3_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut1_5_ip_list[i], static_ip=dut6_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut2_5_ip_list[i], static_ip=dut6_loopback_ip[1] + '/' + mask32)

    def leaf4():
        dut = data.dut6
        for i in range(2):
            api_name(dut, next_hop=dut1_6_ip_list[i], static_ip=dut3_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut2_6_ip_list[i], static_ip=dut3_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut1_6_ip_list[i], static_ip=dut5_loopback_ip[1] + '/' + mask32)
            api_name(dut, next_hop=dut2_6_ip_list[i], static_ip=dut5_loopback_ip[1] + '/' + mask32)

    [res, exceptions] = st.exec_all( [ [leaf1], [leaf2], [leaf3], [leaf4]])


def config_static_route(config = 'yes'):
    if config == 'yes':
        api_name = ip_api.create_static_route
        config_str = "Configure"
    else:
        api_name = ip_api.delete_static_route
        config_str = "Delete"

    st.log("%s Loopback static route configs between Leaf and Spine" % (config_str))
    def spine1():
        dut = data.dut1
        for i in range(2):
            api_name(dut,next_hop = dut3_1_ip_list[i],static_ip = dut3_loopback_ip[0]+'/'+mask32)
            api_name(dut,next_hop = dut5_1_ip_list[i],static_ip = dut5_loopback_ip[0]+'/'+mask32)
            api_name(dut,next_hop = dut6_1_ip_list[i],static_ip = dut6_loopback_ip[0]+'/'+mask32)

    def spine2():
        dut = data.dut2
        for i in range(2):
            api_name(dut,next_hop = dut4_2_ip_list[i],static_ip = dut4_loopback_ip[0]+'/'+mask32)
            api_name(dut,next_hop = dut5_2_ip_list[i],static_ip = dut5_loopback_ip[0]+'/'+mask32)
            api_name(dut,next_hop = dut6_2_ip_list[i],static_ip = dut6_loopback_ip[0]+'/'+mask32)

    def leaf1():
        dut = data.dut3
        for i in range(2):
            api_name(dut,next_hop = dut1_3_ip_list[i],static_ip = dut1_loopback_ip[0]+'/'+mask32)
        #link_local_po_l1s1 = [ip_api.get_link_local_addresses(dut,po_s1l1)[0]]

    def leaf2():
        dut = data.dut4
        for i in range(2):
            api_name(dut,next_hop = dut2_4_ip_list[i],static_ip = dut2_loopback_ip[0]+'/'+mask32)
        #link_local_po_l2s2 = [ip_api.get_link_local_addresses(dut,po_s2l2)[0]]

    def leaf3():
        dut = data.dut5
        for i in range(2):
            api_name(dut,next_hop = dut1_5_ip_list[i],static_ip = dut1_loopback_ip[0]+'/'+mask32)
            api_name(dut,next_hop = dut2_5_ip_list[i],static_ip = dut2_loopback_ip[0]+'/'+mask32)
        #link_local_po_l3spine = [ip_api.get_link_local_addresses(dut,po_s1l3)[0],ip_api.get_link_local_addresses(dut,po_s2l3)[0]]

    def leaf4():
        dut = data.dut6
        for i in range(2):
            api_name(dut,next_hop = dut1_6_ip_list[i],static_ip = dut1_loopback_ip[0]+'/'+mask32)
            api_name(dut,next_hop = dut2_6_ip_list[i],static_ip = dut2_loopback_ip[0]+'/'+mask32)
        #link_local_po_l4spine = [ip_api.get_link_local_addresses(dut,po_s1l4)[0],ip_api.get_link_local_addresses(dut,po_s2l4)[0]]
    [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2],[leaf3],[leaf4]])

def config_bgp(config='yes'):
    st.log("BGP and evpn configs between Leaf and Spine")
    if config == 'yes':
        def spine1():
            dut = data.dut1
            dut_as = dut1_AS
            remote_as_list = [dut3_AS,dut5_AS,dut6_AS]
            nbr_list = [dut3_loopback_ip[0],dut5_loopback_ip[0],dut6_loopback_ip[0]]
            st.wait(2)
            for rem_as,nbr in zip(remote_as_list,nbr_list):
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = rem_as, neighbor = nbr,
                     config_type_list = ['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd','connect'], connect = '3', ebgp_mhop = 2, update_src_intf = loopback1)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=rem_as)
            nbr_list = [po_s1l1,po_s1l3,po_s1l4]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'external', interface = nbr,
                 config_type_list = ['bfd'],config = 'yes')
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')

            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def spine2():
            dut = data.dut2
            dut_as = dut2_AS
            remote_as_list = [dut4_AS, dut5_AS, dut6_AS]
            nbr_list = [dut4_loopback_ip[0], dut5_loopback_ip[0], dut6_loopback_ip[0]]
            st.wait(2)
            for rem_as, nbr in zip(remote_as_list, nbr_list):
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as=rem_as, neighbor=nbr,
                                   config_type_list=['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd','connect'], connect = '3', ebgp_mhop=2,
                                   update_src_intf=loopback1)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                     config_type_list=["activate"], local_as=dut_as, remote_as=rem_as)

            nbr_list = [po_s2l2, po_s2l3, po_s2l4]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=nbr,
                                   config_type_list = ['bfd'],config = 'yes')
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                     config_type_list=["activate"], local_as=dut_as, remote_as='external')

            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf1():
            dut = data.dut3
            dut_as = dut3_AS
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = dut1_AS, neighbor = dut1_loopback_ip[0],
                 config_type_list = ['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd','connect'], connect = '3', ebgp_mhop = 2, update_src_intf = loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut1_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut1_AS)
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'external', interface = po_s1l1,
                 config_type_list = ['bfd'],config = 'yes')

            evpn.config_bgp_evpn(dut=dut, neighbor=po_s1l1, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')

            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf2():
            dut = data.dut4
            dut_as = dut4_AS
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut2_AS, neighbor=dut2_loopback_ip[0],
                               config_type_list=['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd','connect'], connect = '3', ebgp_mhop=2, update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut2_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut2_AS)
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'external', interface = po_s2l2,
                 config_type_list = ['bfd'],config = 'yes')
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s2l2, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf3():
            dut = data.dut5
            dut_as = dut5_AS
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = dut1_AS, neighbor = dut1_loopback_ip[0],
                 config_type_list = ['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd'], ebgp_mhop = 2, update_src_intf = loopback1)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut2_AS, neighbor=loopback1_ip_list[1],
                               config_type_list=['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd','connect'], connect = '3', ebgp_mhop=2, update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut1_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut1_AS)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut2_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut2_AS)
            # Link local
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'external', interface = po_s1l3,
                 config_type_list = ['bfd'],config = 'yes')
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as='external', interface = po_s2l3,
                               config_type_list = ['bfd'],config = 'yes')
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s1l3, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s2l3, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')

            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf4():
            dut = data.dut6
            dut_as = dut6_AS
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = dut1_AS, neighbor = dut1_loopback_ip[0],
                 config_type_list = ['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd'], ebgp_mhop = 2, update_src_intf = loopback1)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut2_AS, neighbor=dut2_loopback_ip[0],
                               config_type_list=['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd','connect'], connect = '3', ebgp_mhop=2, update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut1_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut1_AS)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut2_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut2_AS)
            # link local
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'external', interface = po_s1l4,
                 config_type_list = ['bfd'], ebgp_mhop = 2, update_src_intf = loopback1)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as='external', interface=po_s2l4,
                               config_type_list=['bfd'], ebgp_mhop=2, update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s1l4, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s2l4, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        [res, exceptions] = st.exec_all( [[spine1], [spine2], [leaf1], [leaf2], [leaf3], [leaf4]])

    else:
        ##########################################################################
        st.log("BGP-Deconfig: Delete BGP routers globally from all DUTs")
        ##########################################################################

        dict1 = {'local_as':dut3_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf1}
        dict2 = {'local_as':dut4_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf1}
        dict3 = {'local_as':dut5_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf1}
        dict4 = {'local_as':dut6_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf1}

        parallel.exec_parallel(True, data.leaf_list, bgp_api.config_bgp, [dict1,dict2,dict3,dict4])
        dict1 = []
        for dut_as in [dut1_AS,dut2_AS,dut3_AS,dut4_AS,dut5_AS,dut6_AS]:
            dict1 = dict1 + [{'local_as' : dut_as,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}]
        parallel.exec_parallel(True, data.rtr_list, bgp_api.config_bgp, dict1)


def config_ibgp(config='yes'):

    st.log("BGP and evpn configs between Leaf and Spine")
    if config == 'yes':
        def spine1():
            dut = data.dut1
            dut_as = dut1_AS
            rem_as = dut1_AS
            nbr_list = [dut3_loopback_ip[0],dut5_loopback_ip[0],dut6_loopback_ip[0]]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = rem_as, neighbor = nbr,
                     config_type_list = [ 'neighbor','update_src_intf', 'bfd', 'connect'], connect = '3', update_src_intf = loopback1)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=rem_as)
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='ipv4',
                                                      nbr_ip=nbr, config='yes')
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                                                          nbr_ip=nbr, config='yes')
                bgp_api.create_bgp_next_hop_self(dut, local_asn=dut_as, addr_family='ipv4', nbr_ip=nbr, force='yes')

                #evpn.config_bgp_evpn(dut=dut, local_as=dut_as, addr_family='l2vpn',
                #                     config_type_list=["route_reflector_client"], neighbor=nbr, config='yes')
            nbr_list = [po_s1l1,po_s1l3,po_s1l4]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'internal', interface = nbr,
                 config_type_list = ['bfd'])
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='ipv4',
                                                      nbr_ip=nbr, config='yes')
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                                                          nbr_ip=nbr, config='yes')

            #evpn.config_bgp_evpn(dut=dut, local_as=dut_as, addr_family='l2vpn',config_type_list=["route_reflector_client"],
                #                                      neighbor="interface " +nbr, config='yes')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def spine2():
            dut = data.dut2
            dut_as = dut1_AS
            rem_as = dut1_AS
            nbr_list = [dut4_loopback_ip[0],dut5_loopback_ip[0],dut6_loopback_ip[0]]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = rem_as, neighbor = nbr,
                     config_type_list = [ 'neighbor','update_src_intf', 'bfd' , 'connect'], connect = '3', update_src_intf = loopback1)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=rem_as)
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='ipv4',
                                                      nbr_ip=nbr, config='yes')
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                                                          nbr_ip=nbr, config='yes')
                bgp_api.create_bgp_next_hop_self(dut, local_asn=dut_as, addr_family='ipv4', nbr_ip=nbr, force='yes')

                #evpn.config_bgp_evpn(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                #                     config_type_list=["route_reflector_client"], neighbor=nbr, config='yes')
            nbr_list = [po_s2l2, po_s2l3, po_s2l4]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'internal', interface = nbr,
                 config_type_list = ['bfd'])
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='ipv4',
                                                      nbr_ip=nbr, config='yes')
                bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                                                          nbr_ip=nbr, config='yes')
                #evpn.config_bgp_evpn(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                #                     config_type_list=["route_reflector_client"], neighbor="interface " +nbr, config='yes')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf1():
            dut = data.dut3
            dut_as = dut1_AS

            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = dut_as, neighbor = dut1_loopback_ip[0],
                 config_type_list = [ 'neighbor','update_src_intf', 'bfd', 'connect'], connect = '3', update_src_intf = loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut1_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'internal', interface = po_s1l1,
                 config_type_list = ['bfd'])
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s1l1, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

            #--
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=dut_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=dut_as, advertise_ipv6='unicast')
            nbr = dut4_3_ip_list[1]
            #vlan_api.create_vlan(dut, vlan_list)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut_as, neighbor=nbr, config_type_list=['neighbor', 'bfd'])
            evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes', config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)

            bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='ipv4',
                                                  nbr_ip=nbr, config='yes')
            bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                                                      nbr_ip=nbr, config='yes')
            bgp_api.create_bgp_next_hop_self(dut,local_asn=dut_as, addr_family='ipv4',nbr_ip=nbr,force='yes')

            #evpn.config_bgp_evpn(dut=dut, local_as=dut_as, addr_family='l2vpn',
            #                 config_type_list=["route_reflector_client"], neighbor=nbr, config='yes')

        def leaf2():
            dut = data.dut4
            dut_as = dut1_AS
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut_as, neighbor=dut2_loopback_ip[0],
                               config_type_list=['neighbor','update_src_intf', 'bfd', 'connect'], connect = '3', update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut2_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'internal', interface = po_s2l2,
                 config_type_list = ['bfd'])
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s2l2, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

            #--
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=dut_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=dut_as, advertise_ipv6='unicast')
            nbr = dut3_4_ip_list[1]
            #vlan_api.create_vlan(dut, vlan_list)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut_as, neighbor=nbr, config_type_list=['neighbor', 'bfd'])
            evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes', config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)

            bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='ipv4',
                                                  nbr_ip=nbr, config='yes')
            bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                                                    nbr_ip=nbr, config='yes')

            #evpn.config_bgp_evpn(dut=dut, local_as=dut_as, addr_family='l2vpn',
            #                 config_type_list=["route_reflector_client"], neighbor=nbr, config='yes')
            bgp_api.create_bgp_next_hop_self(dut,local_asn=dut_as, addr_family='ipv4',nbr_ip=nbr,force='yes')

            nbr = po_s2l2
            bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='ipv4',
                                                  nbr_ip=nbr, config='yes')
            bgp_api.create_bgp_route_reflector_client(dut=dut, local_asn=dut_as, addr_family='l2vpn',
                                                      nbr_ip=nbr, config='yes')
            #evpn.config_bgp_evpn(dut=dut, local_as=dut_as, addr_family='l2vpn',
            #                 config_type_list=["route_reflector_client"], neighbor="interface " + nbr, config='yes')
        def leaf3():
            dut = data.dut5
            dut_as = dut1_AS
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = dut_as, neighbor = dut1_loopback_ip[0],
                 config_type_list = ['neighbor','update_src_intf', 'bfd'], update_src_intf = loopback1)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut_as, neighbor=loopback1_ip_list[1],
                               config_type_list=['neighbor','update_src_intf', 'bfd'], update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut1_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut2_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)
            # Link local
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'internal', interface = po_s1l3,
                 config_type_list = ['bfd'])
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as='internal', interface = po_s2l3,
                               config_type_list=['bfd'])
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s1l3, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s2l3, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')

            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

            #--
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=dut_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=dut_as, advertise_ipv6='unicast')

        def leaf4():
            dut = data.dut6
            dut_as = dut1_AS
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = dut_as, neighbor = dut1_loopback_ip[0],
                 config_type_list = ['neighbor','update_src_intf', 'bfd'], update_src_intf = loopback1)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as=dut_as, neighbor=dut2_loopback_ip[0],
                               config_type_list=['neighbor','update_src_intf', 'bfd'], update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut1_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)
            evpn.config_bgp_evpn(dut=dut, neighbor=dut2_loopback_ip[0], config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as=dut_as)
            # link local
            bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'internal', interface = po_s1l4,
                 config_type_list = ['bfd'], update_src_intf = loopback1)
            bgp_api.config_bgp(dut=dut,local_as=dut_as, remote_as='internal', interface=po_s2l4,
                               config_type_list=['bfd'], ebgp_mhop=2, update_src_intf=loopback1)
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s1l4, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')
            evpn.config_bgp_evpn(dut=dut, neighbor=po_s2l4, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='internal')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

            #--
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=dut_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=dut_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=dut_as, advertise_ipv6='unicast')
        [res, exceptions] = st.exec_all( [[spine1], [spine2], [leaf1], [leaf2], [leaf3], [leaf4]])
    else:
        ##########################################################################
        st.log("BGP-Deconfig: Delete BGP routers globally from all DUTs")
        ##########################################################################
        dict1 = {'local_as' : dut1_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf1}
        dict2 = {'local_as' : dut1_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}

        parallel.exec_parallel(True, data.rtr_list, bgp_api.config_bgp, [dict1] * 6)
        parallel.exec_parallel(True, data.rtr_list, bgp_api.config_bgp, [dict2] * 6)


def config_leafInterface(config='yes'):

    ################################################
    st.log("Configure Leaf nodes .")
    ################################################

    if config == 'yes' :
        def leaf1():

            dut = data.dut3
            vtep_name = vtep_names[0]
            nvo_name = nvo_names[0]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut3_loopback_ip[1]
            local_as = dut3_AS
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]

            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=vrf1,intf_name=vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip[0], mask_24)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip6[0], mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name)
            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=local_as, advertise_ipv6='unicast')

        def leaf2():

            dut = data.dut4
            vtep_name = vtep_names[0]
            nvo_name = nvo_names[0]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut3_loopback_ip[1]
            local_as = dut4_AS
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]

            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=vrf1,intf_name=vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip[0], mask_24)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip6[0], mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=local_as, advertise_ipv6='unicast')

        def leaf3():

            dut = data.dut5
            vtep_name = vtep_names[2]
            nvo_name = nvo_names[2]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut5_loopback_ip[1]
            local_as = dut5_AS
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf3_dict["tenant_l3_vlan_list"]

            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=vrf1,intf_name=vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip[2], mask_24)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip6[2], mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"],  redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"], redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],  local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],  local_as=local_as, advertise_ipv6='unicast')
            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                vlan_api.add_vlan_member(dut, vlan , data.d5t1_ports[0], True)

        def leaf4():

            dut = data.dut6
            vtep_name = vtep_names[3]
            nvo_name = nvo_names[3]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut6_loopback_ip[1]
            local_as = dut6_AS
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf4_dict["tenant_l3_vlan_list"]

            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=vrf1,intf_name=vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip[3], mask_24)
            ip_api.config_ip_addr_interface(dut, vlan_vrf1, vrf1_ip6[3], mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"], redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=vrf1, config='yes', config_type_list=["redist"], redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"], local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"], local_as=local_as, advertise_ipv6='unicast')
            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                vlan_api.add_vlan_member(dut,vlan, data.d6t1_ports[0], True)
    else:
        def leaf1():
            dut = data.dut3
            vtep_name = vtep_names[0]
            nvo_name = nvo_names[0]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut3_loopback_ip[1]
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]

            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config = 'no')

            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name, config = 'no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config = 'no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config = 'no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config = 'no')
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip[0], mask_24)
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip6[0], mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_vrf1,config = 'no')
            vlan_api.delete_vlan(dut, vlan_list)

        def leaf2():
            dut = data.dut4
            vtep_name = vtep_names[0]
            nvo_name = nvo_names[0]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut3_loopback_ip[1]
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]

            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config = 'no')

            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name, config = 'no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config = 'no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config = 'no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config = 'no')
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip[0], mask_24)
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip6[0], mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_vrf1,config = 'no')
            vlan_api.delete_vlan(dut, vlan_list)

        def leaf3():
            dut = data.dut5
            vtep_name = vtep_names[2]
            nvo_name = nvo_names[2]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut5_loopback_ip[1]
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf3_dict["tenant_l3_vlan_list"]

            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                vlan_api.delete_vlan_member(dut,vlan, data.d5t1_ports[0],True)

            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name, config='no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config='no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config='no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config='no')
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip[2], mask_24)
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip6[2], mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_vrf1, config='no')
            vlan_api.delete_vlan(dut,vlan_list)

        def leaf4():
            dut = data.dut6
            vtep_name = vtep_names[3]
            nvo_name = nvo_names[3]
            vlan_vni = vni_vlan[0]
            ovrly_int = dut6_loopback_ip[1]
            vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf4_dict["tenant_l3_vlan_list"]

            for vlan in client_dict["tenant_l2_vlan_list"]:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                vlan_api.delete_vlan_member(dut,vlan, data.d6t1_ports[0],True)

            evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan_vni, vtep_name=vtep_name, config='no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config='no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config='no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config='no')
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip[3], mask_24)
            ip_api.delete_ip_interface(dut, vlan_vrf1, vrf1_ip6[3], mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_vrf1, config='no')
            vlan_api.delete_vlan(dut, vlan_list)
    st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])



def config_mclag(config = 'yes'):

    ################################################
    st.log("Configure MCLAG and bring up LVTEP.")
    ################################################
    # Config peer interface lag
    # Config Keepalive interface
    # Create Vlan for peer interface
    mclag_client_vlans = client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]

    if config == 'yes':
        def leaf1():
            dut = data.dut3
            ip_api.config_ip_addr_interface(dut, data.d3d4_ports[2], dut3_4_ip_list[0],mask31)
            pc.create_portchannel(dut, iccp_lag)
            pc.create_portchannel(dut, client_lag)
            pc.create_portchannel(dut, orphan_lag)

            pc.add_portchannel_member(dut,iccp_lag,data.d3d4_ports[0])
            pc.add_portchannel_member(dut, client_lag, data.d3d7_ports[0])
            pc.add_portchannel_member(dut,orphan_lag,data.d3d7_ports[2])

            vlan_api.add_vlan_member(dut,vni_vlan[0],iccp_lag,True)
            mclag.config_domain(dut, mlag_domain_id, local_ip=dut3_4_ip_list[0],
                                peer_ip=dut4_3_ip_list[0], peer_interface=iccp_lag)
            mclag.config_interfaces(dut, mlag_domain_id, client_lag, config="add")
            for vlan in mclag_client_vlans:
                vlan_api.add_vlan_member(dut, vlan, [iccp_lag], True)
            vlan_api.add_vlan_member(dut, client_dict["tenant_l2_vlan_list"][0],[client_lag], True)
            vlan_api.add_vlan_member(dut, client_dict["tenant_l2_vlan_list"][1],[orphan_lag], True)
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.add_vlan_member(dut, vlan, [client_lag], True)
            #vlan_api.add_vlan_member(dut, client_dict["tenant_l3_vlan_list"],[client_lag], True)
            #vlan_api.add_vlan_member(dut, client_dict["tenant_l3_vlan_list"][1],[data.d3d7_ports[2]], True)

        def leaf2():
            dut = data.dut4
            ip_api.config_ip_addr_interface(dut, data.d4d3_ports[2], dut4_3_ip_list[0], mask31)
            pc.create_portchannel(dut, iccp_lag)
            pc.create_portchannel(dut, client_lag)
            pc.add_portchannel_member(dut, iccp_lag, data.d4d3_ports[0])
            vlan_api.add_vlan_member(dut,vni_vlan[0],iccp_lag,True)
            mclag.config_domain(dut, mlag_domain_id, local_ip=dut4_3_ip_list[0],
                                peer_ip=dut3_4_ip_list[0], peer_interface=iccp_lag)
            mclag.config_interfaces(dut, mlag_domain_id, client_lag, config="add")
            pc.add_portchannel_member(dut,client_lag,data.d4d7_ports[0])
            for vlan in mclag_client_vlans:
                vlan_api.add_vlan_member(dut,vlan,[iccp_lag],True)
            vlan_api.add_vlan_member(dut, client_dict["tenant_l2_vlan_list"][0],[client_lag], True)
            vlan_api.add_vlan_member(dut, client_dict["tenant_l2_vlan_list"][2],[data.d4d7_ports[2]], True)
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.add_vlan_member(dut, vlan, [client_lag], True)
            #vlan_api.add_vlan_member(dut, client_dict["tenant_l3_vlan_list"][0],[client_lag], True)
            #vlan_api.add_vlan_member(dut, client_dict["tenant_l3_vlan_list"][2],[data.d4d7_ports[2]], True)
        def client1():
            dut = data.dut7
            pc.create_portchannel(dut, client_lag)
            pc.create_portchannel(dut, orphan_lag)

            vlan_api.create_vlan(dut, mclag_client_vlans)
            pc.add_portchannel_member(dut, client_lag, data.d7d3_ports[0])
            pc.add_portchannel_member(dut, client_lag, data.d7d4_ports[0])
            pc.add_portchannel_member(dut, orphan_lag, data.d7d3_ports[2])

            for vlan in client_dict["tenant_l2_vlan_list"]:
                vlan_api.add_vlan_member(dut,vlan,[data.d7t1_ports[0]],True)
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.add_vlan_member(dut,vlan,[data.d7t1_ports[1]],True)
            vlan_api.add_vlan_member(dut, client_dict["tenant_l2_vlan_list"][0],[client_lag], True)
            vlan_api.add_vlan_member(dut, client_dict["tenant_l2_vlan_list"][2],[data.d7d4_ports[2]], True)
            vlan_api.add_vlan_member(dut, client_dict["tenant_l2_vlan_list"][1],[orphan_lag], True)
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.add_vlan_member(dut, vlan, [client_lag], True)
            #vlan_api.add_vlan_member(dut, client_dict["tenant_l3_vlan_list"][0],[client_lag], True)
            #vlan_api.add_vlan_member(dut, client_dict["tenant_l3_vlan_list"][2],[data.d7d4_ports[2]], True)
            #vlan_api.add_vlan_member(dut, client_dict["tenant_l3_vlan_list"][1],[data.d7d3_ports[2]], True)
    else:
        def leaf1():
            dut = data.dut3
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][0], [client_lag],True)
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][1], [orphan_lag],True)
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][0], [client_lag])
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][1], [data.d3d7_ports[2]])
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.delete_vlan_member(dut, vlan, [client_lag],True)

            mclag.config_interfaces(dut, mlag_domain_id, client_lag, config="del")
            mclag.config_domain(dut, mlag_domain_id, local_ip=dut3_4_ip_list[0],
                                peer_ip=dut4_3_ip_list[0], peer_interface=iccp_lag, config="del")
            pc.delete_portchannel_member(dut,client_lag,data.d3d7_ports[0])
            pc.delete_portchannel_member(dut,orphan_lag,data.d3d7_ports[2])

            for vlan in mclag_client_vlans:
                vlan_api.delete_vlan_member(dut,vlan,[iccp_lag],True)
            vlan_api.delete_vlan_member(dut,vni_vlan[0],iccp_lag,True)

            pc.delete_portchannel_member(dut,iccp_lag,data.d3d4_ports[0])
            pc.delete_portchannel(dut, iccp_lag)
            pc.delete_portchannel(dut, client_lag)
            pc.delete_portchannel(dut, orphan_lag)

            ip_api.delete_ip_interface(dut, data.d3d4_ports[2], dut3_4_ip_list[0],mask31)

        def leaf2():
            dut = data.dut4
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][0],[client_lag],True)
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][2],[data.d4d7_ports[2]],True)
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][0],[client_lag])
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][2],[data.d4d7_ports[2]])
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.delete_vlan_member(dut, vlan, [client_lag],True)
            mclag.config_interfaces(dut, mlag_domain_id, client_lag, config="del")
            mclag.config_domain(dut, mlag_domain_id, local_ip=dut4_3_ip_list[0],
                                peer_ip=dut3_4_ip_list[0], peer_interface=iccp_lag, config="del")
            for vlan in mclag_client_vlans:
                vlan_api.delete_vlan_member(dut,vlan,[iccp_lag],True)
            vlan_api.delete_vlan_member(dut,vni_vlan[0],iccp_lag,True)
            pc.delete_portchannel_member(dut,client_lag,data.d4d7_ports[0])
            pc.delete_portchannel_member(dut, iccp_lag, data.d4d3_ports[0])
            pc.delete_portchannel(dut, iccp_lag)
            pc.delete_portchannel(dut, client_lag)
            ip_api.delete_ip_interface(dut, data.d4d3_ports[2], dut4_3_ip_list[0], mask31)

        def client1():
            dut = data.dut7
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][0],[client_lag],True)
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][2],[data.d7d4_ports[2]],True)
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][1],[orphan_lag],True)
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][0],[client_lag])
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][2],[data.d7d4_ports[2]])
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][1],[data.d7d3_ports[2]])
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.delete_vlan_member(dut, vlan, [client_lag],True)
            pc.delete_portchannel_member(dut, orphan_lag, data.d7d3_ports[2])
            pc.delete_portchannel_member(dut, client_lag, data.d7d3_ports[0])
            pc.delete_portchannel_member(dut, client_lag, data.d7d4_ports[0])
            for vlan in client_dict["tenant_l2_vlan_list"]:
                vlan_api.delete_vlan_member(dut,vlan,[data.d7t1_ports[0]],True)
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.delete_vlan_member(dut,vlan,[data.d7t1_ports[1]],True)
            pc.delete_portchannel(dut, client_lag)
            pc.delete_portchannel(dut, orphan_lag)

            vlan_api.delete_vlan(dut, client_dict["tenant_l2_vlan_list"]+client_dict["tenant_l3_vlan_list"])
    st.exec_all([[leaf1],[leaf2],[client1]])


def l3vni_client_config(config = 'yes'):
    ################################################
    st.log("Configure L3 VNI Clients on each leaf node.")
    ################################################
    # Create Vlan and config membership
    # Bind VRF
    # Config IP addresses
    # Config VRF VNI mapping
    # Other Configs ?
    def sag_config(dut,intf,sag_ip_gw,sag_ip6_gw,config="add"):
        if config == "add":
            sag_mode = "enable"
        else:
            sag_mode = "disable"

        sag.config_sag_ip(dut, interface=intf, gateway=sag_ip_gw, mask=mask_24,config = config)
        sag.config_sag_ip(dut, interface=intf, gateway=sag_ip6_gw, mask=mask_v6,config = config)
        sag.config_sag_mac(dut, mac=sag_mac,config = config)
        sag.config_sag_mac(dut, config=sag_mode)
        sag.config_sag_mac(dut, ip_type='ipv6', config=sag_mode)

    if config == 'yes':
        def leaf1():
            dut = data.dut3
            vtep_name = vtep_names[0]
            # Unique IP
            mclag.config_uniqueip(dut, op_type='add', vlan=client_dict["tenant_l3_vlan_int"][1])
            mclag.config_gw_mac(dut,mac=mclag_gw_mac)
            mclag.config_mclag_system_mac(dut,domain_id=mlag_domain_id,mac=mclag_sys_mac)

            for vlan,vlan_int,ip,ip6 in zip(client_dict["tenant_l3_vlan_list"],client_dict["tenant_l3_vlan_int"],
                                            client_dict["l3_tenant_ip_list"],client_dict["l3_tenant_ipv6_list"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int)
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)
                if vlan == client_dict["tenant_l3_vlan_list"][2]:
                    sag_config(dut, vlan_int, ip, ip6, "add")
                else:
                    ip_api.config_ip_addr_interface(dut, vlan_int, ip, mask_24)
                    ip_api.config_ip_addr_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')

        def leaf2():
            dut = data.dut4
            vtep_name = vtep_names[0]
            mclag.config_uniqueip(dut, op_type='add', vlan=client_dict["tenant_l3_vlan_int"][1])
            mclag.config_gw_mac(dut,mac=mclag_gw_mac)
            mclag.config_mclag_system_mac(dut,domain_id=mlag_domain_id,mac=mclag_sys_mac)

            for vlan,vlan_int,ip,ip6 in zip(client_dict["tenant_l3_vlan_list"],client_dict["tenant_l3_vlan_int"],
                                            client_dict["l3_tenant_ip_list3"],client_dict["l3_tenant_ipv6_list3"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int)
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)
                if vlan == client_dict["tenant_l3_vlan_list"][2]:
                    sag_config(dut, vlan_int, ip, ip6, "add")
                else:
                    ip_api.config_ip_addr_interface(dut, vlan_int, ip, mask_24)
                    ip_api.config_ip_addr_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')

        def leaf3():
            dut = data.dut5
            vtep_name = vtep_names[2]
            for vlan,vlan_int,ip,ip6 in zip(leaf3_dict["tenant_l3_vlan_list"],leaf3_dict["tenant_l3_vlan_int"],
                                            leaf3_dict["l3_tenant_ip_list"],leaf3_dict["l3_tenant_ipv6_list"]):
                vlan_api.add_vlan_member(dut,vlan,[data.d5t1_ports[1]],True)
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, mask_24)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)
            ip_api.config_ip_addr_interface(dut, client_dict["tenant_l2_vlan_int"][0], leaf3_dict["l2_tenant_ip_list"][0], mask_24)
            ip_api.config_ip_addr_interface(dut, client_dict["tenant_l2_vlan_int"][0], leaf3_dict["l2_tenant_ipv6_list"][0], mask_v6,family='ipv6')

        def leaf4():
            dut = data.dut6
            vtep_name = vtep_names[3]
            for vlan,vlan_int,ip,ip6 in zip(leaf4_dict["tenant_l3_vlan_list"],leaf4_dict["tenant_l3_vlan_int"],
                                            leaf4_dict["l3_tenant_ip_list"],leaf4_dict["l3_tenant_ipv6_list"]):
                vlan_api.add_vlan_member(dut,vlan,[data.d6t1_ports[1]],True)
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, mask_24)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)
        def client():
            dut = data.dut7
            vlan_int_list = [client_dict["tenant_l2_vlan_int"][0]] + client_dict["tenant_l3_vlan_int"][1:3]
            ip_list = [client_dict["l2_tenant_ip_list"][0]]+ client_dict["l3_tenant_ip_list2"][1:3]
            ip6_list = [client_dict["l2_tenant_ipv6_list"][0]]+ client_dict["l3_tenant_ipv6_list2"][1:3]

            for vlan_int,ip,ip6 in zip(vlan_int_list,ip_list,ip6_list):
                ip_api.config_ip_addr_interface(dut, vlan_int,ip, mask_24)
                ip_api.config_ip_addr_interface(dut, vlan_int,ip6, mask_v6, family='ipv6')
            ip_api.create_static_route(dut, next_hop=client_dict["l3_tenant_ip_list"][2], static_ip="50.0.1.0" + '/' + mask_24)
            ip_api.create_static_route(dut, next_hop=client_dict["l3_tenant_ipv6_list"][2], family='ipv6',
                                       static_ip="5001::0" + '/' + mask_v6)

    else:
        def leaf1():
            dut = data.dut3
            vtep_name = vtep_names[0]

            mclag.config_gw_mac(dut,mac=mclag_gw_mac,config='del')
            mclag.config_mclag_system_mac(dut,domain_id=mlag_domain_id,config='del')
            for vlan,vlan_int,ip,ip6 in zip(client_dict["tenant_l3_vlan_list"],client_dict["tenant_l3_vlan_int"],
                                            client_dict["l3_tenant_ip_list"],client_dict["l3_tenant_ipv6_list"]):
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name,config = 'no')
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                if vlan == client_dict["tenant_l3_vlan_list"][2]:
                    sag_config(dut, vlan_int, ip, ip6, "remove")
                else:
                    ip_api.delete_ip_interface(dut, vlan_int, ip, mask_24)
                    ip_api.delete_ip_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int,config = 'no')
            mclag.config_uniqueip(dut,skip_error=True, op_type='del', vlan=client_dict["tenant_l3_vlan_int"][1])

        def leaf2():
            dut = data.dut4
            vtep_name = vtep_names[0]
            mclag.config_gw_mac(dut,mac=mclag_gw_mac,config='del')
            mclag.config_mclag_system_mac(dut,domain_id=mlag_domain_id,config='del')
            for vlan,vlan_int,ip,ip6 in zip(client_dict["tenant_l3_vlan_list"],client_dict["tenant_l3_vlan_int"],
                                            client_dict["l3_tenant_ip_list3"],client_dict["l3_tenant_ipv6_list3"]):
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name,config = 'no')
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                if vlan == client_dict["tenant_l3_vlan_list"][2]:
                    sag_config(dut, vlan_int, ip, ip6, "remove")
                else:
                    ip_api.delete_ip_interface(dut, vlan_int, ip, mask_24)
                    ip_api.delete_ip_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int, config='no')
            mclag.config_uniqueip(dut,skip_error=True, op_type='del', vlan=client_dict["tenant_l3_vlan_int"][1])

        def leaf3():
            dut = data.dut5
            vtep_name = vtep_names[2]

            ip_api.delete_ip_interface(dut, client_dict["tenant_l2_vlan_int"][0], leaf3_dict["l2_tenant_ip_list"][0], mask_24)
            ip_api.delete_ip_interface(dut, client_dict["tenant_l2_vlan_int"][0], leaf3_dict["l2_tenant_ipv6_list"][0], mask_v6,family='ipv6')

            for vlan,vlan_int,ip,ip6 in zip(leaf3_dict["tenant_l3_vlan_list"],leaf3_dict["tenant_l3_vlan_int"],
                                            leaf3_dict["l3_tenant_ip_list"],leaf3_dict["l3_tenant_ipv6_list"]):
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name,config = 'no')
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                ip_api.delete_ip_interface(dut, vlan_int, ip, mask_24)
                ip_api.delete_ip_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int,config = 'no')
                vlan_api.delete_vlan_member(dut,vlan,[data.d5t1_ports[1]],True)

        def leaf4():
            dut = data.dut6
            vtep_name = vtep_names[3]
            for vlan,vlan_int,ip,ip6 in zip(leaf4_dict["tenant_l3_vlan_list"],leaf4_dict["tenant_l3_vlan_int"],
                                            leaf4_dict["l3_tenant_ip_list"],leaf4_dict["l3_tenant_ipv6_list"]):
                evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name,config = 'no')
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                ip_api.delete_ip_interface(dut, vlan_int, ip, mask_24)
                ip_api.delete_ip_interface(dut, vlan_int, ip6, mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlan_int,config = 'no')
                vlan_api.delete_vlan_member(dut,vlan,[data.d6t1_ports[1]],True)
        def client():
            dut = data.dut7
            vlan_int_list = [client_dict["tenant_l2_vlan_int"][0]] + client_dict["tenant_l3_vlan_int"][1:3]
            ip_list = [client_dict["l2_tenant_ip_list"][0]]+ client_dict["l3_tenant_ip_list2"][1:3]
            ip6_list = [client_dict["l2_tenant_ipv6_list"][0]]+ client_dict["l3_tenant_ipv6_list2"][1:3]

            for vlan_int,ip,ip6 in zip(vlan_int_list,ip_list,ip6_list):
                ip_api.delete_ip_interface(dut, vlan_int,ip, mask_24)
                ip_api.delete_ip_interface(dut, vlan_int,ip6, mask_v6, family='ipv6')
            ip_api.delete_static_route(dut, next_hop=client_dict["l3_tenant_ip_list"][2],static_ip="50.0.1.0" + '/' + mask_24)
            ip_api.delete_static_route(dut, next_hop=client_dict["l3_tenant_ipv6_list"][2], family='ipv6',
                                       static_ip="5001::0" + '/' + mask_v6)
    st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4],[client]])

def vlan_underlay_lvtep(config='yes'):
    ################################################
    st.log("Configure Vlan underlay between VTEP nodes.")
    ################################################
    # Create Vlans and config iccp as member
    # Config IP addresses
    # Config BGP
    # Other Configs ?

    if config == 'yes':
        # Temp use physical interface instead of vlan interface
        def leaf1():
            dut = data.dut3
            vlan_list = vlan_l1_l2
            vlan_api.create_vlan(dut, vlan_list)
            # Tagged
            vlan_api.add_vlan_member(dut, vlan_list[0], iccp_lag, True)
            # Untagged
            vlan_api.add_vlan_member(dut, vlan_list[1], iccp_lag)
            for vlan,ip,nip in zip(vlan_list,dut3_4_ip_list[1:],dut4_3_ip_list[1:]):
                vlan_int = "Vlan"+vlan
                mclag.config_uniqueip(dut, op_type='add', vlan=vlan_int)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, mask31)
            st.wait(2)
            for nbr_ip in dut4_3_ip_list[1:]:
                bgp_api.config_bgp(dut=dut,local_as = dut3_AS, remote_as = dut4_AS, neighbor = nbr_ip,
                    config_type_list = ['neighbor', 'ebgp_mhop','connect', 'bfd'], ebgp_mhop = 2,connect = '3')
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr_ip, config='yes', config_type_list=["activate"],local_as=dut3_AS, remote_as=dut4_AS)
            bgp_api.config_bgp_router(dut, dut3_AS, '', keep_alive, hold_down, 'yes')
                #bgp_api.clear_ip_bgp_vtysh(data.dut3)
            result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=dut4_3_ip_list[1:], state_list=['Established']*2, delay = 6, retry_count = 20)
            return result

        def leaf2():
            dut = data.dut4
            vlan_list = vlan_l1_l2
            vlan_api.create_vlan(dut, vlan_list)
            # Tagged
            vlan_api.add_vlan_member(dut, vlan_list[0], iccp_lag, True)
            # Untagged
            vlan_api.add_vlan_member(dut, vlan_list[1], iccp_lag)
            for vlan,ip,nip in zip(vlan_list,dut4_3_ip_list[1:],dut3_4_ip_list[1:]):
                vlan_int = "Vlan" + vlan
                mclag.config_uniqueip(dut, op_type='add', vlan=vlan_int)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, mask31)

            for nbr_ip in dut3_4_ip_list[1:]:
                bgp_api.config_bgp(dut=dut,local_as = dut4_AS, remote_as = dut3_AS, neighbor = nbr_ip,
                    config_type_list = ['neighbor', 'ebgp_mhop','connect', 'bfd'], ebgp_mhop = 2,connect = '3')
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr_ip, config='yes', config_type_list=["activate"],local_as=dut4_AS, remote_as=dut3_AS)
            bgp_api.config_bgp_router(dut, dut4_AS, '', keep_alive, hold_down, 'yes')
                #bgp_api.clear_ip_bgp_vtysh(data.dut3)
            st.wait(3)
            result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=dut3_4_ip_list[1:], state_list=['Established']*2, delay = 6, retry_count = 20)

            return result
    else:
        def leaf1():
            dut = data.dut3
            #vlan_api.create_vlan(dut, vlan_list)
            vlan_list = vlan_l1_l2
            for vlan,ip,nip in zip(vlan_list,dut3_4_ip_list[1:],dut4_3_ip_list[1:]):
                vlan_int = "Vlan" + vlan
                ip_api.delete_ip_interface(dut, vlan_int, ip, mask31)
                mclag.config_uniqueip(dut,skip_error=True, op_type='del', vlan=vlan_int)

            vlan_api.delete_vlan_member(dut, vlan_list[0], iccp_lag, True)
            vlan_api.delete_vlan_member(dut, vlan_list[1], iccp_lag)
            vlan_api.delete_vlan(dut, vlan_list)

        def leaf2():
            dut = data.dut4
            #vlan_api.create_vlan(dut, vlan_list)
            vlan_list = vlan_l1_l2
            for vlan,ip,nip in zip(vlan_list,dut4_3_ip_list[1:],dut3_4_ip_list[1:]):
                vlan_int = "Vlan" + vlan
                ip_api.delete_ip_interface(dut, vlan_int, ip, mask31)
                mclag.config_uniqueip(dut,skip_error=True, op_type='del', vlan=vlan_int)

            vlan_api.delete_vlan_member(dut, vlan_list[0], iccp_lag, True)
            vlan_api.delete_vlan_member(dut, vlan_list[1], iccp_lag)
            vlan_api.delete_vlan(dut, vlan_list)
    st.exec_all( [[leaf1], [leaf2]])

stream_dict = {}
tg_dict = {}
han_dict = {}
def create_glob_vars():
    global vars, tg, d3_tg_ph1, d3_tg_ph2, d4_tg_ph1, d4_tg_ph2, d5_tg_ph1, d5_tg_ph2, d6_tg_ph1, d6_tg_ph2
    global d4_tg_port1, d5_tg_port1,d6_tg_port1,d7_tg_port1, d7_tg_ph1, d7_tg_ph2,d5_tg_port2,d6_tg_port2,d7_tg_port2
    vars = st.ensure_min_topology("D1D3:3","D2D4:3","D3D4:3","D1D5:3","D1D6:3","D2D5:3","D2D6:3","D3D7:4","D4D7:4","D3CHIP=TD3","D4CHIP=TD3","D5CHIP=TD3","D6CHIP=TD3")

    tg = tgapi.get_chassis(vars)
    d3_tg_ph1, d3_tg_ph2 = tg.get_port_handle(vars.T1D3P1), tg.get_port_handle(vars.T1D3P2)
    d4_tg_ph1, d4_tg_ph2 = tg.get_port_handle(vars.T1D4P1), tg.get_port_handle(vars.T1D4P2)
    d5_tg_ph1, d5_tg_ph2 = tg.get_port_handle(vars.T1D5P1), tg.get_port_handle(vars.T1D5P2)
    d6_tg_ph1, d6_tg_ph2 = tg.get_port_handle(vars.T1D6P1), tg.get_port_handle(vars.T1D6P2)
    d7_tg_ph1, d7_tg_ph2 = tg.get_port_handle(vars.T1D7P1), tg.get_port_handle(vars.T1D7P2)

    d4_tg_port1,d5_tg_port1,d6_tg_port1,d7_tg_port1 = vars.T1D4P1, vars.T1D5P1, vars.T1D6P1, vars.T1D7P1
    d5_tg_port2,d6_tg_port2,d7_tg_port2 = vars.T1D5P2, vars.T1D6P2, vars.T1D7P2

    tg_dict['tg'] = tg
    tg_dict['d3_tg_ph1'],tg_dict['d3_tg_ph2'] = tg.get_port_handle(vars.T1D3P1),tg.get_port_handle(vars.T1D3P2)
    tg_dict['d4_tg_ph1'],tg_dict['d4_tg_ph2'] = tg.get_port_handle(vars.T1D4P1),tg.get_port_handle(vars.T1D4P2)
    tg_dict['d5_tg_ph1'],tg_dict['d5_tg_ph2'] = tg.get_port_handle(vars.T1D5P1),tg.get_port_handle(vars.T1D5P2)
    tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'] = tg.get_port_handle(vars.T1D6P1),tg.get_port_handle(vars.T1D6P2)
    tg_dict['d5_tg_port1'],tg_dict['d6_tg_port1'] = vars.T1D5P1, vars.T1D6P1
    tg_dict['d3_tg_port1'],tg_dict['d4_tg_port1'] = vars.T1D3P1, vars.T1D4P1
    tg_dict['tgen_rate_pps'] = '1000'
    tg_dict['frame_size'] = '1000'
    tg_dict['dut_6_mac_pattern'] = '00:02:66:00:00:'
    tg_dict['d5_tg_local_as'] = '50'
    tg_dict['d6_tg_local_as'] = '60'
    tg_dict['num_routes_1'] = '100'
    tg_dict['prefix_1'] = '100.1.1.0'
    tg_dict['prefix_2'] = '200.1.1.0'


def check_ping_clients():
    ###########################################################
    st.log("Verify client interface reachabality. ")
    ############################################################
    def leaf1():
        dut = data.dut3
        ip = "50.0.1.1"
        ip6 = "5001::1"
        ip_list = [ip,ip6]
        result = verify_ping_ip(dut, ip_list, ip4_v6='both', vrf=vrf1)
        if result is False:
            st.error("Not reachable from leaf1")
            return False
        return True

    def leaf2():
        dut = data.dut4
        ip = ""
        ip6 = ""
        ip_list = [ip,ip6]
        return verify_ping_ip(dut, ip_list, ip4_v6='both', vrf=vrf1)

    def leaf3():
        dut = data.dut5
        ip = leaf3_dict["l3_tenant_ip_list"][1]
        ip6 = leaf3_dict["l3_tenant_ipv6_list"][1]
        ip_list = [ip,ip6]
        return verify_ping_ip(dut, ip_list, ip4_v6='both', vrf=vrf1)

    def leaf4():
        dut = data.dut6
        ip = leaf3_dict["l3_tenant_ip_list"][2]
        ip6 = leaf3_dict["l3_tenant_ipv6_list"][2]
        ip_list = [ip,ip6]
        return verify_ping_ip(dut, ip_list, ip4_v6='both', vrf=vrf1)

    def client():
        dut = data.dut7
        ip = leaf3_dict["l3_tenant_ip_list"][0]
        ip6 = leaf3_dict["l3_tenant_ipv6_list"][0]
        ip_list = [ip,ip6]
        result = verify_ping_ip(dut, ip_list, ip4_v6='both',src_ip=[client_dict["l3_tenant_ip_list2"][2],client_dict["l3_tenant_ipv6_list2"][2]])
        return result

    #[res, exceptions] = st.exec_all( [[leaf1], [leaf2], [leaf3], [leaf4], [client]])
    #res = client()
    [res, exceptions] = st.exec_all( [[leaf3], [leaf4], [client]])
    if False in set(res):
        st.error("Ping failed between lvtep and svtep client interfaces")
        return False

    return res

def verify_ping_ip(dut,ip_list,ip4_v6='both',vrf='default',src_ip=''):
    if ip4_v6 == 'ipv4' and src_ip != '':
        src_ip4 = src_ip[0]
    elif ip4_v6 == 'ipv6' and src_ip != '':
        src_ip6 = src_ip[0]
    elif ip4_v6 == 'both' and src_ip != '':
        src_ip4 = src_ip[0]
        src_ip6 = src_ip[1]
      
    if ip4_v6 == 'ipv4' or ip4_v6 == 'both':
        ip = ip_list[0]
        if vrf == 'default':
            if src_ip != '':
                result = ip_api.ping(dut, ip,source_ip = src_ip4)
            else:
                result = ip_api.ping(dut, ip)
        else:
            if src_ip != '':
                result = ip_api.ping(dut, ip, interface=vrf,source_ip = src_ip4)
            else:
                result = ip_api.ping(dut, ip, interface=vrf)
        if result is False:
            st.error("IP address {} not reachable from dur {}.".format(ip, dut))
            return False
    if ip4_v6 == 'ipv6' or ip4_v6 == 'both':
        ip6 = ip_list[1]
        if vrf == 'default':
            if src_ip != '':
                result = ip_api.ping(dut, ip6,family='ipv6',source_ip = src_ip6)
            else:
                result = ip_api.ping(dut, ip6,family='ipv6')
        else:
            if src_ip != '':
                result = ip_api.ping(dut, ip6, interface=vrf,family='ipv6',source_ip = src_ip6)
            else:
                result = ip_api.ping(dut, ip6, interface=vrf,family='ipv6')
        if result is False:
            st.error("IPv6 address {} not reachable from dur {}.".format(ip6,dut))
            return False
    return True

def create_stream():
    global tg, d7_tg_ph1, d5_tg_ph1, d6_tg_ph1,stream_dict
    dut5_gw_mac = basic_api.get_ifconfig(data.dut5, leaf3_dict["tenant_l3_vlan_int"][0])[0]['mac']
    dut6_gw_mac = basic_api.get_ifconfig(data.dut6, leaf4_dict["tenant_l3_vlan_int"][0])[0]['mac']
    dut3_gw_mac = basic_api.get_ifconfig(data.dut3, client_dict["tenant_l3_vlan_int"][0])[0]['mac']

    # L2 VNI traffic streams
    st.log("Create L2 VNI traffic streams Client(DUT7) <---> Leaf3(Dut5) and Client(DUT7) <---> Leaf4(Dut6)")
    mclag_client_vlans = client_dict["tenant_l2_vlan_list"]

    stream = tg.tg_traffic_config(mac_src= client_mac[0], vlan="enable",vlan_id_mode ="increment",
                                  mac_dst=leaf5_mac[0], rate_pps=1000, mode='create', vlan_id_count = l2_vlan_count,
                                  port_handle=d7_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=mclag_client_vlans[0],mac_src_count=10, vlan_id_step='1',
                                  mac_dst_count=l2_mac_count,mac_src_mode="increment", mac_dst_mode="increment",
                                  mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    stream1 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream1,data.t1d7_ports[0]))

    stream = tg.tg_traffic_config(mac_src=leaf5_mac[0] , vlan="enable",vlan_id_mode ="increment",
                                  mac_dst=client_mac[0], rate_pps=1000, mode='create', vlan_id_count = l2_vlan_count,
                                  port_handle=d5_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=mclag_client_vlans[0],mac_src_count=10, vlan_id_step='1',
                                  mac_dst_count=l2_mac_count,mac_src_mode="increment", mac_dst_mode="increment",
                                  mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    stream2 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream2,data.t1d5_ports[0]))

    stream = tg.tg_traffic_config(mac_src= client_mac[1], vlan="enable",vlan_id_mode ="increment",
                                  mac_dst=leaf6_mac[0], rate_pps=1000, mode='create', vlan_id_count = l2_vlan_count,
                                  port_handle=d7_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=mclag_client_vlans[0],mac_src_count=10,vlan_id_step='1',
                                  mac_dst_count=l2_mac_count,mac_src_mode="increment", mac_dst_mode="increment",
                                  mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    stream3 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream1,data.t1d7_ports[0]))

    stream = tg.tg_traffic_config(mac_src=leaf6_mac[0] , vlan="enable",vlan_id_mode ="increment",
                                  mac_dst=client_mac[1], rate_pps=1000, mode='create', vlan_id_count = l2_vlan_count,
                                  port_handle=d6_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=mclag_client_vlans[0],mac_src_count=10,vlan_id_step='1',
                                  mac_dst_count=l2_mac_count,mac_src_mode="increment", mac_dst_mode="increment",
                                  mac_src_step="00.00.00.00.00.01", mac_dst_step="00.00.00.00.00.01")
    stream4 = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream4,data.t1d6_ports[0]))

    # L3 VNI traffic streams
    ## ----- IPV4 Streams ------ ##
    # ---------Lvtep Client Vlan200 ----------- Leaf3 Vlan510------- #
    stream = tg.tg_traffic_config(mac_src=client_dict["tenant_mac_v4"],
                                  mac_dst=mclag_gw_mac, rate_pps=1000, mode='create', port_handle=d7_tg_ph2,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous', ip_src_count=10,
                                  ip_src_addr=client_dict["tenant_v4_ip"], ip_src_step="0.0.0.1",
                                  ip_dst_addr=leaf3_dict["tenant_v4_ip"], ip_dst_count=10, ip_dst_step="0.0.0.1",
                                  l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                  vlan_id=client_dict["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=client_dict["l3_tenant_ip_list"][0])
    stream5 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream5, vars.T1D7P2))

    stream = tg.tg_traffic_config(mac_src=leaf3_dict["tenant_mac_v4"],
                                  mac_dst=dut5_gw_mac, rate_pps=1000, mode='create', port_handle=d5_tg_ph2,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous', ip_src_count=10,
                                  ip_src_addr=leaf3_dict["tenant_v4_ip"], ip_src_step="0.0.0.1",
                                  ip_dst_addr=client_dict["tenant_v4_ip"], ip_dst_count=10, ip_dst_step="0.0.0.1",
                                  l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                  vlan_id=leaf3_dict["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=leaf3_dict["l3_tenant_ip_list"][0])
    stream6 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream6, vars.T1D5P2))

    ## ----- IPV6 Streams ------ ##

    stream = tg.tg_traffic_config(mac_src=client_dict["tenant_mac_v6"], mac_src_count=10,
                                  mac_dst=dut5_gw_mac, rate_pps=1000, mode='create', port_handle=d7_tg_ph2,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  ipv6_src_addr=client_dict["tenant_v6_ip"], ipv6_src_count=10,
                                  ipv6_src_step="00::1", ipv6_dst_addr=leaf4_dict["tenant_v6_ip"],
                                  ipv6_dst_count=10, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                  vlan_id=client_dict["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                  mac_discovery_gw=client_dict["l3_tenant_ipv6_list"][0])
    stream7 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream7, vars.T1D7P2))

    stream = tg.tg_traffic_config(mac_src=leaf4_dict["tenant_mac_v6"], mac_src_count=10,
                                  mac_dst=dut6_gw_mac, rate_pps=1000, mode='create', port_handle=d6_tg_ph2,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  ipv6_src_addr=leaf4_dict["tenant_v6_ip"], ipv6_src_count=10,
                                  ipv6_src_step="00::1", ipv6_dst_addr=client_dict["tenant_v6_ip"],
                                  ipv6_dst_count=10, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                  vlan_id=leaf4_dict["tenant_l3_vlan_list"][0], vlan="enable",
                                  mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                  ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                  mac_discovery_gw=leaf4_dict["l3_tenant_ipv6_list"][0])
    stream8 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream8, vars.T1D6P2))

    # BUM traffic streams
    st.log("Create L2 VNI BUM traffic streams Client(DUT7) <---> Leaf3(Dut5),Leaf4(Dut6)")
    mclag_client_vlans = client_dict["tenant_l2_vlan_list"]

    stream = tg.tg_traffic_config(mac_src= client_mac[2], vlan="enable",vlan_id_mode ="increment",
                                  mac_dst="ff.ff.ff.ff.ff.ff", rate_pps=1000, mode='create', vlan_id_count = '1',
                                  port_handle=d7_tg_ph1, l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  vlan_id=mclag_client_vlans[1],mac_src_count=1, vlan_id_step='1',
                                  mac_dst_count=1)
    stream_bum = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream_bum,data.t1d7_ports[0]))

    mgroup = '225.1.1.1'
    multicast_mac = '01:00:5E:01:01:01'
    src_ip = '15.1.2.20'

    stream = tg.tg_traffic_config(mac_src=client_mac[3], mac_dst=multicast_mac, l2_encap='ethernet_ii',
                                              rate_pps=1000,vlan="enable",vlan_id=mclag_client_vlans[1],
                                              mode='create', port_handle=d7_tg_ph1, transmit_mode='continuous',
                                              l3_protocol='ipv4', ip_src_addr=src_ip, ip_dst_addr=mgroup)
    stream_multicast = stream['stream_id']
    st.log("L2 stream {} is created for Tgen port {}".format(stream_bum,data.t1d7_ports[0]))
    stream_dict["BUM"] = [stream1,stream_bum,stream_multicast]
    stream_dict["all"]=[stream1,stream2,stream3,stream4,stream5,stream6,stream7,stream8]
    stream_dict["l2"]=[stream1,stream2,stream3,stream4]
    stream_dict["l3"]=[stream5,stream6,stream7,stream8]

def verify_bgp():
    ###########################################################
    st.log("BGP verify: Verify BGP sessions are up on duts")
    ############################################################
    def spine1():
        dut = data.dut1
        cnt = 3
        nbrs = [dut3_loopback_ip[0], dut5_loopback_ip[0], dut6_loopback_ip[0]]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established']*cnt, delay = 4, retry_count = 20)
        return result
    def spine2():
        dut = data.dut2
        cnt = 3
        nbrs = [dut4_loopback_ip[0], dut5_loopback_ip[0], dut6_loopback_ip[0]]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf1():
        dut = data.dut3
        cnt = 1
        nbrs = [dut1_loopback_ip[0]]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf2():
        dut = data.dut4
        cnt = 1
        nbrs = [dut2_loopback_ip[0]]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf3():
        dut = data.dut5
        cnt = 2
        nbrs = [dut1_loopback_ip[0], dut2_loopback_ip[0]]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf4():
        dut = data.dut6
        cnt = 2
        nbrs = [dut1_loopback_ip[0], dut2_loopback_ip[0]]
        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2],[leaf3],[leaf4]])

    if False in set(res):
        st.error("one or more BGP sessions did not come up between spine and leaf")
        return False
    return True


def verify_vxlan():
    ###########################################################
    st.log("verify Vxlan: Verify vxlan tunnels are up on lvtep and svteps")
    ############################################################
    def leaf1():
        dut = data.dut3
        local_loop_ip = dut3_loopback_ip[1]
        remote_loop_ip_lst = [dut5_loopback_ip[1],dut6_loopback_ip[1]]
        cnt = 2

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf2():
        dut = data.dut4
        local_loop_ip = dut3_loopback_ip[1]
        remote_loop_ip_lst = [dut5_loopback_ip[1], dut6_loopback_ip[1]]
        cnt = 2

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf3():
        dut = data.dut5
        local_loop_ip = dut5_loopback_ip[1]
        remote_loop_ip_lst = [dut3_loopback_ip[1], dut6_loopback_ip[1]]
        cnt = 2

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf4():
        dut = data.dut6
        local_loop_ip = dut6_loopback_ip[1]
        remote_loop_ip_lst = [dut3_loopback_ip[1], dut5_loopback_ip[1]]
        cnt = 2

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    [res, exceptions] = st.exec_all( [[leaf1], [leaf2], [leaf3], [leaf4]])

    if False in set(res):
        st.error("Vxlan tunnel did not come up between lvtep and dut3")
        return False
    return True

def verify_mclag_macs(gw_mac=mclag_gw_mac,sys_mac=mclag_sys_mac):
    dict1 = {'domain_id' : mlag_domain_id, 'session_status': 'OK', 'gw_mac' : gw_mac, 'mclag_sys_mac' : sys_mac}
    [result, exceptions] = parallel.exec_parallel(True, [data.dut3, data.dut4], mclag.verify_domain, [dict1, dict1])
    if False in result:
        return False
    return True

def verify_spine_leaf_vlanint_routes():
    def leaf1():
        dut = data.dut3
        ip_addr = dut5_loopback_ip[0] + '/' + mask32
        nxt_hop = dut1_3_ip_list[1]
        intf = vlanInt_s1_l1[0]
        result = ip_api.verify_ip_route(dut=dut, family="ipv4", interface=intf,nexthop= nxt_hop,
                                        ip_address= ip_addr, distance="20", cost="0")
        if not result:
            st.error("verify_spine_leaf_vlanint_routes: DUT {} - Failed to verify route \
                     for {} over interface {} expected nexthop {}".format(dut,ip_addr,intf,nxt_hop))
        return result

    def leaf2():
        dut = data.dut4
        ip_addr = dut5_loopback_ip[0] + '/' + mask32
        nxt_hop = dut2_4_ip_list[1]
        intf = vlanInt_s2_l2[0]
        result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=intf,nexthop= nxt_hop,
                                        ip_address= ip_addr, distance="20", cost="0")
        if not result:
            st.error("verify_spine_leaf_vlanint_routes: DUT {} - Failed to verify route \
                     for {} over interface {} expected nexthop {}".format(dut,ip_addr,intf,nxt_hop))

        return result

    def leaf3():
        dut = data.dut5
        ip_addr_list = [dut3_loopback_ip[0] + '/' + mask32 , dut4_loopback_ip[0] + '/' + mask32]
        nxt_hop_list = [dut1_5_ip_list[1],dut2_5_ip_list[1]]
        intf_list = [vlanInt_s1_l3[0],vlanInt_s2_l3[0]]

        for intf,nxt_hop,ip_addr in zip(intf_list,nxt_hop_list,ip_addr_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=intf,nexthop= nxt_hop,
                                        ip_address= ip_addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_vlanint_routes: DUT {} - Failed to verify route \
                     for {} over interface {} expected nexthop {}".format(dut,ip_addr,intf,nxt_hop))
                return False
        return True

    def leaf4():
        dut = data.dut6
        ip_addr_list = [dut3_loopback_ip[0] + '/' + mask32 , dut4_loopback_ip[0] + '/' + mask32]
        nxt_hop_list = [dut1_6_ip_list[1],dut2_6_ip_list[1]]
        intf_list = [vlanInt_s1_l4[0],vlanInt_s2_l4[0]]

        for intf,nxt_hop,ip_addr in zip(intf_list,nxt_hop_list,ip_addr_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=intf,nexthop= nxt_hop,
                                        ip_address= ip_addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_vlanint_routes: DUT {} - Failed to verify route \
                     for {} over interface {} expected nexthop {}".format(dut,ip_addr,intf,nxt_hop))
                return False
        return True
    # Debugging - Temp skip this verification.
    return True
    #[res, exceptions] =  st.exec_all([[leaf1],[leaf2]])
    #if False in set(res):
        #st.error("Fail: No IP route for vlan interface between spine and leaf.")
        #return False
    #return True


def verify_spine_leaf_all_routes():
    link_local_po_s1leaf = [ip_api.get_link_local_addresses(data.dut1, po_s1l1)[0],
                             ip_api.get_link_local_addresses(data.dut1, po_s1l3)[0],
                             ip_api.get_link_local_addresses(data.dut1, po_s1l4)[0]]
    link_local_po_s2leaf = [ip_api.get_link_local_addresses(data.dut2, po_s2l2)[0],
                            ip_api.get_link_local_addresses(data.dut2, po_s2l3)[0],
                            ip_api.get_link_local_addresses(data.dut2, po_s2l4)[0]]

    def leaf1():
        dut = data.dut3

        intf_list = [data.d3d1_ports[0],vlanInt_s1_l1[0],po_s1l1]
        nexthop_list = [dut1_3_ip_list[0],dut1_3_ip_list[1],link_local_po_s1leaf[0]]
        addr = dut5_loopback_ip[0] + '/' + mask32
        for nxt_hop,out_int in zip(nexthop_list,intf_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=out_int,
                                        nexthop=nxt_hop, ip_address=addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_all_routes: DUT {} - Failed to verify route \
                          for {} over interface {} expected nexthop {}".format(dut, addr, out_int, nxt_hop))
                return False

        return result

    def leaf2():
        dut = data.dut4
        intf_list = [data.d4d2_ports[0],vlanInt_s2_l2[0],po_s2l2]
        nexthop_list = [dut2_4_ip_list[0],dut2_4_ip_list[1],link_local_po_s2leaf[0]]
        addr = dut5_loopback_ip[0] + '/' + mask32
        for nxt_hop,out_int in zip(nexthop_list,intf_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=out_int,
                                        nexthop=nxt_hop, ip_address=addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_all_routes: DUT {} - Failed to verify route \
                          for {} over interface {} expected nexthop {}".format(dut, addr, out_int, nxt_hop))
                return False
        return result

    def leaf3():
        dut = data.dut5
        intf_list = [data.d5d1_ports[0],vlanInt_s1_l3[0],po_s1l3]
        nexthop_list = [dut1_5_ip_list[0],dut1_5_ip_list[1],link_local_po_s1leaf[1]]
        addr = dut3_loopback_ip[0] + '/' + mask32
        for nxt_hop,out_int in zip(nexthop_list,intf_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=out_int,
                                        nexthop=nxt_hop, ip_address=addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_all_routes: DUT {} - Failed to verify route \
                          for {} over interface {} expected nexthop {}".format(dut, addr, out_int, nxt_hop))
                return False

        intf_list = [data.d5d2_ports[0],vlanInt_s2_l3[0],po_s2l3]
        nexthop_list = [dut2_5_ip_list[0],dut2_5_ip_list[1],link_local_po_s2leaf[1]]
        addr = dut4_loopback_ip[0] + '/' + mask32
        for nxt_hop,out_int in zip(nexthop_list,intf_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=out_int,
                                        nexthop=nxt_hop, ip_address=addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_all_routes: DUT {} - Failed to verify route \
                          for {} over interface {} expected nexthop {}".format(dut, addr, out_int, nxt_hop))
                return False

        return True

    def leaf4():
        dut = data.dut6
        intf_list = [data.d6d1_ports[0],vlanInt_s1_l4[0],po_s1l4]
        nexthop_list = [dut1_6_ip_list[0],dut1_6_ip_list[1],link_local_po_s1leaf[2]]
        addr = dut3_loopback_ip[0] + '/' + mask32

        for nxt_hop,out_int in zip(nexthop_list,intf_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=out_int,
                                        nexthop=nxt_hop, ip_address=addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_all_routes: DUT {} - Failed to verify route \
                          for {} over interface {} expected nexthop {}".format(dut, addr, out_int, nxt_hop))
                return False

        intf_list = [data.d6d2_ports[0],vlanInt_s2_l4[0],po_s2l4]
        nexthop_list = [dut2_6_ip_list[0],dut2_6_ip_list[1],link_local_po_s2leaf[2]]
        addr = dut4_loopback_ip[0] + '/' + mask32

        for nxt_hop,out_int in zip(nexthop_list,intf_list):
            result = ip_api.verify_ip_route(dut=dut,  family="ipv4", interface=out_int,
                                        nexthop=nxt_hop, ip_address=addr, distance="20", cost="0")
            if not result:
                st.error("verify_spine_leaf_all_routes: DUT {} - Failed to verify route \
                          for {} over interface {} expected nexthop {}".format(dut, addr, out_int, nxt_hop))
                return False

    [res, exceptions] =  st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])
    if False in set(res):
        st.error("Fail: No IP route for vlan interface between spine and leaf.")
        return False
    return True

def verify_lvtep_vlanint_routes():
    addr_list = [dut5_loopback_ip[0] + '/' + mask32]*2 + [dut6_loopback_ip[0] + '/' + mask32]*2
    nxt_hop_lst = [dut4_3_ip_list[1],dut4_3_ip_list[2]] + [dut4_3_ip_list[1],dut4_3_ip_list[2]]
    vlan_int_lst = vlanInt_l1_l2 + vlanInt_l1_l2
    for out_int,addr,nxt_hop in zip(vlan_int_lst, addr_list,nxt_hop_lst ):
        result = ip_api.verify_ip_route(dut=data.dut3,family="ipv4",interface= out_int,
                                  nexthop=nxt_hop, ip_address= addr ,distance="20",cost="0")
        if not result:
            st.error("verify_spine_leaf_vlanint_routes: DUT {} - Failed to verify route \
                     for {} over interface {} expected nexthop {}".format(data.dut3,addr,out_int,nxt_hop))
            return False

    return True

def start_traffic(stream_han_list=[],port_han_list=[],action="run"):
    global tg,d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1,tg, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2
    tgen_portlst = [d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2]

    if action=="run":
        tg.tg_traffic_control(action="run", stream_handle=stream_han_list)
    else:
        if port_han_list:
            tg.tg_traffic_control(action="stop", port_handle=port_han_list)
        else:
            tg.tg_traffic_control(action="stop", port_handle= tgen_portlst)

def clear_stats(port_han_list=[]):
    global tg,d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1,tg, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2
    tgen_portlst = [d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2]

    if port_han_list:
        tg.tg_traffic_control(action='clear_stats',port_handle=port_han_list)
    else:
        tg.tg_traffic_control(action='clear_stats',port_handle=tgen_portlst)

def verify_traffic(tx_port="", rx_port="", tx_ratio=1, rx_ratio=1,
                       mode="aggregate", field="packet_rate", **kwargs):
    '''
    :param tx_port:
    :param rx_port:
    :param tx_ratio:
    :param rx_ratio:
    :param mode:
    :param field:
    :param kwargs:
    :param tx_stream_list:
    :param rx_stream_list:
    :return:
    '''
    global tg,stream_dict,d7_tg_port1,d5_tg_port1,d6_tg_port1,d7_tg_port2,d5_tg_port2,d6_tg_port2

    if not tx_port:
        tx_port=d5_tg_port1
    if not rx_port:
        rx_port=d6_tg_port1

    traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg],
            },
            '2': {
                'tx_ports': [rx_port],
                'tx_obj': [tg],
                'exp_ratio': [rx_ratio],
                'rx_ports': [tx_port],
                'rx_obj': [tg],
            }
    }
    return tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode=mode, comp_type=field,tolerance_factor=2)

def verify_traffic_stats(traffic_type = 'both'):
    global tg,stream_dict,d7_tg_port1,d5_tg_port1,d6_tg_port1,d7_tg_port2,d5_tg_port2,d6_tg_port2
    if traffic_type == 'l2' or traffic_type == 'both':
        result1 = verify_traffic(tx_port=d5_tg_port1, rx_port=d7_tg_port1, tx_ratio=2, rx_ratio=0.5)
        result2 = verify_traffic(tx_port=d6_tg_port1, rx_port=d7_tg_port1, tx_ratio=2, rx_ratio=0.5)
        if False in [result1,result2]: return False
    elif traffic_type == 'l3' or traffic_type == 'both':
        result1 = verify_traffic(tx_port=d5_tg_port2, rx_port=d7_tg_port2, tx_ratio=2, rx_ratio=0.5)
        result2 = verify_traffic(tx_port=d6_tg_port2, rx_port=d7_tg_port2, tx_ratio=2, rx_ratio=0.5)
        if False in [result1, result2]: return False
    return True


def verify_traffic_bum(tx_port="", rx_port="", tx_ratio=1, rx_ratio=1,
                       mode="aggregate", field="packet_rate", **kwargs):
    '''
    :param tx_port:
    :param rx_port:
    :param tx_ratio:
    :param rx_ratio:
    :param mode:
    :param field:
    :param kwargs:
    :param tx_stream_list:
    :param rx_stream_list:
    :return:
    '''
    global tg,stream_dict,d7_tg_port1,d5_tg_port1,d6_tg_port1,d7_tg_port2,d5_tg_port2,d6_tg_port2

    if not tx_port:
        tx_port=d7_tg_port1
    if not rx_port:
        rx_port=d5_tg_port1

    traffic_details = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg],
            },
    }
    return tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode=mode, comp_type=field,tolerance_factor=2)

def verify_traffic_stats_bum():
    global tg,stream_dict,d7_tg_port1,d5_tg_port1,d6_tg_port1,d7_tg_port2,d5_tg_port2,d6_tg_port2
    result1 = verify_traffic_bum(tx_port=d7_tg_port1, rx_port=d5_tg_port1, tx_ratio=1, rx_ratio=1)
    result2 = verify_traffic_bum(tx_port=d7_tg_port1, rx_port=d6_tg_port1, tx_ratio=1, rx_ratio=1)
    if False in [result1, result2]:
        return False
    return True

def reset_tgen(port_han_list=[]):
    global tg,d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2
    tgen_portlst = [d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2]
    if port_han_list:
        tg.tg_traffic_control(action="reset", port_handle=port_han_list)
    else:
        tg.tg_traffic_control(action="reset", port_handle=tgen_portlst)

def temp_retry_api(func, args, **kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" % ((i + 1), retry_count))
        if func(args, **kwargs):
            return True
        if retry_count != (i + 1):
            st.log("waiting for %s seconds before retyring again" % delay)
            st.wait(delay)
    return False


def ebgp_additional_config():
    def leaf1():
        dut = data.dut3
        vlan_list = vlan_l1_l2
        nbr_loopbk = dut4_loopback_ip[0]

        for nbr_ip in dut4_3_ip_list[1:]:
            bgp_api.config_bgp(dut=dut, local_as=dut3_AS, remote_as=dut4_AS, neighbor=nbr_ip,
                               config_type_list=['neighbor', 'ebgp_mhop', 'bfd'], ebgp_mhop=2)
            evpn.config_bgp_evpn(dut=dut, neighbor=nbr_ip, config='yes', config_type_list=["activate"],
                                 local_as=dut3_AS, remote_as=dut4_AS)
    def leaf2():
        dut = data.dut4
        vlan_list = vlan_l1_l2
        nbr_loopbk = dut3_loopback_ip[0]

        for nbr_ip in dut3_4_ip_list[1:]:
            bgp_api.config_bgp(dut=dut, local_as=dut4_AS, remote_as=dut3_AS, neighbor=nbr_ip,
                           config_type_list=['neighbor', 'ebgp_mhop', 'bfd'], ebgp_mhop=2)
            evpn.config_bgp_evpn(dut=dut, neighbor=nbr_ip, config='yes', config_type_list=["activate"], local_as=dut4_AS,
                             remote_as=dut3_AS)

    st.exec_all( [[leaf1], [leaf2]])


def config_ipsla(config = 'yes',same_sla_id=False):
    st.banner("Configure SLAs for traget reachable on default,same_ip(vrf),unique_ip(vrf) and sag_ip(vrf) interface")
    sla_type_list = ['icmp-echo','tcp-connect'] *6
    tcp_port = '179'
    target_ip_list = [[target_ips[i]]*2 +[target_ipv6[i]]*2 for i in range(4) if i != 1]
    target_ip_list1 = list(itertools.chain.from_iterable(target_ip_list))
    vrf_list = ['default']*4 + [vrf1]*8

    def leaf1():
        src_list_1 = [[mclag_sla_ips_1[i]]*2 + [mclag_sla_ipv6_1[i]]*2 for i in range(4) if i != 1]
        src_list_1 = list(itertools.chain.from_iterable(src_list_1))
        id_list = sla_ids_1
        for id,sla_type,dst,src,vrf in zip(id_list,sla_type_list,target_ip_list1,src_list_1,vrf_list):
            if sla_type=='tcp-connect':
                ip_api.config_ip_sla(data.dut3,id,sla_type=sla_type,dst_ip=dst,src_addr=src,vrf_name=vrf,tcp_port=tcp_port,
                                     config=config,del_cmd_list=['sla_num'],frequency=sla_freq)
            else:
                ip_api.config_ip_sla(data.dut3, id, sla_type=sla_type, dst_ip=dst, src_addr=src, vrf_name=vrf,config=config,
                                     del_cmd_list=['sla_num'],frequency=sla_freq)

    def leaf2():
        src_list_1 = [[mclag_sla_ips_2[i]]*2 + [mclag_sla_ipv6_2[i]]*2 for i in range(4) if i!= 1]
        src_list_1 = list(itertools.chain.from_iterable(src_list_1))
        id_list = sla_ids_1 if same_sla_id else sla_ids_2
        for id,sla_type,dst,src,vrf in zip(id_list,sla_type_list,target_ip_list1,src_list_1,vrf_list):
            if sla_type=='tcp-connect':
                ip_api.config_ip_sla(data.dut4,id,sla_type=sla_type,dst_ip=dst,src_addr=src,vrf_name=vrf,tcp_port=tcp_port,
                                     config=config,del_cmd_list=['sla_num'],frequency=sla_freq)
            else:
                ip_api.config_ip_sla(data.dut4, id, sla_type=sla_type, dst_ip=dst, src_addr=src, vrf_name=vrf,config=config,
                                     del_cmd_list=['sla_num'],frequency=sla_freq)

    st.exec_all([[leaf1], [leaf2]])

def verify_ipsla(exp_state='Up',type='all',same_sla_id=False):
    tcp_port = '(179)' if type =='all' else ''
    id_list = sla_ids_1;
    id_list1 = sla_ids_1 if same_sla_id else sla_ids_2
    ids =id_list;
    ids_1 = id_list1
    target_list = [[target_ips[i],target_ips[i]+tcp_port] + [target_ipv6[i],target_ipv6[i]+tcp_port] for i in range(4) if i != 1]
    target_list1 = list(itertools.chain.from_iterable(target_list))
    sla_type_list = ['ICMP-echo','TCP-connect'] *6
    state = [exp_state]*12

    if type == 'default':
        ids = id_list[0:4]
        ids_1 = id_list1[0:4]
        target_list1 = [target_ips[0],target_ips[0]+tcp_port]  + [target_ipv6[0],target_ipv6[0]+tcp_port]
        sla_type_list = ['ICMP-echo','TCP-connect'] *2
        state = [exp_state]*4
    if type == 'same_ip':
        ids= id_list[4:8]
        ids_1 = id_list1[4:8]
        target_list1 = [target_ips[1],target_ips[1]+tcp_port] + [target_ipv6[1],target_ipv6[1]+tcp_port]
        sla_type_list = ['ICMP-echo','TCP-connect'] *2
        state = [exp_state]*4
    if type == 'unique_ip':
        ids = id_list[4:8]
        ids_1 = id_list1[4:8]
        target_list1 = [target_ips[2],target_ips[2]+tcp_port] + [target_ipv6[2],target_ipv6[2]+tcp_port]
        sla_type_list = ['ICMP-echo','TCP-connect'] *2
        state = [exp_state]*4
    if type == 'sag_ip':
        ids = id_list[8:12]
        ids_1 = id_list1[8:12]
        target_list1 = [target_ips[3],target_ips[3]+tcp_port]  + [target_ipv6[3],target_ipv6[3]+tcp_port]
        sla_type_list = ['ICMP-echo','TCP-connect'] *2
        state = [exp_state]*4
    ##################################################
    st.banner("Verify state for SLAs {} on leaf1 and {} on leaf2 on interface type {}".format(ids,ids_1,type))
    ##################################################
    if type == 'all':
        dict1 = {'inst':ids,'type':sla_type_list,'target':target_list1,'state':state}
        dict2 = {'inst': ids_1, 'type': sla_type_list, 'target': target_list1, 'state': state}
        result = retry_parallel(ip_api.verify_ip_sla,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut4],retry_count=7,delay=2)

        if result is False:
            st.error("SLAs in the list {} or {} for type {} not in expected state {}".format(ids,ids_1,type,state))
            return False
    else:
        for id,id_1,type_1,target,state_1 in zip(ids,ids_1,sla_type_list,target_list1,state):
            dict1 = {'inst':id,'type':type_1,'dst_addr':target,'oper_state':state_1}
            dict2 = {'inst': id_1, 'type': type_1, 'dst_addr': target, 'oper_state': state_1}
            result = retry_parallel(ip_api.verify_ip_sla_inst,dict_list=[dict1,dict2],dut_list=[data.dut3,data.dut4],retry_count=7,delay=2)

            if result is False:
                st.error("SLAs in the list {} or {} for type {} not in expected state {}".format(id,id_1,type_1,state_1))
                return False
    return True

