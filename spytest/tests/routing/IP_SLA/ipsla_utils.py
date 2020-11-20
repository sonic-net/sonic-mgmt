from ipsla_vars import *
from ipsla_vars import data
from spytest import st,utils
import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.switching.mac as mac_api
from utilities import parallel
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
from spytest.tgen.tgen_utils import *
import apis.routing.vrf as vrf_api
import apis.system.basic as basic_api
import utilities.utils as utils_obj
import apis.switching.mclag as mclag
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *
from utilities.utils import retry_api
from apis.routing import arp
import apis.system.interface as intf_api
import apis.qos.acl_dscp as acl_dscp_api
from spytest.utils import filter_and_select
import apis.routing.ospf as ospf_api


def ipsla_base_config():
    ###################################################
    st.banner(" Begin base Configuration ")
    ###################################################
    config_ip()
    api_list = [[create_stream], [config_dut]]
    ret_val = parallel.exec_all(True, api_list, True)
    if ret_val[0][1] is False:
        return False

    ###################################################
    st.banner("BASE Config End ")
    ###################################################
    return True

def ipsla_base_unconfig():
    config_static_arp_mac('no')
    config_ipsla('no')
    config_bgp(config='no')
    config_ip(config='no')

def config_dut():
    config_bgp()
    result = verify_bgp()
    if not result:
        return False
    config_ipsla()
    result = retry_api(verify_ipsla,retry_count=10,delay=1)
    if not result:
        return False
    config_static_arp_mac()


def config_ip(config='yes'):

    st.banner("L3 configs between DUTs")

    # Config phy router port
    # Config vlan with ip
    # Config vlan with ipv6 link local
    def spine1():
        dut = data.dut1
        # Configure a phy port with IP address
        config_vlan_and_member(dut, [vlan_s1_l1[0]], [data.d1d3_ports[0]], config='yes')

        ip_api.config_ip_addr_interface(dut, vlanInt_s1_l1[0], dut1_3_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, data.d1d4_ports[0], dut1_4_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, vlanInt_s1_l1[0], dut1_3_ipv6_list[0], mask_v6, family='ipv6')
        ip_api.config_ip_addr_interface(dut, data.d1d4_ports[0], dut1_4_ipv6_list[0], mask_v6, family='ipv6')

    def spine1_del():
        dut = data.dut1
        ip_api.delete_ip_interface(dut, vlanInt_s1_l1[0], dut1_3_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, data.d1d4_ports[0], dut1_4_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, vlanInt_s1_l1[0], dut1_3_ipv6_list[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut, data.d1d4_ports[0], dut1_4_ipv6_list[0], mask_v6, family='ipv6')
        config_vlan_and_member(dut, [vlan_s1_l1[0]], [data.d1d3_ports[0]], config='no')

    def spine2():
        dut = data.dut2
        vrf_api.config_vrf(dut, vrf_name=vrf1)
        pc.create_portchannel(dut, po_s2l1)
        pc.add_portchannel_member(dut, po_s2l1, data.d2d3_ports[0])
        config_vlan_and_member(dut, [vlan_s2_l1[0]], [po_s2l1], config='yes')
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlanInt_s2_l1[0])
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=data.d2d4_ports[0])
        ip_api.config_ip_addr_interface(dut, vlanInt_s2_l1[0], dut2_3_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, data.d2d4_ports[0], dut2_4_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, vlanInt_s2_l1[0], dut2_3_ipv6_list[0], mask_v6, family='ipv6')
        ip_api.config_ip_addr_interface(dut, data.d2d4_ports[0], dut2_4_ipv6_list[0], mask_v6, family='ipv6')

    def spine2_del():
        dut = data.dut2
        ip_api.delete_ip_interface(dut, vlanInt_s2_l1[0], dut2_3_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, data.d2d4_ports[0], dut2_4_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, vlanInt_s2_l1[0], dut2_3_ipv6_list[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut, data.d2d4_ports[0], dut2_4_ipv6_list[0], mask_v6, family='ipv6')
        config_vlan_and_member(dut, [vlan_s2_l1[0]], [po_s2l1], config='no')
        pc.delete_portchannel_member(dut, po_s2l1, data.d2d3_ports[0])
        pc.delete_portchannel(dut, po_s2l1)
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=data.d2d4_ports[0],config='no')
        vrf_api.config_vrf(dut, vrf_name=vrf1,config='no')

    def leaf1():
        dut = data.dut3
        config_vlan_and_member(dut, [vlan_s1_l1[0]], [data.d3d1_ports[0]], config='yes')

        ip_api.config_ip_addr_interface(dut, vlanInt_s1_l1[0], dut3_1_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, vlanInt_s1_l1[0], dut3_1_ipv6_list[0], mask_v6, family='ipv6')

        vrf_api.config_vrf(dut, vrf_name=vrf1)
        pc.create_portchannel(dut, po_s2l1)
        pc.add_portchannel_member(dut, po_s2l1, data.d3d2_ports[0])
        config_vlan_and_member(dut, [vlan_s2_l1[0]], [po_s2l1], config='yes')
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlanInt_s2_l1[0])
        ip_api.config_ip_addr_interface(dut, vlanInt_s2_l1[0], dut3_2_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, vlanInt_s2_l1[0], dut3_2_ipv6_list[0], mask_v6, family='ipv6')
        # Traffic stream
        config_vlan_and_member(dut, [vlan_tgen[0]], [data.d3t1_ports[0]], config='yes')
        config_vlan_and_member(dut, [vlan_tgen[1]], [data.d3t1_ports[0]], config='yes')

        ip_api.config_ip_addr_interface(dut, vlanInt_tgen[0], dut3_tg1_ip[0], mask31)
        ip_api.config_ip_addr_interface(dut, vlanInt_tgen[0], dut3_tg1_ipv6[0], mask_v6, family='ipv6')
        #Traffic stream - vrf
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=vlanInt_tgen[1])
        ip_api.config_ip_addr_interface(dut, vlanInt_tgen[1], dut3_tg1_ip[1], mask31)
        ip_api.config_ip_addr_interface(dut, vlanInt_tgen[1], dut3_tg1_ipv6[1], mask_v6, family='ipv6')

    def leaf1_del():
        dut = data.dut3
        ip_api.delete_ip_interface(dut, vlanInt_s1_l1[0], dut3_1_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, vlanInt_s1_l1[0], dut3_1_ipv6_list[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut, vlanInt_s2_l1[0], dut3_2_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, vlanInt_s2_l1[0], dut3_2_ipv6_list[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut, vlanInt_tgen[0], dut3_tg1_ip[0], mask31)
        ip_api.delete_ip_interface(dut, vlanInt_tgen[0], dut3_tg1_ipv6[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut, vlanInt_tgen[1], dut3_tg1_ip[1], mask31)
        ip_api.delete_ip_interface(dut, vlanInt_tgen[1], dut3_tg1_ipv6[1], mask_v6, family='ipv6')
        config_vlan_and_member(dut, [vlan_tgen[0]], [data.d3t1_ports[0]], config='no')
        config_vlan_and_member(dut, [vlan_tgen[1]], [data.d3t1_ports[0]], config='no')
        config_vlan_and_member(dut, [vlan_s2_l1[0]], [po_s2l1], config='no')
        config_vlan_and_member(dut, [vlan_s1_l1[0]], [data.d3d1_ports[0]], config='no')
        pc.delete_portchannel_member(dut, po_s2l1, data.d3d2_ports[0])
        pc.delete_portchannel(dut, po_s2l1)
        vrf_api.config_vrf(dut, vrf_name=vrf1,config='no')

    def leaf2():
        dut = data.dut4
        # D4 --- D1
        ip_api.config_ip_addr_interface(dut, data.d4d1_ports[0], dut4_1_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, data.d4d1_ports[0], dut4_1_ipv6_list[0], mask_v6, family='ipv6')
        # D4 ---- D2
        vrf_api.config_vrf(dut, vrf_name=vrf1)
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=data.d4d2_ports[0])
        ip_api.config_ip_addr_interface(dut, data.d4d2_ports[0], dut4_2_ip_list[0], mask31)
        ip_api.config_ip_addr_interface(dut, data.d4d2_ports[0], dut4_2_ipv6_list[0], mask_v6, family='ipv6')

        # Target default vrf vlan interface
        config_vlan_and_member(dut, target_vlans, [data.d4t1_ports[0]]*len(target_vlans))
        # Target user vrf vlan interface
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=target_vlan_intfs[2])
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=target_vlan_intfs[3])
        for vlanI,ip,ip6 in zip(target_vlan_intfs,target_ips,target_ipv6):
            ip_api.config_ip_addr_interface(dut, vlanI, ip, mask24)
            ip_api.config_ip_addr_interface(dut, vlanI, ip6, mask_v6, family = 'ipv6')

    def leaf2_del():
        dut = data.dut4
        ip_api.delete_ip_interface(dut, data.d4d1_ports[0], dut4_1_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, data.d4d1_ports[0], dut4_1_ipv6_list[0], mask_v6, family='ipv6')
        ip_api.delete_ip_interface(dut, data.d4d2_ports[0], dut4_2_ip_list[0], mask31)
        ip_api.delete_ip_interface(dut, data.d4d2_ports[0], dut4_2_ipv6_list[0], mask_v6, family='ipv6')
        config_vlan_and_member(dut, target_vlans, [data.d4t1_ports[0]] * len(target_vlans),config='no')
        vrf_api.bind_vrf_interface(dut, vrf_name=vrf1, intf_name=data.d4d2_ports[0],config='no')
        vrf_api.config_vrf(dut, vrf_name=vrf1,config='no')

    if config == 'yes':
        [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2]])
        data.dut3_vlan10_mac = basic_api.get_ifconfig(data.dut3, vlanInt_tgen[0])[0]['mac']
        data.dut3_vlan20_mac = basic_api.get_ifconfig(data.dut3, vlanInt_tgen[1])[0]['mac']
    else:
        [res, exceptions] = st.exec_all([[spine1_del],[spine2_del],[leaf1_del],[leaf2_del]])

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


def config_bgp(config='yes'):
    st.log("BGP and evpn configs between Leaf and Spine")
    if config == 'yes':
        def spine1():
            dut = data.dut1
            dut_as = dut1_AS
            remote_as_list = [dut3_AS,dut4_AS]
            nbr_list = [dut3_1_ipv6_list[0],dut4_1_ipv6_list[0]]
            ip_api.config_route_map_global_nexthop(dut, 'rmap_v6', config='yes')
            for rem_as,nbr in zip(remote_as_list,nbr_list):
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as=rem_as, neighbor=nbr,
                                   config_type_list=['neighbor', 'ebgp_mhop' 'bfd', 'connect', 'redist'],
                                   redistribute='connected', connect='3', ebgp_mhop=2)
                bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist", "activate","routeMap"],
                                   neighbor=nbr, redistribute='connected', addr_family='ipv6',routeMap='rmap_v6', diRection='in')

        def spine2():
            dut = data.dut2
            dut_as = dut2_AS
            remote_as_list = [dut3_AS, dut4_AS]
            nbr_list = [dut3_2_ipv6_list[0], dut4_2_ipv6_list[0]]
            ip_api.config_route_map_global_nexthop(dut, 'rmap_v6', config='yes')
            for rem_as, nbr in zip(remote_as_list, nbr_list):
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as=rem_as, neighbor=nbr,
                                   config_type_list=['neighbor', 'ebgp_mhop' 'bfd', 'connect', 'redist'],
                                   redistribute='connected', connect='3', ebgp_mhop=2,vrf_name = vrf1)
                bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist", "activate","routeMap"],
                                   neighbor=nbr, redistribute='connected', addr_family='ipv6',vrf_name = vrf1,
                                   routeMap='rmap_v6', diRection='in')

        def leaf1():
            dut = data.dut3
            dut_as = dut3_AS
            remote_as_list = [dut1_AS, dut2_AS]
            nbr_list = [dut1_3_ipv6_list[0],dut2_3_ipv6_list[0]]
            ip_api.config_route_map_global_nexthop(dut, 'rmap_v6', config='yes')
            st.wait(2)
            for rem_as, nbr,vrf in zip(remote_as_list, nbr_list,["default",vrf1]):
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as=rem_as, neighbor=nbr,
                                   config_type_list=['neighbor', 'ebgp_mhop' 'bfd', 'connect', 'redist'],
                                   redistribute='connected', connect='3', ebgp_mhop=2,vrf_name = vrf)
                bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist", "activate","routeMap"],
                                   neighbor=nbr, redistribute='connected', addr_family='ipv6',vrf_name = vrf,
                                   routeMap='rmap_v6', diRection='in')

        def leaf2():
            dut = data.dut4
            dut_as = dut4_AS
            remote_as_list = [dut1_AS, dut2_AS]
            nbr_list = [dut1_4_ipv6_list[0],dut2_4_ipv6_list[0]]
            ip_api.config_route_map_global_nexthop(dut, 'rmap_v6', config='yes')
            st.wait(2)
            for rem_as, nbr,vrf in zip(remote_as_list, nbr_list,["default",vrf1]):
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as=rem_as, neighbor=nbr,
                                   config_type_list=['neighbor', 'ebgp_mhop' 'bfd', 'connect', 'redist'],
                                   redistribute='connected', connect='3', ebgp_mhop=2,vrf_name = vrf)
                bgp_api.config_bgp(dut, local_as=dut_as, config='yes', config_type_list=["redist", "activate","routeMap"],
                                   neighbor=nbr, redistribute='connected', addr_family='ipv6',vrf_name = vrf,
                                   routeMap='rmap_v6', diRection='in')

        [res, exceptions] = st.exec_all( [[spine1], [spine2], [leaf1], [leaf2]])

    else:
        ##########################################################################
        st.log("BGP-Deconfig: Delete BGP routers globally from all DUTs")
        ##########################################################################
        dict1 = []
        for dut_as in [dut2_AS,dut3_AS,dut4_AS]:
            dict1 = dict1 + [{'local_as' : dut_as,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf1}]
        parallel.exec_parallel(True,[data.dut3,data.dut2,data.dut4], bgp_api.config_bgp, dict1)
        dict1=[]
        for dut_as in [dut1_AS,dut2_AS,dut3_AS,dut4_AS]:
            dict1 = dict1 + [{'local_as' : dut_as,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}]
        parallel.exec_parallel(True, data.dut_list, bgp_api.config_bgp, dict1)


def config_loopback(config='yes'):
    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip_api.delete_ip_interface
        config_str = "Delete"

    st.log("%s Loopback configs between Leaf and Spine" % (config_str))
    if config == 'yes':
        parallel.exec_parallel(True, data.dut_list, ip_api.configure_loopback, [{'loopback_name': loopback1}] * 4)
        utils.exec_all(True, [[api_name, dut, loopback1, ip, mask32]
                              for dut, ip in zip(data.dut_list, loopback1_ip_list)])

    else:

        utils.exec_all(True, [[api_name, dut, loopback1, ip, mask32]
                              for dut, ip in zip(data.dut_list, loopback1_ip_list)])
        parallel.exec_parallel(True, data.dut_list, ip_api.configure_loopback,
                               [{'loopback_name': loopback1, 'config': 'no'}] * 4)


def config_unnumbered_5549(config='yes'):
    st.banner("Configure ospf ,ipv4 unnumbered and bgp 5549")
    if config == 'yes':
        def dut1():
            dut = data.dut1
            loopbk_ip = dut1_loopback_ip[0]
            intf_list = [data.d1d3_ports[1],data.d1d4_ports[1]]
            intf_list_v6 = [data.d1d3_ports[2],data.d1d4_ports[2]]
            dut_as = dut1_AS
            remote_as_list = [dut3_AS,dut4_AS]
            nbr_list = [dut3_loopback_ip[0],dut4_loopback_ip[0]]

            st.wait(2)
            for rem_as,nbr,intf in zip(remote_as_list,nbr_list,intf_list):
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = rem_as, neighbor = nbr,
                                   config_type_list = ['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd','connect', 'activate'],
                                   connect = '3', ebgp_mhop = 2, update_src_intf = intf)
                bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor=nbr, config_type_list=['activate'],
                                   addr_family='ipv6')

            ospf_api.config_ospf_router_id(dut, loopbk_ip)
            ospf_api.config_ospf_network(dut, loopbk_ip + '/' + mask32,0)
            for intf in intf_list:
                ospf_api.config_interface_ip_ospf_network_type( dut, intf, 'point-to-point')
                ip_api.config_unnumbered_interface(dut,interface = intf, loop_back=loopback1)

            ospf_api.config_ospf_router_redistribute(dut, 'connected')
            for intf in intf_list_v6:
                ip_api.config_interface_ip6_link_local(dut, intf, action='enable')
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=intf,
                                   config_type_list=['bfd'], config='yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', neighbor=intf,
                                   config_type_list=['activate'], config='yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', neighbor=intf,
                                   config_type_list=['activate'], addr_family = 'ipv6',config='yes')

        def dut3():
            dut = data.dut3
            loopbk_ip = dut3_loopback_ip[0]
            intf = data.d3d1_ports[1]
            intf_v6 = data.d3d1_ports[2]

            dut_as = dut3_AS
            rem_as = dut1_AS
            nbr = dut1_loopback_ip[0]

            ospf_api.config_ospf_router_id(dut, loopbk_ip)
            ospf_api.config_ospf_network(dut, loopbk_ip + '/' + mask32,0)
            ospf_api.config_interface_ip_ospf_network_type( dut, intf, 'point-to-point')
            ospf_api.config_ospf_router_redistribute(dut, 'connected')
            ip_api.config_unnumbered_interface(dut,interface = intf, loop_back=loopback1)
            # IPv4 unnumbered BGP config
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as=rem_as, neighbor=nbr,
                               config_type_list=['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd', 'connect',
                                                 'activate'], connect='3', ebgp_mhop=2, update_src_intf=intf)
            bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor=nbr,addr_family = 'ipv6',
                               config_type_list=['activate'])
            ip_api.config_interface_ip6_link_local(dut, intf_v6, action='enable')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=intf_v6,
                               config_type_list=['bfd'], config='yes')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', neighbor=intf_v6,
                               config_type_list=['activate'], config='yes')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', neighbor=intf_v6,
                               config_type_list=['activate'], config='yes',addr_family = 'ipv6')


        def dut4():
            dut = data.dut4
            loopbk_ip = dut4_loopback_ip[0]
            intf = data.d4d1_ports[1]
            intf_v6 = data.d4d1_ports[2]

            dut_as = dut4_AS
            rem_as = dut1_AS
            nbr = dut1_loopback_ip[0]

            ospf_api.config_ospf_router_id(dut, loopbk_ip)
            ospf_api.config_ospf_network(dut, loopbk_ip + '/' + mask32,0)
            ospf_api.config_interface_ip_ospf_network_type( dut, intf, 'point-to-point')
            ospf_api.config_ospf_router_redistribute(dut, 'connected')
            ip_api.config_unnumbered_interface(dut,interface = intf, loop_back=loopback1)
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as=rem_as, neighbor=nbr,
                               config_type_list=['neighbor', 'ebgp_mhop', 'update_src_intf', 'bfd', 'connect',
                                                 'activate'], connect='3', ebgp_mhop=2, update_src_intf=intf)
            bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor=nbr, addr_family='ipv6',
                               config_type_list=['activate'])

            ip_api.config_interface_ip6_link_local(dut, intf_v6, action='enable')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=intf_v6,
                               config_type_list=['bfd'], config='yes')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', neighbor=intf_v6,
                               config_type_list=['activate'], config='yes')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', neighbor=intf_v6,
                               config_type_list=['activate'], config='yes', addr_family='ipv6')

    else:

        def dut1():
            dut = data.dut1
            loopbk_ip = dut1_loopback_ip[0]
            intf_list = [data.d1d3_ports[1], data.d1d4_ports[1]]
            intf_list_v6 = [data.d1d3_ports[2], data.d1d4_ports[2]]

            dut_as = dut1_AS
            remote_as_list = [dut3_AS,dut4_AS]
            nbr_list = [dut3_loopback_ip[0],dut4_loopback_ip[0]]
            for rem_as,nbr in zip(remote_as_list,nbr_list):
                bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor=nbr, config_type_list=['neighbor'], config='no')

            for intf in intf_list_v6:
                #bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=intf,
                #                   config_type_list=['bfd'], config='no')
                bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor="interface " + intf,
                                   config_type_list=['neighbor'], config='no')
                ip_api.config_interface_ip6_link_local(dut, intf, action='disable')
            for intf in intf_list:
                ospf_api.config_interface_ip_ospf_network_type(dut, intf, 'point-to-point',config='no')
                ospf_api.config_ospf_network(dut, loopbk_ip + '/' + mask32, 0, config='no')
                ip_api.config_unnumbered_interface(dut, interface=intf, loop_back=loopbk_ip,action='del')
            ospf_api.config_ospf_router_id(dut, loopbk_ip,config='no')

        def dut3():

            dut = data.dut3
            loopbk_ip = dut3_loopback_ip[0]
            intf = data.d3d1_ports[1]
            intf_v6 = data.d3d1_ports[2]
            dut_as = dut3_AS
            nbr = dut1_loopback_ip[0]
            #bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=intf_v6,
            #                   config_type_list=['bfd'], config='no')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor=nbr, config_type_list=['neighbor'], config='no')
            ip_api.config_interface_ip6_link_local(dut, intf_v6, action='disable')

            ospf_api.config_interface_ip_ospf_network_type( dut, intf, 'point-to-point',config='no')
            ospf_api.config_ospf_network(dut, loopbk_ip + '/' + mask32,0,config='no')
            ip_api.config_unnumbered_interface(dut,interface = intf, loop_back=loopbk_ip,action='del')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor="interface "+intf_v6, config_type_list=['neighbor'], config='no')
            ospf_api.config_ospf_router_id(dut, loopbk_ip,config='no')

        def dut4():
            dut = data.dut4
            loopbk_ip = dut4_loopback_ip[0]
            intf = data.d4d1_ports[1]
            intf_v6 = data.d4d1_ports[2]

            dut_as = dut4_AS
            nbr = dut1_loopback_ip[0]
            #bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=intf_v6,
            #                   config_type_list=['bfd'], config='no')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor=nbr, config_type_list=['neighbor'], config='no')
            ip_api.config_interface_ip6_link_local(dut, intf_v6, action='disable')

            ospf_api.config_interface_ip_ospf_network_type( dut, intf, 'point-to-point',config='no')
            ospf_api.config_ospf_network(dut, loopbk_ip + '/' + mask32,0,config='no')
            ip_api.config_unnumbered_interface(dut,interface = intf, loop_back=loopbk_ip,action='del')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, neighbor="interface "+intf_v6
                               , config_type_list=['neighbor'], config='no')
            ospf_api.config_ospf_router_id(dut, loopbk_ip,config='no')
    [res, exceptions] = st.exec_all([[dut1], [dut3], [dut4]])


def config_ipsla(config = 'yes'):
    # Config all ip sla D3-D1
    # Config all ip sla D4-D2
    # Configure static routes with SLAs
    if config == 'yes':
        static_route_api = ip_api.create_static_route
    else:
        static_route_api = ip_api.delete_static_route


    dut = data.dut3
    if config == 'no':
        addr_family_lst = ['ipv4', 'ipv6'] * 2
        mask = [mask24, mask_v6] * 2
        src_ip_lst = [dut1_3_ip_list[0],dut1_3_ipv6_list[0]]*2
        dst_ip_lst = [target_ips_subnet[0],target_ipv6_subnet[0],target_ips_subnet[1],target_ipv6_subnet[1]]

        for i,nxt_hop,targ_ip,addr_family,m in zip(range(1,5),src_ip_lst,dst_ip_lst ,addr_family_lst,mask):
            static_route_api(dut, next_hop=nxt_hop, static_ip=targ_ip + '/' + m, family = addr_family, track = i)

    # Vrf
        src_ip_lst = [dut2_3_ip_list[0], dut2_3_ipv6_list[0],dut2_3_ip_list[0],dut2_3_ipv6_list[0]]
        dst_ip_lst = [target_ips_subnet[2],target_ipv6_subnet[2],target_ips_subnet[3],target_ipv6_subnet[3]]
        for i, nxt_hop, targ_ip,addr_family,m in zip(range(5, 9), src_ip_lst,dst_ip_lst , addr_family_lst,mask):
            static_route_api(dut, next_hop=nxt_hop, static_ip=targ_ip + '/' + m, family=addr_family,vrf=vrf1, track = i)


    sla_lst_icmp = ["icmp-echo"]*2
    sla_lst_tcp = ["tcp-connect"] * 2
    dst_ip_lst = [target_ips[0],target_ipv6[0]]
    src_ip_lst = [dut3_1_ip_list[0],dut3_1_ipv6_list[0]]
    addr_family_lst = ['ipv4', 'ipv6'] * 2
    mask = [mask24, mask_v6] * 2

    for id,sla,dst,src in zip(range(1,3),sla_lst_icmp,dst_ip_lst,src_ip_lst):
        ip_api.config_ip_sla(dut, id, sla_type=sla, dst_ip=dst, src_addr=src,frequency=sla_freq,config=config,del_cmd_list=['sla_num'])

    dst_ip_lst = [target_ips[1],target_ipv6[1]]
    src_ip_lst = [dut3_1_ip_list[0],dut3_1_ipv6_list[0]]

    for id,sla,dst,src,port in zip(range(3,5),sla_lst_tcp,dst_ip_lst,src_ip_lst,tcp_ports):
        ip_api.config_ip_sla(dut, id, sla_type=sla, dst_ip=dst, tcp_port=port,frequency=sla_freq,config=config,del_cmd_list=['sla_num'])

    dst_ip_lst = [target_ips[2],target_ipv6[2]]
    src_ip_lst = [dut3_2_ip_list[0],dut3_2_ipv6_list[0]]
    for id,sla,dst,src in zip(range(5,7),sla_lst_icmp,dst_ip_lst,src_ip_lst):
        ip_api.config_ip_sla(dut, id, sla_type=sla, dst_ip=dst, src_addr=src,vrf_name=vrf1,frequency=sla_freq,config=config,del_cmd_list=['sla_num'])

    dst_ip_lst = [target_ips[3],target_ipv6[3]]
    src_ip_lst = [dut3_2_ip_list[0],dut3_2_ipv6_list[0]]

    for id,sla,dst,src in zip(range(7,9),sla_lst_tcp,dst_ip_lst,src_ip_lst):
        ip_api.config_ip_sla(dut, id, sla_type=sla, dst_ip=dst, tcp_port=tcp_ports[1],vrf_name=vrf1,frequency=sla_freq,config=config,del_cmd_list=['sla_num'])

    # MAP IP SLAs to static routes.
    if config == 'yes':
        src_ip_lst = [dut1_3_ip_list[0],dut1_3_ipv6_list[0]]*2
        dst_ip_lst = [target_ips_subnet[0],target_ipv6_subnet[0],target_ips_subnet[1],target_ipv6_subnet[1]]

        for i,nxt_hop,targ_ip,addr_family,m in zip(range(1,5),src_ip_lst,dst_ip_lst ,addr_family_lst,mask):
            static_route_api(dut, next_hop=nxt_hop, static_ip=targ_ip + '/' + m, family = addr_family, track = i)

    # Vrf
        src_ip_lst = [dut2_3_ip_list[0], dut2_3_ipv6_list[0],dut2_3_ip_list[0],dut2_3_ipv6_list[0]]
        dst_ip_lst = [target_ips_subnet[2],target_ipv6_subnet[2],target_ips_subnet[3],target_ipv6_subnet[3]]
        for i, nxt_hop, targ_ip,addr_family,m in zip(range(5, 9), src_ip_lst,dst_ip_lst , addr_family_lst,mask):
            static_route_api(dut, next_hop=nxt_hop, static_ip=targ_ip + '/' + m, family=addr_family,vrf=vrf1, track = i)

def verify_ipsla(exp_state='Up'):
    dut = data.dut3
    port1 = tcp_ports[0]
    port2 = tcp_ports[1]
    sla_id = list(range(1,9))

    sla_lst = ["ICMP-echo"]*2 + ["TCP-connect"]*2 + ["ICMP-echo"]*2 + ["TCP-connect"]*2
    dst_ip_lst = [target_ips[0], target_ipv6[0],target_ips[1]+"("+port1+")", target_ipv6[1]+"("+port2+")",
                  target_ips[2], target_ipv6[2],target_ips[3]+"("+port2+")", target_ipv6[3]+"("+port2+")"]
    state = [exp_state] * 8
    result = ip_api.verify_ip_sla(dut, sla_id, type=sla_lst, target=dst_ip_lst, state=state)

    if result is False:
        st.error("One or more IP SLAs are down.")
        return False
    return True

def verify_ipsla_instance_params():
    dut = data.dut3
    sla_id_lst = list(range(1,9))

    type_lst = ["ICMP-echo"]*2 + ["TCP-connect"]*2 + ["ICMP-echo"]*2 + ["TCP-connect"]*2

    dst_ip_lst = [target_ips[0], target_ipv6[0],target_ips[1], target_ipv6[1],
                  target_ips[2], target_ipv6[2],target_ips[3], target_ipv6[3]]
    vrf_lst = ["default"] * 4 + [vrf1] * 4

    for sla_id,type,vrf,dst_ip in zip(sla_id_lst,type_lst,vrf_lst,dst_ip_lst):
        result = retry_api(ip_api.verify_ip_sla_inst,dut, inst=str(sla_id), type=type, freq=sla_freq, vrf_name=vrf,dst_addr=dst_ip,oper_state='Up',
                           retry_count=10,delay=1)
        if result is False:
            st.error("One or more IP SLAs are down.")
            return False

    for id in [1,2,5,6]:
        result = ip_api.verify_ip_sla_inst(dut, inst=str(id), type="ICMP-echo",threshold=3,timeout=2,icmp_size=64,ttl=3,tos=30)
        if result is False:
            st.error("One or more ICMP SLA parameter do not match with configured values.")
            return False
    for id in [3,4,7,8]:
        result = ip_api.verify_ip_sla_inst(dut, inst=str(id), type="TCP-connect",threshold=4,timeout=3,ttl=4,tos=40)
        if result is False:
            st.error("One or more TCP SLA parameter do not match with configured values.")
            return False
    return True


def verify_ipsla_static_route(entry=True, vrf='all', addr_family='ipv4', sla_type='ICMP-echo'):
    dut = data.dut3
    if vrf == 'default':
        if addr_family == 'ipv4':
            if sla_type == 'ICMP-echo':
                src_ip_list = [dut1_3_ip_list[0]]
                dst_nw = [target_ips_subnet[0]]
            elif sla_type == 'TCP-connect':
                src_ip_list =[dut1_3_ip_list[0]]
                dst_nw = [target_ips_subnet[1]]
            else:
                src_ip_list =[dut1_3_ip_list[0]]*2
                dst_nw =[target_ips_subnet[0],target_ips_subnet[1]]
            addr_family_lst = ['ipv4'] * len(src_ip_list)
            mask_lst = [mask24] * len(src_ip_list)
            vrf_lst = [None]*len(src_ip_list)
        elif addr_family == 'ipv6':
            if sla_type == 'ICMP-echo':
                src_ip_list = [dut1_3_ipv6_list[0]]
                dst_nw = [target_ipv6_subnet[0]]
            elif sla_type == 'TCP-connect':
                src_ip_list =[dut1_3_ipv6_list[0]]
                dst_nw = [target_ipv6_subnet[1]]
            else:
                src_ip_list =[dut1_3_ipv6_list[0]]*2
                dst_nw =[target_ipv6_subnet[0],target_ipv6_subnet[1]]
            addr_family_lst = ['ipv6'] * len(src_ip_list)
            mask_lst = [mask_v6] * len(src_ip_list)
            vrf_lst = [None] * len(src_ip_list)
        else:
            src_ip_list =[dut1_3_ip_list[0]]*2 + [dut1_3_ipv6_list[0]]*2
            dst_nw = [target_ips_subnet[0],target_ips_subnet[1],target_ipv6_subnet[0],target_ipv6_subnet[1]]
            addr_family_lst = ['ipv4'] * 2 + ['ipv6'] * 2
            mask_lst = [mask32] * 2 + [mask_v6] *2
            vrf_lst = [None] * len(mask_lst)
    elif vrf == vrf1:
        if addr_family == 'ipv4':
            if sla_type == 'ICMP-echo':
                src_ip_list = [dut2_3_ip_list[0]]
                dst_nw = [target_ips_subnet[2]]
            elif sla_type == 'TCP-connect':
                src_ip_list =[dut2_3_ip_list[0]]
                dst_nw = [target_ips_subnet[3]]
            else:
                src_ip_list =[dut2_3_ip_list[0]]*2
                dst_nw =[target_ips_subnet[2],target_ips_subnet[3]]
            addr_family_lst = ['ipv4'] * len(src_ip_list)
            mask_lst = [mask24] * len(src_ip_list)
            vrf_lst = [vrf] * len(src_ip_list)
        elif addr_family == 'ipv6':
            if sla_type == 'ICMP-echo':
                src_ip_list = [dut2_3_ipv6_list[0]]
                dst_nw = [target_ipv6_subnet[2]]
            elif sla_type == 'TCP-connect':
                src_ip_list =[dut2_3_ipv6_list[0]]
                dst_nw = [target_ipv6_subnet[3]]
            else:
                src_ip_list =[dut2_3_ipv6_list[0]]*2
                dst_nw =[target_ipv6_subnet[2],target_ipv6_subnet[3]]
            addr_family_lst = ['ipv6'] * len(src_ip_list)
            mask_lst = [mask_v6] * len(src_ip_list)
            vrf_lst = [vrf] * len(src_ip_list)
        else:
            src_ip_list =[dut2_3_ip_list[0]]*2 + [dut2_3_ipv6_list[0]]*2
            dst_nw = [target_ips_subnet[2],target_ips_subnet[3],target_ipv6_subnet[2],target_ipv6_subnet[3]]
            addr_family_lst = ['ipv4'] * 2 + ['ipv6'] * 2
            mask_lst = [mask24] * 2 + [mask_v6] * 2
            vrf_lst = [vrf] * len(mask_lst)
    else:
        src_ip_list =[dut1_3_ip_list[0]]*2 + [dut1_3_ipv6_list[0]]*2 + [dut2_3_ip_list[0]]*2 + [dut2_3_ipv6_list[0]]*2
        dst_nw = [target_ips_subnet[0],target_ips_subnet[1],target_ipv6_subnet[0],target_ipv6_subnet[1],target_ips_subnet[2],
                  target_ips_subnet[3],target_ipv6_subnet[2],target_ipv6_subnet[3]]
        addr_family_lst = ['ipv4'] * 2 + ['ipv6'] * 2 + ['ipv4'] * 2 + ['ipv6'] * 2
        mask_lst = [mask24] * 2 + [mask_v6] * 2 + [mask24] * 2 + [mask_v6] * 2
        vrf_lst = [None] * 4 + [vrf1] * 4

    for nxt_hop,targ_ip,family,mask,vrf_name in zip(src_ip_list,dst_nw,addr_family_lst,mask_lst,vrf_lst):
        result = ip_api.verify_ip_route(data.dut3, type='S', nexthop=nxt_hop, ip_address=targ_ip + '/' + mask, family=family,
                                    vrf_name=vrf_name)
        vrf_str= 'Default' if vrf_name is None else vrf_name
        if entry:
            if result is False:
                st.error("{} Static route to IP address {} not in routing table on dut {}.".format(vrf_str,targ_ip + '/' + mask, dut))
                return False
        else:
            if result is True:
                st.error("{} Static route to IP address {} not removed from routing table on dut {}.".format(vrf_str,targ_ip + '/' + mask, dut))
                return False

    return True


def create_stream(config='yes'):
    dut3_vlan10_mac = data.dut3_vlan10_mac
    dut3_vlan20_mac = data.dut3_vlan20_mac
    data.stream_handles = {}
    data.stream_details = {}

    if config == 'no':
        data.tg.tg_traffic_config(mode='reset',port_handle=data.d3_tg_ph1)
    else:
        ############################################################
        st.banner("Default Vrf: IPv4 Traffic config for ICMP SLA")
        ############################################################
        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[0],mac_dst=dut3_vlan10_mac, rate_pps=data.traffic_rate, mode='create',
                                      port_handle=data.d3_tg_ph1,l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ip_src_count=1, ip_src_addr=tgen_dut3_ips[0], ip_src_step="0.0.0.1",
                                      ip_dst_addr=tgen_dut4_ips[0], ip_dst_count=1, ip_dst_step="0.0.0.1",
                                      l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                      vlan_id=vlan_tgen[0], vlan="enable", mac_discovery_gw=dut3_tg1_ip[0])
        data.stream_handles['default_ipv4_icmp_stream'] = stream['stream_id']
        data.stream_details[data.stream_handles['default_ipv4_icmp_stream']] = "IPv4 traffic ICMP session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[0],dut3_vlan10_mac,
                                                                                                vlan_tgen[0],tgen_dut3_ips[0],tgen_dut4_ips[0],
                                                                                                data.traffic_rate)

        ############################################################
        st.banner("Default Vrf: IPv4 Traffic config for TCP SLA")
        ############################################################

        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[1],mac_dst=dut3_vlan10_mac, rate_pps=data.traffic_rate, mode='create',
                                      port_handle=data.d3_tg_ph1,l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ip_src_count=1, ip_src_addr=tgen_dut3_ips[0], ip_src_step="0.0.0.1",
                                      ip_dst_addr=tgen_dut4_ips[1], ip_dst_count=1, ip_dst_step="0.0.0.1",
                                      l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                      vlan_id=vlan_tgen[0], vlan="enable", mac_discovery_gw=dut3_tg1_ip[0])
        data.stream_handles['default_ipv4_tcp_stream'] = stream['stream_id']
        data.stream_details[data.stream_handles['default_ipv4_tcp_stream']] = "IPv4 traffic TCP session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[1],dut3_vlan10_mac,
                                                                                                vlan_tgen[0],tgen_dut3_ips[0],tgen_dut4_ips[1],
                                                                                                data.traffic_rate)

        ############################################################
        st.banner("User Vrf: IPv4 Traffic config for ICMP SLA")
        ############################################################

        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[2],mac_dst=dut3_vlan20_mac, rate_pps=data.traffic_rate, mode='create',
                                      port_handle=data.d3_tg_ph1,l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ip_src_count=1, ip_src_addr=tgen_dut3_ips[1], ip_src_step="0.0.0.1",
                                      ip_dst_addr=tgen_dut4_ips[2], ip_dst_count=1, ip_dst_step="0.0.0.1",
                                      l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                      vlan_id=vlan_tgen[1], vlan="enable", mac_discovery_gw=dut3_tg1_ip[1])
        data.stream_handles['{}_ipv4_icmp_stream'.format(vrf1)] = stream['stream_id']
        data.stream_details[data.stream_handles['{}_ipv4_icmp_stream'.format(vrf1)]] = "VRF IPv4 traffic ICMP session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[2],dut3_vlan20_mac,
                                                                                                vlan_tgen[1],tgen_dut3_ips[1],tgen_dut4_ips[2],
                                                                                                data.traffic_rate)

        ############################################################
        st.banner("User Vrf: IPv4 Traffic config for TCP SLA")
        ############################################################

        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[3],mac_dst=dut3_vlan20_mac, rate_pps=data.traffic_rate, mode='create',
                                      port_handle=data.d3_tg_ph1,l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ip_src_count=1, ip_src_addr=tgen_dut3_ips[1], ip_src_step="0.0.0.1",
                                      ip_dst_addr=tgen_dut4_ips[3], ip_dst_count=1, ip_dst_step="0.0.0.1",
                                      l3_protocol='ipv4', l3_length='512', ip_src_mode="increment", ip_dst_mode="increment",
                                      vlan_id=vlan_tgen[1], vlan="enable", mac_discovery_gw=dut3_tg1_ip[1])
        data.stream_handles['{}_ipv4_tcp_stream'.format(vrf1)] = stream['stream_id']
        data.stream_details[data.stream_handles['{}_ipv4_tcp_stream'.format(vrf1)]] = "VRF IPv4 traffic TCP session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[3],dut3_vlan20_mac,
                                                                                                vlan_tgen[1],tgen_dut3_ips[1],tgen_dut4_ips[3],
                                                                                                data.traffic_rate)

        ############################################################
        st.banner("Default Vrf: IPv6 Traffic config for ICMP SLA")
        ############################################################

        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[0], mac_src_count=1,
                                      mac_dst=dut3_vlan10_mac, rate_pps=data.traffic_rate, mode='create', port_handle=data.d3_tg_ph1,
                                      l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ipv6_src_addr=tgen_dut3_ipv6[0], ipv6_src_count=1,
                                      ipv6_src_step="00::1", ipv6_dst_addr=tgen_dut4_ipv6[0],
                                      ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                      vlan_id=vlan_tgen[0], vlan="enable",
                                      mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                      ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                      mac_discovery_gw=dut3_tg1_ipv6[0])
        data.stream_handles['default_ipv6_icmp_stream'] = stream['stream_id']
        data.stream_details[data.stream_handles['default_ipv6_icmp_stream']] = "IPv6 traffic ICMP session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[0],dut3_vlan10_mac,
                                                                                                vlan_tgen[0],tgen_dut3_ipv6[0],tgen_dut4_ipv6[0],
                                                                                                data.traffic_rate)

        ############################################################
        st.banner("Default Vrf: IPv6 Traffic config for TCP SLA")
        ############################################################

        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[1], mac_src_count=1,
                                      mac_dst=dut3_vlan10_mac, rate_pps=data.traffic_rate, mode='create', port_handle=data.d3_tg_ph1,
                                      l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ipv6_src_addr=tgen_dut3_ipv6[0], ipv6_src_count=1,
                                      ipv6_src_step="00::1", ipv6_dst_addr=tgen_dut4_ipv6[1],
                                      ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                      vlan_id=vlan_tgen[0], vlan="enable",
                                      mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                      ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                      mac_discovery_gw=dut3_tg1_ipv6[0])
        data.stream_handles['default_ipv6_tcp_stream'] = stream['stream_id']
        data.stream_details[data.stream_handles['default_ipv6_tcp_stream']] = "IPv6 traffic TCP SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[1],dut3_vlan10_mac,
                                                                                                vlan_tgen[0],tgen_dut3_ipv6[0],tgen_dut4_ipv6[1],
                                                                                                data.traffic_rate)

        ############################################################
        st.banner("User Vrf: IPv6 Traffic config for ICMP SLA")
        ############################################################

        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[2], mac_src_count=1,
                                      mac_dst=dut3_vlan20_mac, rate_pps=data.traffic_rate, mode='create', port_handle=data.d3_tg_ph1,
                                      l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ipv6_src_addr=tgen_dut3_ipv6[1], ipv6_src_count=1,
                                      ipv6_src_step="00::1", ipv6_dst_addr=tgen_dut4_ipv6[2],
                                      ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                      vlan_id=vlan_tgen[1], vlan="enable",
                                      mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                      ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                      mac_discovery_gw=dut3_tg1_ipv6[1])
        data.stream_handles['{}_ipv6_icmp_stream'.format(vrf1)] = stream['stream_id']
        data.stream_details[data.stream_handles['{}_ipv6_icmp_stream'.format(vrf1)]] = "VRF IPv6 traffic ICMP session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[2],dut3_vlan20_mac,
                                                                                                vlan_tgen[1],tgen_dut3_ipv6[1],tgen_dut4_ipv6[2],
                                                                                                data.traffic_rate)
        ############################################################
        st.banner("User Vrf: IPv6 Traffic config for TCP SLA")
        ############################################################

        stream = data.tg.tg_traffic_config(mac_src=dut3_tgen_mac[3], mac_src_count=1,
                                      mac_dst=dut3_vlan20_mac, rate_pps=data.traffic_rate, mode='create', port_handle=data.d3_tg_ph1,
                                      l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                      ipv6_src_addr=tgen_dut3_ipv6[1], ipv6_src_count=1,
                                      ipv6_src_step="00::1", ipv6_dst_addr=tgen_dut4_ipv6[3],
                                      ipv6_dst_count=1, ipv6_dst_step="00::1", l3_protocol='ipv6', l3_length='512',
                                      vlan_id=vlan_tgen[1], vlan="enable",
                                      mac_src_mode="increment", mac_src_step="00.00.00.00.00.01",
                                      ipv6_src_mode="increment", ipv6_dst_mode="increment",
                                      mac_discovery_gw=dut3_tg1_ipv6[1])
        data.stream_handles['{}_ipv6_tcp_stream'.format(vrf1)] = stream['stream_id']
        data.stream_details[data.stream_handles['{}_ipv6_tcp_stream'.format(vrf1)]] = "VRF IPv6 traffic TCP session SRC-MAC:{}" \
                                                                           " DEST-MAC:{} VLAN-ID:{} SRC-IP:{} " \
                                                                           " DEST IP:{} " \
                                                                           "Rate:{} fps".format(dut3_tgen_mac[3],dut3_vlan20_mac,
                                                                                                vlan_tgen[1],tgen_dut3_ipv6[1],tgen_dut4_ipv6[3],
                                                                                                data.traffic_rate)



def verify_bgp():
    ###########################################################
    st.log("BGP verify: Verify BGP sessions are up on duts")
    ############################################################
    def spine1():
        dut = data.dut1
        cnt = 3
        nbrs = [dut3_1_ipv6_list[0],dut4_1_ipv6_list[0]]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established']*cnt, delay = 4, retry_count = 20)
        return result
    def spine2():
        dut = data.dut2
        cnt = 2
        nbrs = [dut3_2_ipv6_list[0],dut4_2_ipv6_list[0]]
        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt,vrf_name=vrf1, delay = 4, retry_count = 20)
        return result
    def leaf1():
        dut = data.dut3
        cnt = 1
        nbrs = [dut1_3_ipv6_list[0],dut2_3_ipv6_list[0]]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf2():
        dut = data.dut4
        cnt = 1
        nbrs = [dut1_4_ipv6_list[0],dut2_4_ipv6_list[0]]

        result1 = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=[dut1_4_ipv6_list[0]], state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        result2 = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=[dut2_4_ipv6_list[0]],state_list=['Established'] * cnt,vrf_name=vrf1, delay=4, retry_count=20)

        if result1 and result2:
            return True
        else:
            return False
    [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2]])

    if False in set(res):
        st.error("one or more BGP sessions did not come up between spine and leaf")
        return False
    return True

def run_traffic(action='start',version='both',sla='ICMP-echo',vrf='default'):
    if 'ICMP-echo' in sla : sla='icmp'
    if 'TCP-connect' in sla: sla='tcp'
    if version == 'both':
        stream_handle = [data.stream_handles['{}_{}_{}_stream'.format(vrf,version,sla)] for version in ['ipv4','ipv6']]
    else:
        stream_handle = [data.stream_handles['{}_{}_{}_stream'.format(vrf,version,sla)]]

    if action =='start': st.log(" #### Starting Traffic for  streams #####")
    if action == 'stop': st.log(" #### Stopping Traffic for streams  #####")
    for stream in stream_handle:
        st.log("HANDLE :{} ---> {}".format(stream,data.stream_details[stream]))
    if action == 'start':
        data.tg.tg_traffic_control(action='clear_stats',port_handle=data.tg_handles)
        data.tg.tg_traffic_control(action='run', stream_handle=stream_handle)
    else:
        data.tg.tg_traffic_control(action='stop', stream_handle=stream_handle)


def verify_traffic(src_tg_obj=None,dest_tg_obj=None,src_port=None,dest_port=None,exp_ratio=1,comp_type='packet_rate',**kwargs):
    ret_val= True
    if src_tg_obj is None: src_tg_obj = data.tg
    if dest_tg_obj is None : dest_tg_obj = data.tg
    if src_port is None : src_port = data.t1d3_ports[0]
    if dest_port is None: dest_port = data.t1d4_ports[0]
    traffic_data = {
        '1': {
            'tx_ports': [src_port] if type(src_port) is str else list(src_port),
            'tx_obj': [src_tg_obj],
            'exp_ratio': [exp_ratio],
            'rx_ports': [dest_port] if type(dest_port) is str else list(dest_port),
            'rx_obj': [dest_tg_obj]
        }
    }
    traffic_data['1']['tx_obj'] = traffic_data['1']['tx_obj']*len(traffic_data['1']['tx_ports'])
    traffic_data['1']['rx_obj'] = traffic_data['1']['rx_obj'] * len(traffic_data['1']['rx_ports'])
    delay = kwargs.pop('delay',data.delay_factor)
    retry_count = kwargs.pop('retry_count',2)
    for iteration in range(retry_count):
        st.log("\n>>>>   ITERATION : {} <<<<<\n".format(iteration+1))
        aggregate_result = validate_tgen_traffic(traffic_details=traffic_data, mode='aggregate', comp_type=comp_type, delay_factor=delay)
        if aggregate_result:
            st.log('Traffic verification passed ')
            ret_val = True
            break
        else:
            ret_val =False
            st.log('Traffic verification Failed ')
            continue
    return ret_val

def config_static_arp_mac(config='yes'):
    if config == 'yes':
        ####################################################
        st.banner("Add static arp/mac toward dut4 destination tgen hosts")
        ####################################################
        for vlan,mac,ip in zip(target_vlans,dut4_tgen_mac,tgen_dut4_ips):
            arp.add_static_arp(data.dut4,ip,mac,interface='Vlan{}'.format(vlan))
        for vlan,mac,ip in zip(target_vlans,dut4_tgen_mac, tgen_dut4_ipv6):
            arp.config_static_ndp(data.dut4,ip,mac,'Vlan{}'.format(vlan),operation="add")
        for vlan,mac in zip(target_vlans,dut4_tgen_mac):
            mac_api.config_mac(data.dut4, mac, vlan, data.d4t1_ports[0])
    else:
        for ip in tgen_dut4_ips: arp.delete_static_arp(data.dut4,ip)
        for vlan,mac,ip in zip(target_vlans,dut4_tgen_mac, tgen_dut4_ipv6):
            arp.config_static_ndp(data.dut4, ip, mac, 'Vlan{}'.format(vlan), operation="del")
        for vlan,mac in zip(target_vlans,dut4_tgen_mac):mac_api.delete_mac(data.dut4, mac, vlan)


def add_static_arp(addr_family='ipv4'):
    if addr_family == 'ipv4':
        for vlan,mac,ip in zip(target_vlans,dut4_tgen_mac,tgen_dut4_ips):
            arp.add_static_arp(data.dut4,ip,mac,interface='Vlan{}'.format(vlan))
    else:
        for vlan,mac,ip in zip(target_vlans,dut4_tgen_mac, tgen_dut4_ipv6):
            arp.config_static_ndp(data.dut4,ip,mac,'Vlan{}'.format(vlan),operation="add")


def failMsg(msg,tech_support=False,tc_name='',debug=True):
    st.error("\n++++++++++++++++++++++++++++++++++++++++++++++" \
    " \n FAILED : {} \n++++++++++++++++++++++++++++++++++++++++++++++".format(msg))
    if tech_support:
        st.generate_tech_support(dut=None,name=tc_name)


def get_tc_name(level=1):
    import sys
    return sys._getframe(level).f_code.co_name


def verify_sla_basic(vrf,sla):
    ################################
    st.banner(" SLA-TEST for {} {} Started".format(vrf,sla))
    ################################
    tc_result = True ;err_list=[]
    tech_support =  data.tech_support_on_fail
    run_traffic(version='both',vrf=vrf,sla=sla)
    tc_name = get_tc_name(level=2)
    if vrf == 'default' and sla =='ICMP-echo':
        target_vlan = target_vlan_intfs[0];target_ip= target_ips[0];target_v6 = target_ipv6[0]
        sla_id_list = ['1','2']
        tcp_port_list = ['','']
    elif vrf == 'default' and sla == 'TCP-connect':
        target_vlan = target_vlan_intfs[1];target_ip = target_ips[1];target_v6 = target_ipv6[1]
        sla_id_list = ['3', '4']
        tcp_port_list = ['(22)','(179)']
    elif vrf == vrf1 and sla == 'ICMP-echo':
        target_vlan = target_vlan_intfs[2];target_ip = target_ips[2];target_v6 = target_ipv6[2]
        sla_id_list = ['5', '6']
        tcp_port_list = ['', '']
    elif vrf == vrf1 and sla == 'TCP-connect':
        target_vlan = target_vlan_intfs[3];target_ip = target_ips[3];target_v6 = target_ipv6[3]
        sla_id_list = ['7', '8']
        tcp_port_list = ['(179)','(179)']

    ##################################################
    st.banner("Verify static route installed")
    ###################################################

    result = verify_ipsla_static_route(entry=True,vrf=vrf,sla_type=sla,addr_family='ipv4')
    if result is False:
        err = "Static route for ICMP echo target not present"
        failMsg(err, tech_support, tc_name);tech_support = False;
        tc_result = False;  err_list.append(err)

    result = verify_ipsla_static_route(entry=True,vrf=vrf,sla_type=sla,addr_family='ipv6')
    if result is False:
        err = "IPv6 Static route for ICMP echo target not present"
        failMsg(err, tech_support, tc_name);tech_support = False;
        tc_result = False;  err_list.append(err)


    ########################################################
    st.banner("Delete ip address from dut4 target interface  {}".format(target_vlan))
    ########################################################
    ip_api.delete_ip_interface(data.dut4, target_vlan,target_ip, mask24)

    ########################################################
    st.banner("Verify {} SLA goes down only for ipv4".format(sla))
    ########################################################
    result1 = retry_api(ip_api.verify_ip_sla,data.dut3, sla_id_list, type=[sla]*2,
                        target=[target_ip+tcp_port_list[0],target_v6+tcp_port_list[1]],
                        state=["Down","Up"],retry_count=10,delay=1)
    if result1 is False:
        err = "FAIL: {} IP SLA is not down though target is not reachable.\n or ipv6 is unexpectedly down".format(sla)
        failMsg(err,tech_support,tc_name);tech_support=False;tc_result=False;err_list.append(err)

    ########################################################
    st.banner("Verify Static route gets uninstalled only for ipv4 after SLA expiry")
    ########################################################
    result = verify_ipsla_static_route(entry=False,vrf=vrf,sla_type=sla,addr_family='ipv4')
    if result is False:
        err = "Static route not removed from routing table after SLA expiry"
        failMsg(err,tech_support,tc_name);tech_support=False;tc_result=False;err_list.append(err)
    result = verify_ipsla_static_route(entry=True, vrf=vrf, sla_type=sla, addr_family='ipv6')
    if result is False:
        err = "IPv6 Static route removed with ipv4 sla expiry"
        failMsg(err,tech_support,tc_name);tech_support=False;tc_result=False;err_list.append(err)


    ########################################################
    st.banner("Re-add ip address for {} target".format(sla))
    ########################################################
    ip_api.config_ip_addr_interface(data.dut4, target_vlan,target_ip, mask24)
    add_static_arp('ipv4')
    #########################################################
    st.banner("# Step - Verify {} IP SLA is UP. #".format(sla))
    #########################################################
    result = retry_api(ip_api.verify_ip_sla,data.dut3,[sla_id_list[0]], type=[sla], target=[target_ip+tcp_port_list[0]], state=["Up"],retry_count=10,delay=1)
    if result is False :
        err = "FAIL: {} IPv6 IP SLA is not down though target is not reachable.\n or ipv4 is unexpectedly down".format(sla)
        tc_result = False;err_list.append(err)
        failMsg(err,tech_support,tc_name=tc_name);tech_support=False

    ############################################################
    st.banner("Verify static route gets reinstalled after SLA is UP")
    ############################################################

    result = verify_ipsla_static_route(entry=True,vrf=vrf,sla_type=sla,addr_family='ipv4')
    if result is False:
        err = "Static route not re-installed after SLA is UP"
        failMsg(err,tech_support,tc_name);tech_support=False;tc_result=False;err_list.append(err)

    #############################################################
    st.banner("Remove IPv6 address of {}".format(target_vlan))
    #############################################################
    ip_api.delete_ip_interface(data.dut4,target_vlan,target_v6, mask_v6, family='ipv6')

    ##############################################################
    st.banner("# Step - Verify {} IP SLA goes down. #".format(sla))
    ##############################################################
    result1 = retry_api(ip_api.verify_ip_sla,data.dut3,sla_id_list, type=[sla]*2,
                        target=[target_ip+tcp_port_list[0],target_v6+tcp_port_list[1]], state=["Up","Down"],
                        retry_count=10,delay=1)
    if result1 is False:
        err = "{} IPv6 IP SLA is not down though target is not reachable or ipv4 is unexpectedly down".format(sla)
        tc_result = False;err_list.append(err)
        failMsg(err,tech_support,tc_name=tc_name);tech_support=False

    ##############################################################
    st.banner("Verify only IPv6 static entry gets removed after SLA timeout")
    ##############################################################
    result = verify_ipsla_static_route(entry=False,vrf=vrf,sla_type=sla,addr_family='ipv6')
    if result is False:
        err = "IPv6 Static route not removed from routing table after SLA expiry"
        failMsg(err,tech_support,tc_name);tech_support=False;tc_result=False;err_list.append(err)
    result = verify_ipsla_static_route(entry=True, vrf=vrf, sla_type=sla, addr_family='ipv4')
    if result is False:
        err = "IPv4 Static route removed with ipv6 sla expiry"
        failMsg(err,tech_support,tc_name);tech_support=False;tc_result=False;err_list.append(err)


    ##########################################################
    st.banner("Re-Add IPv6 of {}".format(target_vlan))
    ##########################################################
    ip_api.config_ip_addr_interface(data.dut4,target_vlan,target_v6, mask_v6, family='ipv6')
    add_static_arp('ipv6')
    ##########################################################
    st.banner("# Step - Verify {} IP SLA is UP. #".format(sla))
    ##########################################################
    result = retry_api(ip_api.verify_ip_sla,data.dut3, [sla_id_list[1]], type=[sla], target=[target_v6+tcp_port_list[1]], state=["Up"],retry_count=10,delay=1)
    if result is False :
        err = "FAIL: {} IPv6 IP SLA is not UP after target becomes reachable".format(sla)
        tc_result = False;err_list.append(err)
        failMsg(err,tech_support,tc_name=tc_name);tech_support=False

    ##############################################################
    st.banner("Verify ipv6 static route gets reinstalled after SLA is up")
    ##############################################################
    result = verify_ipsla_static_route(entry=True,vrf=vrf,sla_type=sla,addr_family='ipv6')
    if result is False:
        err = "IPv6 Static route not getting re-installed after SLA is UP"
        failMsg(err,tech_support,tc_name);tech_support=False;tc_result=False;err_list.append(err)

    if not verify_traffic():
        err = "Traffic failure after SLAs are up"
        failMsg(err,tech_support,tc_name);tc_result=False;err_list.append(err)

    run_traffic(action='stop',version='both', vrf=vrf, sla=sla)
    #####################################
    st.banner("SLA-TEST for {} {} Ended".format(vrf, sla))
    #####################################
    if not tc_result:
        return False,err_list[0]

    return True,None

def config_ipsla_params(config = 'yes'):

    dut = data.dut3
    dst_icmp_ip_lst = [target_ips[0],target_ipv6[0],target_ips[2],target_ipv6[2]]
    dst_tcp_ip_lst = [target_ips[1],target_ipv6[1],target_ips[3],target_ipv6[3]]
    tcp_ports = ['22','179','179','179']


    for id,dst in zip([1,2,5,6],dst_icmp_ip_lst):
        ip_api.config_ip_sla(dut, id, sla_type="icmp-echo", dst_ip=dst ,threshold=3,timeout=2,
                                     data_size=64,ttl=3,tos=30,config=config,del_cmd_list=['threshold','timeout','datasize','ttl','tos'])

    for id,dst,tcp_port in zip([3,4,7,8],dst_tcp_ip_lst,tcp_ports):
        ip_api.config_ip_sla(dut, id, sla_type="tcp-connect", dst_ip=dst ,tcp_port=tcp_port,threshold=4,timeout=3,
                                     ttl=4,tos=40,config=config,del_cmd_list=['threshold','timeout','datasize','ttl','tos'])



def config_ip_sla_scale(sla_id=1, sla_count=50, sla_type='icmp-echo', addr_family='ipv4', vrf='default', vlan=1001,
                        tcp_port='22', targ_config=True, route_config=True, config='yes'):
    if config == 'yes':
        static_route_api = ip_api.create_static_route
    else:
        static_route_api = ip_api.delete_static_route
    if vrf == 'default':
        if addr_family == 'ipv4':
            src_ip = dut3_1_ip_list[0]
            dst_ip_lst = ["40.1." + str(i) + ".1" for i in range(1, sla_count + 1)]
            nxt_hop = dut1_3_ip_list[0]
            mask = mask24
    else:
        if addr_family == 'ipv4':
            src_ip = dut3_2_ip_list[0]
            dst_ip_lst = ["40.1." + str(i) + ".1" for i in range(1, sla_count + 1)]
            nxt_hop = dut2_3_ip_list[0]
            mask = mask24

    def ipsla_dut_config():
        dut = data.dut3
        for id, dst in zip(range(sla_id, sla_id + sla_count), dst_ip_lst):

            if sla_type == 'icmp-echo':
                ip_api.config_ip_sla(dut, id, sla_type=sla_type, dst_ip=dst, src_addr=src_ip, frequency=sla_freq,threshold=3,timeout=2,
                                     data_size=64,ttl=3,tos=30,del_cmd_list=['sla_num'], vrf_name=vrf, config=config)
            else:
                ip_api.config_ip_sla(dut, id, sla_type=sla_type, dst_ip=dst, tcp_port=tcp_port,threshold=3,timeout=2,ttl=3,tos=30,
                                     frequency=sla_freq,src_port='200', del_cmd_list=['sla_num'], vrf_name=vrf, config=config)
        if route_config:
            dst_ip_subnet_lst = ["40.1." + str(i) + ".0" for i in range(1, sla_count + 1)]
            for i, targ_ip in zip(range(sla_id, sla_id + sla_count), dst_ip_subnet_lst):
                vrf_str = None if vrf =='default' else vrf
                static_route_api(dut, next_hop=nxt_hop, static_ip=targ_ip + '/' + mask,
                                 family=addr_family, vrf=vrf_str, track=i)

    def target_dut_config():
        dut = data.dut4
        vlan_lst = [i for i in range(vlan, vlan + sla_count)]
        vlanInt_lst = ['Vlan' + str(i) for i in range(vlan, vlan + sla_count)]
        range_vlan = str(vlan) + '-' + str(vlan + sla_count - 1)
        ip_config = 'add'

        if config == 'yes':
            # config_vlan_and_member(dut, vlan_lst, [data.d4t1_ports[0]]*len(vlan_lst))
            vlan_api.create_vlan(dut, vlan_lst)
            vlan_api.add_vlan_member(dut, range_vlan, data.d4t1_ports[0], True)
            if vrf != 'default':
                for vlanI in vlanInt_lst:
                    vrf_api.bind_vrf_interface(dut, vrf_name=vrf, intf_name=vlanI)
        else:
            ip_config = 'remove'

        for vlanI, ip in zip(vlanInt_lst, dst_ip_lst):
            ip_api.config_ip_addr_interface(dut, vlanI, ip, mask, family=addr_family, config=ip_config)
        if config != 'yes':
            # config_vlan_and_member(dut, vlan_lst, [data.d4t1_ports[0]]*len(vlan_lst),config = 'no')
            if vrf != 'default':
                for vlanI in vlanInt_lst:
                    vrf_api.bind_vrf_interface(dut, vrf_name=vrf, intf_name=vlanI, config='no')
            vlan_api.delete_vlan_member(dut, range_vlan, data.d4t1_ports[0], True)
            vlan_api.delete_vlan(dut, vlan_lst)

    if targ_config:
        [res, exceptions] = st.exec_all([[ipsla_dut_config], [target_dut_config]])
    else:
        ipsla_dut_config()

    return True


def verify_ipsla_scale(sla_id=9, sla_count=17, sla_type='ICMP-echo', exp_state='Up', tcp_port='(22)'):
    dut = data.dut3
    sla_id = list(range(sla_id, sla_id + sla_count))

    sla_lst = [sla_type] * sla_count
    state = [exp_state] * sla_count
    if sla_type == 'ICMP-echo':
        dst_ip_lst = ["40.1." + str(i) + ".1" for i in range(1, sla_count + 1)]
        result = retry_api(ip_api.verify_ip_sla,dut, sla_id, type=sla_lst, target=dst_ip_lst, state=state,retry_count=10,delay=2)
    else:
        dst_ip_lst = ["40.1." + str(i) + ".1" + tcp_port for i in range(1, sla_count + 1)]
        result = retry_api(ip_api.verify_ip_sla,dut, sla_id, type=sla_lst, target=dst_ip_lst, state=state, retry_count=10,delay=2)

    if result is False:
        st.error("One or more IP SLAs are down.")
        return False
    return True


def verify_sla_transition_count(sla_id=1, sla_count=50, tx_cnt='0'):
    dut = data.dut3
    sla_id_lst = list(range(sla_id, sla_id + sla_count))
    trans_cnt = [tx_cnt] * sla_count
    ip_api.clear_ip_sla(data.dut3, inst='all')
    st.wait(3)
    result = ip_api.verify_ip_sla(dut, sla_id_lst, transitions=trans_cnt)

    if result is False:
        st.error("One or more IP SLAs are flapping - transition > 0 .")
        return False
    return True

def verify_static_route_scale(sla_count=17, addr_family='ipv4', mask='24', vrf='default'):
    dut = data.dut3
    dst_ip_subnet_lst = ["40.1." + str(i) + ".0" + '/' + mask for i in range(1, sla_count + 1)]

    lst_len = len(dst_ip_subnet_lst)
    if vrf == 'default':
        nxt_hop = dut1_3_ip_list[0]
        vrf_str = ''
    else:
        nxt_hop = dut2_3_ip_list[0]
        vrf_str = vrf

    result = ip_api.verify_multiple_routes(dut, type=['S'] * lst_len, nexthop=[nxt_hop] * lst_len,
                                           ip_address=dst_ip_subnet_lst,
                                           family=addr_family, vrf_name=vrf)
    if result is False:
        st.error("Static {} route to IP address not in routing table on dut {}.".format(vrf_str, dut))
        return False
    return True


def verify_policy_counters_incrementing(dut,policy,flow_list,interface=None,increment=True):
    if interface:
        acl_dscp_api.config_service_policy_table(dut,policy_kind='clear_interface',interface_name=interface,stage='in')
    else:
        acl_dscp_api.config_service_policy_table(dut, policy_kind='clear_policy',service_policy_name=policy)
    ####################################
    st.banner('Verify service policy counters increments')
    ####################################
    packet_count = {}
    match_list = list()
    for flow in flow_list:
        match  ={'policy_name':policy,'class_name':flow}
        match_list.append(match)

    for iteration in range(2):
        iteration = iteration + 1
        if interface:
            output = acl_dscp_api.show(dut,interface_name=interface)
        else:
            output = acl_dscp_api.show(dut, service_policy_name=policy)

        if output:
            for match_1 in match_list:
                entry_v4 = filter_and_select(output,None,match=match_1)
                if entry_v4:
                    packet_count['{}_{}'.format(match_1['class_name'],iteration)] = int(entry_v4[0]['match_pkts_val'])
                    st.log("{} Policy Packet Match Count : {} packets".
                           format(match_1['class_name'],packet_count['{}_{}'.format(match_1['class_name'],iteration)]))
                else:
                    st.error("####### Packet count entry not found     #######")
                    return False
        else:
            st.error("Empty output")
            return False
        if iteration == 1 :
            st.wait(10, 'Wait for fetching packet match count')

    if increment:
        for flow in flow_list:
            if packet_count['{}_2'.format(flow)] == packet_count['{}_1'.format(flow)]:
               st.error("{} policy match counters not incremented".format(flow))
               return False
        st.log('\n>>>>>>>>> Policy Match counters incremented as expected <<<<<<<<<<<\n')
    else:
        for flow in flow_list:
            if packet_count['{}_2'.format(flow)] != packet_count['{}_1'.format(flow)]:
                st.error("{} policy match counters incremented".format(flow))
                return False
    return True


def verify_traffic_counters(dut,nexthop_intf=[]):
    #######################################################
    st.banner("Verify Traffic gets forwarded on nexthop interfaces {}".format(nexthop_intf))
    #######################################################
    ingress_intf = data.d3t1_ports[0]
    intf_api.clear_interface_counters(dut)
    st.wait(3,'wait for traffic counters to stabilise')
    output = intf_api.get_interface_counter_value(dut, [ingress_intf]+ nexthop_intf, ['rx_ok', 'tx_ok'])
    ingress_count = int(output[ingress_intf]['rx_ok'])
    egress_count = 0
    for intf in nexthop_intf: egress_count += int(output[intf]['tx_ok'])
    pkt_diff = abs(ingress_count-egress_count)
    st.log(" Ingress Packet count : {} packets ".format(ingress_count))
    st.log(" Egress Packet count on {} : {} packets ".format(nexthop_intf,egress_count))
    if egress_count < 1000:
        failMsg('Traffic did not forward via nexthop interfaces {}'.format(nexthop_intf))
        return False
    return True



def config_mclag(config = 'yes'):

    ################################################
    st.log("Configure MCLAG and bring up LVTEP.")
    ################################################
    # Config peer interface lag
    # Config Keepalive interface
    # Create Vlan for peer interface
    if config == 'yes':
        def leaf1():
            dut = data.dut3
            vlan_api.create_vlan(dut, client_vlans)
            ip_api.config_ip_addr_interface(dut, data.d3d2_ports[1], dut3_2_ip_list[1],mask31)
            pc.create_portchannel(dut, iccp_lag)
            pc.create_portchannel(dut, client_lag)
            pc.add_portchannel_member(dut,iccp_lag,data.d3d2_ports[2])
            pc.add_portchannel_member(dut, client_lag, data.d3d1_ports[1])

            #vlan_api.add_vlan_member(dut,vni_vlan[0],iccp_lag,True)
            mclag.config_domain(dut, mlag_domain_id, local_ip=dut3_2_ip_list[1],
                                peer_ip=dut2_3_ip_list[1], peer_interface=iccp_lag)

            mclag.config_interfaces(dut, mlag_domain_id, client_lag, config="add")

            for vlan in client_vlans:
                vlan_api.add_vlan_member(dut, vlan, [iccp_lag,client_lag], True)


        def leaf2():
            dut = data.dut2
            vlan_api.create_vlan(dut, client_vlans)
            ip_api.config_ip_addr_interface(dut, data.d2d3_ports[1], dut2_3_ip_list[1], mask31)
            pc.create_portchannel(dut, iccp_lag)
            pc.create_portchannel(dut, client_lag)
            pc.add_portchannel_member(dut, iccp_lag, data.d2d3_ports[2])
            pc.add_portchannel_member(dut,client_lag,data.d2d1_ports[1])

            #vlan_api.add_vlan_member(dut,vni_vlan[0],iccp_lag,True)
            mclag.config_domain(dut, mlag_domain_id, local_ip=dut2_3_ip_list[1],
                                peer_ip=dut3_2_ip_list[1], peer_interface=iccp_lag)
            mclag.config_interfaces(dut, mlag_domain_id, client_lag, config="add")

            for vlan in client_vlans:
                vlan_api.add_vlan_member(dut, vlan, [iccp_lag,client_lag], True)

        def client1():
            dut = data.dut1
            vlan_api.create_vlan(dut, client_vlans)
            pc.create_portchannel(dut, client_lag)
            pc.add_portchannel_member(dut, client_lag, data.d1d3_ports[1])
            pc.add_portchannel_member(dut, client_lag, data.d1d2_ports[1])

            for vlan in client_vlans:
                vlan_api.add_vlan_member(dut, vlan, [iccp_lag,client_lag], True)

    '''
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
            dut = data.dut2
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][0],[client_lag],True)
            vlan_api.delete_vlan_member(dut, client_dict["tenant_l2_vlan_list"][2],[data.d4d7_ports[2]],True)
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][0],[client_lag])
            #vlan_api.delete_vlan_member(dut, client_dict["tenant_l3_vlan_list"][2],[data.d4d7_ports[2]])
            for vlan in client_dict["tenant_l3_vlan_list"]:
                vlan_api.delete_vlan_member(dut, vlan, [client_lag,True])
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
            dut = data.dut1
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
    '''
    st.exec_all([[leaf1],[leaf2],[client1]])
