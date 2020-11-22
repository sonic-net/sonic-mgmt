from spytest import st
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *

import apis.common.asic_bcm as bcm
import apis.routing.ip as ip
import apis.routing.arp as arp
import apis.routing.evpn as evpn
import apis.system.interface as intf
import apis.switching.mac as mac
from apis.system import basic
import apis.switching.portchannel as pc
import apis.routing.bgp as bgp_api
import apis.switching.vlan as vlan_api
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.routing.vrf as vrf_api
import utilities.utils as utils_obj
from utilities import parallel

from ecmp_vars import *

def verify_intf_counters(**kwargs):
    global saved_output
    
    rx=kwargs['rx']
    tx=kwargs.get('tx',[])
    ratio=kwargs.get('ratio',[[1.0]])
    tolerance=kwargs.get('tolerance',10.0)
    rx_var=kwargs.get('rx_var','pkt_rx_512_1023_octets')
    tx_var=kwargs.get('tx_var','pkt_tx_512_1023_octets')
    ratio = [ratio[0],[]] if len(ratio) == 1 else ratio    #when tx=[]
    saved_flag = kwargs.get('saved_flag',False)
    clear_save = kwargs.get('clear_save',False)
    
    retvar = True
    pass_msgs = []
    fail_msgs = []
    st.log("verify_intf_counters: kwargs={}.".format(kwargs))
    st.log("rx={},tx={},ratio={},tolerance={},rx_var={},tx_var={},saved_flag={},clear_save={}.".format(rx,tx,ratio,tolerance,rx_var,tx_var,saved_flag,clear_save))
    
    if clear_save:
        saved_output={}
    out=[]
    if saved_flag:
        if ','.join(rx[0]) in saved_output.keys():
            out=saved_output.get(','.join(rx[0]))
    if out == []:
        out=intf.show_interface_counters_detailed(rx[0][0], rx[0][1])
        saved_output[','.join(rx[0])]=out
    cnt_ref=int(out[0][rx_var])*ratio[0][0]*1.0
    if cnt_ref == 0.0:
        st.log("Error:verify_intf_counters: Reference count is 0.")
        return False
    
    for pair,rat1,var in zip(rx[1:]+tx, ratio[0][1:]+ratio[1], [rx_var]*len(rx[1:])+[tx_var]*len(tx)):
        dut,port = pair
        out=[]
        if saved_flag:
            if ','.join(pair) in saved_output.keys():
                out=saved_output.get(','.join(pair))
        if out == []:
            out=intf.show_interface_counters_detailed(dut, port)
            saved_output[','.join(pair)]=out
        cnt=int(out[0][var])
        diffpc = cnt
        if rat1*1.0 != 0.0:
            diffpc = abs((cnt_ref*rat1*1.0 - cnt) * 100 / (cnt_ref*rat1))
        if diffpc < tolerance:
            pass_msgs += ["Traffic check Passed: dut={}, port={}, var={}, count={}, ref_count={}, ratio={}, diff_percent={}.".format(dut, port, var, cnt, cnt_ref, rat1, diffpc)]
        else:
            st.log("Traffic check FAILED: dut={}, port={}, var={}, count={}, ref_count={}, ratio={}, diff_percent={}.".format(dut, port, var, cnt, cnt_ref, rat1, diffpc))
            fail_msgs += ["Traffic check FAILED: dut={}, port={}, var={}, count={}, ref_count={}, ratio={}, diff_percent={}.".format(dut, port, var, cnt, cnt_ref, rat1, diffpc)]
            retvar = False
    
    for msg in pass_msgs+fail_msgs:
        st.log(msg)
    return retvar

def more_debugs(**kwargs):
    if not get_more_debugs_flag:
        st.log("Inside more_debugs: get_more_debugs_flag is set to False...")
        return True
    duts = kwargs['duts']
    st.banner("MORE DEBUGS START...")
    def ecmp_debugs(dut):
        #intf.clear_interface_counters(dut1)
        ip.show_ip_loadshare(dut)
        bcm_cmdlist = ["l3 ecmp egress show",
        "g raw RTAG7_HASH_FIELD_BMAP_1",
        "g raw RTAG7_HASH_FIELD_BMAP_2",
        "g raw RTAG7_HASH_FIELD_BMAP_3",
        "g raw RTAG7_IPV4_TCP_UDP_HASH_FIELD_BMAP_1",
        "g raw RTAG7_IPV4_TCP_UDP_HASH_FIELD_BMAP_2",
        "g raw RTAG7_IPV6_TCP_UDP_HASH_FIELD_BMAP_1",
        "g raw RTAG7_IPV6_TCP_UDP_HASH_FIELD_BMAP_2",
        "g raw RTAG7_HASH_SEED_A",
        "g raw RTAG7_HASH_SEED_B",
        "d chg RTAG7_PORT_BASED_HASH",
        "g raw HASH_CONTROL",
        "l3 egress show"]
        for b_cmd in bcm_cmdlist:
            bcm.bcmcmd_show(dut,b_cmd)
        ip.show_ip_route(dut)
        arp.show_arp(dut)
        arp.show_ndp(dut)
        evpn.show_ip_neigh(dut)
        bcm.bcmcmd_l3_defip_show(dut)
        bcm.bcmcmd_l3_l3table_show(dut)
        bcm.bcmcmd_l3_ip6host_show(dut)
        bcm.bcmcmd_l3_ip6route_show(dut)
        bcm.read_l2(dut)
        bcm.bcm_cmd_l3_intf_show(dut)
        intf.show_interfaces_counters(dut)
        mac.get_mac(dut)
        ip.show_ip_route(dut, family='ipv6')
    [res, exceptions]=utils.exec_all(True, [[ecmp_debugs, dut] for dut in duts])
    st.banner("MORE DEBUGS END...")
    return False if None not in set(res) else True

def gen_tech_supp(**kwargs):
    if not gen_tech_support_flag:
        st.log("Inside gen_tech_sup: gen_tech_support_flag is set to False...")
        return True
    fname = kwargs.get('filename','default')
    basic.get_techsupport(filename=fname)
    st.log("END OF TECH SUPPORT")

# Vxlan testcase utils.

def ecmp_base_config():
    ###################################################
    st.banner(" Begin base Configuration for ECMP Over VxLAN")
    ###################################################
    config_ip()
    config_loopback()
    config_bgp()
    st.wait(5)
    result = verify_bgp()
    if not result:
        st.error('BGP neighbor is not up between duts')
        return False
    config_leafInterface()
    st.wait(5)
    result = verify_vxlan()
    if not result:
        st.error('VxLAN tunnel is not up between the leaf nodes')
        return False
    tenant_vni_config()
    static_routes_config()
    st.wait(5)
    result = verify_ecmp_routes()
    if not result:
        st.error('ECMP routes are not proper in the leafs.')
        return False
    
    ###################################################
    st.banner("BASE Config End ")
    ###################################################
    return True

def ecmp_base_unconfig():
    #st.banner(" Begin base Un-Configuration ")
    #policy_config_base('no')
    #classifier_config_base('no')
    #access_list_base('no')
    #tenant_vni_config('no')
    #config_leaf2_client('no')
    #config_leafInterface('no')
    #config_bgp('no')
    #config_loopback('no')
    #config_ip('no')
    ###################################################
    st.banner("BASE De-Config Ends ")
    ###################################################

def config_ip(config='yes'):
    if config == 'yes':
        action = 'enable'
    else:
        action = 'disable'
    st.log("Enable IPv6 over portchannel interfaces between Leaf and Spine")
    
    def spine1():
        dut = data.dut1
        po_list = [data.po_s1l1, data.po_s1l2, data.po_s1l3]
        po_members = [[data.d1d3_ports[0],data.d1d3_ports[1]],[data.d1d4_ports[0],data.d1d4_ports[1]],\
                [data.d1d5_ports[0],data.d1d5_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)
    
    def spine2():
        dut = data.dut2
        po_list = [data.po_s2l1, data.po_s2l2, data.po_s2l3]
        po_members = [[data.d2d3_ports[0],data.d2d3_ports[1]],[data.d2d4_ports[0],data.d2d4_ports[1]],\
                [data.d2d5_ports[0],data.d2d5_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)
    
    def leaf1():
        dut = data.dut3
        po_list = [data.po_s1l1, data.po_s2l1]
        po_members = [[data.d3d1_ports[0],data.d3d1_ports[1]],[data.d3d2_ports[0],data.d3d2_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)
    
    def leaf2():
        dut = data.dut4
        po_list = [data.po_s1l2, data.po_s2l2]
        po_members = [[data.d4d1_ports[0],data.d4d1_ports[1]],[data.d4d2_ports[0],data.d4d2_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)
    
    def leaf3():
        dut = data.dut5
        po_list = [data.po_s1l3, data.po_s2l3]
        po_members = [[data.d5d1_ports[0],data.d5d1_ports[1]],[data.d5d2_ports[0],data.d5d2_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)
    
    # Enable IPv6 between Spine and Leaf portchannels
    [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2],[leaf3]])

def config_loopback(config='yes'):
    #import apis.routing.ip as ip
    if config == 'yes':
        api_name = ip.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip.config_ip_addr_interface
        config_str = "Delete"
    
    st.log("%s Loopback configs between Leaf and Spine"%(config_str))
    if config == 'yes' :
        parallel.exec_parallel(True, data.rtr_list, ip.configure_loopback, [{'loopback_name': data.loopback1}] * 5)
        utils.exec_all(True, [[api_name, dut, data.loopback1, ip1, data.mask32]
                              for dut, ip1 in zip(data.rtr_list, data.loopback1_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip.configure_loopback, [{'loopback_name': data.loopback2}] * 5)
        utils.exec_all(True, [[ip.config_ip_addr_interface, dut, data.loopback2, ip1, data.mask32]
                              for dut, ip1 in zip(data.rtr_list, data.loopback2_ip_list)])
    
    else:
        utils.exec_all(True, [[ip.config_ip_addr_interface, dut, data.loopback2, ip1, data.mask32,'ipv4','remove']
                              for dut, ip1 in zip(data.rtr_list, data.loopback2_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip.configure_loopback,
                               [{'loopback_name': data.loopback2,'config':'no'}] * 5)
        utils.exec_all(True, [[ip.config_ip_addr_interface, dut, data.loopback1, ip1, data.mask32,'ipv4','remove']
                              for dut, ip1 in zip(data.rtr_list, data.loopback1_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip.configure_loopback,
                               [{'loopback_name': data.loopback1,'config':'no'}] * 5)

def config_bgp(config='yes'):
    st.log("BGP and evpn configs between Leaf and Spine")
    if config == 'yes':
        def spine1():
            dut = data.dut1
            dut_as = data.dut1_AS
            nbr_list = [data.po_s1l1,data.po_s1l2,data.po_s1l3]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut,local_as = dut_as, remote_as = 'external', interface = nbr,
                 config_type_list = ['bfd'],config = 'yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as,config='yes', config_type_list=["neighbor"], remote_as='external', neighbor=nbr)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                 config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def spine2():
            dut = data.dut2
            dut_as = data.dut2_AS
            nbr_list = [data.po_s2l1,data.po_s2l2, data.po_s2l3]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=nbr,
                                   config_type_list = ['bfd'],config = 'yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as,config='yes', config_type_list=["neighbor"], remote_as='external', neighbor=nbr)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                     config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf1():
            dut = data.dut3
            dut_as = data.dut3_AS
            nbr_list = [data.po_s1l1,data.po_s2l1]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=nbr,
                                   config_type_list = ['bfd'],config = 'yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as,config='yes', config_type_list=["neighbor"], remote_as='external', neighbor=nbr)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                     config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf2():
            dut = data.dut4
            dut_as = data.dut4_AS
            nbr_list = [data.po_s1l2,data.po_s2l2]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=nbr,
                                   config_type_list = ['bfd'],config = 'yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as,config='yes', config_type_list=["neighbor"], remote_as='external', neighbor=nbr)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                     config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf3():
            dut = data.dut5
            dut_as = data.dut5_AS
            nbr_list = [data.po_s1l3,data.po_s2l3]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=nbr,
                                   config_type_list = ['bfd'],config = 'yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as,config='yes', config_type_list=["neighbor"], remote_as='external', neighbor=nbr)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                     config_type_list=["activate"], local_as=dut_as, remote_as='external')
            bgp_api.config_bgp(dut=dut, local_as=dut_as, config='yes', config_type_list=["multipath-relax", "max_path_ebgp"], max_path_ebgp='10')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        [res, exceptions] = st.exec_all( [[spine1], [spine2], [leaf1], [leaf2], [leaf3]])

    else:
        ##########################################################################
        st.banner("BGP-Deconfig: Delete BGP routers globally from all DUTs")
        ##########################################################################

        dict1 = {'local_as':data.dut3_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':data.vrf1}
        dict2 = {'local_as':data.dut4_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':data.vrf1}
        dict3 = {'local_as':data.dut5_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':data.vrf1}

        parallel.exec_parallel(True, data.leaf_list, bgp_api.config_bgp, [dict1,dict2,dict3])
        dict1 = []
        for dut_as in [data.dut1_AS,data.dut2_AS,data.dut3_AS,data.dut4_AS,data.dut5_AS]:
            dict1 = dict1 + [{'local_as' : dut_as,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}]
        parallel.exec_parallel(True, data.rtr_list, bgp_api.config_bgp, dict1)


def config_leafInterface(config='yes'):

    ################################################
    st.log("Configure Leaf nodes .")
    ################################################

    if config == 'yes' :
        def leaf1():

            dut = data.dut3
            vtep_name = data.vtep_names[0]
            nvo_name = data.nvo_names[0]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut3_loopback_ip[1]
            local_as = data.dut3_AS
            vlan_list = [vlan_vni] + data.leaf1_dict['tenant_vlan_list']
            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=data.vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=data.vrf1,intf_name=data.vlan_vrf1)
            ip.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip[0], data.mask_24)
            ip.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip6[0], data.mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name)
            for vlan in data.leaf1_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='static')
                               
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='static', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=local_as, advertise_ipv6='unicast')

        def leaf2():

            dut = data.dut4
            vtep_name = data.vtep_names[1]
            nvo_name = data.nvo_names[1]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut4_loopback_ip[1]
            local_as = data.dut4_AS
            vlan_list = [vlan_vni] + data.leaf2_dict['tenant_vlan_list']
            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=data.vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=data.vrf1,intf_name=data.vlan_vrf1)
            ip.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip[1], data.mask_24)
            ip.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip6[1], data.mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            for vlan in data.leaf2_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='static')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='static', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],
                                 local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],
                                 local_as=local_as, advertise_ipv6='unicast')

        def leaf3():

            dut = data.dut5
            vtep_name = data.vtep_names[2]
            nvo_name = data.nvo_names[2]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut5_loopback_ip[1]
            local_as = data.dut5_AS
            vlan_list = [vlan_vni] + data.leaf3_dict['tenant_vlan_list']
            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=data.vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=data.vrf1,intf_name=data.vlan_vrf1)
            ip.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip[2], data.mask_24)
            ip.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip6[2], data.mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"],  redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist", "max_path_ebgp"], redistribute='static', max_path_ebgp='10')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist", "max_path_ebgp"], redistribute='static', max_path_ebgp='10', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],  local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],  local_as=local_as, advertise_ipv6='unicast')
            for vlan in data.leaf3_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
    
    else:
        def leaf1():
            dut = data.dut3
            vtep_name = data.vtep_names[0]
            nvo_name = data.nvo_names[0]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut3_loopback_ip[1]
            vlan_list = [vlan_vni] + data.leaf1_dict['tenant_vlan_list']
            for vlan in data.leaf1_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config = 'no')
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name, config = 'no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config = 'no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config = 'no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config = 'no')
            ip.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip[0], data.mask_24)
            ip.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip6[0], data.mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=data.vlan_vrf1,config = 'no')
            vlan_api.delete_vlan(dut, vlan_list)

        def leaf2():
            dut = data.dut4
            vtep_name = data.vtep_names[1]
            nvo_name = data.nvo_names[1]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut4_loopback_ip[1]
            vlan_list = [vlan_vni] + data.leaf2_dict['tenant_vlan_list']
            for vlan in data.leaf2_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config = 'no')
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name, config = 'no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config = 'no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config = 'no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config = 'no')
            ip.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip[1], data.mask_24)
            ip.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip6[1], data.mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=data.vlan_vrf1,config = 'no')
            vlan_api.delete_vlan(dut, vlan_list)

        def leaf3():
            dut = data.dut5
            vtep_name = data.vtep_names[2]
            nvo_name = data.nvo_names[2]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut5_loopback_ip[1]
            vlan_list = [vlan_vni] + data.leaf3_dict['tenant_vlan_list']
            for vlan in data.leaf3_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                vlan_api.delete_vlan_member(dut,vlan, data.d5t1_ports[0],True)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name, config='no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config='no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config='no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config='no')
            ip.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip[2], data.mask_24)
            ip.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip6[2], data.mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=data.vlan_vrf1, config='no')
            vlan_api.delete_vlan(dut,vlan_list)

    st.exec_all([[leaf1],[leaf2],[leaf3]])

def tenant_vni_config(config = 'yes'):
    ################################################
    st.log("Configure L3 VNI Clients on each leaf node.")
    ################################################
    if config == 'yes' :
        def leaf1():
            dut = data.dut3
            vlan_api.add_vlan_member(dut, data.leaf1_dict["tenant_vlan_list"][0], data.d3t1_ports[0], True)
            vlan_api.add_vlan_member(dut, data.leaf1_dict["tenant_vlan_list"][1], data.d3t1_ports[1], True)
            for vlan_int,ip1,ip6 in zip(data.leaf1_dict["tenant_vlan_int"], data.leaf1_dict["tenant_ip_list"],data.leaf1_dict["tenant_ipv6_list"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int)
                ip.config_ip_addr_interface(dut, vlan_int, ip1, data.mask_24)
                ip.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
            data.dut3_gw_mac = basic.get_ifconfig(dut, data.leaf1_dict["tenant_vlan_int"][0])[0]['mac']
        def leaf2():
            dut = data.dut4
            vlan_api.add_vlan_member(dut, data.leaf2_dict["tenant_vlan_list"][0], data.d4t1_ports[0], True)
            vlan_api.add_vlan_member(dut, data.leaf2_dict["tenant_vlan_list"][1], data.d4t1_ports[1], True)
            for vlan_int,ip1,ip6 in zip(data.leaf2_dict["tenant_vlan_int"], data.leaf2_dict["tenant_ip_list"], data.leaf2_dict["tenant_ipv6_list"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int)
                ip.config_ip_addr_interface(dut, vlan_int, ip1, data.mask_24)
                ip.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
            data.dut4_gw_mac = basic.get_ifconfig(dut, data.leaf2_dict["tenant_vlan_int"][0])[0]['mac']
        def leaf3():
            dut = data.dut5
            vlan_api.add_vlan_member(dut, data.leaf3_dict["tenant_vlan_list"][0], data.d5t1_ports[0], True)
            vlan_api.add_vlan_member(dut, data.leaf3_dict["tenant_vlan_list"][1], data.d5t1_ports[1], True)
            for vlan_int,ip1,ip6 in zip(data.leaf3_dict["tenant_vlan_int"], data.leaf3_dict["tenant_ip_list"], data.leaf3_dict["tenant_ipv6_list"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int)
                ip.config_ip_addr_interface(dut, vlan_int, ip1, data.mask_24)
                ip.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
            data.dut5_gw_mac = basic.get_ifconfig(dut, data.leaf3_dict["tenant_vlan_int"][0])[0]['mac']
    else:
        def leaf1():
            dut = data.dut3
            for vlan_int, ip1, ip6 in zip(data.leaf1_dict["tenant_vlan_int"], data.leaf1_dict["tenant_ip_list"], data.leaf1_dict["tenant_ipv6_list"]):
                ip.delete_ip_interface(dut, vlan_int, ip1, data.mask_24)
                ip.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int,config='no')
            vlan_api.delete_vlan_member(dut, data.leaf1_dict["tenant_vlan_list"][0], data.d3t1_ports[0], True)
            vlan_api.delete_vlan_member(dut, data.leaf1_dict["tenant_vlan_list"][1], data.d3t1_ports[1], True)
        def leaf2():
            dut = data.dut4
            for vlan_int, ip1, ip6 in zip(data.leaf2_dict["tenant_vlan_int"], data.leaf2_dict["tenant_ip_list"], data.leaf2_dict["tenant_ipv6_list"]):
                ip.delete_ip_interface(dut, vlan_int, ip1, data.mask_24)
                ip.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int,config='no')
            vlan_api.delete_vlan_member(dut, data.leaf2_dict["tenant_vlan_list"][0], data.d4t1_ports[0], True)
            vlan_api.delete_vlan_member(dut, data.leaf2_dict["tenant_vlan_list"][1], data.d4t1_ports[1], True)
        def leaf3():
            dut = data.dut5
            for vlan_int, ip1, ip6 in zip(data.leaf3_dict["tenant_vlan_int"], data.leaf3_dict["tenant_ip_list"], data.leaf3_dict["tenant_ipv6_list"]):
                ip.delete_ip_interface(dut, vlan_int, ip1, data.mask_24)
                ip.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int, config='no')
            vlan_api.delete_vlan_member(dut, data.leaf3_dict["tenant_vlan_list"][0], data.d5t1_ports[0], True)
            vlan_api.delete_vlan_member(dut, data.leaf3_dict["tenant_vlan_list"][1], data.d5t1_ports[1], True)
    [res, exceptions] = st.exec_all([[leaf1], [leaf2],[leaf3]])
    return res

def static_routes_config(config = 'yes'):
    ################################################
    st.log("Configure Static routes on leafs which creates ECMP.")
    ################################################
    if config == 'yes' :
        
        def leaf1():
            dut = data.dut3
            ip.create_static_route(dut, data.leaf1_dict["tenant_v4_ip"][0], data.st_ip_1[1], vrf=data.vrf1)
            ip.create_static_route(dut, data.leaf1_dict["tenant_v4_ip"][1], data.st_ip_1[1], vrf=data.vrf1)
            ip.create_static_route(dut, data.leaf1_dict["tenant_v6_ip"][0], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
            ip.create_static_route(dut, data.leaf1_dict["tenant_v6_ip"][1], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
        
        def leaf2():
            dut = data.dut4
            ip.create_static_route(dut, data.leaf2_dict["tenant_v4_ip"][0], data.st_ip_1[1], vrf=data.vrf1)
            ip.create_static_route(dut, data.leaf2_dict["tenant_v4_ip"][1], data.st_ip_1[1], vrf=data.vrf1)
            ip.create_static_route(dut, data.leaf2_dict["tenant_v6_ip"][0], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
            ip.create_static_route(dut, data.leaf2_dict["tenant_v6_ip"][1], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
    
    else:
        def leaf1():
            dut = data.dut3
            ip.delete_static_route(dut, data.leaf1_dict["tenant_v4_ip"][0], data.st_ip_1[1], vrf=data.vrf1)
            ip.delete_static_route(dut, data.leaf1_dict["tenant_v4_ip"][1], data.st_ip_1[1], vrf=data.vrf1)
            ip.delete_static_route(dut, data.leaf1_dict["tenant_v6_ip"][0], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
            ip.delete_static_route(dut, data.leaf1_dict["tenant_v6_ip"][1], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
        
        def leaf2():
            dut = data.dut4
            ip.delete_static_route(dut, data.leaf2_dict["tenant_v4_ip"][0], data.st_ip_1[1], vrf=data.vrf1)
            ip.delete_static_route(dut, data.leaf2_dict["tenant_v4_ip"][1], data.st_ip_1[1], vrf=data.vrf1)
            ip.delete_static_route(dut, data.leaf2_dict["tenant_v6_ip"][0], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
            ip.delete_static_route(dut, data.leaf2_dict["tenant_v6_ip"][1], data.st_ip6_1[1], vrf=data.vrf1, family='ipv6')
    
    [res, exceptions] = st.exec_all([[leaf1], [leaf2]])
    return res

def verify_ecmp_routes():
    st.log("Within verify_ecmp_routes...")
    def verify_ecmp_routes_leaf1():
        st.log("Within verify_ecmp_routes_leaf1...")
        dut = data.dut3
        res1=ip.verify_multiple_routes(dut, ip_address=[data.st_ip_1[1]]*2, nexthop=data.leaf1_dict["tenant_v4_ip"][:2], vrf_name=data.vrf1)
        res2=ip.verify_multiple_routes(dut, ip_address=[data.st_ip6_1[1]]*2, nexthop=data.leaf1_dict["tenant_v6_ip"][:2], family='ipv6', vrf_name=data.vrf1)
        out1=ip.show_ip_route(dut, summary_routes='summary', vrf_name=data.vrf1)
        res3=True if (out1[0]['fib_static'] == '1') else False
        out2=ip.show_ip_route(dut, summary_routes='summary', family='ipv6', vrf_name=data.vrf1)
        res4=True if (out2[0]['fib_static'] == '1') else False
        res = list(set([res1, res2, res3, res4]))
        st.log("verify_config_base_leaf1: res1={}, res2={}, res3={}, res4={}.".format(res1, res2, res3, res4))
        return res[0] if len(res)==1 else False
    
    def verify_ecmp_routes_leaf2():
        st.log("Within verify_ecmp_routes_leaf2...")
        dut = data.dut4
        res1=ip.verify_multiple_routes(dut, ip_address=[data.st_ip_1[1]]*2, nexthop=data.leaf2_dict["tenant_v4_ip"][:2], vrf_name=data.vrf1)
        res2=ip.verify_multiple_routes(dut, ip_address=[data.st_ip6_1[1]]*2, nexthop=data.leaf2_dict["tenant_v6_ip"][:2], family='ipv6', vrf_name=data.vrf1)
        out1=ip.show_ip_route(dut, summary_routes='summary', vrf_name=data.vrf1)
        res3=True if (out1[0]['fib_static'] == '1') else False
        out2=ip.show_ip_route(dut, summary_routes='summary', family='ipv6', vrf_name=data.vrf1)
        res4=True if (out2[0]['fib_static'] == '1') else False
        res = list(set([res1, res2, res3, res4]))
        st.log("verify_config_base_leaf2: res1={}, res2={}, res3={}, res4={}.".format(res1, res2, res3, res4))
        return res[0] if len(res)==1 else False
    
    def verify_ecmp_routes_leaf3():
        st.log("Within verify_ecmp_routes_leaf2...")
        dut = data.dut5
        res1=ip.verify_multiple_routes(dut, ip_address=[data.st_ip_1[1]]*2, nexthop=data.loopback2_ip_list[2:4], vrf_name=data.vrf1)
        res2=ip.verify_multiple_routes(dut, ip_address=[data.st_ip6_1[1]]*2, nexthop=map(lambda x: '::ffff:'+x,data.loopback2_ip_list[2:4]), family='ipv6', vrf_name=data.vrf1)
        res3=ip.verify_multiple_routes(dut, ip_address=map(lambda x: x+'/'+data.mask32,data.loopback2_ip_list[2:4]*2), interface=[data.po_s1l3]*2+[data.po_s2l3]*2)
        res = list(set([res1, res2, res3]))
        st.log("verify_config_base_leaf3: res1={}, res2={}, res3={}.".format(res1, res2, res3))
        return res[0] if len(res)==1 else False
    
    [res, exceptions] = utils.exec_all(True, [[verify_ecmp_routes_leaf1], [verify_ecmp_routes_leaf2], [verify_ecmp_routes_leaf3]])
    return False if False in set(res) else True

def verify_bgp():
    ###########################################################
    st.log("BGP verify: Verify BGP sessions are up on duts")
    ############################################################
    def spine1():
        dut = data.dut1
        cnt = 4
        nbrs = [data.po_s1l1,data.po_s1l2,data.po_s1l3]
        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established']*cnt, delay = 4, retry_count = 20)
        return result
    def spine2():
        dut = data.dut2
        cnt = 4
        nbrs = [data.po_s2l1,data.po_s2l2,data.po_s2l3]
        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf1():
        dut = data.dut3
        cnt = 2
        nbrs = [data.po_s1l1,data.po_s2l1]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf2():
        dut = data.dut4
        cnt = 2
        nbrs = [data.po_s1l2,data.po_s2l2]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    def leaf3():
        dut = data.dut5
        cnt = 2
        nbrs = [data.po_s1l3,data.po_s2l3]

        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established'] * cnt, delay = 4, retry_count = 20)
        return result
    [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2],[leaf3]])

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
        local_loop_ip = data.dut3_loopback_ip[1]
        remote_loop_ip_lst = [data.dut4_loopback_ip[1],data.dut5_loopback_ip[1]]
        cnt = 2
        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf2():
        dut = data.dut4
        local_loop_ip = data.dut4_loopback_ip[1]
        remote_loop_ip_lst = [data.dut3_loopback_ip[1],data.dut5_loopback_ip[1]]
        cnt = 2

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf3():
        dut = data.dut5
        local_loop_ip = data.dut5_loopback_ip[1]
        remote_loop_ip_lst = [data.dut3_loopback_ip[1],data.dut4_loopback_ip[1]]
        cnt = 2

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    [res, exceptions] = st.exec_all( [[leaf1], [leaf2], [leaf3]])

    if False in set(res):
        st.error("Vxlan tunnel did not come up between lvtep and dut3")
        return False
    return True
