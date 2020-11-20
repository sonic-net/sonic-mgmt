
from evpn_pbr_vars import data

from spytest import st,utils,tgapi

import apis.switching.portchannel as pc
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
import apis.routing.evpn as evpn
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
import apis.routing.vrf as vrf_api
import apis.system.basic as basic_api
import apis.routing.sag as sag
import apis.qos.acl as acl_api
import apis.routing.arp as arp
import apis.switching.mac as mac_api
import apis.qos.acl_dscp as acl_dscp_api
from spytest.utils import filter_and_select
import utilities.utils as utils_obj
from utilities import parallel

def evpn_pbr_base_config():
    ###################################################
    st.banner(" Begin base Configuration for PBR Over VxLAN")
    ###################################################
    config_ip()
    config_loopback()
    config_bgp()
    st.wait(4)
    result = verify_bgp()
    if not result:
        st.error('BGP neighbor is not up between duts')
        #config_bgp(config='no')
        #config_loopback(config='no')
        #config_ip(config='no')
        return False
    config_leafInterface()
    result = verify_vxlan()
    if not result:
        st.error('VxLAN tunnel is not up between the leaf nodes')
        #config_leafInterface(config='no')
        #config_bgp(config='no')
        #config_loopback(config='no')
        #config_ip(config='no')
        return False

    config_leaf2_client()
    tenant_vni_config()

    st.exec_all([[create_stream], [pbr_configs]], first_on_main=True)
    result = verify_base_policy()
    if not result:
        st.error("Failed to validate PBR Configuration on all the leaf nodes")
        return False

    ###################################################
    st.banner("BASE Config End ")
    ###################################################
    return True

def pbr_configs():
    access_list_base()
    classifier_config_base()
    policy_config_base()

def evpn_pbr_base_unconfig():
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
        #api_name = ip_api.config_ip_addr_interface
        action = 'enable'
    else:
        #api_name = ip_api.delete_ip_interface
        action = 'disable'

    st.log("Enable IPv6 over portchannel interfaces between Leaf and Spine")

    def spine1():
        dut = data.dut1
        po_list = [data.po_s1l1, data.po_s1l2, data.po_s1l3, data.po_s1l4]
        po_members = [[data.d1d3_ports[0],data.d1d3_ports[1]],[data.d1d4_ports[0],data.d1d4_ports[1]],\
                [data.d1d5_ports[0],data.d1d5_ports[1]],[data.d1d6_ports[0],data.d1d6_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)

    def spine2():
        dut = data.dut2
        po_list = [data.po_s2l1, data.po_s2l2, data.po_s2l3, data.po_s2l4]
        po_members = [[data.d2d3_ports[0],data.d2d3_ports[1]],[data.d2d4_ports[0],data.d2d4_ports[1]],\
                [data.d2d5_ports[0],data.d2d5_ports[1]],[data.d2d6_ports[0],data.d2d6_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
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
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
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
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
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
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)

    def leaf4():
        dut = data.dut6
        po_list = [data.po_s1l4, data.po_s2l4]
        po_members = [[data.d6d1_ports[0],data.d6d1_ports[1]],[data.d6d2_ports[0],data.d6d2_ports[1]]]
        if config == "yes":
            for po, mems in zip(po_list, po_members):
                pc.create_portchannel(dut, po)
                pc.add_portchannel_member(dut, po, mems)
        ip_api.config_interface_ip6_link_local(dut, po_list, action=action)
        if config != "yes":
            for po, mems in zip(po_list, po_members):
                pc.delete_portchannel_member(dut, po, mems)
                pc.delete_portchannel(dut, po)

    # Enable IPv6 between Spine and Leaf portchannels
    [res, exceptions] =  st.exec_all([[spine1],[spine2],[leaf1],[leaf2],[leaf3],[leaf4]])

def config_leaf2_client(config='yes'):
    def leaf2():
        dut = data.dut4
        port_list = [data.d4d7_ports[0],data.d4d7_ports[1]]
        if config == "yes":
            pc.create_portchannel(dut, data.po_leaf2)
            pc.add_portchannel_member(dut,data.po_leaf2, port_list)
            config_vlan_and_member(dut,data.client_dict["tenant_vlan_list"],data.po_leaf2,config = 'add')

        if config != "yes":
            #config_vlan_and_member(dut,data.client_dict["tenant_vlan_list"],[data.po_leaf2]*len(data.client_dict["tenant_vlan_list"]),config = 'no')
            pc.delete_portchannel_member(dut,data.po_leaf2, port_list)
            pc.delete_portchannel(dut, data.po_leaf2)

    def client():
        dut = data.dut7
        port_list = [data.d7d4_ports[0],data.d7d4_ports[1]]
        if config == "yes":
            pc.create_portchannel(dut, data.po_leaf2)
            pc.add_portchannel_member(dut,data.po_leaf2, port_list)
            config_vlan_and_member(dut,data.client_dict["tenant_vlan_list"],data.po_leaf2,config = 'add')
        if config != "yes":
            #config_vlan_and_member(dut,client_dict["tenant_vlan_list"],[po_leaf2]*len(client_dict["tenant_vlan_list"]),config = 'no')
            pc.delete_portchannel_member(dut,data.po_leaf2, port_list)
            pc.delete_portchannel(dut, data.po_leaf2)

    [res, exceptions] =  st.exec_all([[leaf2],[client]])


def config_vlan_and_member(dut,vlan_list,port,config='add'):
    if len(vlan_list) > 1:
        vlan_range = vlan_list[0] + ' ' + vlan_list[-1]
    else:
        vlan = vlan_list[0]
    if config == 'add':
        if len(vlan_list) > 1 :
            vlan_api.config_vlan_range(dut,vlan_range)
            vlan_api.config_vlan_range_members(dut,vlan_range,port)
        else:
            vlan_api.create_vlan(dut, vlan)
            vlan_api.add_vlan_member(dut, vlan, port, True)

    else:
        if len(vlan_list) > 1 :
            vlan_api.config_vlan_range_members(dut,vlan_range,port,config='del')
            vlan_api.config_vlan_range(dut,vlan_range,config='del')

        else:
            vlan_api.delete_vlan_member(dut, vlan, port, True)
            vlan_api.delete_vlan(dut, vlan)



def config_loopback(config='yes'):

    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip_api.config_ip_addr_interface
        config_str = "Delete"

    st.log("%s Loopback configs between Leaf and Spine"%(config_str))
    if config == 'yes' :
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback, [{'loopback_name': data.loopback1}] * 6)
        utils.exec_all(True, [[api_name, dut, data.loopback1, ip, data.mask32]
                              for dut, ip in zip(data.rtr_list, data.loopback1_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback, [{'loopback_name': data.loopback2}] * 6)
        utils.exec_all(True, [[api_name, dut, data.loopback2, ip, data.mask32]
                              for dut, ip in zip(data.rtr_list, data.loopback2_ip_list)])

    else:
        utils.exec_all(True, [[api_name, dut, data.loopback2, ip, data.mask32,'ipv4','remove']
                              for dut, ip in zip(data.rtr_list, data.loopback2_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback,
                               [{'loopback_name': data.loopback2,'config':'no'}] * 6)
        utils.exec_all(True, [[api_name, dut, data.loopback1, ip, data.mask32,'ipv4','remove']
                              for dut, ip in zip(data.rtr_list, data.loopback1_ip_list)])
        parallel.exec_parallel(True, data.rtr_list, ip_api.configure_loopback,
                               [{'loopback_name': data.loopback1,'config':'no'}] * 6)

def config_bgp(config='yes'):
    st.log("BGP and evpn configs between Leaf and Spine")
    if config == 'yes':
        def spine1():
            dut = data.dut1
            dut_as = data.dut1_AS
            nbr_list = [data.po_s1l1,data.po_s1l2,data.po_s1l3,data.po_s1l4]
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
            nbr_list = [data.po_s2l1,data.po_s2l2, data.po_s2l3, data.po_s2l4]
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
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        def leaf4():
            dut = data.dut6
            dut_as = data.dut6_AS
            nbr_list = [data.po_s1l4,data.po_s2l4]
            for nbr in nbr_list:
                bgp_api.config_bgp(dut=dut, local_as=dut_as, remote_as='external', interface=nbr,
                                   config_type_list = ['bfd'],config = 'yes')
                bgp_api.config_bgp(dut=dut, local_as=dut_as,config='yes', config_type_list=["neighbor"], remote_as='external', neighbor=nbr)
                evpn.config_bgp_evpn(dut=dut, neighbor=nbr, config='yes',
                                     config_type_list=["activate"], local_as=dut_as, remote_as='external')
            evpn.config_bgp_evpn(dut=dut, config='yes', config_type_list=["advertise_all_vni"], local_as=dut_as)

        [res, exceptions] = st.exec_all( [[spine1], [spine2], [leaf1], [leaf2], [leaf3], [leaf4]])

    else:
        ##########################################################################
        st.banner("BGP-Deconfig: Delete BGP routers globally from all DUTs")
        ##########################################################################

        dict1 = {'local_as':data.dut3_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':data.vrf1}
        dict2 = {'local_as':data.dut4_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':data.vrf1}
        dict3 = {'local_as':data.dut5_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':data.vrf1}
        dict4 = {'local_as':data.dut6_AS,'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':data.vrf1}

        parallel.exec_parallel(True, data.leaf_list, bgp_api.config_bgp, [dict1,dict2,dict3,dict4])
        dict1 = []
        for dut_as in [data.dut1_AS,data.dut2_AS,data.dut3_AS,data.dut4_AS,data.dut5_AS,data.dut6_AS]:
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
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf1_dict['tenant_vlan_list']
            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=data.vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=data.vrf1,intf_name=data.vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip[0], data.mask_24)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip6[0], data.mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name)
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf1_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
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
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf2_dict['tenant_vlan_list']
            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=data.vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=data.vrf1,intf_name=data.vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip[1], data.mask_24)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip6[1], data.mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf2_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"],
                               redistribute='connected', addr_family='ipv6')
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
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf3_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf3_dict['tenant_vlan_list']
            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=data.vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=data.vrf1,intf_name=data.vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip[2], data.mask_24)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip6[2], data.mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"],  redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"],  local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"],  local_as=local_as, advertise_ipv6='unicast')
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf3_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                #vlan_api.add_vlan_member(dut, vlan , data.d5t1_ports[0], True)

        def leaf4():

            dut = data.dut6
            vtep_name = data.vtep_names[3]
            nvo_name = data.nvo_names[3]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut6_loopback_ip[1]
            local_as = data.dut6_AS
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf4_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf4_dict['tenant_vlan_list']
            vlan_api.create_vlan(dut, vlan_list)
            vrf_api.config_vrf(dut,vrf_name=data.vrf1)
            vrf_api.bind_vrf_interface(dut,vrf_name=data.vrf1,intf_name=data.vlan_vrf1)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip[3], data.mask_24)
            ip_api.config_ip_addr_interface(dut, data.vlan_vrf1, data.vrf1_ip6[3], data.mask_v6, family='ipv6')

            evpn.create_overlay_intf(dut, vtep_name, ovrly_int)
            evpn.create_evpn_instance(dut, nvo_name, vtep_name)
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name)

            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected')
            bgp_api.config_bgp(dut, local_as=local_as, vrf_name=data.vrf1, config='yes', config_type_list=["redist"], redistribute='connected', addr_family='ipv6')
            bgp_api.config_bgp(dut, local_as=local_as, config='yes', config_type_list=["redist"], redistribute='connected')

            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv4_vrf"], local_as=local_as, advertise_ipv4='unicast')
            evpn.config_bgp_evpn(dut, vrf_name=data.vrf1, config='yes', config_type_list=["advertise_ipv6_vrf"], local_as=local_as, advertise_ipv6='unicast')
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf4_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                #vlan_api.add_vlan_member(dut,vlan, data.d6t1_ports[0], True)
    else:
        def leaf1():
            dut = data.dut3
            vtep_name = data.vtep_names[0]
            nvo_name = data.nvo_names[0]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut3_loopback_ip[1]
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf1_dict['tenant_vlan_list']
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf1_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config = 'no')

            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name, config = 'no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config = 'no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config = 'no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config = 'no')
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip[0], data.mask_24)
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip6[0], data.mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=data.vlan_vrf1,config = 'no')
            vlan_api.delete_vlan(dut, vlan_list)

        def leaf2():
            dut = data.dut4
            vtep_name = data.vtep_names[1]
            nvo_name = data.nvo_names[1]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut4_loopback_ip[1]
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + client_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf2_dict['tenant_vlan_list']
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf2_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config = 'no')

            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name, config = 'no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config = 'no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config = 'no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config = 'no')
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip[1], data.mask_24)
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip6[1], data.mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=data.vlan_vrf1,config = 'no')
            vlan_api.delete_vlan(dut, vlan_list)

        def leaf3():
            dut = data.dut5
            vtep_name = data.vtep_names[2]
            nvo_name = data.nvo_names[2]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut5_loopback_ip[1]
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf3_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf3_dict['tenant_vlan_list']
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf3_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                vlan_api.delete_vlan_member(dut,vlan, data.d5t1_ports[0],True)

            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name, config='no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config='no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config='no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config='no')
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip[2], data.mask_24)
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip6[2], data.mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=data.vlan_vrf1, config='no')
            vlan_api.delete_vlan(dut,vlan_list)

        def leaf4():
            dut = data.dut6
            vtep_name = data.vtep_names[3]
            nvo_name = data.nvo_names[3]
            vlan_vni = data.vni_vlan[0]
            ovrly_int = data.dut6_loopback_ip[1]
            #vlan_list = [vlan_vni] + client_dict["tenant_l2_vlan_list"] + leaf4_dict["tenant_l3_vlan_list"]
            vlan_list = [vlan_vni] + data.leaf4_dict['tenant_vlan_list']
            #for vlan in client_dict["tenant_l2_vlan_list"]:
            for vlan in data.leaf4_dict['tenant_vlan_list']:
                evpn.map_vlan_vni(dut, vtep_name, vlan, vlan, config='no')
                vlan_api.delete_vlan_member(dut,vlan, data.d6t1_ports[0],True)

            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan_vni, vtep_name=vtep_name, config='no')
            evpn.map_vlan_vni(dut, vtep_name, vlan_vni, vlan_vni, config='no')
            evpn.create_evpn_instance(dut, nvo_name, vtep_name, config='no')
            evpn.create_overlay_intf(dut, vtep_name, ovrly_int, config='no')
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip[3], data.mask_24)
            ip_api.delete_ip_interface(dut, data.vlan_vrf1, data.vrf1_ip6[3], data.mask_v6, family='ipv6')
            vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=data.vlan_vrf1, config='no')
            vlan_api.delete_vlan(dut, vlan_list)
    st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])

stream_dict = {}
tg_dict = {}
han_dict = {}
def create_glob_vars():
    global vars, tg, d3_tg_ph1, d3_tg_ph2, d4_tg_ph1, d4_tg_ph2, d5_tg_ph1, d5_tg_ph2, d6_tg_ph1, d6_tg_ph2
    global d4_tg_port1, d5_tg_port1,d6_tg_port1,d7_tg_port1, d7_tg_ph1, d7_tg_ph2,d5_tg_port2,d6_tg_port2,d7_tg_port2,d3_tg_port1,d3_tg_port2
    vars = st.ensure_min_topology("D1D3:3","D2D4:3","D3D4:3","D1D5:3","D1D6:3","D2D5:3","D2D6:3","D3D7:4","D4D7:4","D3CHIP=TD3","D4CHIP=TD3","D5CHIP=TD3","D6CHIP=TD3")

    tg = tgapi.get_chassis(vars)
    d3_tg_ph1, d3_tg_ph2 = tg.get_port_handle(vars.T1D3P1), tg.get_port_handle(vars.T1D3P2)
    d4_tg_ph1, d4_tg_ph2 = tg.get_port_handle(vars.T1D4P1), tg.get_port_handle(vars.T1D4P2)
    d5_tg_ph1, d5_tg_ph2 = tg.get_port_handle(vars.T1D5P1), tg.get_port_handle(vars.T1D5P2)
    d6_tg_ph1, d6_tg_ph2 = tg.get_port_handle(vars.T1D6P1), tg.get_port_handle(vars.T1D6P2)
    d7_tg_ph1, d7_tg_ph2 = tg.get_port_handle(vars.T1D7P1), tg.get_port_handle(vars.T1D7P2)

    d4_tg_port1,d5_tg_port1,d6_tg_port1,d7_tg_port1,d3_tg_port1,d3_tg_port2 = vars.T1D4P1, vars.T1D5P1, vars.T1D6P1, vars.T1D7P1,vars.T1D3P1,vars.T1D3P2
    d5_tg_port2,d6_tg_port2,d7_tg_port2 = vars.T1D5P2, vars.T1D6P2, vars.T1D7P2

    tg_dict['tg'] = tg
    tg_dict['d3_tg_ph1'],tg_dict['d3_tg_ph2'] = tg.get_port_handle(vars.T1D3P1),tg.get_port_handle(vars.T1D3P2)
    tg_dict['d4_tg_ph1'],tg_dict['d4_tg_ph2'] = tg.get_port_handle(vars.T1D4P1),tg.get_port_handle(vars.T1D4P2)
    tg_dict['d5_tg_ph1'],tg_dict['d5_tg_ph2'] = tg.get_port_handle(vars.T1D5P1),tg.get_port_handle(vars.T1D5P2)
    tg_dict['d6_tg_ph1'],tg_dict['d6_tg_ph2'] = tg.get_port_handle(vars.T1D6P1),tg.get_port_handle(vars.T1D6P2)
    tg_dict['d5_tg_port1'],tg_dict['d6_tg_port1'] = vars.T1D5P1, vars.T1D6P1
    tg_dict['d3_tg_port1'],tg_dict['d4_tg_port1'] = vars.T1D3P1, vars.T1D4P1
    tg_dict['d3_tg_port2'] = vars.T1D3P2
    tg_dict['tgen_rate_pps'] = '1000'
    tg_dict['frame_size'] = '1000'
    tg_dict['dut_6_mac_pattern'] = '00:02:66:00:00:'
    tg_dict['d5_tg_local_as'] = '50'
    tg_dict['d6_tg_local_as'] = '60'
    tg_dict['num_routes_1'] = '100'
    tg_dict['prefix_1'] = '100.1.1.0'
    tg_dict['prefix_2'] = '200.1.1.0'


def tenant_vni_config(config = 'yes'):
    ################################################
    st.log("Configure L3 VNI Clients on each leaf node.")
    ################################################
    def sag_config(dut,intf,sag_ip_gw,sag_ip6_gw,config="add"):
        if config == "add":
            sag_mode = "enable"
        else:
            sag_mode = "disable"

        sag.config_sag_ip(dut, interface=intf, gateway=sag_ip_gw, mask=data.mask_24,config = config)
        sag.config_sag_ip(dut, interface=intf, gateway=sag_ip6_gw, mask=data.mask_v6,config = config)
        sag.config_sag_mac(dut, mac=data.sag_mac,config = config)
        sag.config_sag_mac(dut, config=sag_mode)
        sag.config_sag_mac(dut, ip_type='ipv6', config=sag_mode)
    if config == 'yes' :

        def leaf1():
            dut = data.dut3
            config_vlan_and_member(dut,data.leaf1_dict["tenant_vlan_list"],data.d3t1_ports[0],config = 'add')

            for vlan,vlan_int,ip,ip6 in zip(data.leaf1_dict["tenant_vlan_list"],data.leaf1_dict["tenant_vlan_int"],
                                            data.leaf1_dict["tenant_ip_list"],data.leaf1_dict["tenant_ipv6_list"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                #evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                #evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)
            data.dut3_gw_mac = basic_api.get_ifconfig(data.dut3, data.leaf1_dict["tenant_vlan_int"][0])[0]['mac']
        def leaf2():
            dut = data.dut4
            for vlan,vlan_int,ip,ip6 in zip(data.leaf2_dict["tenant_vlan_list"],data.leaf2_dict["tenant_vlan_int"],
                                            data.leaf2_dict["tenant_ip_list"],data.leaf2_dict["tenant_ipv6_list"]):
                #vlan_api.add_vlan_member(dut,vlan,[data.d4t1_ports[0]],True)
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int)
                if vlan == data.leaf2_dict["tenant_vlan_list"][2]:
                    sag_config(dut, vlan_int, ip, ip6, "add")
                else:
                    ip_api.config_ip_addr_interface(dut, vlan_int, ip, data.mask_24)
                    ip_api.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')

        def leaf3():
            dut = data.dut5
            config_vlan_and_member(dut,data.leaf3_dict["tenant_vlan_list"],data.d5t1_ports[0],config = 'add')

            for vlan,vlan_int,ip,ip6 in zip(data.leaf3_dict["tenant_vlan_list"],data.leaf3_dict["tenant_vlan_int"],
                                            data.leaf3_dict["tenant_ip_list"],data.leaf3_dict["tenant_ipv6_list"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                #evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                #evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)

            # SAG Config - Same vlan interface as Leaf2
            vtep_name = data.vtep_names[2]
            vlan = data.leaf2_dict["tenant_vlan_list"][2]
            vlan_int = data.leaf2_dict["tenant_vlan_int"][2]
            ip = data.leaf2_dict["tenant_ip_list"][2]
            ip6 = data.leaf2_dict["tenant_ipv6_list"][2]
            config_vlan_and_member(dut,[vlan],data.d5t1_ports[0],config = 'add')

            evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            evpn.map_vrf_vni(dut, vrf_name=data.vrf1, vni=vlan, vtep_name=vtep_name)
            sag_config(dut, vlan_int, ip, ip6, "add")


        def leaf4():
            dut = data.dut6
            vtep_name = data.vtep_names[2]
            config_vlan_and_member(dut,data.leaf4_dict["tenant_vlan_list"],data.d6t1_ports[0],config = 'add')

            for vlan,vlan_int,ip,ip6 in zip(data.leaf4_dict["tenant_vlan_list"],data.leaf4_dict["tenant_vlan_int"],
                                            data.leaf4_dict["tenant_ip_list"],data.leaf4_dict["tenant_ipv6_list"]):
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                #evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
                #evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)
                arp.add_static_arp(dut, data.leaf4_dict["tenant_v4_ip"], data.tg_dest_mac_list[0], interface=data.leaf4_dict["tenant_vlan_int"][0])
                mac_api.config_mac(dut,mac=data.tg_dest_mac_list[0],vlan=data.leaf4_dict["tenant_vlan_list"][0],intf=data.d6t1_ports[0])
                arp.config_static_ndp(dut,data.leaf4_dict["tenant_v6_ip"][0], data.tg_dest_mac_list[1],interface=data.leaf4_dict["tenant_vlan_int"][0])
                arp.config_static_ndp(dut,data.leaf4_dict["tenant_v6_ip"][1], data.tg_dest_mac_list[2],interface=data.leaf4_dict["tenant_vlan_int"][2])
                mac_api.config_mac(dut,data.tg_dest_mac_list[1],data.leaf4_dict["tenant_vlan_list"][0],data.d6t1_ports[0])
                mac_api.config_mac(dut,data.tg_dest_mac_list[2],data.leaf4_dict["tenant_vlan_list"][2],data.d6t1_ports[0])

        def client():
            dut = data.dut7
            config_vlan_and_member(dut,data.client_dict["tenant_vlan_list"],data.po_leaf2,config = 'add')
            config_vlan_and_member(dut,data.client_dict["tenant_vlan_list"],data.d7t1_ports[0],config = 'add')

            for vlan,vlan_int,ip,ip6 in zip(data.client_dict["tenant_vlan_list"],data.client_dict["tenant_vlan_int"],
                                            data.client_dict["tenant_ip_list"],data.client_dict["tenant_ipv6_list"]):
                ip_api.config_ip_addr_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.config_ip_addr_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
            # Static route for Leaf1 <---> Leaf3
            ip_api.create_static_route(dut, next_hop= data.leaf2_dict["tenant_ip_list"][0], static_ip= data.route_list[0] + '/' + data.mask_24)
            ip_api.create_static_route(dut, next_hop= data.leaf2_dict["tenant_ip_list"][1], static_ip= data.route_list[1] + '/' + data.mask_24)
            ip_api.create_static_route(dut, next_hop= data.leaf2_dict["tenant_ipv6_list"][0], static_ip= data.route_list_6[0] + '/' + data.mask_v6, family = 'ipv6')
            ip_api.create_static_route(dut, next_hop= data.leaf2_dict["tenant_ipv6_list"][1], static_ip= data.route_list_6[1] + '/' + data.mask_v6, family = 'ipv6')
            ip_api.create_static_route(dut, next_hop= data.leaf2_dict["tenant_ipv6_list"][1], static_ip= data.route_list_6[2] + '/' + data.mask_v6, family = 'ipv6')
    else:
        def leaf1():
            dut = data.dut3
            for vlan, vlan_int, ip, ip6 in zip(data.leaf1_dict["tenant_vlan_list"], data.leaf1_dict["tenant_vlan_int"],
                                               data.leaf1_dict["tenant_ip_list"], data.leaf1_dict["tenant_ipv6_list"]):
                ip_api.delete_ip_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int,config='no')

            vlan_api.delete_vlan_member(dut, data.leaf1_dict["tenant_vlan_list"], data.d3t1_ports[0], True)


        def leaf2():
            dut = data.dut4
            for vlan, vlan_int, ip, ip6 in zip(data.leaf2_dict["tenant_vlan_list"], data.leaf2_dict["tenant_vlan_int"],
                                               data.leaf2_dict["tenant_ip_list"], data.leaf2_dict["tenant_ipv6_list"]):
                if vlan == data.leaf2_dict["tenant_vlan_list"][2]:
                    sag_config(dut, vlan_int, ip, ip6, "remove")
                else:
                    ip_api.delete_ip_interface(dut, vlan_int, ip, data.mask_24)
                    ip_api.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int,config='no')


        def leaf3():
            dut = data.dut5
            vtep_name = data.vtep_names[1]

            # SAG Config - Same vlan interface as Leaf2
            vtep_name = data.vtep_names[2]
            vlan = data.leaf2_dict["tenant_vlan_list"][2]
            vlan_int = data.leaf2_dict["tenant_vlan_int"][2]
            ip = data.leaf2_dict["tenant_ip_list"][2]
            ip6 = data.leaf2_dict["tenant_ipv6_list"][2]
            sag_config(dut, vlan_int, ip, ip6, "remove")


            #evpn.map_vlan_vni(dut, vtep_name, vlan, vlan)
            #evpn.map_vrf_vni(dut, vrf_name=vrf1, vni=vlan, vtep_name=vtep_name)
            for vlan, vlan_int, ip, ip6 in zip(data.leaf3_dict["tenant_vlan_list"], data.leaf3_dict["tenant_vlan_int"],
                                               data.leaf3_dict["tenant_ip_list"], data.leaf3_dict["tenant_ipv6_list"]):
                ip_api.delete_ip_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int, config='no')
            config_vlan_and_member(dut, data.leaf3_dict["tenant_vlan_list"], data.d5t1_ports[0], config='del')

            #config_vlan_and_member(dut, [vlan], [data.d5t1_ports[0]], config='no')

        def leaf4():
            dut = data.dut6
            vtep_name = data.vtep_names[2]
            for vlan, vlan_int, ip, ip6 in zip(data.leaf4_dict["tenant_vlan_list"], data.leaf4_dict["tenant_vlan_int"],
                                               data.leaf4_dict["tenant_ip_list"], data.leaf4_dict["tenant_ipv6_list"]):


                arp.add_static_arp(dut, data.leaf4_dict["tenant_v4_ip"], data.tg_dest_mac_list[0],
                                   interface=data.leaf4_dict["tenant_vlan_int"][0])
                mac_api.config_mac(dut, mac=data.tg_dest_mac_list[0], vlan=data.leaf4_dict["tenant_vlan_list"][0],
                                   intf=data.d6t1_ports[0])
                arp.config_static_ndp(dut, data.leaf4_dict["tenant_v6_ip"][0], data.tg_dest_mac_list[1],
                                      interface=data.leaf4_dict["tenant_vlan_int"][0], config='no')
                arp.config_static_ndp(dut, data.leaf4_dict["tenant_v6_ip"][1], data.tg_dest_mac_list[2],
                                      interface=data.leaf4_dict["tenant_vlan_int"][2], config='no')
                mac_api.config_mac(dut, data.tg_dest_mac_list[1], data.leaf4_dict["tenant_vlan_list"][0], data.d6t1_ports[0])
                mac_api.config_mac(dut, data.tg_dest_mac_list[2], data.leaf4_dict["tenant_vlan_list"][2], data.d6t1_ports[0])
                ip_api.delete_ip_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
                vrf_api.bind_vrf_interface(dut, vrf_name=data.vrf1, intf_name=vlan_int, config='no')
            config_vlan_and_member(dut, data.leaf4_dict["tenant_vlan_list"], data.d6t1_ports[0], config='del')

        def client():
            dut = data.dut7
            ip_api.delete_static_route(dut, next_hop=data.leaf2_dict["tenant_ip_list"][0],
                                       static_ip=data.route_list[0] + '/' + data.mask_24)
            ip_api.delete_static_route(dut, next_hop=data.leaf2_dict["tenant_ip_list"][1],
                                       static_ip=data.route_list[1] + '/' + data.mask_24)
            ip_api.delete_static_route(dut, next_hop=data.leaf2_dict["tenant_ipv6_list"][0],
                                       static_ip=data.route_list_6[0] + '/' + data.mask_v6, family='ipv6')
            ip_api.delete_static_route(dut, next_hop=data.leaf2_dict["tenant_ipv6_list"][1],
                                       static_ip=data.route_list_6[1] + '/' + data.mask_v6, family='ipv6')
            ip_api.delete_static_route(dut, next_hop=data.leaf2_dict["tenant_ipv6_list"][1],
                                       static_ip=data.route_list_6[2] + '/' + data.mask_v6, family='ipv6')

            for vlan, vlan_int, ip, ip6 in zip(data.client_dict["tenant_vlan_list"], data.client_dict["tenant_vlan_int"],
                                               data.client_dict["tenant_ip_list"], data.client_dict["tenant_ipv6_list"]):
                ip_api.delete_ip_interface(dut, vlan_int, ip, data.mask_24)
                ip_api.delete_ip_interface(dut, vlan_int, ip6, data.mask_v6, family='ipv6')
            vlan_api.delete_vlan_member(dut, data.client_dict["tenant_vlan_list"], data.d7t1_ports[0], True)

            config_vlan_and_member(dut, data.client_dict["tenant_vlan_list"], data.po_leaf2, config='del')

    [res, exceptions] = st.exec_all([[leaf1], [leaf2],[leaf3], [leaf4], [client]])
    return res


def create_stream():
    global tg, d7_tg_ph1, d3_tg_ph1, d6_tg_ph1,stream_dict
    # L3 VNI traffic streams
    # IPV4 UDP---------Leaf1 Vlan110--Leaf2--Leaf3-- Leaf4 Vlan410------- #
    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v4"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',l4_protocol='udp',
                                  ip_src_addr=data.leaf1_dict["tenant_v4_ip"][0], udp_dst_port='443',
                                  ip_dst_addr=data.leaf4_dict["tenant_v4_ip"], l3_protocol='ipv4', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=data.leaf1_dict["tenant_ip_list"][0])
    stream1 = stream['stream_id']
    st.log("Ipv4 UDP stream {} is created for Tgen port {}".format(stream1, vars.T1D3P1))

    # IPV4 TCP---------Leaf1 Vlan110--Leaf2--Leaf3-- Leaf4 Vlan410------- #
    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v4"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',l4_protocol='tcp',
                                  ip_src_addr=data.leaf1_dict["tenant_v4_ip"][0],
                                  ip_dst_addr=data.leaf4_dict["tenant_v4_ip"], l3_protocol='ipv4', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=data.leaf1_dict["tenant_ip_list"][0])
    stream2 = stream['stream_id']
    st.log("Ipv4 TCP stream {} is created for Tgen port {}".format(stream2, vars.T1D3P1))

    # IPV4 TCP---------Leaf1 Vlan110--Leaf3-- Leaf4 Vlan410------- #
    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v4"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  ip_src_addr=data.leaf1_dict["tenant_v4_ip"][1],
                                  ip_dst_addr=data.leaf4_dict["tenant_v4_ip"], l3_protocol='ipv4', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=data.leaf1_dict["tenant_ip_list"][0])
    stream3 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream3, vars.T1D3P1))

    # IPV4 TCP---------Leaf1 Vlan110-- Leaf4 Vlan410------- #
    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v4"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  ip_src_addr=data.leaf1_dict["tenant_v4_ip"][2],
                                  ip_dst_addr=data.leaf4_dict["tenant_v4_ip"], l3_protocol='ipv4', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=data.leaf1_dict["tenant_ip_list"][0])
    stream4 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream4, vars.T1D3P1))

    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v6"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',l4_protocol='udp',
                                  ipv6_src_addr=data.leaf1_dict["tenant_v6_ip"], udp_dst_port='443',
                                  ipv6_dst_addr=data.leaf4_dict["tenant_v6_ip"][0], l3_protocol='ipv6', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable", frame_size='128',
                                  mac_discovery_gw=data.leaf1_dict["tenant_ipv6_list"][0])
    stream5 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream5, vars.T1D3P1))

    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v6"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',l4_protocol='tcp',
                                  ipv6_src_addr=data.leaf1_dict["tenant_v6_ip"],
                                  ipv6_dst_addr=data.leaf4_dict["tenant_v6_ip"][0], l3_protocol='ipv6', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable", frame_size='128',
                                  mac_discovery_gw=data.leaf1_dict["tenant_ipv6_list"][0])
    stream6 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream6, vars.T1D3P1))

    # IPv6 traffic specific subnet Path - Leaf1--Leaf2--Leaf3--Leaf4
    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v6"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  ipv6_src_addr=data.leaf1_dict["tenant_v6_ip"],l4_protocol='udp', udp_dst_port='443',
                                  ipv6_dst_addr=data.leaf4_dict["tenant_v6_ip"][1], l3_protocol='ipv6', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable", frame_size='128',
                                  mac_discovery_gw=data.leaf1_dict["tenant_ipv6_list"][0])
    stream7 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream7, vars.T1D3P1))

    ## Add default route streams for IPv4 and IPv6 - PENDING ##
    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v4"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  ip_src_addr=data.leaf1_dict["tenant_v4_ip"][0],
                                  ip_dst_addr=data.leaf1_dict["tenant_v4_ip"][3], l3_protocol='ipv4', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable",
                                  mac_discovery_gw=data.leaf1_dict["tenant_ip_list"][0])
    stream8 = stream['stream_id']
    st.log("Ipv4 stream {} is created for Tgen port {}".format(stream8, vars.T1D3P1))

    stream = tg.tg_traffic_config(mac_src=data.leaf1_dict["tenant_mac_v6"],
                                  mac_dst=data.dut3_gw_mac, rate_pps=1000, mode='create', port_handle=d3_tg_ph1,
                                  l2_encap='ethernet_ii_vlan', transmit_mode='continuous',
                                  ipv6_src_addr=data.leaf1_dict["tenant_v6_ip"],
                                  ipv6_dst_addr=data.leaf1_dict["tenant_ipv6_list"][4], l3_protocol='ipv6', l3_length='512',
                                  vlan_id=data.leaf1_dict["tenant_vlan_list"][0], vlan="enable", frame_size='128',
                                  mac_discovery_gw=data.leaf1_dict["tenant_ipv6_list"][0])
    stream9 = stream['stream_id']
    st.log("Ipv6 stream {} is created for Tgen port {}".format(stream9, vars.T1D3P1))

    #####
    stream_dict["v4"]=[stream1,stream2]
    stream_dict["v4_diff"]=[stream3,stream4]
    stream_dict["difaultRoute"]=[stream8,stream9]
    stream_dict["v6"]=[stream5,stream6,stream7]
    stream_dict["all"]=[stream1,stream2,stream3,stream4,stream5,stream6,stream7]

    dut4_host_mac = basic_api.get_ifconfig(data.dut7, data.client_dict["tenant_vlan_int"][0])[0]['mac']

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config', intf_ip_addr=data.leaf2_dict["tenant_v4_ip"][2],
                                 gateway=data.leaf2_dict["tenant_ip_list"][2], vlan='1', vlan_id_step='0',
                                 vlan_id=data.leaf2_dict["tenant_vlan_list"][2], arp_send_req='1',
                                 gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr=dut4_host_mac)
    host1 = han["handle"]
    st.log("Ipv4 host {} is created for Tgen port {}".format(host1, vars.T1D5P1))

    han = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config',
                                 ipv6_intf_addr=data.leaf2_dict["tenant_v6_ip"][2], ipv6_prefix_length='96',
                                 ipv6_gateway=data.leaf2_dict["tenant_ipv6_list"][2],src_mac_addr=dut4_host_mac,
                                 arp_send_req='1', vlan='1', vlan_id=data.leaf2_dict["tenant_vlan_list"][2],
                                 vlan_id_step='0', count=1, ipv6_intf_addr_step='0::1', ipv6_gateway_step='0::0')
    host2 = han["handle"]
    st.log("Ipv6 host {} is created for Tgen port {}".format(host2, vars.T1D5P1))

    stream_dict["hosts"] = [host1,host2]


def verify_bgp():
    ###########################################################
    st.log("BGP verify: Verify BGP sessions are up on duts")
    ############################################################
    def spine1():
        dut = data.dut1
        cnt = 4
        nbrs = [data.po_s1l1,data.po_s1l2,data.po_s1l3,data.po_s1l4]
        result = utils_obj.retry_api(ip_bgp.check_bgp_session, dut, nbr_list=nbrs, state_list=['Established']*cnt, delay = 4, retry_count = 20)
        return result
    def spine2():
        dut = data.dut2
        cnt = 4
        nbrs = [data.po_s2l1,data.po_s2l2,data.po_s2l3,data.po_s2l4]
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
    def leaf4():
        dut = data.dut6
        cnt = 2
        nbrs = [data.po_s1l4,data.po_s2l4]
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
        local_loop_ip = data.dut3_loopback_ip[1]
        remote_loop_ip_lst = [data.dut4_loopback_ip[1],data.dut5_loopback_ip[1],data.dut6_loopback_ip[1]]
        cnt = 3
        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf2():
        dut = data.dut4
        local_loop_ip = data.dut4_loopback_ip[1]
        remote_loop_ip_lst = [data.dut3_loopback_ip[1],data.dut5_loopback_ip[1],data.dut6_loopback_ip[1]]
        cnt = 3

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf3():
        dut = data.dut5
        local_loop_ip = data.dut5_loopback_ip[1]
        remote_loop_ip_lst = [data.dut3_loopback_ip[1],data.dut4_loopback_ip[1],data.dut6_loopback_ip[1]]
        cnt = 3

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    def leaf4():
        dut = data.dut6
        local_loop_ip = data.dut6_loopback_ip[1]
        remote_loop_ip_lst = [data.dut3_loopback_ip[1],data.dut4_loopback_ip[1],data.dut5_loopback_ip[1]]
        cnt = 3

        result = evpn.verify_vxlan_tunnel_status(dut, local_loop_ip, remote_loop_ip_lst, ['oper_up'] * cnt)
        return result

    [res, exceptions] = st.exec_all( [[leaf1], [leaf2], [leaf3], [leaf4]])

    if False in set(res):
        st.error("Vxlan tunnel did not come up between lvtep and dut3")
        return False
    return True

def start_traffic(stream_han_list=[],port_han_list=[],action="run"):
    global tg,d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2,d3_tg_ph1
    tgen_portlst = [d3_tg_ph1,d7_tg_ph1, d5_tg_ph1 ,d6_tg_ph1, d7_tg_ph2, d5_tg_ph2 , d6_tg_ph2]

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
    global tg,stream_dict,d3_tg_port1,d6_tg_port1,d3_tg_port2

    if not tx_port:
        tx_port=d3_tg_port1
    if not rx_port:
        rx_port=d6_tg_port1

    traffic_data = {
            '1': {
                'tx_ports': [tx_port],
                'tx_obj': [tg],
                'exp_ratio': [tx_ratio],
                'rx_ports': [rx_port],
                'rx_obj': [tg],
            }
    }
    aggregate_result= tgapi.validate_tgen_traffic(traffic_details=traffic_data, mode=mode, comp_type=field,tolerance_factor=2)

    if aggregate_result:
        st.log('Traffic verification passed ')
        return True
    else:
        st.error('Traffic verification failed')
        return False



def access_list_base(config='yes'):
    if config == 'yes':
        ####################################################
        st.banner("Configure IPv4/IPv6 premit access-lists")
        ####################################################
        def leaf1():
            acl_api.create_acl_table(data.dut3, name=data.leaf1_leaf2_udp443tcp_acl, stage='INGRESS', type='ip', ports=[])
            acl_api.create_acl_table(data.dut3, name=data.leaf1_leaf2_udp443tcp_aclv6, stage='INGRESS', type='ipv6', ports=[])
            acl_api.create_acl_table(data.dut3, name=data.leaf1_leaf3_ipprefix20, stage='INGRESS', type='ip', ports=[])
            acl_api.create_acl_table(data.dut3, name=data.leaf1_leaf4, stage='INGRESS', type='ip', ports=[])
            acl_api.create_acl_rule(data.dut3,acl_type='ip',rule_name=data.leaf1_leaf2_udp443tcp_acl,rule_seq='10',packet_action='permit',table_name=data.leaf1_leaf2_udp443tcp_acl,src_ip='any', dst_ip='any',l4_protocol='udp',dst_port='443')
            acl_api.create_acl_rule(data.dut3,acl_type='ip',rule_name=data.leaf1_leaf2_udp443tcp_acl,rule_seq='20',packet_action='permit',table_name=data.leaf1_leaf2_udp443tcp_acl,src_ip='any', dst_ip='any',l4_protocol='tcp')
            acl_api.create_acl_rule(data.dut3,acl_type='ipv6',rule_name=data.leaf1_leaf2_udp443tcp_aclv6,rule_seq='10',packet_action='permit',table_name=data.leaf1_leaf2_udp443tcp_aclv6,src_ip='any', dst_ip='any',l4_protocol='udp',dst_port='443')
            acl_api.create_acl_rule(data.dut3,acl_type='ipv6',rule_name=data.leaf1_leaf2_udp443tcp_aclv6,rule_seq='20',packet_action='permit',table_name=data.leaf1_leaf2_udp443tcp_aclv6,src_ip='any', dst_ip='any',l4_protocol='tcp')
            acl_api.create_acl_rule(data.dut3,acl_type='ip',rule_name=data.leaf1_leaf3_ipprefix20,rule_seq='10',packet_action='permit',table_name=data.leaf1_leaf3_ipprefix20,src_ip=data.dut3_acl_ip_list[0], dst_ip='any',l4_protocol='ip')
            acl_api.create_acl_rule(data.dut3,acl_type='ip',rule_name=data.leaf1_leaf4,rule_seq='10',packet_action='permit',table_name=data.leaf1_leaf4,src_ip=data.dut3_acl_ip_list[1], dst_ip='any',l4_protocol='ip')
        def leaf2():
            acl_api.create_acl_table(data.dut4, name=data.leafvniacl, stage='INGRESS', type='ip', ports=[])
            acl_api.create_acl_table(data.dut4, name=data.leafvniaclv6, stage='INGRESS', type='ipv6', ports=[])
            acl_api.create_acl_table(data.dut4, name=data.leaf2_leaf3_ipany_acl, stage='INGRESS', type='ip', ports=[])
            acl_api.create_acl_table(data.dut4, name=data.leaf2_leaf3_ipv6_nat_acl, stage='INGRESS', type='ipv6', ports=[])
            acl_api.create_acl_table(data.dut4, name=data.leaf2_leaf4_ipv6any_acl, stage='INGRESS', type='ipv6', ports=[])
            acl_api.create_acl_rule(data.dut4,acl_type='ip',rule_name=data.leafvniacl,rule_seq='10',packet_action='permit',table_name=data.leafvniacl,src_ip='any', dst_ip='any',l4_protocol='ip')
            acl_api.create_acl_rule(data.dut4,acl_type='ipv6',rule_name=data.leafvniaclv6,rule_seq='10',packet_action='permit',table_name=data.leafvniaclv6,src_ip='any', dst_ip='any',l4_protocol='ipv6')
            acl_api.create_acl_rule(data.dut4,acl_type='ip',rule_name=data.leaf2_leaf3_ipany_acl,rule_seq='10',packet_action='permit',table_name=data.leaf2_leaf3_ipany_acl,src_ip='any', dst_ip='any',l4_protocol='ip')
            acl_api.create_acl_rule(data.dut4,acl_type='ipv6',rule_name=data.leaf2_leaf3_ipv6_nat_acl,rule_seq='10',packet_action='permit',table_name=data.leaf2_leaf3_ipv6_nat_acl,src_ip='any', dst_ip=data.dut3_acl_ip_list[2],l4_protocol='ipv6')
            acl_api.create_acl_rule(data.dut4,acl_type='ipv6',rule_name=data.leaf2_leaf4_ipv6any_acl,rule_seq='10',packet_action='permit',table_name=data.leaf2_leaf4_ipv6any_acl,src_ip='any', dst_ip='any',l4_protocol='ipv6')
        def leaf3():
            acl_api.create_acl_table(data.dut5, name=data.leaf3_ip_acl, stage='INGRESS', type='ip', ports=[])
            acl_api.create_acl_table(data.dut5, name=data.leaf3_ipv6_acl, stage='INGRESS', type='ipv6', ports=[])
            acl_api.create_acl_rule(data.dut5,acl_type='ip',rule_name=data.leaf3_ip_acl,rule_seq='10',packet_action='permit',table_name=data.leaf3_ip_acl,src_ip='any', dst_ip='any',l4_protocol='ip')
            acl_api.create_acl_rule(data.dut5,acl_type='ipv6',rule_name=data.leaf3_ipv6_acl,rule_seq='10',packet_action='permit',table_name=data.leaf3_ipv6_acl,src_ip='any', dst_ip='any',l4_protocol='ipv6')
        def leaf4():
            acl_api.create_acl_table(data.dut6, name=data.leaf4_ip_acl, stage='INGRESS', type='ip', ports=[])
            acl_api.create_acl_table(data.dut6, name=data.leaf4_ipv6_acl, stage='INGRESS', type='ipv6', ports=[])
            acl_api.create_acl_rule(data.dut6,acl_type='ip',rule_name=data.leaf4_ip_acl,rule_seq='10',packet_action='permit',table_name=data.leaf4_ip_acl,src_ip='any', dst_ip='any',l4_protocol='ip')
            acl_api.create_acl_rule(data.dut6,acl_type='ipv6',rule_name=data.leaf4_ipv6_acl,rule_seq='10',packet_action='permit',table_name=data.leaf4_ipv6_acl,src_ip='any', dst_ip='any',l4_protocol='ipv6')

        [res, exceptions] =  st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])

    else:
        ###############################################
        st.banner("Delete all IP/IPv6 access-lists")
        ###############################################
        def leaf1():
            acl_api.delete_acl_table(data.dut3,acl_table_name=data.leaf1_leaf2_udp443tcp_acl,acl_type='ip')
            acl_api.delete_acl_table(data.dut3,acl_table_name=data.leaf1_leaf2_udp443tcp_aclv6,acl_type='ipv6')
            acl_api.delete_acl_table(data.dut3,acl_table_name=data.leaf1_leaf3_ipprefix20,acl_type='ip')
            acl_api.delete_acl_table(data.dut3,acl_table_name=data.leaf1_leaf4,acl_type='ip')
        def leaf2():
            acl_api.delete_acl_table(data.dut4,acl_table_name=data.leaf2_leaf3_ipany_acl,acl_type='ip')
            acl_api.delete_acl_table(data.dut4,acl_table_name=data.leaf2_leaf3_ipv6_nat_acl,acl_type='ipv6')
            acl_api.delete_acl_table(data.dut4,acl_table_name=data.leaf2_leaf4_ipv6any_acl,acl_type='ipv6')
            acl_api.delete_acl_table(data.dut4,acl_table_name=data.leafvniacl,acl_type='ip')
            acl_api.delete_acl_table(data.dut4,acl_table_name=data.leafvniaclv6,acl_type='ipv6')
        def leaf3():
            acl_api.delete_acl_table(data.dut5,acl_table_name=data.leaf3_ip_acl,acl_type='ip')
            acl_api.delete_acl_table(data.dut5,acl_table_name=data.leaf3_ipv6_acl,acl_type='ipv6')
        def leaf4():
            acl_api.delete_acl_table(data.dut6,acl_table_name=data.leaf4_ip_acl,acl_type='ip')
            acl_api.delete_acl_table(data.dut6,acl_table_name=data.leaf4_ipv6_acl,acl_type='ipv6')

        [res, exceptions] =  st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])

def classifier_config_base(config='yes'):
    if config =='yes':
        ###############################################
        st.banner("Configure Classifiers for ip/ipv6 for permit acl")
        ###############################################
        def leaf1():
            acl_dscp_api.config_classifier_table(data.dut3,enable='create',class_name=data.class_leaf12_udp443tcp_acl,match_type='acl',class_criteria='acl',criteria_value=data.leaf1_leaf2_udp443tcp_acl,acl_type='ip')
            acl_dscp_api.config_classifier_table(data.dut3,enable='create',class_name=data.class_leaf12_udp443tcp_aclv6,match_type='acl',class_criteria='acl',criteria_value=data.leaf1_leaf2_udp443tcp_aclv6,acl_type='ipv6')
            acl_dscp_api.config_classifier_table(data.dut3,enable='create',class_name=data.class_leaf13_ipprefix20,match_type='acl',class_criteria='acl',criteria_value=data.leaf1_leaf3_ipprefix20,acl_type='ip')
            acl_dscp_api.config_classifier_table(data.dut3,enable='create',class_name=data.class_leaf14,match_type='acl',class_criteria='acl',criteria_value=data.leaf1_leaf4,acl_type='ip')

        def leaf2():
            acl_dscp_api.config_classifier_table(data.dut4,enable='create',class_name=data.class_leaf23_ipany_acl,match_type='acl',class_criteria='acl',criteria_value=data.leaf2_leaf3_ipany_acl,acl_type='ip')
            acl_dscp_api.config_classifier_table(data.dut4,enable='create',class_name=data.class_leaf23_ipv6_nat,match_type='acl',class_criteria='acl',criteria_value=data.leaf2_leaf3_ipv6_nat_acl,acl_type='ipv6')
            acl_dscp_api.config_classifier_table(data.dut4,enable='create',class_name=data.class_leaf24_ipv6any_acl,match_type='acl',class_criteria='acl',criteria_value=data.leaf2_leaf4_ipv6any_acl,acl_type='ipv6')
            acl_dscp_api.config_classifier_table(data.dut4,enable='create',class_name=data.class_leafvniacl,match_type='acl',class_criteria='acl',criteria_value=data.leafvniacl,acl_type='ip')
            acl_dscp_api.config_classifier_table(data.dut4,enable='create',class_name=data.class_leafvniaclv6,match_type='acl',class_criteria='acl',criteria_value=data.leafvniaclv6,acl_type='ipv6')

        def leaf3():
            acl_dscp_api.config_classifier_table(data.dut5,enable='create',class_name=data.class_leaf3_ip,match_type='acl',class_criteria='acl',criteria_value=data.leaf3_ip_acl,acl_type='ip')
            acl_dscp_api.config_classifier_table(data.dut5,enable='create',class_name=data.class_leaf3_ipv6,match_type='acl',class_criteria='acl',criteria_value=data.leaf3_ipv6_acl,acl_type='ipv6')

        def leaf4():
            acl_dscp_api.config_classifier_table(data.dut6,enable='create',class_name=data.class_leaf4_ip,match_type='acl',class_criteria='acl',criteria_value=data.leaf4_ip_acl,acl_type='ip')
            acl_dscp_api.config_classifier_table(data.dut6,enable='create',class_name=data.class_leaf4_ipv6,match_type='acl',class_criteria='acl',criteria_value=data.leaf4_ipv6_acl,acl_type='ipv6')

        [res, exceptions] =  st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])

    else:
        ###############################################
        st.banner("Delete Classifiers")
        ###############################################
        acl_dscp_api.config_classifier_table(data.dut3,enable='del',class_name=data.class_leaf12_udp443tcp_acl,match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut3, enable='del', class_name=data.class_leaf12_udp443tcp_aclv6, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut3,enable='del',class_name=data.class_leaf13_ipprefix20,match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut3, enable='del', class_name=data.class_leaf14, match_type='acl')

        acl_dscp_api.config_classifier_table(data.dut4,enable='del',class_name=data.class_leaf23_ipany_acl,match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut4,enable='del',class_name=data.class_leaf23_ipv6_nat,match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut4, enable='del', class_name=data.class_leaf24_ipv6any_acl, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut4, enable='del', class_name=data.class_leafvniacl, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut4, enable='del', class_name=data.class_leafvniaclv6, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut5, enable='del', class_name=data.class_leaf3_ip, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut5, enable='del', class_name=data.class_leaf3_ipv6, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut6, enable='del', class_name=data.class_leaf4_ip, match_type='acl')
        acl_dscp_api.config_classifier_table(data.dut6, enable='del', class_name=data.class_leaf4_ipv6, match_type='acl')

def policy_config_base(config='yes'):
    if config =='yes':
        #############################################################################
        st.banner("Configure policy map with ip and ipv6 flows for interface level")
        #############################################################################
        def leaf1():
            acl_dscp_api.config_flow_update_table(data.dut3,flow='add',policy_name=data.policy_class_leaf1,policy_type='forwarding',
                                              class_name=data.class_leaf12_udp443tcp_acl,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf2_dict['tenant_ip_list'][0],data.leaf3_dict['tenant_ip_list'][0]],
                                              next_hop_priority=[30,20])

            acl_dscp_api.config_flow_update_table(data.dut3,flow='add',policy_name=data.policy_class_leaf1,policy_type='forwarding',
                                              class_name=data.class_leaf12_udp443tcp_aclv6,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf2_dict['tenant_ipv6_list'][0],data.leaf3_dict['tenant_ipv6_list'][0]],
                                              next_hop_priority=[30,20],version='ipv6')

            acl_dscp_api.config_flow_update_table(data.dut3,flow='add',policy_name=data.policy_class_leaf1,policy_type='forwarding',
                                              class_name=data.class_leaf13_ipprefix20,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf3_dict['tenant_ip_list'][0]],
                                              next_hop_priority=[30])

            acl_dscp_api.config_flow_update_table(data.dut3,flow='add',policy_name=data.policy_class_leaf1,policy_type='forwarding',
                                              class_name=data.class_leaf14,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf4_dict['tenant_ip_list'][0]],
                                              next_hop_priority=[30])
            acl_dscp_api.config_service_policy_table(data.dut3, service_policy_name=data.policy_class_leaf1,policy_kind='bind', policy_type='forwarding',interface_name=data.leaf1_dict["tenant_vlan_int"][0])

        def leaf2():
            acl_dscp_api.config_flow_update_table(data.dut4,flow='add',policy_name=data.policy_class_leaf2,policy_type='forwarding',
                                              class_name=data.class_leaf23_ipany_acl,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf3_dict['tenant_ip_list'][0]],next_hop_priority=[30])

            acl_dscp_api.config_flow_update_table(data.dut4,flow='add',policy_name=data.policy_class_leaf2,policy_type='forwarding',
                                              class_name=data.class_leaf23_ipv6_nat,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf3_dict['tenant_ipv6_list'][0]],next_hop_priority=[30],version='ipv6')

            acl_dscp_api.config_flow_update_table(data.dut4,flow='add',policy_name=data.policy_class_leaf2,policy_type='forwarding',
                                              class_name=data.class_leaf24_ipv6any_acl,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf4_dict['tenant_ipv6_list'][0]],
                                              next_hop_priority=[30],version='ipv6')

            acl_dscp_api.config_flow_update_table(data.dut4,flow='add',policy_name=data.policy_class_leaf2vni,policy_type='forwarding',
                                              class_name=data.class_leafvniacl,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.client_dict['tenant_ip_list'][0]],
                                              next_hop_priority=[30])

            acl_dscp_api.config_flow_update_table(data.dut4,flow='add',policy_name=data.policy_class_leaf2vni,policy_type='forwarding',
                                              class_name=data.class_leafvniaclv6,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.client_dict['tenant_ipv6_list'][0]],
                                              next_hop_priority=[30],version='ipv6')

            acl_dscp_api.config_service_policy_table(data.dut4, service_policy_name=data.policy_class_leaf2,policy_kind='bind', policy_type='forwarding',interface_name=data.leaf2_dict["tenant_vlan_int"][1])
            acl_dscp_api.config_service_policy_table(data.dut4, service_policy_name=data.policy_class_leaf2vni,policy_kind='bind', policy_type='forwarding',interface_name=data.vlan_vrf1)
        def leaf3():
            acl_dscp_api.config_flow_update_table(data.dut5,flow='add',policy_name=data.policy_class_leaf3,policy_type='forwarding',
                                              class_name=data.class_leaf3_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf4_dict['tenant_ip_list'][0]],
                                              next_hop_priority=[30])

            acl_dscp_api.config_flow_update_table(data.dut5,flow='add',policy_name=data.policy_class_leaf3,policy_type='forwarding',
                                              class_name=data.class_leaf3_ipv6,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf4_dict['tenant_ipv6_list'][0]],
                                              next_hop_priority=[30],version='ipv6')

            acl_dscp_api.config_service_policy_table(data.dut5, service_policy_name=data.policy_class_leaf3,policy_kind='bind', policy_type='forwarding',interface_name=data.vlan_vrf1)
        def leaf4():
            acl_dscp_api.config_flow_update_table(data.dut6,flow='add',policy_name=data.policy_class_leaf4,policy_type='forwarding',
                                              class_name=data.class_leaf4_ip,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf4_dict['tenant_v4_ip']],
                                              next_hop_priority=[30])

            acl_dscp_api.config_flow_update_table(data.dut6,flow='add',policy_name=data.policy_class_leaf4,policy_type='forwarding',
                                              class_name=data.class_leaf4_ipv6,flow_priority=10,priority_option='next-hop',
                                              next_hop=[data.leaf4_dict['tenant_v6_ip'][0]],
                                              next_hop_priority=[30],version='ipv6')
            acl_dscp_api.config_service_policy_table(data.dut6, service_policy_name=data.policy_class_leaf4,policy_kind='bind', policy_type='forwarding',interface_name=data.vlan_vrf1)

        [res, exceptions] =  st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])
    else:
        st.banner("Unconfigure policy map")
        def leaf1():
            acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name=data.policy_class_leaf1,
                                              class_name=data.class_leaf12_udp443tcp_acl, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name=data.policy_class_leaf1,
                                              class_name=data.class_leaf12_udp443tcp_aclv6, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name=data.policy_class_leaf1,
                                              class_name=data.class_leaf13_ipprefix20, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut3, flow='del', policy_name=data.policy_class_leaf1,
                                              class_name=data.class_leaf14, policy_type='forwarding')
        def leaf2():
            acl_dscp_api.config_flow_update_table(data.dut4, flow='del', policy_name=data.policy_class_leaf2,
                                              class_name=data.class_leaf23_ipany_acl, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut4, flow='del', policy_name=data.policy_class_leaf2,
                                              class_name=data.class_leaf23_ipv6_nat, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut4, flow='del', policy_name=data.policy_class_leaf2,
                                              class_name=data.class_leaf24_ipv6any_acl, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut4, flow='del', policy_name=data.policy_class_leaf2vni,
                                              class_name=data.class_leafvniacl, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut4, flow='del', policy_name=data.policy_class_leaf2vni,
                                              class_name=data.class_leafvniaclv6, policy_type='forwarding')
        def leaf3():
            acl_dscp_api.config_flow_update_table(data.dut5, flow='del', policy_name=data.policy_class_leaf3,
                                              class_name=data.class_leaf3_ip, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut5, flow='del', policy_name=data.policy_class_leaf3,
                                              class_name=data.class_leaf3_ipv6, policy_type='forwarding')
        def leaf4():
            acl_dscp_api.config_flow_update_table(data.dut6, flow='del', policy_name=data.policy_class_leaf4,
                                              class_name=data.class_leaf4_ip, policy_type='forwarding')
            acl_dscp_api.config_flow_update_table(data.dut6, flow='del', policy_name=data.policy_class_leaf4,
                                              class_name=data.class_leaf4_ipv6, policy_type='forwarding')
        [res, exceptions] =  st.exec_all([[leaf1],[leaf2],[leaf3],[leaf4]])

def verify_base_policy():
    #############################################
    st.banner('Verify all Policy configs ')
    #############################################
    match_port_leaf1 = [{'policy_name':data.policy_class_leaf1,'policy_type':'forwarding','class_name':data.class_leaf12_udp443tcp_acl,
               'next_hop':data.leaf2_dict['tenant_ip_list'][0]},
                  {'policy_name':data.policy_class_leaf1,'policy_type':'forwarding','class_name':data.class_leaf12_udp443tcp_aclv6,
               'next_hop':data.leaf2_dict['tenant_ipv6_list'][0]},
                  {'policy_name':data.policy_class_leaf1,'policy_type':'forwarding','class_name':data.class_leaf13_ipprefix20,
               'next_hop':data.leaf3_dict['tenant_ip_list'][0]},
                  {'policy_name':data.policy_class_leaf1,'policy_type':'forwarding','class_name':data.class_leaf14,
               'next_hop':data.leaf4_dict['tenant_ip_list'][0]}]

    match_port_leaf2 = [{'policy_name':data.policy_class_leaf2,'policy_type':'forwarding','class_name':data.class_leaf23_ipany_acl,
               'next_hop':data.leaf3_dict['tenant_ip_list'][0]},
                  {'policy_name':data.policy_class_leaf2,'policy_type':'forwarding','class_name':data.class_leaf23_ipv6_nat,
               'next_hop':data.leaf3_dict['tenant_ipv6_list'][0]},
                  {'policy_name':data.policy_class_leaf2,'policy_type':'forwarding','class_name':data.class_leaf24_ipv6any_acl,
               'next_hop':data.leaf4_dict['tenant_ipv6_list'][0]}]

    match_port_leaf3 = [{'policy_name':data.policy_class_leaf3,'policy_type':'forwarding','class_name':data.class_leaf3_ip,
                   'next_hop':data.leaf4_dict['tenant_ip_list'][0]},
                      {'policy_name':data.policy_class_leaf3,'policy_type':'forwarding','class_name':data.class_leaf3_ipv6,
                   'next_hop':data.leaf4_dict['tenant_ipv6_list'][0]}]

    match_port_leaf4 = [{'policy_name':data.policy_class_leaf4,'policy_type':'forwarding','class_name':data.class_leaf4_ip,
                   'next_hop':data.leaf4_dict['tenant_v4_ip']},
                      {'policy_name':data.policy_class_leaf4,'policy_type':'forwarding','class_name':data.class_leaf4_ipv6,
                   'next_hop':data.leaf4_dict['tenant_v6_ip'][0]}]

    dict1 = {'policy_name':data.policy_class_leaf1, 'verify_list':match_port_leaf1}
    dict2 = {'policy_name':data.policy_class_leaf2, 'verify_list':match_port_leaf2}
    dict3 = {'policy_name':data.policy_class_leaf3, 'verify_list':match_port_leaf3}
    dict4 = {'policy_name':data.policy_class_leaf4, 'verify_list':match_port_leaf4}
    [result, exceptions] = parallel.exec_parallel(True, [data.dut3, data.dut4, data.dut5, data.dut6], acl_dscp_api.verify, [dict1, dict2, dict3, dict4])
    if False in result:
        st.error('Policy verification failed on all the leafs')
        return False

    return True

def verify_policy_counters_incrementing(dut,policy,flow_list,interface=None,increment=True):
    ####################################
    st.banner('Verify service policy counters ')
    ####################################
    packet_count = {}
    match_list = list()
    for flow in flow_list:
        match  ={'policy_name':policy,'class_name':flow}
        match_list.append(match)

    output = acl_dscp_api.show(dut, service_policy_name=policy)

    if output:
        for match_1 in match_list:
            entry_v4 = filter_and_select(output,None,match=match_1)
            if entry_v4:
                packet_count['{}_{}'.format(match_1['class_name'],0)] = int(entry_v4[0]['match_pkts_val'])
                st.log("{} Policy Packet Match Count : {} packets".
                           format(match_1['class_name'],packet_count['{}_{}'.format(match_1['class_name'],0)]))
                pktcount =packet_count['{}_{}'.format(match_1['class_name'],0)]
                st.log("Total pkts incremented {} ".format(pktcount))
            else:
                st.error("####### Packet count entry not found     #######")
                return False
    else:
        st.error("Empty output")
        return False

    if increment:
        for flow in flow_list:
            if packet_count['{}_0'.format(flow)] >0:
               st.log("{} policy match counters incremented".format(flow))
            else:
                st.error("{} policy match counters not incremented".format(flow))
                return False
    else:
        for flow in flow_list:
            if packet_count['{}_0'.format(flow)] !=0:
                st.error("{} policy match counters incremented".format(flow))
                return False
            else:
                st.log("{} policy match counters not incremented".format(flow))
    return True
