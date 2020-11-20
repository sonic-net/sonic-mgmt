
import struct
import socket

from spytest import st,utils
import apis.switching.portchannel as pc
import apis.system.port as port_api
import apis.switching.vlan as vlan_api
import apis.routing.ip as ip_api
from apis.routing import arp
from utilities import parallel
import apis.routing.bgp as bgp_api
import apis.routing.ip_bgp as ip_bgp
from spytest.tgen.tgen_utils import validate_tgen_traffic
import apis.routing.vrf as vrf_api
import apis.routing.pim as pim_api
import apis.routing.igmp as igmp_api
import apis.system.basic as basic_api
from pim_vars import *
import apis.common.asic as asicapi


def pim_base_config():
    ###################################################
    hdrMsg("########## BASE Config Starts ########")
    ###################################################
    debug_enable()
    api_list = [[config_tgen],[config_dut]]
    ret_val = parallel.exec_all(True, api_list, True)
    if ret_val[0][1] is False:
        return False
    ###################################################
    hdrMsg("########## BASE Config End ########")
    ###################################################
    return True


def config_dut():
    config_lag()
    result = verify_lag()
    if result is False:
        failMsg("One or more Port-Channles are not UP")
        return False
    config_vlan()
    config_vlan(vrf=vrf_name)
    config_ip()
    config_ip(vrf=vrf_name)
    config_static_arp()
    config_igp(igp=igp)
    config_igp(igp=igp,vrf=vrf_name)
    config_igmp_pim()
    config_igmp_pim(vrf=vrf_name)
    result = verify_igp(igp=igp)
    if result is False:
        failMsg("One or more {} sessions are not up".format(igp))
        return False
    result = verify_igp(igp=igp,vrf=vrf_name)
    if result is False:
        failMsg("VRF : {} One or more {} sessions are not up".format(vrf_name,igp))
        return False
    result = verify_pim_session()
    if result is False:
        failMsg("One or more PIM sessions did not come UP")
        return False
    result = verify_pim_session(vrf=vrf_name)
    if result is False:
        failMsg("VRF : {} -One or more PIM sessions did not come UP".format(vrf_name))
        return False
    return True

def pim_base_deconfig():
    ###################################################
    hdrMsg("########## BASE De-Config Starts ########")
    ###################################################
    debug_enable(config='no')
    api_list = [[deconfig_tgen], [deconfig_dut]]
    parallel.exec_all(True, api_list, True)
    ###################################################
    hdrMsg("########## BASE De-Config End ########")
    ###################################################

def deconfig_tgen():
    config_tgen(config='no')

def deconfig_dut():
    config_igmp_pim(config='no')
    config_igmp_pim(config='no',vrf=vrf_name)
    config_igp(igp=igp,config='no',vrf=vrf_name)
    config_igp(igp=igp,config='no')
    config_static_arp(config='no')
    config_ip(config='no')
    create_bind_vrf(config='no')
    config_vlan(config='no')
    config_vlan(config='no',vrf=vrf_name)
    config_lag(config='no')

def config_lag(config='yes'):
    if config == 'yes':
        member_flag = 'add'
        ###################################################
        hdrMsg("LAG-Config: Configure {} between D1 and D3 with 2 member ports".format(data.d1d3_lag_intf))
        ###################################################

        utils.exec_all(True, [[pc.create_portchannel, data.dut1, [data.d1d3_lag_intf], False],
                              [pc.create_portchannel, data.dut3, [data.d1d3_lag_intf], False]])

        ###################################################
        hdrMsg("LAG-Config: Configure two  single-port LAGs {} and {} between D3 and D2".format(data.d3d2_lag_intf_1,data.d3d2_lag_intf_2))
        ###################################################
        utils.exec_all(True, [[pc.create_portchannel, data.dut2, [data.d3d2_lag_intf_1,data.d3d2_lag_intf_2], False],
                              [pc.create_portchannel, data.dut3, [data.d3d2_lag_intf_1,data.d3d2_lag_intf_2], False]])

    else:
        member_flag = 'del'

    ###################################################################
    hdrMsg("LAG-Config: {} member ports to {} on D1 and D3".format(member_flag,data.d1d3_lag_intf))
    ###################################################################
    utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut1,data.d1d3_lag_intf,data.d1d3_ports[0:2],member_flag],
                          [pc.add_del_portchannel_member, data.dut3, data.d1d3_lag_intf,data.d3d1_ports[0:2],member_flag]])

    ###################################################################
    hdrMsg("LAG-Config: {} member ports to {} and {} on D2 and D3".format(member_flag,data.d3d2_lag_intf_1,data.d3d2_lag_intf_2))
    ###################################################################
    utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut3,data.d3d2_lag_intf_1,[data.d3d2_ports[0]],member_flag],
                          [pc.add_del_portchannel_member, data.dut2, data.d3d2_lag_intf_1,[data.d2d3_ports[0]],member_flag]])
    utils.exec_all(True, [[pc.add_del_portchannel_member, data.dut3,data.d3d2_lag_intf_2,[data.d3d2_ports[1]],member_flag],
                          [pc.add_del_portchannel_member, data.dut2, data.d3d2_lag_intf_2,[data.d2d3_ports[1]],member_flag]])

    if config == 'no':
        ###################################################################
        hdrMsg("{} Port-channels from all duts".format(member_flag))
        ###################################################################
        utils.exec_all(True, [[pc.delete_portchannel, data.dut1, [data.d1d3_lag_intf]],
                              [pc.delete_portchannel, data.dut2, [data.d3d2_lag_intf_1,data.d3d2_lag_intf_2]],
                              [pc.delete_portchannel, data.dut3, [data.d1d3_lag_intf,data.d3d2_lag_intf_1,data.d3d2_lag_intf_2]]])



def config_vlan(config='yes',vrf='default'):
    if vrf == 'default':
        key_append ='' ;index = 0
        d2d4_port = data.d2d4_ports[0];d4d2_port = data.d4d2_ports[0]
    else:
        key_append = '_vrf' ;index =1
        d2d4_port = data.d2d4_ports[1];d4d2_port = data.d4d2_ports[1]

    dut1_vlan_list = data['d1_vlan_id' + key_append]
    dut2_vlan_list = data['d2_vlan_id' + key_append]
    dut3_vlan_list = data['d3_vlan_id' + key_append]
    dut4_vlan_list = data['d4_vlan_id' + key_append]
    loopback = data['loopback'+key_append]

    if config == 'yes':
        ###################################################################
        hdrMsg("Vlan-Config: Configure Vlans {} on D1 ,Vlans {} on D2 ,Vlans {} on D3 and Vlans {} on D4"
               .format(dut1_vlan_list,dut2_vlan_list,dut3_vlan_list,dut4_vlan_list))
        ###################################################################
        utils.exec_all(True,[[vlan_api.create_vlan,data.dut1,dut1_vlan_list],
                             [vlan_api.create_vlan,data.dut2,dut2_vlan_list],
                             [vlan_api.create_vlan,data.dut3,dut3_vlan_list],
                             [vlan_api.create_vlan,data.dut4,dut4_vlan_list]])


        ###################################################################
        hdrMsg("Vlan-Config: Configure port between D1 and D2 as tagged on vlan {}".format(dut1_vlan_list[0]))
        ###################################################################
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_vlan_list[0],[data.d1d2_ports[0]], True],
                             [vlan_api.add_vlan_member,data.dut2,dut1_vlan_list[0],[data.d2d1_ports[0]], True]])

        ###################################################################
        hdrMsg("Vlan-Config: Configure lag port {} between D1 and D3 as tagged on vlan {}".format(data.lag_intf_list[0],dut1_vlan_list[1]))
        ###################################################################
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_vlan_list[1],[data.lag_intf_list[0]], True],
                             [vlan_api.add_vlan_member,data.dut3,dut1_vlan_list[1],[data.lag_intf_list[0]], True]])

        ###################################################################
        hdrMsg("Vlan-Config: Configure a tagged Vlan member between D1 and D3 on vlan {}".format(dut1_vlan_list[2]))
        ###################################################################
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut1,dut1_vlan_list[2],[data.d1d3_ports[2]], True],
                             [vlan_api.add_vlan_member,data.dut3,dut1_vlan_list[2],[data.d3d1_ports[2]], True]])

        ###################################################################
        hdrMsg("Vlan-Config: Configure an untagged Vlan member between D2 and D4 on vlan {}".format(dut2_vlan_list[1]))
        ###################################################################

        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut2,dut2_vlan_list[1],[d2d4_port],False],
                             [vlan_api.add_vlan_member,data.dut4,dut2_vlan_list[1],[d4d2_port],False]])

        ###################################################################
        hdrMsg("Vlan-Config: Configure a tagged Vlan member between D3 and D4 on vlan {}".format(dut3_vlan_list[2]))
        ###################################################################
        utils.exec_all(True,[[vlan_api.add_vlan_member,data.dut3,dut3_vlan_list[2],[data.d3d4_ports[0]], True],
                             [vlan_api.add_vlan_member,data.dut4,dut3_vlan_list[2],[data.d4d3_ports[0]], True]])

        ###################################################################
        hdrMsg("Vlan-Config: Configure a tagged Vlan member between D3 and Tgen on vlan {}".format(dut3_vlan_list[3]))
        ###################################################################
        vlan_api.add_vlan_member(data.dut3,dut3_vlan_list[3],[data.d3tg_ports[index]], True)

        if vrf == 'default':
            ###################################################################
            hdrMsg("VRF {} : Create Loopback interfaces on D1 and D3".format(vrf))
            ###################################################################
            parallel.exec_parallel(True, [data.dut1, data.dut3], ip_api.configure_loopback,[{'loopback_name': loopback}] * 2)


    else:
        ###################################################################
        hdrMsg("Vlan-DeConfig: Remove all Vlan membership from ports on all DUTs")
        ###################################################################
        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_vlan_list[0],[data.d1d2_ports[0]]],
                             [vlan_api.delete_vlan_member,data.dut2,dut1_vlan_list[0],[data.d2d1_ports[0]]]])

        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_vlan_list[1],[data.lag_intf_list[0]]],
                             [vlan_api.delete_vlan_member,data.dut3,dut1_vlan_list[1],[data.lag_intf_list[0]]]])

        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut1,dut1_vlan_list[2],[data.d1d3_ports[2]]],
                             [vlan_api.delete_vlan_member,data.dut3,dut1_vlan_list[2],[data.d3d1_ports[2]]]])

        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut2,dut2_vlan_list[1],[d2d4_port]],
                             [vlan_api.delete_vlan_member,data.dut4,dut2_vlan_list[1],[d4d2_port]]])

        utils.exec_all(True,[[vlan_api.delete_vlan_member,data.dut3,dut3_vlan_list[2],[data.d3d4_ports[0]]],
                             [vlan_api.delete_vlan_member,data.dut4,dut3_vlan_list[2],[data.d4d3_ports[0]]]])

        vlan_api.delete_vlan_member(data.dut3, dut3_vlan_list[3], [data.d3tg_ports[index]])

        ###################################################################
        hdrMsg("Vlan-DeConfig: Delete all configured Vlans from all 4 DUTs")
        ###################################################################
        utils.exec_all(True,[[vlan_api.delete_vlan,data.dut1,dut1_vlan_list],
                             [vlan_api.delete_vlan,data.dut2,dut2_vlan_list],
                             [vlan_api.delete_vlan,data.dut3,dut3_vlan_list],
                             [vlan_api.delete_vlan,data.dut4,dut4_vlan_list]])
        if vrf == 'default':
            ###################################################################
            hdrMsg("VRF {} : Delete Loopback interfaces on D1 and D3".format(vrf))
            ###################################################################
            parallel.exec_parallel(True, [data.dut1, data.dut3], ip_api.configure_loopback,[{'loopback_name': loopback,'config':'no'}] * 2)


def create_bind_vrf(vrf=vrf_name,config='yes'):
    if config == 'yes':
        ###################################################################
        hdrMsg("VRF-Config: Configure VRF {} on all DUTs".format(vrf))
        ###################################################################
        dict1 = {'vrf_name': vrf, 'skip_error': True}
        parallel.exec_parallel(True,data.dut_list, vrf_api.config_vrf, [dict1]*len(data.dut_list))

    ###################################################################
    hdrMsg("VRF-Config : Bind VRF {} to Vlan and physical interfaces on all DUTs".format(vrf))
    ###################################################################

    d1_vrf_intf_list = data.d1_vlan_intf_vrf + [data.d1d4_ports[1]] + [data.d1tg_ports[1]] + [data.loopback_vrf]
    d2_vrf_intf_list = data.d2_vlan_intf_vrf + [data.d3d2_lag_intf_2] + [data.d2tg_ports[1]]
    d3_vrf_intf_list = data.d3_vlan_intf_vrf + [data.d3d2_lag_intf_2] + [data.loopback_vrf]
    d4_vrf_intf_list = data.d4_vlan_intf_vrf + [data.d4d1_ports[1]] + [data.d4tg_ports[1]]

    dict1 = {'vrf_name':[vrf_name]*len(d1_vrf_intf_list), 'intf_name':  d1_vrf_intf_list,'skip_error':True,'config':config}
    dict2 = {'vrf_name':[vrf_name]*len(d2_vrf_intf_list), 'intf_name':  d2_vrf_intf_list,'skip_error':True,'config':config}
    dict3 = {'vrf_name':[vrf_name]*len(d3_vrf_intf_list), 'intf_name': d3_vrf_intf_list, 'skip_error': True,'config':config}
    dict4 = {'vrf_name':[vrf_name]*len(d4_vrf_intf_list), 'intf_name': d4_vrf_intf_list, 'skip_error': True,'config':config}
    parallel.exec_parallel(True, data.dut_list, vrf_api.bind_vrf_interface, [dict1, dict2,dict3,dict4])

    if config == 'no':
        ###################################################################
        hdrMsg("VRF-Config: Delete VRF {} on all DUTs".format(vrf))
        ###################################################################
        dict1 = {'vrf_name': vrf, 'skip_error': True,'config':'no'}
        parallel.exec_parallel(True,data.dut_list, vrf_api.config_vrf, [dict1]*len(data.dut_list))



def config_ip(config='yes',vrf='default'):
    if vrf =='default':
        key_append = ''
        index = 0
        lag_23 = data.d3d2_lag_intf_1
        #d1d4_phy = data.d1d4_ports[0]
        #d4d1_phy = data.d4d1_ports[0]
    else:
        create_bind_vrf(config=config)
        key_append = '_vrf'
        index = 1
        lag_23 = data.d3d2_lag_intf_2
        #d1d4_phy = data.d1d4_ports[1]
        #d4d1_phy = data.d4d1_ports[1]
    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip_api.delete_ip_interface
        config_str = "Delete"


    ###################################################################
    hdrMsg("VRF {} :IP-Config: {} ip addresses on {} between D1 and D2 ".format(vrf,config_str,data['d1d2_vlan_intf'+key_append]))
    ###################################################################

    utils.exec_all(True, [[api_name, data.dut1, data['d1d2_vlan_intf'+key_append][0], data.d1d2_ip, data.mask],
                          [api_name, data.dut2, data['d1d2_vlan_intf'+key_append][0], data.d2d1_ip, data.mask]])

    ###################################################################
    hdrMsg("VRF {} :IP-Config: {} ip addresses on {}  between D1 and D3 ".format(vrf, config_str, data['d1d3_vlan_intf'+key_append]))
    ###################################################################

    utils.exec_all(True, [[api_name, data.dut1, data['d1d3_vlan_intf'+key_append][0], data.d1d3_ip[0], data.mask],
                          [api_name, data.dut3, data['d3d1_vlan_intf'+key_append][0], data.d3d1_ip[0], data.mask]])

    utils.exec_all(True, [[api_name, data.dut1, data['d1d3_vlan_intf'+key_append][1], data.d1d3_ip[1], data.mask],
                          [api_name, data.dut3, data['d3d1_vlan_intf'+key_append][1], data.d3d1_ip[1], data.mask]])

    ###################################################################
    hdrMsg("VRF {} :IP-Config: {} ip addresses on physical port between D1 and D4 ".format(vrf,config_str))
    ###################################################################

    utils.exec_all(True, [[api_name, data.dut1, data.d1d4_ports[index], data.d1d4_ip, data.mask],
                          [api_name, data.dut4, data.d4d1_ports[index], data.d4d1_ip, data.mask]])

    ###################################################################
    hdrMsg("VRF {} :IP-Config: {} ip addresses on {} between D2 and D3 ".format(vrf,config_str,lag_23))
    ###################################################################
    utils.exec_all(True, [[api_name, data.dut2, lag_23, data.d2d3_ip, data.mask],
                          [api_name, data.dut3, lag_23, data.d3d2_ip, data.mask]])

    ###################################################################
    hdrMsg("VRF {} :IP-Config: {} ip addresses on {} between D2 and D4 ".format(vrf,config_str,data['d2d4_vlan_intf'+key_append]))
    ###################################################################
    utils.exec_all(True, [[api_name, data.dut2, data['d2d4_vlan_intf'+key_append][0], data.d2d4_ip, data.mask],
                          [api_name, data.dut4, data['d2d4_vlan_intf'+key_append][0], data.d4d2_ip, data.mask]])

    ###################################################################
    hdrMsg("VRF {} :IP-Config: {} ip addresses on {} between D3 and D4 ".format(vrf,config_str,data['d3d4_vlan_intf'+key_append]))
    ###################################################################
    utils.exec_all(True, [[api_name, data.dut3, data['d3d4_vlan_intf'+key_append][0], data.d3d4_ip, data.mask],
                          [api_name, data.dut4, data['d3d4_vlan_intf'+key_append][0], data.d4d3_ip, data.mask]])
    if config == 'yes':
        ###################################################################
        hdrMsg("VRF {} :IP-Config: Configure ip addresses on Loopback interfaces in D1 and D3")
        ###################################################################
        utils.exec_all(True, [[api_name, data.dut1, data['loopback'+key_append], data.d1_loopback_ip, '32'],
                              [api_name, data.dut3, data['loopback'+key_append], data.d3_loopback_ip, '32']])
    else:
        if vrf == 'default':
            ###################################################################
            hdrMsg("VRF {} :IP-Config: Delete ip addresses on Loopback interfaces in D1 and D3")
            ###################################################################
            utils.exec_all(True, [[api_name, data.dut1, data['loopback' + key_append], data.d1_loopback_ip, '32'],
                                  [api_name, data.dut3, data['loopback' + key_append], data.d3_loopback_ip, '32']])

    ###################################################################
    hdrMsg("VRF {} :IP-Config: {} ip addresses on between D1,D2,D3,D4 and TGEN interfaces ".format(vrf,config_str))
    ###################################################################
    utils.exec_all(True, [[api_name, data.dut1, data.d1tg_ports[index], data.d1tg_ip, data.mask],
                          [api_name, data.dut2, data.d2tg_ports[index], data.d2tg_ip, data.mask],
                          [api_name, data.dut3, data['d3tg_vlan_intf'+key_append][0], data.d3tg_ip, data.mask],
                          [api_name, data.dut4, data.d4tg_ports[index], data.d4tg_ip, data.mask]])



def config_static_arp(config='yes'):
    if config == 'yes':
        arp.add_static_arp(data.dut1,data.tgd1_ip,data.src_mac[data.tg_d1_handles[0]], interface=data.d1tg_ports[0])
        arp.add_static_arp(data.dut1, data.tgd1_ip, data.src_mac[data.tg_d1_handles[1]], interface=data.d1tg_ports[1])
        arp.add_static_arp(data.dut2, data.tgd2_ip, data.src_mac[data.tg_d2_handles[0]], interface=data.d2tg_ports[0])
        arp.add_static_arp(data.dut2, data.tgd2_ip, data.src_mac[data.tg_d2_handles[1]], interface=data.d2tg_ports[1])
    else:
        arp.delete_static_arp(data.dut1, data.tgd1_ip)
        arp.delete_static_arp(data.dut2, data.tgd2_ip)

def config_igp(igp='bgp',config='yes',vrf='default'):
    if igp == 'ospf':
        config_ospf(config=config,vrf=vrf)
    else:
        config_bgp(config=config,vrf=vrf)



def config_ospf(config='yes',vrf='default'):
    #if vrf =='default':
        #key_append = ''
        #index = 0
        #lag_23 = data.d3d2_lag_intf_1
        #d1d4_phy = data.d1d4_ports[0]
        #d4d1_phy = data.d4d1_ports[0]
    #else:
        #key_append = '_vrf'
        #index = 1
        #lag_23 = data.d3d2_lag_intf_2
        #d1d4_phy = data.d1d4_ports[1]
        #d4d1_phy = data.d4d1_ports[1]

    #d1_l3_list = [data['d1d2_vlan_intf' + key_append], data.d1tg_ports[index], data.d1d4_ports[index] + data['d1d3_vlan_intf' + key_append]]
    #d2_l3_list = [data['d1d2_vlan_intf' + key_append], data.d2tg_ports[index], data['d2d4_vlan_intf' + key_append],lag_23]
    #d3_l3_list = data['d1d3_vlan_intf' + key_append] + [lag_23, data['d3d4_vlan_intf' + key_append], data['d3tg_vlan_intf' + key_append]]
    #d4_l3_list = [data.d4d1_ports[index], data['d2d4_vlan_intf' + key_append], data['d3d4_vlan_intf' + key_append],data.d4tg_ports[index]]
    ###################################################################
    hdrMsg("VRF {} : OSPF-Config: Enable OSPF globally on area 0 ".format(vrf))
    ###################################################################


    ###################################################################
    hdrMsg("VRF {} : OSPF-Config: Enable OSPF on all ip interfaces on all DUTs".format(vrf))
    ###################################################################



def config_bgp(vrf='default',config='yes'):
    if config== 'yes':
        ##########################################################################
        hdrMsg("VRF-{} BGP-config: Configure BGP routers on all 4 DUTs".format(vrf))
        ##########################################################################
        dict1 = {'local_as':data.d1_as,'router_id':data.d1_routerid,'config_type_list':['router_id'],'vrf_name':vrf}
        dict2 = {'local_as':data.d2_as,'router_id':data.d2_routerid,'config_type_list':['router_id'],'vrf_name':vrf}
        dict3 = {'local_as': data.d3_as, 'router_id': data.d3_routerid, 'config_type_list': ['router_id'],'vrf_name': vrf}
        dict4 = {'local_as':data.d4_as,'router_id':data.d4_routerid,'config_type_list':['router_id'],'vrf_name':vrf}
        parallel.exec_parallel(True,data.dut_list, bgp_api.config_bgp, [dict1, dict2,dict3,dict4])

        ##########################################################################
        hdrMsg("VRF-{} BGP-config: Configure eBGP neighbors between D1 and D2".format(vrf))
        ##########################################################################
        dict1 = {'config_type_list': ['neighbor'], 'remote_as': data.d2_as, 'neighbor': data.d2d1_ip,'vrf_name':vrf,'local_as':data.d1_as}
        dict2 = {'config_type_list': ['neighbor'], 'remote_as': data.d1_as, 'neighbor': data.d1d2_ip,'vrf_name':vrf,'local_as':data.d2_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])

        ##########################################################################
        hdrMsg("VRF-{} BGP-config: Configure 2 eBGP neighbors between D1 and D3".format(vrf))
        ##########################################################################
        for nbr_1,nbr_2 in zip(data.d3d1_ip,data.d1d3_ip):
            dict1 = {'config_type_list': ['neighbor'], 'remote_as': data.d3_as, 'neighbor': nbr_1,'vrf_name':vrf,'local_as':data.d1_as}
            dict2 = {'config_type_list': ['neighbor',"max_path_ebgp"], 'max_path_ebgp':1,'remote_as': data.d1_as, 'neighbor': nbr_2,'vrf_name':vrf,'local_as':data.d3_as}
            parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_api.config_bgp, [dict1, dict2])

        ##########################################################################
        hdrMsg("VRF-{} BGP-config: Configure eBGP neighbors between D1 and D4".format(vrf))
        ##########################################################################
        dict1 = {'config_type_list': ['neighbor'], 'remote_as': data.d4_as, 'neighbor': data.d4d1_ip,'vrf_name':vrf,'local_as':data.d1_as}
        dict2 = {'config_type_list': ['neighbor'], 'remote_as': data.d1_as, 'neighbor': data.d1d4_ip,'vrf_name':vrf,'local_as':data.d4_as}
        parallel.exec_parallel(True, [data.dut1, data.dut4], bgp_api.config_bgp, [dict1, dict2])

        ##########################################################################
        hdrMsg("VRF-{} BGP-config: Configure eBGP neighbors between D2 and D3".format(vrf))
        ##########################################################################
        dict1 = {'config_type_list': ['neighbor'], 'remote_as': data.d3_as, 'neighbor': data.d3d2_ip,'vrf_name':vrf,'local_as':data.d2_as}
        dict2 = {'config_type_list': ['neighbor'], 'remote_as': data.d2_as, 'neighbor': data.d2d3_ip,'vrf_name':vrf,'local_as':data.d3_as}
        parallel.exec_parallel(True, [data.dut2, data.dut3], bgp_api.config_bgp, [dict1, dict2])

        ##########################################################################
        hdrMsg("VRF-{} BGP-config: Configure eBGP neighbors between D2 and D4".format(vrf))
        ##########################################################################
        dict1 = {'config_type_list': ['neighbor'], 'remote_as': data.d4_as, 'neighbor': data.d4d2_ip,'vrf_name':vrf,'local_as':data.d2_as}
        dict2 = {'config_type_list': ['neighbor'], 'remote_as': data.d2_as, 'neighbor': data.d2d4_ip,'vrf_name':vrf,'local_as':data.d4_as}
        parallel.exec_parallel(True, [data.dut2, data.dut4], bgp_api.config_bgp, [dict1, dict2])

        ##########################################################################
        hdrMsg("BGP-config: Advertise route to multicast sources from dut1 and dut2 ")
        ##########################################################################
        dict1 = {'config_type_list': ['network'], 'network': '{}/{}'.format(data.mcast_source_nw[0],data.mask),'vrf_name':vrf,'local_as':data.d1_as}
        dict2 = {'config_type_list': ['network'], 'network': '{}/{}'.format(data.mcast_source_nw[1],data.mask),'vrf_name':vrf,'local_as':data.d2_as}
        parallel.exec_parallel(True, [data.dut1, data.dut2], bgp_api.config_bgp, [dict1, dict2])
        dict1 = {'config_type_list': ['network'], 'network': '{}/32'.format(data.d1_loopback_ip),'vrf_name': vrf,'local_as':data.d1_as}
        parallel.exec_parallel(True, [data.dut1], bgp_api.config_bgp, [dict1])
    else:
        ##########################################################################
        hdrMsg("VRF={} BGP-Deconfig: Delete BGP routers globally from all DUTs".format(vrf))
        ##########################################################################
        dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no','vrf_name':vrf,'local_as':data.d1_as}
        dict2 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'vrf_name': vrf,'local_as': data.d2_as}
        dict3 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'vrf_name': vrf,'local_as': data.d3_as}
        dict4 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no', 'vrf_name': vrf, 'local_as': data.d4_as}
        parallel.exec_parallel(True, data.dut_list, bgp_api.config_bgp, [dict1,dict2,dict3,dict4])


def config_igmp_pim(config='yes',vrf='default'):
    if vrf =='default':
        key_append = ''
        index = 0
        lag_23 = data.d3d2_lag_intf_1
        #d1d4_phy = data.d1d4_ports[0]
        #d4d1_phy = data.d4d1_ports[0]
        key_append =''
    else:
        key_append = '_vrf'
        index = 1
        lag_23 = data.d3d2_lag_intf_2
        #d1d4_phy = data.d1d4_ports[1]
        #d4d1_phy = data.d4d1_ports[1]

    d1_l3_list = [data['d1d2_vlan_intf' + key_append][0], data.d1tg_ports[index], data.d1d4_ports[index]] + data['d1d3_vlan_intf' + key_append] + [data['loopback'+ key_append]]
    d2_l3_list = [data['d1d2_vlan_intf' + key_append][0], data.d2tg_ports[index], data['d2d4_vlan_intf' + key_append][0],lag_23]
    d3_l3_list = data['d1d3_vlan_intf' + key_append] + [lag_23, data['d3d4_vlan_intf' + key_append][0], data['d3tg_vlan_intf' + key_append][0]] + [data['loopback'+ key_append]]
    d4_l3_list = [data.d4d1_ports[index], data['d2d4_vlan_intf' + key_append][0], data['d3d4_vlan_intf' + key_append][0],data.d4tg_ports[index]]

    ###################################################################
    hdrMsg("VRF {} : PIM-Config: Enable pim on all ip interfaces on all DUTs".format(vrf))
    ###################################################################

    dict1 = []
    for intf_lst in [d1_l3_list,d2_l3_list,d3_l3_list,d4_l3_list]:
        dict1.append({'pim_enable':'','intf':intf_lst,'config':config})
    parallel.exec_parallel(True,data.dut_list,pim_api.config_intf_pim,dict1)

    ###################################################################
    hdrMsg("VRF {} : IGMP-Config: Enable IGMP on L3 interface on D3 and D4 connected to Tgen ports".format(vrf))
    ###################################################################
    dict1 = {'intf':data['d3tg_vlan_intf'+key_append][0],'igmp_enable':'','config':config}
    dict2 = {'intf':data.d4tg_ports[index],'igmp_enable':'','config':config}
    parallel.exec_parallel(True,[data.dut3,data.dut4],igmp_api.config_igmp,[dict1,dict2])



def config_pim_hello(config='yes',vrf='default',hello=''):
    if vrf =='default':
        key_append = ''
        index = 0
        lag_23 = data.d3d2_lag_intf_1
        #d1d4_phy = data.d1d4_ports[0]
        #d4d1_phy = data.d4d1_ports[0]
        key_append =''
    else:
        key_append = '_vrf'
        index = 1
        lag_23 = data.d3d2_lag_intf_2
        #d1d4_phy = data.d1d4_ports[1]
        #d4d1_phy = data.d4d1_ports[1]

    d1_l3_list = [data['d1d2_vlan_intf' + key_append][0], data.d1tg_ports[index], data.d1d4_ports[index]] + data['d1d3_vlan_intf' + key_append] + [data['loopback'+ key_append]]
    d2_l3_list = [data['d1d2_vlan_intf' + key_append][0], data.d2tg_ports[index], data['d2d4_vlan_intf' + key_append][0],lag_23]
    d3_l3_list = data['d1d3_vlan_intf' + key_append] + [lag_23, data['d3d4_vlan_intf' + key_append][0], data['d3tg_vlan_intf' + key_append][0]] + [data['loopback'+ key_append]]
    d4_l3_list = [data.d4d1_ports[index], data['d2d4_vlan_intf' + key_append][0], data['d3d4_vlan_intf' + key_append][0],data.d4tg_ports[index]]

    dict1 = []
    for intf_lst in [d1_l3_list,d2_l3_list,d3_l3_list,d4_l3_list]:
        dict1.append({'hello_intv': hello,'intf':intf_lst,'config':config})
    parallel.exec_parallel(True,data.dut_list,pim_api.config_intf_pim,dict1)



def config_tgen(config='yes'):
    if config== 'yes':
        config_igmp_host()
        for handle in [data.tg_d1_handles[0],data.tg_d2_handles[0]]:
            config_mcast_stream(handle,vrf='default')
        for handle in [data.tg_d1_handles[1],data.tg_d2_handles[1]]:
            config_mcast_stream(handle,vrf=vrf_name)
        #config_host_source()
    else:
        ##########################################################################
        hdrMsg("TGEN-DeConfig: Delete Traffic Streams/hosts on all TG ports ")
        ##########################################################################
        data.tg1.tg_traffic_control(action='reset', port_handle=data.tg_d1_handles +data.tg_d2_handles)
        for key in data.host_handles.keys():
            if 'R1_default' in key or 'R2_default' in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key],port_handle=data.tg_d3_handles[0],mode='destroy')
            elif 'R1_{}'.format(vrf_name) in key or 'R2_{}'.format(vrf_name) in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key], port_handle=data.tg_d3_handles[1], mode='destroy')
            elif 'R3_default' in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key], port_handle=data.tg_d4_handles[0], mode='destroy')
            elif 'R3_{}'.format(vrf_name) in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key], port_handle=data.tg_d4_handles[1], mode='destroy')
            elif 'S1_host_default' in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key], port_handle=data.tg_d1_handles[0],mode='destroy')
            elif 'S1_host_{}'.format(vrf_name) in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key], port_handle=data.tg_d1_handles[1],mode='destroy')
            elif 'S2_host_default' in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key], port_handle=data.tg_d2_handles[0],mode='destroy')
            elif 'S2_host_{}'.format(vrf_name) in key:
                data.tg1.tg_interface_config(handle=data.host_handles[key], port_handle=data.tg_d2_handles[1],mode='destroy')



def config_host_source():
    S1_host = data.tg1.tg_interface_config(port_handle=data.tg_d1_handles[0], mode='config', intf_ip_addr=data.tgd1_ip, gateway=data.d1tg_ip,
                                 src_mac_addr=data.src_mac[data.tg_d1_handles[0]])
    data.host_handles['S1_host_default'] = S1_host['handle']
    S1_host_vrf = data.tg1.tg_interface_config(port_handle=data.tg_d1_handles[1], mode='config', intf_ip_addr=data.tgd1_ip, gateway=data.d1tg_ip,
                                 src_mac_addr=data.src_mac[data.tg_d1_handles[1]])
    data.host_handles['S1_host_{}'.format(vrf_name)] = S1_host_vrf['handle']

    S2_host = data.tg1.tg_interface_config(port_handle=data.tg_d2_handles[0], mode='config', intf_ip_addr=data.tgd2_ip, gateway=data.d2tg_ip,
                                 src_mac_addr=data.src_mac[data.tg_d2_handles[0]])
    data.host_handles['S2_host_default'] = S2_host['handle']
    S2_host_vrf = data.tg1.tg_interface_config(port_handle=data.tg_d2_handles[1], mode='config', intf_ip_addr=data.tgd2_ip, gateway=data.d2tg_ip,
                                 src_mac_addr=data.src_mac[data.tg_d2_handles[1]])
    data.host_handles['S2_host_{}'.format(vrf_name)] = S2_host_vrf['handle']

    data.tg1.tg_arp_control(handle=data.host_handles['S1_host_default'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.host_handles['S1_host_{}'.format(vrf_name)], arp_target='all')
    data.tg1.tg_arp_control(handle=data.host_handles['S2_host_default'], arp_target='all')
    data.tg1.tg_arp_control(handle=data.host_handles['S2_host_{}'.format(vrf_name)], arp_target='all')


def config_igmp_host():
    data.host_handles ={}
    data.igmp_sessions = {}
    ###################################################################
    hdrMsg("Default-vrf: HOST: Create 2 tagged Receivers on LHR1")
    ###################################################################
    R1 = data.tg1.tg_interface_config(port_handle=data.tg_d3_handles[0], mode='config', intf_ip_addr=data.tgd3_ip_1, gateway=data.d3tg_ip,
                                 arp_send_req='1', vlan='1', vlan_id=data.d3tg_vlan_id[0])


    R2 = data.tg1.tg_interface_config(port_handle=data.tg_d3_handles[0], mode='config', intf_ip_addr=data.tgd3_ip_2, gateway=data.d3tg_ip,
                                 arp_send_req='1', vlan='1', vlan_id=data.d3tg_vlan_id[0])


    data.host_handles['R1_default'] = R1['handle']
    data.host_handles['R2_default'] = R2['handle']

    R1_igmp_session = data.tg1.tg_emulation_igmp_config(handle=data.host_handles['R1_default'], mode='create', igmp_version='v3')
    R2_igmp_session = data.tg1.tg_emulation_igmp_config(handle=data.host_handles['R2_default'], mode='create', igmp_version='v3')

    data.igmp_sessions['R1_default_igmp'] = R1_igmp_session['host_handle']
    data.igmp_sessions['R2_default_igmp'] = R2_igmp_session['host_handle']
    ###################################################################
    hdrMsg("Default-vrf: HOST: Create 1 L3 receiver on LHR2")
    ###################################################################
    R3 = data.tg1.tg_interface_config(port_handle=data.tg_d4_handles[0], mode='config', intf_ip_addr=data.tgd4_ip, gateway=data.d4tg_ip,
                                 arp_send_req='1')
    data.host_handles['R3_default'] = R3['handle']
    R3_igmp_session = data.tg1.tg_emulation_igmp_config(handle=data.host_handles['R3_default'], mode='create',igmp_version='v3')
    data.igmp_sessions['R3_default_igmp'] = R3_igmp_session['host_handle']
    ###################################################################
    hdrMsg("{}: HOST: Create 2 tagged Receivers on LHR1".format(vrf_name))
    ###################################################################
    R1_vrf = data.tg1.tg_interface_config(port_handle=data.tg_d3_handles[1], mode='config', intf_ip_addr=data.tgd3_ip_1, gateway=data.d3tg_ip,
                                 arp_send_req='1', vlan='1', vlan_id=data.d3tg_vlan_id_vrf[0])


    R2_vrf = data.tg1.tg_interface_config(port_handle=data.tg_d3_handles[1], mode='config', intf_ip_addr=data.tgd3_ip_2, gateway=data.d3tg_ip,
                                 arp_send_req='1', vlan='1', vlan_id=data.d3tg_vlan_id_vrf[0])

    data.host_handles['R1_{}'.format(vrf_name)] = R1_vrf['handle']
    data.host_handles['R2_{}'.format(vrf_name)] = R2_vrf['handle']

    R1_igmp_session_vrf = data.tg1.tg_emulation_igmp_config(handle=data.host_handles['R1_{}'.format(vrf_name)], mode='create', igmp_version='v3')
    R2_igmp_session_vrf = data.tg1.tg_emulation_igmp_config(handle=data.host_handles['R2_{}'.format(vrf_name)], mode='create', igmp_version='v3')

    data.igmp_sessions['R1_{}_igmp'.format(vrf_name)] = R1_igmp_session_vrf['host_handle']
    data.igmp_sessions['R2_{}_igmp'.format(vrf_name)] = R2_igmp_session_vrf['host_handle']
    ###################################################################
    hdrMsg("{}: HOST: Create 1 L3 receiver on LHR2".format(vrf_name))
    ###################################################################

    R3_vrf = data.tg1.tg_interface_config(port_handle=data.tg_d4_handles[1], mode='config', intf_ip_addr=data.tgd4_ip, gateway=data.d4tg_ip,
                                 arp_send_req='1')
    data.host_handles['R3_{}'.format(vrf_name)] = R3_vrf['handle']
    R3_igmp_session_vrf = data.tg1.tg_emulation_igmp_config(handle=data.host_handles['R3_{}'.format(vrf_name)], mode='create', igmp_version='v3')
    data.igmp_sessions['R3_{}_igmp'.format(vrf_name)] = R3_igmp_session_vrf['host_handle']

    #config_tgen_source_pools()



def config_tgen_source_pools():
    for src in data.mcast_sources:
        source = data.tg1.tg_emulation_multicast_source_config(mode='create', ip_addr_start=src, num_sources=1)
        data.sources[src] = source['mul_source_handle']


def send_igmpv3_report(host='R1',groups=[],sources=[],filter='include',
        vrf='default',mode='join',remove_others='yes',group_incr_ip='0.0.0.1',
        group_prefix_len='32',group_incr='1',session=0,return_val='no'):
    #if vrf == 'default':
        #index = 0
    #else:
        #index = 1
    #if 'R1' or 'R2' in host:
        #tg_port = data.tg_d3_handles
    #else:
        #tg_port = data.tg_d4_handles
    session_handle= data.igmp_sessions['{}_{}_igmp'.format(host,vrf)]
    group_handle = config_igmp_groups(host,vrf,groups,sources,filter,
            remove_others,mode,group_incr_ip,group_prefix_len,group_incr)
    if 'ixia' in data.tgen_type:
        if mode !='leave':
            data.tg1.tg_emulation_igmp_control(handle=session_handle, mode='start')
    if session == 0:
        for s_g in group_handle:
            st.log("Sending IGMPv3 Report {} ".format(s_g))
            data.tg1.tg_emulation_igmp_control(mode=mode, handle=s_g)
    else:
        data.tg1.tg_emulation_igmp_control(mode=mode,handle=session_handle)
    if return_val == 'yes':
        return group_handle

def config_igmp_groups(host='R1',vrf='default',groups=[],sources=[],filter='include',
        remove_others='yes',mode='join',group_incr_ip='0.0.0.1',
        group_prefix_len='32',group_incr='1'):
    if type(groups) is not list : groups = [groups]
    if type(sources) is not list : sources = [sources]
    handle_list = []
    session_handle = data.igmp_sessions['{}_{}_igmp'.format(host,vrf)]
    if mode == 'leave' and filter =='include' and len(sources) != 0:
        key = '{}_{}_{}_{}_{}_{}_{}'.format(host, vrf, groups[0],groups[-1], sources[0], sources[-1], filter)
        if key in data.igmp_config.keys():
            handle_list.append(data.igmp_config[key])
        return handle_list
    elif mode == 'leave' and filter =='include' and len(sources) == 0:
        key = '{}_{}_{}_null_{}'.format(host, vrf, groups[0], filter)
        if key in data.igmp_config.keys():
            handle_list.append(data.igmp_config[key])
        return handle_list

    if remove_others == 'yes':
        data.tg1.tg_emulation_igmp_group_config(mode='clear_all', handle=session_handle)
        for key in data.igmp_config.keys():
            if host in key and  vrf in key:
                del data.igmp_config[key]

    if len(sources) != 0:
        key = '{}_{}_{}_{}_{}_{}_{}'.format(host,vrf,groups[0],groups[-1], sources[0], sources[-1],filter)
        source_list = data.tg1.tg_emulation_multicast_source_config(mode='create', ip_addr_start=data.mcast_sources[0], num_sources=len(sources),
                                                 ip_prefix_len=8, ip_addr_step=data.src_incr_ip,ip_addr_step_val=data.src_incr)
        source_handle = source_list['mul_source_handle']
        if key not in data.igmp_config.keys():
            group = data.tg1.tg_emulation_multicast_group_config(mode='create', ip_addr_start=groups[0], num_groups=len(groups),
                                                                 ip_prefix_len=group_prefix_len,ip_addr_step_val=group_incr,ip_addr_step=group_incr_ip)
            data.groups['{}_{}'.format(groups[0],groups[-1])] = group['mul_group_handle']
            group_handle = data.groups['{}_{}'.format(groups[0],groups[-1])]
            config = data.tg1.tg_emulation_igmp_group_config(mode='create', session_handle=session_handle,
                        group_pool_handle=group_handle, g_filter_mode=filter,source_pool_handle=source_handle)
            data.igmp_config[key] = config['group_handle']

        handle_list.append(data.igmp_config[key])
        data.igmp_group_all_handles[key]=data.igmp_config[key]
    else:
        src = 'null'
        for grp in groups:
            key = '{}_{}_{}_{}_{}'.format(host, vrf, grp,src, filter)
            if key not in data.igmp_config.keys():
                group = data.tg1.tg_emulation_multicast_group_config(mode='create', ip_addr_start=grp, num_groups=1)
                data.groups[grp] = group['mul_group_handle']
                group_handle = data.groups[grp]
                config = data.tg1.tg_emulation_igmp_group_config(mode='create', session_handle=session_handle,
                                                     group_pool_handle=group_handle, g_filter_mode=filter)
                data.igmp_config[key] = config['group_handle']
            handle_list.append(data.igmp_config[key])
            data.igmp_group_all_handles[key]= data.igmp_config[key]

    return handle_list



def config_mcast_stream(tg_handle,groups=data.igmp_group_list,vrf='default'):
    if tg_handle in data.tg_d1_handles:
        source= 'S1';src_ip = data.tgd1_ip
    else:
        source ='S2';src_ip = data.tgd2_ip

    if 'default' in vrf:
        port_handle2 = [data.tg_d3_handles[0],data.tg_d4_handles[0]]
    else:
        port_handle2 = [data.tg_d3_handles[1], data.tg_d4_handles[1]]

    for group in groups:
        ##########################################################################
        hdrMsg("TGEN: Configure Stream for Multicast group {} for VRF {}".format(group,vrf))
        ##########################################################################


        mcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[tg_handle], mac_dst= data.tg_mcast_mac[group], l2_encap='ethernet_ii',
                                             rate_pps=data.traffic_rate, \
                                             mode='create', port_handle=tg_handle, transmit_mode='continuous',
                                             l3_protocol='ipv4', ip_src_addr=src_ip , ip_dst_addr=group,port_handle2=port_handle2)
        data.stream_handles['{}_{}_{}'.format(group,source,vrf)] = mcast_stream['stream_id']
        data.stream_list.append(data.stream_handles['{}_{}_{}'.format(group,source,vrf)])
        data.stream_details[data.stream_handles['{}_{}_{}'.format(group,source,vrf)]] = "Multicast Traffic for {} - Source {} {} Rate:{} " \
                                                                             "fps".format(group,src_ip,source,data.traffic_rate)



def multicast_traffic(action='start',groups=data.igmp_group_list,source='S1',vrf='default'):
    if type(groups) is not list : groups = [groups]
    stream_handle = [data.stream_handles['{}_{}_{}'.format(group,source,vrf)] for group in groups]
    if action =='start': st.log(" #### Starting Multicast Traffic for  #####")
    if action == 'stop': st.log(" #### Stopping Multicast Traffic for  #####")
    for stream in stream_handle:
        st.log("HANDLE :{} ---> {}".format(stream,data.stream_details[stream]))
    if action == 'start':
        data.tg1.tg_traffic_control(action='clear_stats', port_handle=data.tg_handles)
        data.tg1.tg_traffic_control(action='run', stream_handle=stream_handle)
    else:
        data.tg1.tg_traffic_control(action='stop', stream_handle=stream_handle)



def verify_mcast_traffic(src_tg_obj=None,dest_tg_obj=None,src_port=None,dest_port=None,exp_ratio=1,comp_type='packet_rate',**kwargs):
    ret_val= True
    if type(src_port) is not list: src_port = [src_port]
    if type(dest_port) is not list: dest_port = [dest_port]
    if type(exp_ratio) is not list: exp_ratio = [exp_ratio]

    traffic_data = {
        '1': {
            'tx_ports': src_port,
            'tx_obj': [src_tg_obj]*len(src_port),
            'exp_ratio': exp_ratio *len(src_port),
            'rx_ports': dest_port,
            'rx_obj': [dest_tg_obj]*len(dest_port)

        }
    }

    mode = kwargs.get('mode','streamblock')
    if mode == 'streamblock' : traffic_data['1']['stream_list'] = kwargs['tx_stream_list']
    if 'delay' in kwargs:
        delay = kwargs['delay']
    else:
        delay =data.delay_factor
    for iteration in range(2):
        st.log("\n>>>>   ITERATION : {} <<<<<\n".format(iteration+1))
        aggregate_result = validate_tgen_traffic(traffic_details=traffic_data, mode=mode, comp_type=comp_type, delay_factor=delay,
                                                 tolerance_factor=2)
        if aggregate_result:
            st.log('Traffic verification passed ')
            ret_val = True
            break
        else:
            ret_val =False
            st.log('Traffic verification Failed ')
            continue
    return ret_val



def verify_lag():
    ###################################################################
    hdrMsg("Verify Port-Channels are UP on DUT1 and DUT3")
    ###################################################################
    ret_val = True;
    err_list = []
    result = retry_api(pc.verify_portchannel_state, data.dut1, portchannel=data.d1d3_lag_intf)
    if result is False:
        err_list.append("{} did not come up on dut1".format(data.d1d3_lag_intf))
        ret_val = False

    ###################################################################
    hdrMsg("Verify Port-Channels are UP on DUT2 and DUT3")
    ###################################################################
    result = retry_api(pc.verify_portchannel_state, data.dut2, portchannel=data.d3d2_lag_intf_1)
    if result is False:
        err_list.append("{} did not come up on dut2".format(data.d3d2_lag_intf_1))
        ret_val = False
    result = retry_api(pc.verify_portchannel_state, data.dut2, portchannel=data.d3d2_lag_intf_2)
    if result is False:
        err_list.append("{} did not come up on dut2".format(data.d3d2_lag_intf_2))
        ret_val = False
    if len(err_list) == 0:
        err_list.append('')
    return ret_val, err_list[0]


def verify_igp(igp=igp,vrf='default'):
    if igp == 'ospf':
        result = verify_ospf(vrf=vrf)
    else:
        result = verify_bgp(vrf=vrf)
    return result

def verify_ospf(vrf='default'):
    return True

def verify_bgp(vrf='default'):
    ###########################################################
    hdrMsg("VRF-{} BGP verify: Verify BGP sessions are up on dut1".format(vrf))
    ############################################################
    result = retry_api(ip_bgp.check_bgp_session,data.dut1,nbr_list=data.d1_nbrs,state_list=['Established']*len(data.d1_nbrs),vrf_name=vrf,retry_count=30,delay=1)
    #result = retry_api(ip_bgp.check_bgp_session,data.dut1,nbr_list=data.d1_nbrs,state_list=['Established']*len(data.d1_nbrs))

    if result is False:
        st.error("one or more BGP sessions did not come up on DUT1")
        return False
    ###########################################################
    hdrMsg("VRF-{} BGP verify: Verify BGP sessions are up on dut2".format(vrf))
    ############################################################
    result = retry_api(ip_bgp.check_bgp_session,data.dut2,nbr_list=data.d2_nbrs,state_list=['Established']*len(data.d2_nbrs),vrf_name=vrf,retry_count=30,delay=1)
    #result = retry_api(ip_bgp.check_bgp_session,data.dut2,nbr_list=data.d2_nbrs,state_list=['Established']*len(data.d2_nbrs))

    if result is False:
        st.error("one or more BGP sessions did not come up on DUT2")
        return False
    return True


def verify_pim_session(vrf='default'):
    ###########################################################
    hdrMsg("VRF-{} PIM verify: Verify PIM sessions are up on all duts".format(vrf))
    ############################################################
    dict1 = {'cmd_type': 'neighbor', 'neighbor': data.d1_nbrs, 'vrf':vrf}
    dict2 = {'cmd_type': 'neighbor', 'neighbor': data.d2_nbrs, 'vrf':vrf}
    dict3 = {'cmd_type': 'neighbor', 'neighbor': data.d3_nbrs, 'vrf':vrf}
    dict4 = {'cmd_type': 'neighbor', 'neighbor': data.d4_nbrs, 'vrf':vrf}
    dict_list = [dict1,dict2,dict3,dict4]
    result = retry_parallel(pim_api.verify_pim_show,dict_list, data.dut_list, retry_count=20,delay=1)
    return result

def get_pim_neighbor_count(dut,vrf='all'):

    output = pim_api.verify_pim_show(dut,cmd_type='neighbor',vrf=vrf,return_output='')
    ###########################################################
    hdrMsg(" PIM neighbor count for dut - {},VRF-{} is {} ".format(dut,vrf,len(output)))
    ############################################################
    return len(output)

def get_packet_count(dut,pkt_type='prune_tx',interface='',vrf='all'):
    output = pim_api.verify_pim_show(dut,cmd_type='interface traffic',vrf=vrf,return_output='')
    for item in output:
        if item['interface'] == interface:
            st.log("Interface {} : {} : {}".format(interface,pkt_type,item[pkt_type]))
            return item[pkt_type]


def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n %s \n######################################################################"%msg)

def failMsg(msg,tech_support=False,tc_name=''):
    st.error("\n++++++++++++++++++++++++++++++++++++++++++++++" \
    " \n FAILED : {} \n++++++++++++++++++++++++++++++++++++++++++++++".format(msg))
    if tech_support:
        st.generate_tech_support(dut=None,name=tc_name)
        debug_pim_failure()

def retry_api(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
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


def retry_parallel(func,dict_list=[],dut_list=[],retry_count=5,delay=1):
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        result = parallel.exec_parallel(True,dut_list,func,dict_list)
        if False not in result[0]:
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False


def retry_null_output(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        if len(func(args,**kwargs)) == 0:
            return True
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False

def retry_output_count(func,args,**kwargs):
    retry_count = kwargs.get("retry_count", 5)
    delay = kwargs.get("delay", 1)
    exp_count = kwargs.get("count", data.max_mroutes)
    if 'retry_count' in kwargs: del kwargs['retry_count']
    if 'delay' in kwargs: del kwargs['delay']
    if 'count' in kwargs: del kwargs['count']
    for i in range(retry_count):
        st.log("Attempt %s of %s" %((i+1),retry_count))
        output = func(args,**kwargs)
        if len(output) == exp_count:
            return True,output
        if retry_count != (i+1):
            st.log("waiting for %s seconds before retyring again"%delay)
            st.wait(delay)
    return False,output



def scale_pre_config():
    ############################
    hdrMsg("Scale Pre-Configs")
    ############################
    config_scale_test()
    config_vlan_scale()
    config_ip_scale()
    config_bgp_scale()
    config_pim_scale()
    config_tgen_scale()
    data.tg1.tg_traffic_control(action='run', stream_handle=data.scale_streams)
    config_pim_params()
    #config_igmp_params()
    for vrf in vrf_list: pim_api.config_pim_global(data.dut3, vrf=vrf, ecmp='', ecmp_rebalance='')
    ############################
    hdrMsg("Scale Pre-Configs End...")
    ############################

def scale_post_config():
    ############################
    hdrMsg("Scale Post-Configs")
    ############################
    #config_igmp_params(config='no')
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.scale_streams)
    for vrf in vrf_list: pim_api.config_pim_global(data.dut3, vrf=vrf, ecmp='', ecmp_rebalance='',config='no')
    for vrf in vrf_list:  send_igmpv3_report(host='R1', groups=data.dynamic_group_list_scale, sources=[data.tgd1_ip],
                                              filter='include', vrf=vrf, mode='leave', group_incr_ip='0.0.0.1',
                                              group_incr='1', group_prefix_len='32')
    config_pim_params(config='no')
    config_bgp_scale(config='no')
    config_pim_scale(config='no')
    config_ip_scale(config='no')
    config_vlan_scale(config='no')
    config_scale_test(config='yes')
    for intf in [data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]]:
        igmp_api.config_igmp(data.dut3,intf=intf,source=data.tgd1_ip,group=data.igmp_static_groups,join='',config='no')
    dict1= {'intf':data.d3d1_vlan_intf[0],'oif':data.d3tg_vlan_intf[0],'source':data.tgd1_ip,'group':data.static_mroute_groups,'config':'no','skip_error':True}
    dict2 = {'intf': data.d1tg_ports[0],'oif': data.d3d1_vlan_intf[0],'source': data.tgd1_ip, 'group': data.static_mroute_groups,'config':'no','skip_error':True}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])


    dict1= {'intf':data.d3d1_vlan_intf_vrf[0],'oif':data.d3tg_vlan_intf_vrf[0],'source':data.tgd1_ip,'group':data.static_mroute_groups,'config':'no','skip_error':True}
    dict2 = {'intf': data.d1tg_ports[1],'oif': data.d3d1_vlan_intf_vrf[0],'source': data.tgd1_ip, 'group': data.static_mroute_groups,'config':'no','skip_error':True}
    parallel.exec_parallel(True, [data.dut3, data.dut1], pim_api.config_ip_mroute, [dict1,dict2])


    ############################
    hdrMsg("Scale Post-Configs End...")
    ############################


def verify_pim_scale():
    err_list=[]
    tc_result = True
    tech_support = data.tech_support_on_fail

    #############################################################
    hdrMsg("Step: Verify non-default PIM parameters ")
    #############################################################
    result,err = verify_pim_params()
    if result is False:
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        err_list.append(err);tc_result=False
        return tc_result,err
    """
    #############################################################
    hdrMsg("Step: Verify non-default PIM parameters ")
    #############################################################
    result,err = verify_igmp_params()
    if result is False:
        failMsg(err,debug='no')
        err_list.append(err);tc_result=False
        return tc_result,err
    """
    #############################################################
    hdrMsg("Step: Verify all {} PIM neighbors are UP ".format(data.max_pim_nbrs))
    #############################################################
    result,_ = retry_output_count(pim_api.verify_pim_show,data.dut3,cmd_type='neighbor',vrf = 'all',count=data.max_pim_nbrs,
                                return_output='',retry_count=15,delay=3)
    if result is False:
        err = 'Max configured {} PIM neighbors not up'.format(data.max_pim_nbrs)
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        return tc_result,err

    #############################################################
    hdrMsg("Step: Verify BFD over PIM is UP")
    #############################################################
    for nbr in data.d3d1_vlan_intf:
        result = retry_api(pim_api.verify_pim_show, data.dut3, cmd_type='neighbor {}'.format(nbr),
                       bfd_status='Up', retry_count=12, delay=10)
        if result is False:
            err = 'BFD session not up on PIM interface {}'.format(nbr)
            err_list.append(err);tc_result=False;
            failMsg(err, tech_support, tc_name='pim_scale_onfail');
            tech_support = False;

    for nbr in data.d3d1_vlan_intf_vrf:
        result = retry_api(pim_api.verify_pim_show, data.dut3, cmd_type='neighbor {}'.format(nbr),
                       bfd_status='Up', vrf=vrf_name, retry_count=12, delay=10)
        if result is False:
            err = 'BFD session not up on PIM interface {}'.format(nbr)
            err_list.append(err);tc_result=False
            failMsg(err, tech_support, tc_name='pim_scale_onfail');
            tech_support = False;

    #############################################################
    hdrMsg("Step: Verify all multicast {} groups are programmed in IGMP table ".format(data.max_mroutes))
    #############################################################

    result = retry_api(pim_api.grep_total_count, data.dut3, cmd='show ip igmp vrf all groups', grep='INCL',
                       exp_count=data.max_igmp,retry_count=15,delay=25)
    if result is False:
        err = 'Max dynamic IGMP groups {} not learnt'.format(data.max_igmp)
        err_list.append(err);tc_result=False;
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        return tc_result,err
    #############################################################
    hdrMsg("Step: Verify RPF nexthop is resolved for all Multicast groups on both default and user-vrf")
    #############################################################
    """
    for vrf in vrf_list:
        oif_dict = get_oif_dict(vrf)
        if len(oif_dict.keys()) == 0 or len(oif_dict.keys()) != (data.mroute_count_per_vrf-(data.static_mroute/2)):
            err = 'RPF nexthop not resolved for {} multicast groups on {}'.format(data.mroute_count_per_vrf,vrf)
            err_list.append(err);tc_result=False;failMsg(err,debug='no')
            return tc_result, err
    """

    result = retry_api(pim_api.grep_total_count, data.dut3, cmd='show ip pim rpf', grep='none',
                       exp_count=0,retry_count=15,delay=25)
    if result is False:
        err = 'RPF nexthops not resolved for all {} groups on default vrf '.format(data.max_igmp/2)
        err_list.append(err);tc_result=False;
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        return tc_result,err

    result = retry_api(pim_api.grep_total_count, data.dut3, cmd='show ip pim vrf {} rpf'.format(vrf_name), grep='none',
                       exp_count=0,retry_count=15,delay=25)
    if result is False:
        err = 'RPF nexthops not resolved for all {} groups on user vrf '.format(data.max_igmp/2)
        err_list.append(err);tc_result=False;
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        return tc_result,err

    """
    #############################################################
    hdrMsg("Step: Verify {} mroute entries programmed on LHR node".format(data.max_mroutes))
    #############################################################
    result,output = retry_output_count(pim_api.verify_ip_mroute,data.dut3,vrf='all',return_output='',retry_count=15,delay=3,
                                       count=data.max_mroutes)
    if result is False:
        err = 'Max mroutes {} not installed on LHR node '.format(data.max_mroutes)
        err_list.append(err);tc_result=False;failMsg(err)
        return tc_result, err

    #############################################################
    hdrMsg("Step: Verify {} mroute entries programmed on FHR node".format(data.max_mroutes))
    #############################################################
    result,output = retry_output_count(pim_api.verify_ip_mroute,data.dut1,vrf='all',return_output='',retry_count=15,delay=3,
                                       count=data.max_mroutes)
    if result is False:
        err = 'Max mroutes {} not installed on FHR node '.format(data.max_mroutes)
        err_list.append(err);tc_result=False;failMsg(err)
        return tc_result, err

    """
    #############################################################
    hdrMsg("Step: Verify IP multicast table to get the total mroute entries installed on LHR and FHR nodes across VRFs ")
    #############################################################
    dict1 = [{'tot_mcast_routes': data.mroute_count_per_vrf,'tot_mcast_routes_ac':data.max_mroutes,'skip_error':True}]
    result = retry_parallel(pim_api.verify_ip_multicast, dict1 * 2, [data.dut3,data.dut1], retry_count=15, delay=10)
    if result is False:
        err = 'Max mroutes {} not installed on LHR node '.format(data.max_mroutes)
        err_list.append(err);tc_result=False;
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        return tc_result, err

    #############################################################
    hdrMsg("Step: Verify Multicast traaffic for all {} multicast groups on default-vrf".format(data.mroute_count_per_vrf))
    #############################################################

    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[0]],
                                  dest_port=data.tgd3_ports[0], exp_ratio=1,delay=2,mode='aggregate')
    if result is False:
        err = 'Multicast Traffic failed on default-vrf with {} mroute entries installed '.format(data.mroute_count_per_vrf)
        err_list.append(err);tc_result=False;
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        return tc_result, err

    #############################################################
    hdrMsg("Step: Verify Multicast traaffic for all {} multicast groups on user-vrf".format(data.mroute_count_per_vrf))
    #############################################################
    result = verify_mcast_traffic(data.tg1, data.tg1, src_port=[data.tgd1_ports[1]],
                                  dest_port=data.tgd3_ports[1], exp_ratio=1,delay=2,mode='aggregate')
    if result is False:
        err = 'Multicast Traffic failed on user-vrf with {} mroute entries installed '.format(data.mroute_count_per_vrf)
        err_list.append(err);tc_result=False;
        failMsg(err, tech_support, tc_name='pim_scale_onfail');
        tech_support = False;
        return tc_result, err

    if tc_result is True:
        err_list.append(' ')
    return tc_result,err_list[0]

def config_vlan_scale(config='yes'):

    if config == 'yes':
        ###################################################################
        hdrMsg("Vlan-Config: Configure Vlans {} on D1,D2 ,D3 and D4".format(data.d1d3_vlan_id_scale[2:]))
        ###################################################################
        utils.exec_all(True, [[vlan_api.config_vlan_range, data.dut1,'{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])],
                              [vlan_api.config_vlan_range, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])],
                              [vlan_api.config_vlan_range, data.dut2,'{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])],
                              [vlan_api.config_vlan_range, data.dut4,'{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])]])


        ###################################################################
        hdrMsg("Vlan-Config: Configure lag port {} between D1 and D3 as tagged on all vlans {} to {} ".format(data.lag_intf_list[0],
                                                                                                  data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]))
        ###################################################################
        utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut1, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])
                                  ,[data.lag_intf_list[0]]],
                              [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),
                                [data.lag_intf_list[0]]]])

        ###################################################################
        hdrMsg("Vlan-Config: Configure lag port {} between D2 and D3 as tagged on all vlans {} to {} ".format(data.lag_intf_list[1],
                                                                                                  data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]))
        ###################################################################
        utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut2, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])
                                  ,[data.lag_intf_list[1]]],
                              [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),
                                [data.lag_intf_list[1]]]])

        ###################################################################
        hdrMsg("Vlan-Config: Configure port between D4 and D3 as tagged on all vlans {} to {} ".format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]))
        ###################################################################
        utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])
                                  ,[data.d3d4_ports[0]]],
                              [vlan_api.config_vlan_range_members, data.dut4, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),
                                [data.d4d3_ports[0]]]])

    else:
        ###################################################################
        hdrMsg("Vlan-DeConfig: Remove all Vlan membership from ports ")
        ###################################################################
        utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut1, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])
                                  ,[data.lag_intf_list[0]],'del'],
                              [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),
                                [data.lag_intf_list[0]],'del']])

        utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut2, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])
                                  ,[data.lag_intf_list[1]],'del'],
                              [vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),
                                [data.lag_intf_list[1]],'del']])

        utils.exec_all(True, [[vlan_api.config_vlan_range_members, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1])
                                  ,[data.d3d4_ports[0]],'del'],
                              [vlan_api.config_vlan_range_members, data.dut4, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),
                                [data.d4d3_ports[0]],'del']])

        ###################################################################
        hdrMsg("Vlan-DeConfig: Delete all configured Vlans from  DUTs")
        ###################################################################
        utils.exec_all(True, [[vlan_api.config_vlan_range, data.dut1,'{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),'del'],
                              [vlan_api.config_vlan_range, data.dut2,'{} {}'.format(data.d1d3_vlan_id_scale[2], data.d1d3_vlan_id_scale[-1]), 'del'],
                              [vlan_api.config_vlan_range, data.dut3, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]), 'del'],
                              [vlan_api.config_vlan_range, data.dut4, '{} {}'.format(data.d1d3_vlan_id_scale[2],data.d1d3_vlan_id_scale[-1]),'del']])

def config_ip_scale(config='yes'):
    if config == 'yes':
        api_name = ip_api.config_ip_addr_interface
        config_str = "Configure"
    else:
        api_name = ip_api.delete_ip_interface
        config_str = "Delete"


    ###################################################################
    hdrMsg("IP-Config: {} ip addresses between D1 ,D2 D4 and D3 on all configured scale Vlans".format(config_str))
    ###################################################################
    for vlan,d1_ip,d2_ip,d3_ip,d4_ip in zip(data.d1d3_vlan_intf_scale[2:],data.d1d3_ip_scale[2:],data.d2d3_ip_scale,
                                            data.d3d1_ip_scale[2:],data.d4d3_ip_scale):
        utils.exec_all(True, [[api_name, data.dut1,vlan,d1_ip, data.mask],
                              [api_name, data.dut2, vlan, d2_ip, data.mask],
                              [api_name, data.dut3, vlan, d3_ip, data.mask],
                          [api_name, data.dut4,vlan, d4_ip, data.mask]])



def config_pim_scale(config='yes'):
    dict1 = []
    for intf_lst in [data.d1d3_vlan_intf_scale[2:]]*4:
        dict1.append({'pim_enable':'','intf':intf_lst,'config':config})
    parallel.exec_parallel(True,[data.dut1,data.dut2,data.dut3,data.dut4],pim_api.config_intf_pim,dict1)
    if config == 'yes':
        dict1 =[]
        for intf_lst in [data.d1d3_vlan_intf_scale[0:2]+data.d1d3_vlan_intf_vrf] * 2:
            dict1.append({'intf': intf_lst, 'config': config,'bfd_enable':'yes'})
        parallel.exec_parallel(True, [data.dut1,data.dut3], pim_api.config_intf_pim, dict1)

def config_bgp_scale(config='yes'):
    ##########################################################################
    hdrMsg("BGP-Scale-config: Configure eBGP neighbors between D1 and D3")
    ##########################################################################
    for nbr_1, nbr_2 in zip(data.d3d1_ip_scale[2:], data.d1d3_ip_scale[2:]):
        dict1 = {'config_type_list': ['neighbor'],'local_as':data.d1_as ,'remote_as': data.d3_as, 'neighbor': nbr_1, 'config':config}
        dict2 = {'config_type_list': ['neighbor'],'remote_as': data.d1_as,'local_as':data.d3_as, 'neighbor': nbr_2, 'config': config}
        parallel.exec_parallel(True, [data.dut1, data.dut3], bgp_api.config_bgp, [dict1, dict2])

    for vrf in vrf_list: bgp_api.config_bgp(data.dut3,config_type_list=["max_path_ebgp"],max_path_ebgp='32',local_as=data.d3_as,config=config,vrf_name=vrf)

def config_tgen_scale(config='yes'):
    if config == 'yes':
        data.scale_streams = []
        if data.tgen_type == 'ixia':
            mcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tg_d1_handles[0]], mac_dst_mode='list',
                                                      mac_dst=data.dest_mac_list_scale,
                                                      l2_encap='ethernet_ii',rate_pps=data.scale_traffic_rate,
                                                      mode='create', port_handle=data.tg_d1_handles[0], transmit_mode='continuous',
                                                      l3_protocol='ipv4', ip_src_addr=data.tgd1_ip, ip_dst_addr=data.ssm_group_list[0],
                                                      ip_dst_mode='increment',ip_dst_count=data.mroute_count_per_vrf)
            data.scale_stream_default = mcast_stream['stream_id']
            data.scale_streams.append(data.scale_stream_default)

            mcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tg_d1_handles[1]], mac_dst_mode='list',
                                                      mac_dst=data.dest_mac_list_scale,
                                                      l2_encap='ethernet_ii',rate_pps=data.scale_traffic_rate,
                                                      mode='create', port_handle=data.tg_d1_handles[1], transmit_mode='continuous',
                                                      l3_protocol='ipv4', ip_src_addr=data.tgd1_ip, ip_dst_addr=data.ssm_group_list[0],
                                                      ip_dst_mode='increment',ip_dst_count=data.mroute_count_per_vrf)
            data.scale_stream_vrf = mcast_stream['stream_id']
            data.scale_streams.append(data.scale_stream_vrf)
        else:
            mcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tg_d1_handles[0]],
                                                      mac_dst=data.dest_mac_list_scale_spirent_1,
                                                      l2_encap='ethernet_ii', rate_pps=data.scale_traffic_rate,
                                                      mode='create', port_handle=data.tg_d1_handles[0],
                                                      transmit_mode='continuous',
                                                      l3_protocol='ipv4', ip_src_addr=data.tgd1_ip,
                                                      ip_dst_addr=data.ssm_group_list[0],
                                                      ip_dst_mode='increment', ip_dst_count=data.mroute_count_per_vrf/2)
            data.scale_stream_default = mcast_stream['stream_id']
            data.scale_streams.append(data.scale_stream_default)

            mcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tg_d1_handles[0]],
                                                      mac_dst=data.dest_mac_list_scale_spirent_2,
                                                      l2_encap='ethernet_ii', rate_pps=data.scale_traffic_rate,
                                                      mode='create', port_handle=data.tg_d1_handles[0],
                                                      transmit_mode='continuous',
                                                      l3_protocol='ipv4', ip_src_addr=data.tgd1_ip,
                                                      ip_dst_addr=data.group_list_scale[data.mroute_count_per_vrf/2],
                                                      ip_dst_mode='increment', ip_dst_count=data.mroute_count_per_vrf/2)
            data.scale_stream_default = mcast_stream['stream_id']
            data.scale_streams.append(data.scale_stream_default)
            mcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tg_d1_handles[1]],
                                                      mac_dst=data.dest_mac_list_scale_spirent_1,
                                                      l2_encap='ethernet_ii', rate_pps=data.scale_traffic_rate,
                                                      mode='create', port_handle=data.tg_d1_handles[1],
                                                      transmit_mode='continuous',
                                                      l3_protocol='ipv4', ip_src_addr=data.tgd1_ip,
                                                      ip_dst_addr=data.ssm_group_list[0],
                                                      ip_dst_mode='increment', ip_dst_count=data.mroute_count_per_vrf/2)
            data.scale_stream_vrf = mcast_stream['stream_id']
            data.scale_streams.append(data.scale_stream_vrf)

            mcast_stream = data.tg1.tg_traffic_config(mac_src=data.src_mac[data.tg_d1_handles[1]],
                                                      mac_dst=data.dest_mac_list_scale_spirent_2,
                                                      l2_encap='ethernet_ii', rate_pps=data.scale_traffic_rate,
                                                      mode='create', port_handle=data.tg_d1_handles[1],
                                                      transmit_mode='continuous',
                                                      l3_protocol='ipv4', ip_src_addr=data.tgd1_ip,
                                                      ip_dst_addr=data.group_list_scale[data.mroute_count_per_vrf/2],
                                                      ip_dst_mode='increment', ip_dst_count=data.mroute_count_per_vrf/2)
            data.scale_stream_vrf = mcast_stream['stream_id']
            data.scale_streams.append(data.scale_stream_vrf)



def config_scale_test(config='no'):
    if config == 'no':
        api_name = ip_api.delete_ip_interface
        port_api.shutdown(data.dut1, data.d1d2_ports + data.d1d4_ports)
        port_api.shutdown(data.dut2, data.d2d4_ports)
    else:
        api_name = ip_api.config_ip_addr_interface
        port_api.noshutdown(data.dut1, data.d1d2_ports + data.d1d4_ports)
        port_api.noshutdown(data.dut2, data.d2d4_ports)

    dict1 = {'pim_enable':'','intf':[data.d3d2_lag_intf_1,data.d3d2_lag_intf_2,data.d3d4_vlan_intf[0],data.d3d4_vlan_intf_vrf[0]],'config':config}
    dict2 = {'pim_enable':'','intf':[data.d3d2_lag_intf_1,data.d3d2_lag_intf_2],'config':config}
    dict3 = {'pim_enable':'','intf':[data.d3d4_vlan_intf[0],data.d3d4_vlan_intf_vrf[0]],'config':config}
    parallel.exec_parallel(True,[data.dut3,data.dut2,data.dut4],pim_api.config_intf_pim,[dict1,dict2,dict3])


    # Remove ip address fromm L3 lag
    utils.exec_all(True, [[api_name, data.dut2,data.d3d2_lag_intf_1 , data.d2d3_ip, data.mask],
                          [api_name, data.dut3,data.d3d2_lag_intf_1, data.d3d2_ip, data.mask]])

    utils.exec_all(True, [[api_name, data.dut2,data.d3d2_lag_intf_2 , data.d2d3_ip, data.mask],
                          [api_name, data.dut3,data.d3d2_lag_intf_2, data.d3d2_ip, data.mask]])

    utils.exec_all(True, [[api_name, data.dut3, data['d3d4_vlan_intf'][0], data.d3d4_ip, data.mask],
                          [api_name, data.dut4, data['d3d4_vlan_intf'][0], data.d4d3_ip, data.mask]])

    utils.exec_all(True, [[api_name, data.dut3, data['d3d4_vlan_intf_vrf'][0], data.d3d4_ip, data.mask],
                          [api_name, data.dut4, data['d3d4_vlan_intf_vrf'][0], data.d4d3_ip, data.mask]])


def config_pim_params(config='yes'):

    dut_pair = [data.dut1, data.dut3]
    parallel.exec_parallel(True, dut_pair, pim_api.config_pim_global,
                            [{'join_prune_interval': data.join_prune_int,
                              'config': config,'skip_error':True,'maxtime':data.maxtime}] * 2)
    if config == 'yes':
        for key_append,hello_int in zip(['', '_vrf'],[data.hello_interval,data.hello_interval_vrf]):
            dict1 = []
            dict1.append({'intf': data['d1d3_vlan_intf' + key_append][0], 'hello_intv': hello_int,
                          'config' : config,'skip_error':True,'maxtime':data.maxtime})
            parallel.exec_parallel(True, dut_pair, pim_api.config_intf_pim, dict1*2)
    else:
        for key_append,hello_int in zip(['', '_vrf'],[data.hello_interval,data.hello_interval_vrf]):
            dict1 = []
            dict1.append({'intf': data['d1d3_vlan_intf' + key_append][0], 'hello_intv': '','config' : config})
            parallel.exec_parallel(True, dut_pair, pim_api.config_intf_pim, dict1*2)



def config_igmp_params(config='yes'):
    if config == 'yes':
        igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],
                        query_max_response=250,query_interval=200,
                        last_member_query_interval=12,last_member_query_count=4)
    else:
        igmp_api.config_igmp(data.dut3,intf=[data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],
                        query_max_response='',query_interval='',
                        last_member_query_interval='',last_member_query_count='',config='no')

def verify_igmp_params():
    for intf,vrf in zip([data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],vrf_list):
        result = igmp_api.verify_igmp_interface(data.dut3, interface=intf, query_interval=30,
                                            last_member_query_count=4,vrf=vrf,skip_error=True)
        if result is False:
            err ="IGMP params are incorrect"
            return False,err
    return True,' '

def verify_pim_params():
    ret_val = True;
    err_list = []
    dut_pair = [data.dut1, data.dut3]

    #############################################################
    hdrMsg("Verify PIM hello interval and hold timers")
    #############################################################
    for key_append, hello_int ,vrf in zip(['', '_vrf'], [data.hello_interval, data.hello_interval_vrf],vrf_list):
        dict1 = [{'interface': data['d1d3_vlan_intf' + key_append][0], 'period': hello_int,'vrf':vrf,'skip_error':True}]
        result = retry_parallel(pim_api.verify_pim_interface_detail, dict1 * 2, dut_pair, retry_count=3, delay=1)
        if result is False:
            err = "PIM hello interval verification failed."
            failMsg(err);
            err_list.append(err);
            ret_val = False

    #############################################################
    hdrMsg("Verify Global PIM Join-Prune interval timers")
    #############################################################
    dict1 = [{'upstream_join_timer': data.join_prune_int,'skip_error':True}]
    result = retry_parallel(pim_api.verify_ip_multicast, dict1 * 2, dut_pair, retry_count=2, delay=1)

    if result is False:
        err = "PIM global Join-Prune interval verification failed."
        failMsg(err);
        err_list.append(err);
        ret_val = False
    if ret_val is True:
        err_list.append(' ')
    return ret_val, err_list[0]


def get_oif_dict(vrf='default'):
    group_iif = {}
    data.scale_iif = []
    _,output = retry_output_count(pim_api.verify_pim_show,data.dut3,cmd_type ='rpf',return_output='',vrf=vrf,
                                       count=(data.mroute_count_per_vrf-data.static_mroute_vrf))
    if len(output) != 0:
        for i in range(len(output)):
            data.scale_iif.append(output[i]['rpfiface'])
            group_iif['{}_{}'.format(vrf,output[i]['group'])] = data.scale_iif[i]
    return group_iif

def ip2mac(mcast_ip):
    mcast_mac =  '01:00:5E:'
    octets = mcast_ip.split('.')
    second_oct = int(octets[1]) & 127
    third_oct = int(octets[2])
    fourth_oct = int(octets[3])
    mcast_mac = mcast_mac + format(second_oct,'02x') + ':' + format(third_oct, '02x') + ':' + format(fourth_oct, '02x')
    return mcast_mac


def get_scale_mac_list_to_str(mac_list):
    mac_str = ""
    for mac in mac_list:
        mac_str += mac +" "
    return mac_str.strip()

def ip_to_int(ipstr):
    return struct.unpack('!I', socket.inet_aton(ipstr))[0]


def int_to_ip(n):
    return socket.inet_ntoa(struct.pack('!I', n))

def incr_ipv4(ipaddr, mask=32, step=1):
    # To separate the mask if provided with ip.
    ipaddr,save_mask = [ipaddr, ''] if ipaddr.find('/') == -1 else ipaddr.split('/')
    ip_int = ip_to_int(ipaddr)
    # Saving the diff value.
    ip_int_old = ip_int
    ip_int >>= 32 - mask
    ip_int <<= 32 - mask
    ip_diff = ip_int_old - ip_int
    # Actual logic.
    ip_int >>= 32 - mask
    ip_int += step
    ip_int <<= 32 - mask
    ip_int += ip_diff
    ipaddr = int_to_ip(ip_int)
    ipaddr = '/'.join([ipaddr,save_mask]) if save_mask != '' else ipaddr
    return ipaddr

def range_ipv4(start_ip, count, mask=32):
    ip_list = []
    for _ in range(count):
        ip_list.append(start_ip)
        start_ip = incr_ipv4(start_ip, mask)
    return ip_list


def get_missing_entries(output,key='group'):
    parsed_group_list = [output[i][key] for i in range(len(output))]
    not_found_list = []
    for grp in data.group_list_scale:
        if grp not in parsed_group_list:
            not_found_list.append(grp)
    return not_found_list


def debug_enable(config='yes'):
    dict_list = [{'type_list': ['events', 'nht', 'packet_dump', 'packets', 'trace', 'trace_detail', 'zebra'],
                  'direction': 'both', 'pkt_type' : 'all','config':config}]*4
    parallel.exec_parallel(True, data.dut_list, pim_api.debug_pim, dict_list)
    dict_list = [{'config':config}] * 4
    parallel.exec_parallel(True, data.dut_list, igmp_api.debug_igmp, dict_list)
    utils.exec_all(True, [[basic_api.debug_bfdconfig_using_frrlog,data.dut1,config,'bfd.log'],
                          [basic_api.debug_bfdconfig_using_frrlog,data.dut2,config,'bfd.log'],
                          [basic_api.debug_bfdconfig_using_frrlog,data.dut3,config,'bfd.log'],
                          [basic_api.debug_bfdconfig_using_frrlog,data.dut4,config,'bfd.log']])


def debug_pim_failure():
    hdrMsg('Debug commands starts!')
    for intf,vrf in zip([data.d3tg_vlan_intf[0],data.d3tg_vlan_intf_vrf[0]],vrf_list):
        igmp_api.verify_igmp_stats(data.dut3, vrf=vrf,interface=intf,return_output='',skip_error=True,skip_tmpl=True)
    dict_list = [{'vrf':'all','return_output':'','skip_error':True}]*2
    parallel.exec_parallel(True,[data.dut3,data.dut1],pim_api.verify_ip_multicast, dict_list)
    parallel.exec_foreach(True, data.dut_list, debug_pim_failure_per_dut)
    hdrMsg('End of Debug commands')


def debug_pim_failure_per_dut(dut):
    pim_api.verify_ip_mroute(dut,skip_tmpl=True,skip_error=True,return_output='')
    pim_api.verify_pim_show(dut,cmd_type='neighbor',vrf='all',skip_tmpl=True,skip_error=True,return_output='')
    pim_api.verify_pim_show(dut, cmd_type='state', vrf='all', skip_tmpl=True, skip_error=True, return_output='')
    pim_api.verify_pim_show(dut, cmd_type='upstream', vrf='all', skip_tmpl=True, skip_error=True, return_output='')
    pim_api.verify_pim_show(dut, cmd_type='rpf', vrf='all', skip_tmpl=True, skip_error=True, return_output='')
    igmp_api.verify_igmp_interface(dut,vrf='all',interface='detail',skip_tmpl=True, skip_error=True, return_output='')
    ip_api.get_interface_ip_address(dut)
    ip_api.get_interface_ip_address(dut,family='ipv6')
    ip_api.show_ip_route(dut)
    ip_api.show_ip_route(dut,vrf_name=vrf_name)
    ip_api.show_ip_route(dut,family='ipv6')
    ip_api.show_ip_route(dut, family='ipv6',vrf_name=vrf_name)
    asicapi.dump_ipmc_table(dut)
    asicapi.dump_multicast(dut)

