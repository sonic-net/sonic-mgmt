#############################################################################
#Script Title : L3 Scale Enhancement
#Author       : Meenal Annamalai
#Mail-id      : meenal.annamalai@broadcom.com
#############################################################################
import pytest
import datetime
import random
import re

from spytest import st, utils
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import *

import apis.routing.ip as ipfeature
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.system.port as port_obj
import apis.system.basic as basic_obj
import apis.routing.bgp as bgp_obj
import apis.routing.arp as arp_api
from apis.system import port
import apis.system.reboot as reboot_api
import apis.common.asic_bcm as asicapi

from L3SclEnhancement_vars import *
#from L3SclEnhancement_lib import *
from L3SclEnhancement_lib import ipv6_list, ip_range, get_handles, hdrMsg
from L3SclEnhancement_lib import retry_api
from L3SclEnhancement_lib import verify_arp_count
from L3SclEnhancement_lib import verify_bgp_nbr_count
from L3SclEnhancement_lib import verify_ipv6_bgp_nbr_count
from L3SclEnhancement_lib import verify_ndp_count
from L3SclEnhancement_lib import verify_ipv6_route_count_hardware
from L3SclEnhancement_lib import verify_route_count_hardware

from utilities import parallel

vars = dict()

@pytest.fixture(scope='module', autouse = True)
def L3ScaleEnhancement_Prologue_Epilogue(request):
    global tg1
    global tg2
    global tg3
    global tg4
    global tg_ph_1
    global tg_ph_2
    global tg_ph_3
    global tg_ph_4
    global plat_name
    global all_triggers_flag
    global tr1
    global tr2
    global tr3
    global tr4
    global vars
    st.log("Initialize.............................................................................................................")
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:2")
    #Declaring Global Variables
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg3 = tgen_obj_dict[vars['tgen_list'][0]]
    tg4 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg1.get_port_handle(vars.T1D2P1)
    tg_ph_3 = tg2.get_port_handle(vars.T1D1P2)
    tg_ph_4 = tg2.get_port_handle(vars.T1D2P2)
    plat_name = basic_obj.get_hwsku(vars.D1)
    all_triggers_flag = 0
    tr1 = {}
    tr2 = {}
    tr3 = {}
    tr4 = {}

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    ############################################################################################
    hdrMsg("\n####### Check platform and update the scale numbers ##############\n")
    ############################################################################################
    if "7816" in plat_name:
       globals().update(TH2)
    elif "7712" in plat_name:
       globals().update(TH)
    elif "7326" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "5712" in plat_name:
       globals().update(TD2)
    elif "IX4" in plat_name:
       globals().update(TH2)
    elif "S5232f-C32" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "Z9332f" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "IX8" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "IX9" in plat_name:
       globals().update(TH2)
    elif "9716" in plat_name:
       globals().update(TH2)
    elif "7726" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "9032v1" in plat_name:
       globals().update(TH)
    elif "IX1B" in plat_name:
       globals().update(TH)
    elif "S5248f" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "S5296f" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "5835" in plat_name:
       globals().update(TD3)
       st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "IX8A" in plat_name:
        globals().update(TD3)
        st.exec_all([[ipfeature.config_system_max_routes, dut1], [ipfeature.config_system_max_routes, dut2]])
    elif "Z9264f" in plat_name:
       globals().update(TH2)
    else:
       st.report_fail('platform_check_fail',plat_name)
       pytest.skip('Platform check failed!! Aborting Base config! Support Platforms - 7816, 5712, 7712 and 7326')

    st.log("Platform is {}".format(plat_name))

    ############################################################################################
    hdrMsg("\n########## Enable debugs ############\n")
    ############################################################################################
    enable_debugs()

    ############################################################################################
    hdrMsg("\n####### Configure IP address on link1 between DUT1 and DUT2 ##############\n")
    ############################################################################################
    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1, vars.D1D2P1, data.d1d2_1_ip_addr, data.mask],[ipfeature.config_ip_addr_interface,dut2, vars.D2D1P1, data.d2d1_1_ip_addr, data.mask]])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1, vars.D1D2P1, data.d1d2_ipv6_addr, data.maskv6,'ipv6'],[ipfeature.config_ip_addr_interface, dut2, vars.D2D1P1, data.d2d1_ipv6_addr, data.maskv6,'ipv6']])

    ############################################################################################
    hdrMsg("\n########## Enable router bgp and configure router id ##############\n")
    ############################################################################################

    dict1 = {'local_as':'10','router_id':data.rtrid1,'config_type_list':['router_id']}
    dict2 = {'local_as':'20','router_id':data.rtrid2,'config_type_list':['router_id']}
    parallel.exec_parallel(True, [dut1, dut2], bgp_obj.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg(" \n########## Configure BGP neighbor on DUT1 and DUT2 ##############\n ")
    ############################################################################################
    dict1 = {'neighbor':data.d2d1_1_ip_addr,'remote_as':'20','config_type_list':["neighbor","connect"],'connect':1, 'local_as':'10'}
    dict2 = {'neighbor':data.d1d2_1_ip_addr,'remote_as':'10','config_type_list':["neighbor","connect"],'connect':1, 'local_as':'20'}
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    bgp_obj.create_bgp_neighbor(dut1,"10",data.d2d1_ipv6_addr,"20",family="ipv6")
    bgp_obj.create_bgp_neighbor(dut2,"20",data.d1d2_ipv6_addr,"10",family="ipv6")

    ipfeature.create_static_route(dut2, data.d2d1_1_ip_addr, '0.0.0.0/0', shell="vtysh", family='ipv4')
    ipfeature.create_static_route(dut2, data.d2d1_ipv6_addr, '::/0', shell="vtysh", family='ipv6')

    ############################################################################################
    hdrMsg(" \n####### Verify BGP neighborship on DUT1 and DUT2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", neighbor=data.d2d1_1_ip_addr, state='Established', retry_count=5,delay=5):
        base_uncfg()
        pytest.skip('BGP neighborship between Dut1 and Dut2 failed!! Aborting Base config')

    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", family='ipv6', neighbor=data.d2d1_ipv6_addr, state='Established', retry_count=5,delay=5):
        base_uncfg()
        pytest.skip('BGP neighborship between Dut1 and Dut2 failed!! Aborting Base config')

    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################

    vlan_obj.create_vlan(dut1, data.vlan)
    vlan_obj.add_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.verify_vlan_config(dut1, data.vlan, tagged=vars.D1T1P1)
    vlan_obj.create_vlan(dut2, data.vlan)
    vlan_obj.add_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)
    vlan_obj.verify_vlan_config(dut2, data.vlan, tagged=vars.D2T1P1)
    vlan_obj.create_vlan(dut1, data.vlan201)
    vlan_obj.add_vlan_member(dut1, data.vlan201, [vars.D1T1P2], tagging_mode=True)
    vlan_obj.verify_vlan_config(dut1, data.vlan201, tagged=vars.D1T1P2)
    vlan_obj.create_vlan(dut2, data.vlan201)
    vlan_obj.add_vlan_member(dut2, data.vlan201, [vars.D2T1P2], tagging_mode=True)
    vlan_obj.verify_vlan_config(dut2, data.vlan201, tagged=vars.D2T1P2)

    ############################################################################################
    hdrMsg("\n############# Assign IP address to Vlan interfaces ##############\n")
    ############################################################################################

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1, data.vlan1,data.d1t1_ip_addr,data.mask],[ipfeature.config_ip_addr_interface,dut2, data.vlan1, data.d2t1_ip_addr, data.mask]])
    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1, data.vlan1,data.d1t1_ipv6_addr,data.maskv6, "ipv6"],[ipfeature.config_ip_addr_interface,dut2, data.vlan1, data.d2t1_ipv6_addr, data.maskv6, "ipv6"]])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1, data.vlan201_1,data.d1t1_ipv6_addr2,data.maskv6, "ipv6"],[ipfeature.config_ip_addr_interface,dut2, data.vlan201_1, data.d2t1_ipv6_addr2, data.maskv6, "ipv6"]])
    ############################################################################################
    hdrMsg(" \n############# Configure BGP neighbors on DUTs to TG1 and TG2 ##############\n")
    ############################################################################################

    dict1 = {'neighbor':data.t1d1_ip_addr,'local_as':'10','remote_as':'100','config_type_list':["neighbor","connect"],'connect':1}
    dict2 = {'neighbor':data.t1d2_ip_addr,'local_as':'20','remote_as':'200','config_type_list':["neighbor","connect"],'connect':1}
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    dict1 = {'neighbor':data.t1d1_ipv6_addr,'local_as':'10','remote_as':'100','config_type_list':["neighbor","connect"],'connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.t1d2_ipv6_addr,'local_as':'20','remote_as':'200','config_type_list':["neighbor","connect"],'connect':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    #config_route_map(dut2, 'UseGlobal' ,type = 'next_hop_v6')
    #config_route_map(dut1, 'UseGlobal' ,type = 'next_hop_v6')
    ipfeature.config_route_map_global_nexthop(dut1,route_map='UseGlobal')
    ipfeature.config_route_map_global_nexthop(dut2,route_map='UseGlobal')

    dict1 = {'neighbor':data.t1d1_ipv6_addr,'local_as':'10','remote_as':'100','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.t1d2_ipv6_addr,'local_as':'20','remote_as':'200','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal', 'diRection':'in','connect':1,'addr_family':'ipv6' }
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    dict1 = {'neighbor':data.d2d1_ipv6_addr,'local_as':'10','remote_as':'20','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.d1d2_ipv6_addr,'local_as':'20','remote_as':'10','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    yield

    ############################################################################################
    hdrMsg("Base Cleanup")
    ############################################################################################

    base_uncfg()

@pytest.fixture(scope="function")
def L3Scl_fixture_002(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global h3,h4
    hdrMsg("### CLEANUP for TC2 ###")
    #
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='stop')
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h3['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h4['handle'],mode='destroy')
    debug_cmds()

@pytest.fixture(scope="function")
def L3Scl_fixture_003(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global h5,h6
    hdrMsg("### CLEANUP for TC3 ###")
    #
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='stop')
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h5['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h6['handle'],mode='destroy')
    debug_cmds()

@pytest.fixture(scope="function")
def L3Scl_fixture_004(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global h11,h22,h33,h44
    hdrMsg("### CLEANUP for TC4 ###")
    #
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_rtr1['conf']['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_rtr2['conf']['handle'], mode='stop')
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='stop')
    st.wait(7)
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h11['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h22['handle'],mode='destroy')
    tg3.tg_interface_config(port_handle = tg_ph_3, handle=h33['handle'],mode='destroy')
    tg4.tg_interface_config(port_handle = tg_ph_4, handle=h44['handle'],mode='destroy')
    debug_cmds()

@pytest.fixture(scope="function")
def L3Scl_fixture_005(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    vars = st.get_testbed_vars()
    yield
    hdrMsg("### CLEANUP for TC5 ###")
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    num_loops = max_arp_count/8000
    for i in reversed(range(0,num_loops)):
        secondary_ip = 'no' if i == 0 else 'yes'
        ipfeature.delete_ip_interface(vars.D1, data.vlan201_1, data.ip_list_2[i], data.mask, is_secondary_ip=secondary_ip)

    ############################################################################################
    hdrMsg("\n####### Clear mac in D1 and D2 ##############\n")
    ############################################################################################
    mac_obj.clear_mac(vars.D1)
    mac_obj.clear_mac(vars.D2)
    st.wait(2)

    ############################################################################################
    hdrMsg("\n####### Show mac count in D1 and D2 ############\n")
    ############################################################################################
    D5_mac_cnt = mac_obj.get_mac_count(vars.D1)
    D6_mac_cnt = mac_obj.get_mac_count(vars.D2)



@pytest.fixture(scope="function")
def L3Scl_fixture_006(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    vars = st.get_testbed_vars()
    yield
    #
    hdrMsg("### CLEANUP for TC6 ###")
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    st.wait(5)
    tg1.tg_interface_config(port_handle=tg_ph_3, handle=h2['handle'], mode='destroy')
    st.wait(5)
    #ipfeature.delete_ip_interface(vars.D1,data.vlan1 , data.gw_ipv6, data.maskv6,family='ipv6')

    ############################################################################################
    hdrMsg("\n####### Clear mac in D1 and D2 ##############\n")
    ############################################################################################
    mac_obj.clear_mac(vars.D1)
    mac_obj.clear_mac(vars.D2)
    st.wait(2)

    ############################################################################################
    hdrMsg("\n####### Show mac count in D1 and D2 ############\n")
    ############################################################################################
    D5_mac_cnt = mac_obj.get_mac_count(vars.D1)
    D6_mac_cnt = mac_obj.get_mac_count(vars.D2)

@pytest.mark.functionality
def test_L3Scl_002(L3Scl_fixture_002):
    global h3
    global h4
    global bgp_conf
    global bgp_route1
    global bgp_conf2
    global bgp_route2
    global tr1
    global tr2

    hdrMsg("TC ID: FtRtPerfFn003; TC SUMMARY : Verify 1D Scale of Max ipv6 routes with prefix <=64 on default vrf")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    ############################################################################################
    hdrMsg(" \n####### Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    h3 = {}
    h4 = {}
    h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,\
            vlan_id=data.vlan, vlan='1', \
            ipv6_prefix_length='64', ipv6_gateway=data.d1t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h3.update(h11)
    st.log("INTFCONF: "+str(h3))

    h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t1d2_ipv6_addr,\
            vlan_id=data.vlan, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d2t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
    h4.update(h22)
    st.log("INTFCONF: "+str(h4))

    ############################################################################################
    hdrMsg(" \n####### Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################
    num_routes = ipv6_scale/2
    wait_time = ipv6_scale/10000*perf_time

    #shutdown Dut2 - Dut1 interface to allow Dut2 to populate TG2 routes first before routes received from Dut1
    port.shutdown(vars.D2,[vars.D2D1P1])
    st.wait(2)

    # Configuring BGP device on top of interface.
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h3['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='100', remote_as='10', remote_ipv6_addr=data.d1t1_ipv6_addr)
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route1 = tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix_ipv6,as_path = 'as_seq:100')
    st.log("BGPROUTE: "+str(bgp_route1))

    # Starting the BGP device.
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    #bgp_ctrl2=tg1.tg_emulation_bgp_control(handle=bgp_route1['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    # Configuring BGP device on top of interface.
    bgp_conf2 = tg2.tg_emulation_bgp_config(handle=h4['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.vlan, remote_as='20', remote_ipv6_addr=data.d2t1_ipv6_addr)
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route2 = tg2.tg_emulation_bgp_route_config(handle=bgp_conf2['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix2_ipv6,as_path = 'as_seq:200')
    st.log("BGPROUTE: "+str(bgp_route2))

    # Starting the BGP device.
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='start')
    #bgp_ctrl2=tg2.tg_emulation_bgp_control(handle=bgp_route2['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)
    port.noshutdown(vars.D2,[vars.D2D1P1])
    st.wait(15)

    ############################################################################################
    hdrMsg(" \n####### Configure BGP neighbors on DUTs to TG1 and TG2 ##############\n")
    ############################################################################################
    bgp_obj.create_bgp_neighbor(dut1,"10",data.t1d1_ipv6_addr,"100",family="ipv6")
    bgp_obj.create_bgp_neighbor(dut1,"10",data.d2d1_ipv6_addr,"20",family="ipv6")

    bgp_obj.create_bgp_neighbor(dut2,"20",data.t1d2_ipv6_addr,"200",family="ipv6")
    bgp_obj.create_bgp_neighbor(dut2,"20",data.d1d2_ipv6_addr,"10",family="ipv6")
    #bgp_obj.create_bgp_neighbor(dut2,"20",data.t1d2_ipv6_addr,"200",keep_alive="60",hold="180",family="ipv6")

    ############################################################################################
    hdrMsg(" \n####### Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", family='ipv6',neighbor=data.t1d1_ipv6_addr, state='Established', retry_count=4,delay=5):
        st.report_fail('bgp_ip_peer_establish_fail',data.t1d1_ipv6_addr)

    if not retry_api(bgp_obj.verify_bgp_summary, dut2, shell="vtysh", family='ipv6',neighbor=data.t1d2_ipv6_addr, state='Established', retry_count=4,delay=5):
        st.report_fail('bgp_ip_peer_establish_fail',data.t1d2_ipv6_addr)

    ############################################################################################
    hdrMsg("\n########## Configure bound stream ############\n")
    ############################################################################################
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h4['handle'], emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0',high_speed_result_analysis=0)
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h3['handle'], emulation_dst_handle=bgp_route2['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0',high_speed_result_analysis=0)
    st.log("BOUND_STREAM: "+str(tr1))
    st.log("BOUND_STREAM: "+str(tr2))

    ############################################################################################
    hdrMsg("\n########## Verify all routes are installed by sending traffic ############\n")
    ############################################################################################
    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
        st.report_fail('fib_failure_route_fail',"count")

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res=tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: "+str(res))
    st.wait(4)
    res=tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: "+str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## Verify traffic ############\n")
    ############################################################################################
    traffic_params = {
        '1': {
            'tx_ports' : [vars.T1D1P1],
            'tx_obj' : [tg1],
            'exp_ratio' : [1],
            'rx_ports' : [vars.T1D2P1],
            'rx_obj' : [tg2]
            }
    }
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')

    traffic_params = {
        '1': {
            'tx_ports' : [vars.T1D2P1],
            'tx_obj' : [tg2],
            'exp_ratio' : [1],
            'rx_ports' : [vars.T1D1P1],
            'rx_obj' : [tg1]
            }
    }

    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')

    BGP_triggers(family='ipv6',scl_num=ipv6_scale)

    st.log('Verified Platform {} for IPv6 max scale {}'.format(plat_name,ipv6_scale))
    st.report_pass('test_case_passed')

@pytest.mark.functionality
def test_L3Scl_003(L3Scl_fixture_003):
    global h5
    global h6
    global bgp_conf
    global bgp_conf2
    global tr1
    global tr2

    hdrMsg("TC ID: FtRtPerfFn005; TC SUMMARY : Verify 1D Scale of Max ipv6 routes with prefix >64 on default vrf")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes = ipv6_scale_abv_64/2
    wait_time = ipv6_scale_abv_64/10000*perf_time
    ############################################################################################
    hdrMsg(" \n####### Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h5 = {}
    h6 = {}
    h55=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,\
            vlan_id=data.vlan, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d1t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h5.update(h55)
    st.log("INTFCONF: "+str(h5))

    h66=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t1d2_ipv6_addr,\
            vlan_id=data.vlan, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d2t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
    h6.update(h66)
    st.log("INTFCONF: "+str(h6))

    ############################################################################################
    hdrMsg(" \n####### Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################

    # Configuring BGP device on top of interface.
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h5['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='100', remote_as='10', remote_ipv6_addr=data.d1t1_ipv6_addr)
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route1=tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix_ipv6,as_path = 'as_seq:100',ipv6_prefix_length='72')
    st.log("BGPROUTE: "+str(bgp_route1))

    # Configuring BGP device on top of interface.
    bgp_conf2 = tg2.tg_emulation_bgp_config(handle=h6['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.vlan, remote_as='20', remote_ipv6_addr=data.d2t1_ipv6_addr)
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route2=tg2.tg_emulation_bgp_route_config(handle=bgp_conf2['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix2_ipv6,as_path = 'as_seq:200',ipv6_prefix_length='72')
    st.log("BGPROUTE: "+str(bgp_route2))

    # Starting the BGP device.
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='start')
    #bgp_ctrl2=tg2.tg_emulation_bgp_control(handle=bgp_route2['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    # Starting the BGP device.
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    #bgp_ctrl2=tg1.tg_emulation_bgp_control(handle=bgp_route1['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.

    ############################################################################################
    hdrMsg(" \n####### Configure BGP neighbors on DUTs to TG1 and TG2 ##############\n")
    ############################################################################################

    bgp_obj.create_bgp_neighbor(dut1,"10",data.t1d1_ipv6_addr,"100",family="ipv6")

    bgp_obj.create_bgp_neighbor(dut2,"20",data.t1d2_ipv6_addr,"200",family="ipv6")

    ############################################################################################
    hdrMsg(" \n####### Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################

    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", family='ipv6',neighbor=data.t1d1_ipv6_addr, state='Established', retry_count=4,delay=5):
        st.report_fail('bgp_ip_peer_establish_fail',data.t1d1_ipv6_addr)

    if not retry_api(bgp_obj.verify_bgp_summary, dut2, shell="vtysh", family='ipv6',neighbor=data.t1d2_ipv6_addr, state='Established', retry_count=4,delay=5):
        st.report_fail('bgp_ip_peer_establish_fail',data.t1d2_ipv6_addr)

    ############################################################################################
    hdrMsg("\n########## Configure bound stream ############\n")
    ############################################################################################

    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h6['handle'], emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0')
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h5['handle'], emulation_dst_handle=bgp_route2['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0')
    st.log("BOUND_STREAM: "+str(tr1))
    st.log("BOUND_STREAM: "+str(tr2))

    st.log("Flap the NH intf")
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(2)

    port.noshutdown(vars.D1,[vars.D1T1P1])
    st.wait(15)

    ############################################################################################
    hdrMsg("\n########## Verify routes installed ############\n")
    ############################################################################################
    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale_abv_64, retry_count=5,delay=5):
        debug_cmds()
        st.report_fail('fib_failure_route_fail',"count")

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.wait(5)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(4)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## Verify traffic ############\n")
    ############################################################################################
    traffic_params = {
        '1': {
            'tx_ports' : [vars.T1D1P1],
            'tx_obj' : [tg1],
            'exp_ratio' : [1],
            'rx_ports' : [vars.T1D2P1],
            'rx_obj' : [tg2]
            }
    }
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')

    traffic_params = {
        '1': {
            'tx_ports' : [vars.T1D2P1],
            'tx_obj' : [tg2],
            'exp_ratio' : [1],
            'rx_ports' : [vars.T1D1P1],
            'rx_obj' : [tg1]
            }
    }

    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')

    ipv6_scale=ipv6_scale_abv_64
    BGP_triggers(family='ipv6',scl_num=ipv6_scale)

    st.log('Verified Platform {} for IPv6 >/64 max scale {}'.format(plat_name,ipv6_scale))
    st.report_pass('test_case_passed')

@pytest.mark.functionality
def test_L3Scl_004(L3Scl_fixture_004):
    global h11
    global h22
    global h33
    global h44
    global bgp_rtr2
    global bgp_rtr1
    global bgp_conf
    global bgp_conf2
    global tr1
    global tr2
    global tr3
    global tr4

    hdrMsg("TC ID: FtRtPerfFn007; TC SUMMARY : Verify 1D Scale of Max ipv4+ipv6 routes with IPv6 prefix =<64 on default vrf")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes_v4 =ipv4_scale_ipv4ipv6/2
    num_routes_v6 =ipv6_scale_ipv4ipv6/2
    wait_time = ipv4_scale_ipv4ipv6/10000*perf_time
    ############################################################################################
    hdrMsg("\n####### STEP 4.1: Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################

    h11 = {}
    h22 = {}
    h33 = {}
    h44 = {}

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,\
            vlan_id=data.vlan,vlan='1', \
            gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h11.update(h1)
    st.log("INTFCONF: "+str(h11))

    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,\
            vlan_id=data.vlan,vlan='1', \
            gateway=data.d2t1_ip_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
    h22.update(h2)
    st.log("INTFCONF: "+str(h22))

    tg3.tg_traffic_control(action='reset',port_handle=tg_ph_3)
    tg4.tg_traffic_control(action='reset',port_handle=tg_ph_4)

    h3=tg3.tg_interface_config(port_handle=tg_ph_3, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr2,\
            vlan_id=data.vlan201,vlan='1', \
            ipv6_prefix_length='64', ipv6_gateway=data.d1t1_ipv6_addr2, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h33.update(h3)
    st.log("INTFCONF: "+str(h33))

    h4=tg4.tg_interface_config(port_handle=tg_ph_4, mode='config', ipv6_intf_addr=data.t1d2_ipv6_addr2,\
            vlan_id=data.vlan201, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d2t1_ipv6_addr2, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
    h44.update(h4)
    st.log("INTFCONF: "+str(h44))

    ############################################################################################
    hdrMsg(" \n####### STEP 4.2:  Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################

    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '100',
                 'remote_as'             : '10',
                 'remote_ip_addr'        : data.d1t1_ip_addr
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' : num_routes_v4,
                  'as_path'    : 'as_seq:100',
                  'prefix'     : data.prefix1
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    # Configuring BGP device on top of interface.
    # Initializing dict_vars for easy readability.
    conf_var2 = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '20',
                 'remote_ip_addr'        : data.d2t1_ip_addr
               }

    route_var2 = { 'mode'       : 'add',
                  'num_routes' : num_routes_v4,
                   'as_path'    : 'as_seq:200',
                  'prefix'     : data.prefix2
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    # Configuring the BGP router.
    bgp_rtr2 = tg_bgp_config(tg = tg2,
        handle    = h22['handle'],
        conf_var  = conf_var2,
        route_var = route_var2,
        ctrl_var  = ctrl_start)
    st.wait(5)

    # Configuring the BGP router.
    bgp_rtr1 = tg_bgp_config(tg = tg1,
        handle    = h11['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    # Configuring BGP device on top of interface.
    bgp_conf = tg3.tg_emulation_bgp_config(handle=h33['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='100', remote_as='10', remote_ipv6_addr=data.d1t1_ipv6_addr2)
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route1=tg3.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6', num_routes=num_routes_v6, prefix=data.prefix_ipv6, as_path = 'as_seq:100')
    st.log("BGPROUTE: "+str(bgp_route1))

    # Configuring BGP device on top of interface.
    bgp_conf2 = tg4.tg_emulation_bgp_config(handle=h44['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='200', remote_as='20', remote_ipv6_addr=data.d2t1_ipv6_addr2)
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route2=tg4.tg_emulation_bgp_route_config(handle=bgp_conf2['handle'], mode='add', ip_version='6', num_routes=num_routes_v6, prefix=data.prefix2_ipv6,as_path = 'as_seq:200')
    st.log("BGPROUTE: "+str(bgp_route2))

    # Starting the BGP device #2.
    bgp_ctrl=tg4.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    # Starting the BGP device #1.
    bgp_ctrl=tg3.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.

    ##
    ############################################################################################
    hdrMsg("\n############ STEP 4.4: Configure BGP neighbors on DUTs to TG1 and TG2 ##############\n")
    ############################################################################################

    bgp_obj.create_bgp_neighbor(dut1,"10",data.t1d1_ip_addr,"100",keep_alive="60",hold="180",family="ipv4")

    bgp_obj.create_bgp_neighbor(dut2,"20",data.t1d2_ip_addr,"200",keep_alive="60",hold="180",family="ipv4")

    bgp_obj.create_bgp_neighbor(dut1,"10",data.t1d1_ipv6_addr2,"100",keep_alive="60",hold="180",family="ipv6")

    bgp_obj.create_bgp_neighbor(dut2,"20",data.t1d2_ipv6_addr2,"200",keep_alive="60",hold="180",family="ipv6")

    dict1 = {'neighbor':data.t1d1_ipv6_addr2,'local_as':'10','remote_as':'100','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.t1d2_ipv6_addr2,'local_as':'20','remote_as':'200','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal', 'diRection':'in','connect':1,'addr_family':'ipv6' }
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg(" \n####### STEP 4.5: Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################

    if not bgp_obj.verify_bgp_summary(dut1, shell="vtysh",
                                      neighbor=data.t1d1_ip_addr, state='Established'):
        st.report_fail('bgp_ip_peer_establish_fail',data.t1d1_ip_addr)

    if not bgp_obj.verify_bgp_summary(dut2, shell="vtysh",
                                      neighbor=data.t1d2_ip_addr, state='Established'):
        st.report_fail('bgp_ip_peer_establish_fail', data.t1d2_ip_addr)

    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", family='ipv6', neighbor=data.t1d1_ipv6_addr2, state='Established', retry_count=4,delay=5):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d1_ipv6_addr2)

    if not retry_api(bgp_obj.verify_bgp_summary,dut2, shell="vtysh", family='ipv6', neighbor=data.t1d2_ipv6_addr2, state='Established', retry_count=4,delay=5):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d2_ipv6_addr2)

    ############################################################################################
    hdrMsg("\n########## STEP 4.6: Configure bound stream ############\n")
    ############################################################################################

    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h22['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h11['handle'], emulation_dst_handle=bgp_rtr2['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')

    tr3 = tg4.tg_traffic_config(port_handle=tg_ph_4, emulation_src_handle=h44['handle'], emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
    tr4 = tg3.tg_traffic_config(port_handle=tg_ph_3, emulation_src_handle=h33['handle'], emulation_dst_handle=bgp_route2['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')

    ############################################################################################
    hdrMsg("\n########## STEP 4.7: Verify all routes are installed in the h/w table ############\n")
    ############################################################################################

    st.log("Verification of number of IPv4 route entries in hardware")
    retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale_ipv4ipv6, retry_count=retry_time, delay=delay_time)

    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale_ipv4ipv6, retry_count=retry_time, delay=delay_time):
        debug_cmds()
        st.report_fail('fib_failure_route_fail',"count")

    ############################################################################################
    hdrMsg("\n########## STEP 4.8: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    st.log("BOUND_STREAM: " + str(tr3))
    st.log("BOUND_STREAM: " + str(tr4))
    res = tg1.tg_traffic_control(action='run',
                                 handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
    st.wait(5)
    res = tg1.tg_traffic_control(action='stop',
                                 handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
    st.log("TR_CTRL: "+str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 4.9: Verify traffic ############\n")
    ############################################################################################

    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ipv4_scale = ipv4_scale_ipv4ipv6
    ipv6_scale = ipv6_scale_ipv4ipv6

    wait_time = ipv4_scale_ipv4ipv6/10000*perf_time
    t = wait_time/4

    ############################################################################################
    hdrMsg("\n########## STEP 4.10: Clear bgp neighbor ############\n")
    ############################################################################################

    st.log("clear bgp neighbors")
    bgp_obj.clear_ip_bgp_vrf_vtysh(vars.D1,data.vrf_name[1])

    ############################################################################################
    hdrMsg("\n########## STEP 4.11: Clear IPv6 bgp neighbor ############\n")
    ############################################################################################

    st.log("clear ipv6 bgp neighbors")
    bgp_obj.clear_ip_bgp_vrf_vtysh(vars.D1,data.vrf_name[1],family='ipv6')

    ############################################################################################
    hdrMsg("\n########## STEP 4.12: Verify routes in Dut1 by sending traffic ############\n")
    ############################################################################################
    st.log("Verification of number of IPv4 route entries in hardware")
    retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale_ipv4ipv6, retry_count=retry_time, delay=delay_time)

    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale_ipv4ipv6, retry_count=retry_time, delay=delay_time):
        st.report_fail('fib_failure_route_fail',"count")

    ############################################################################################
    hdrMsg("\n########## STEP 4.13: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    st.log("BOUND_STREAM: " + str(tr3))
    st.log("BOUND_STREAM: " + str(tr4))
    res = tg1.tg_traffic_control(action='run',
                                 handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
    st.wait(5)
    res = tg1.tg_traffic_control(action='stop',
                                 handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 4.14: Verify traffic ############\n")
    ############################################################################################

    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## STEP 4.15: Flap the interface in Dut1 ############\n")
    ############################################################################################

    st.log("Flap the NH intf")
    port.shutdown(dut2,[vars.D2D1P1])
    st.wait(2)

    port.noshutdown(dut2,[vars.D2D1P1])
    st.wait(15)
    ############################################################################################
    hdrMsg("\n########## STEP 4.16: Verify routes in Dut1 by sending traffic ############\n")
    ############################################################################################
    st.log("Verification of number of IPv4 route entries in hardware")
    retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale_ipv4ipv6, retry_count=retry_time, delay=delay_time)

    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale_ipv4ipv6, retry_count=retry_time, delay=delay_time):
        debug_cmds()
        st.report_fail('fib_failure_route_fail',"count")

    ############################################################################################
    hdrMsg("\n########## STEP 4.17: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    st.log("BOUND_STREAM: " + str(tr3))
    st.log("BOUND_STREAM: " + str(tr4))
    res = tg1.tg_traffic_control(action='run',
                                 handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
    st.wait(5)
    res = tg1.tg_traffic_control(action='stop',
                                 handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 4.18: Verify traffic ############\n")
    ############################################################################################

    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    if all_triggers_flag:
        ############################################################################################
        hdrMsg("\n########## STEP 4.19: Clear the mac table in Dut1 ############\n")
        ############################################################################################

        mac_obj.clear_mac(dut1)
        st.wait(2)

        ############################################################################################
        hdrMsg("\n########## STEP 4.20: Clear arp table in Dut1 ############\n")
        ############################################################################################
        arp_api.clear_arp_table(vars.D1)

        ############################################################################################
        hdrMsg("\n########## STEP 4.21: Verify routes in Dut1 by sending traffic ############\n")
        ############################################################################################

        if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            st.report_fail('fib_failure_route_fail',"count")
        else:
            st.log("Traffic test passed.\n")

        ############################################################################################
        hdrMsg("\n########## STEP 4.22: Start and stop the traffic ############\n")
        ############################################################################################

        tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
        tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
        st.log("BOUND_STREAM: " + str(tr1))
        st.log("BOUND_STREAM: " + str(tr2))
        st.log("BOUND_STREAM: " + str(tr3))
        st.log("BOUND_STREAM: " + str(tr4))
        res = tg1.tg_traffic_control(action='run',
                                     handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
        st.wait(5)
        res = tg1.tg_traffic_control(action='stop',
                                     handle=[tr1['stream_id'], tr2['stream_id'], tr3['stream_id'], tr4['stream_id']])
        st.log("TR_CTRL: " + str(res))
        st.wait(2)

        ############################################################################################
        hdrMsg("\n########## STEP 4.23: Verify traffic ############\n")
        ############################################################################################

        traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
        aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

        if aggrResult:
            st.log('Traffic verification passed for mode aggregate')
        else:
            debug_cmds()
            st.report_fail('ip_traffic_fail')
            st.log('Traffic verification failed for mode aggregate')

        traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
        aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

        if aggrResult:
            st.log('Traffic verification passed for mode aggregate')
        else:
            debug_cmds()
            st.report_fail('ip_traffic_fail')
            st.log('Traffic verification failed for mode aggregate')

    st.log('Verified Platform {} for IPv4+IPv6  max scale {} and {}'.format(plat_name,ipv4_scale,ipv6_scale))
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def L3Scl_fixture_001(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global vars
    global h1,h2
    hdrMsg("### CLEANUP for TC1 ###")
    #
    st.wait(2)
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_rtr1['conf']['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_rtr2['conf']['handle'], mode='stop')
    st.wait(5)
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h1['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h2['handle'],mode='destroy')
    debug_cmds()

@pytest.mark.functionality
def test_L3Scl_001(L3Scl_fixture_001):
    global h1
    global h2
    global bgp_rtr2
    global bgp_rtr1
    global tr1
    global tr2

    hdrMsg("TC ID: FtRtPerfFn001; TC SUMMARY : Verify 1D Scale of Max ipv4 routes with different prefix ranges on default vrf")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes_dut2 = ipv4_scale/4
    num_routes_dut1 = ipv4_scale/4*3
    wait_time = ipv4_scale/10000*perf_time

    ############################################################################################
    hdrMsg(" \n####### Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    h1 = {}
    h2 = {}
    h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,\
            vlan_id=data.vlan,vlan='1', \
            gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1',netmask = '255.255.0.0')
    h1.update(h11)
    st.log("INTFCONF: "+str(h1))

    h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,\
            vlan_id=data.vlan, vlan='1',\
            gateway=data.d2t1_ip_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1',netmask = '255.255.0.0')
    h2.update(h22)
    st.log("INTFCONF: "+str(h2))

    ############################################################################################
    hdrMsg(" \n####### Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################
    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '100',
                 'remote_as'             : '10',
                 'remote_ip_addr'        : data.d1t1_ip_addr
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' : num_routes_dut1,
                  'as_path'    : 'as_seq:100',
                  'prefix'     : data.prefix1
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    conf_var2 = { 'mode'                 : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '20',
                 'remote_ip_addr'        : data.d2t1_ip_addr
                }
    route_var2 = { 'mode'       : 'add',
                  'num_routes' : num_routes_dut2,
                   'as_path'    : 'as_seq:200',
                  'prefix'     : data.prefix2
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    # Configuring the BGP router.
    bgp_rtr2 = tg_bgp_config(tg = tg2,
        handle    = h2['handle'],
        conf_var  = conf_var2,
        route_var = route_var2,
        ctrl_var  = ctrl_start)
    st.wait(5)
    # Configuring the BGP router.
    bgp_rtr1 = tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    ############################################################################################
    hdrMsg("\n####### Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", neighbor=data.t1d1_ip_addr, state='Established', retry_count=retry_time,delay=delay_time):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d1_ip_addr)

    if not retry_api(bgp_obj.verify_bgp_summary, dut2, shell="vtysh", neighbor=data.t1d2_ip_addr, state='Established', retry_count=retry_time,delay=delay_time):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d2_ip_addr)

    ############################################################################################
    hdrMsg("\n########## Configure bound stream ############\n")
    ############################################################################################
    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1['handle'], emulation_dst_handle=bgp_rtr2['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)

    ############################################################################################
    hdrMsg("\n########## Verify Traffic ############\n")
    ############################################################################################
    t = wait_time/4
    st.wait(t)
    st.log("Verification of number of IPv4 route entries in hardware")
    retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=data.num_of_routes, retry_count=5,delay=5)

    BGP_triggers(scl_num=ipv4_scale)

    st.log('Verified Platform {} for IPv4 max scale {}'.format(plat_name,ipv4_scale))
    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_L3Scl_005(L3Scl_fixture_005):

    hdrMsg("TC ID: FtRtPerfFn018; FtOpSoRtPerfFn027; TC SUMMARY : Verify 1D scale of ipv4 host routes in default-vrf ")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    arp_api.get_arp_ageout_time(vars.D1)
    arp_api.set_arp_ageout_time(vars.D1, 3600)

    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()

    #total = show_arp_count(vars.D1)
    total = arp_api.get_arp_count(vars.D1)
    st.log("ARP COUNT:"+str(total))
    cnt = 0
    host_count = 8000
    wait_time = 15
    duration = 15
    tr = {}
    num_loops = max_arp_count/host_count
    mac_list = ['00:0a:00:00:01:01','00:0b:00:00:01:01','00:0c:00:00:01:01','00:0d:00:00:01:01','00:0e:00:00:01:01','00:0f:00:00:01:01','00:aa:00:00:01:01','00:bb:00:00:01:01','00:cc:00:00:01:01','00:dd:00:00:01:01','00:ee:00:00:01:01']
    mac_dst=str(mac_obj.get_sbin_intf_mac(dut1, data.vlan201_1))
    for i in range(0,num_loops):
        secondary_ip = 'no' if i == 0 else 'yes'
        ipfeature.config_ip_addr_interface(dut1, data.vlan201_1, data.ip_list_2[i], data.mask, is_secondary_ip=secondary_ip)
        tr = create_l3_host(tg3, tg_ph_3, host_count,data.ip_list_3[i], data.vlan201, data.ip_list_2[i],mac_list[i],mac_dst)
        tg1.tg_traffic_control(action='stop', handle=tr)
    ############################################################################################
    hdrMsg("\n########## Verify ARP total count in Dut1 ############\n")
    ############################################################################################
    # Verify ARP and counters at the DUT.
    if not retry_api(verify_arp_count, vars.D1, expected_count=max_arp_count-5, retry_count=3, delay=3):
        st.log('Expected ARP entries not found')
        st.report_fail('arp_create_fail',max_arp_count-5)

    ############################################################################################
    hdrMsg("\n########## STEP - Verify ARP performance ############\n")
    ############################################################################################
    #default_nd = show_nd_count(vars.D1)
    tg3.tg_traffic_control(action='reset',port_handle=tg_ph_3)
    #host_count=max_arp_count
    tr = create_l3_host(tg3, tg_ph_3, host_count, data.ip_list_3[0], data.vlan201, data.ip_list_2[0],mac_list[0], mac_dst)
    arp_api.clear_arp_table(vars.D1)
    st.log('Shutdown DUT_TG interface.')
    port.shutdown(vars.D1,[vars.D1T1P2])
    st.wait(4)
    #
    default_arp = arp_api.get_arp_count(vars.D1)
    st.log('Unshut DUT_TG interface.')
    port.noshutdown(vars.D1,[vars.D1T1P2])

    arp_install_time = measure_arp_learn_time(dut1, default_arp, host_count)

    tg1.tg_traffic_control(action='stop', handle=tr)
    st.log("ARP Performance - Installation time for {} ARP entries - {}".format(host_count,arp_install_time))
    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_L3Scl_006(L3Scl_fixture_006):
    global h1
    global h2
    hdrMsg("TC ID: FtRtPerfFn019;FtOpSoRtPerfFn028; TC SUMMARY : Verify 1D scale of ipv6 host routes in default-vrf ")
    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()

    #total = show_nd_count(vars.D1)
    total = arp_api.get_ndp_count(vars.D1)
    st.log("ND COUNT:"+str(total))
    '''
    ############################################################################################
    hdrMsg("\n########## STEP - Configure IPv6 address on vlan in DUT1 ##########\n")
    ############################################################################################
    ipfeature.config_ip_addr_interface(dut1,'Vlan'+data.vlan201 ,data.d1t1_ipv6_addr2, data.maskv6,family='ipv6')
    '''
    ############################################################################################
    hdrMsg("\n########## STEP 6.1 - Configure IPv6 hosts scale on TGEN ##########\n")
    ############################################################################################
    default_nd = arp_api.get_ndp_count(vars.D1)
    nd_cnt = 8000

    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.src_ipv6,  ipv6_gateway=data.gw_ipv6, src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id=data.vlan, count=nd_cnt, arp_send_req='1', ipv6_gateway_step='::', ipv6_intf_addr_step='::1',ipv6_prefix_length = '64')
    h2 = tg2.tg_interface_config(port_handle=tg_ph_3, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr2,  ipv6_gateway=data.d1t1_ipv6_addr2, src_mac_addr='00:0b:01:00:00:01', vlan='1', vlan_id=data.vlan201, count=nd_cnt, arp_send_req='1', ipv6_gateway_step='::', ipv6_intf_addr_step='::1',ipv6_prefix_length = '64')

    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    res2=tg2.tg_arp_control(handle=h2['handle'], arp_target='all')

    nd_install_time = measure_nd_learn_time(dut1, default_nd, max_nd_count)
    ############################################################################################
    hdrMsg("\n########## STEP 6.2 - Verify ND total count in Dut1 ############\n")
    ############################################################################################
    # Verify ND and counters at the DUT.
    if not retry_api(verify_ndp_count, vars.D1, expected_count=max_nd_count-1,retry_count=5, delay=13):
        st.log('Expected ND entries not found')
        st.report_fail('ND_entry_count_fail',max_nd_count)

    '''
    Removing this section due to inconcistent ixia issues.
    ############################################################################################
    hdrMsg("\n########## STEP 6.3 - Verify ND performance ############\n")
    ############################################################################################
    #default_nd = show_nd_count(vars.D1)
    st.log('Shutdown DUT_TG interface.')
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(5)

    default_nd = arp_api.get_ndp_count(vars.D1)
    st.log('Unshut DUT_TG interface.')
    port.noshutdown(vars.D1,[vars.D1T1P1])

    nd_install_time = measure_nd_learn_time(dut1, default_nd, max_nd_count)
    ############################################################################################
    hdrMsg("\n########## STEP 6.4 - Clear ND table in Dut1 ############\n")
    ############################################################################################
    arp_api.clear_ndp_table(vars.D1)
    st.wait(14)
    ############################################################################################
    hdrMsg("\n########## STEP 6.5 - Verify ND total count ############\n")
    ############################################################################################
    # Verify ND and counters at the DUT.
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(4)
    port.noshutdown(vars.D1,[vars.D1T1P1])
    st.wait(4)
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(4)
    port.noshutdown(vars.D1,[vars.D1T1P1])
    st.wait(4)

    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    st.wait(2)
    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')

    if not retry_api(verify_ndp_count, vars.D1, expected_count=max_nd_count,retry_count=5, delay=3):
        st.log('Expected ND entries not found')
        st.report_fail('ND_entry_count_fail',max_nd_count)
    '''
    st.log("ND Performance - Installation time for {} ND entries - {}".format(max_nd_count,nd_install_time))
    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_L3Scl_ECMP_007(L3Scl_fixture_007):
    global bgp_rtr1
    global bgp_rtr2
    global h1
    global h2
    global bgp_rtr2
    global bgp_rtr1
    global tr11
    global tr1
    global tr2

    hdrMsg("TC ID: FtRtPerfFn009; TC SUMMARY : Verify 1D Scale of Max ipv4 routes with 64 ECMP paths on default-vrf.")
    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    bgp_rtr1 = {}
    bgp_rtr2 = {}

    h1 = {}
    h2 = {}


    num_routes = data.ipv4_scale_ecmp/2
    wait_time = 2
    ##
    ############################################################################################
    hdrMsg("STEP-7.1: Remove ip address from physical interface \n")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan1,data.d1t1_ip_addr, data.mask],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ip_addr, data.mask]])

    ############################################################################################
    hdrMsg("\n############# STEP-7.2: Assign IP address to Vlan interfaces ##############\n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,'Vlan'+vlan,ip1,'24'],[ipfeature.config_ip_addr_interface,dut2,'Vlan'+vlan,ip2,'24']])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,data.vlan1,data.d1t1_ip_addr,'16'],[ipfeature.config_ip_addr_interface,dut2, data.vlan1, data.d2t1_ip_addr, '16']])

    ############################################################################################
    hdrMsg("\n########## STEP-7.3: Configure EBGP between Dut1 and Dut2 for all interfaces ##########\n")
    ############################################################################################
    dict1 = {'local_as':'10','router_id':data.rtrid1, 'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp}
    dict2 = {'local_as':'20','router_id':data.rtrid2,'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp}
    parallel.exec_parallel(True, [dut1, dut2], bgp_obj.config_bgp, [dict1, dict2])

    for i,ip1,ip2 in zip(range(0,data.max_ecmp+2),data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        dict1 = {'neighbor':ip2,'remote_as':'20','config_type_list':["neighbor","connect"],'connect':1, 'local_as':'10'}
        dict2 = {'neighbor':ip1,'remote_as':'10','config_type_list':["neighbor","connect"],'connect':1, 'local_as':'20'}
        parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    dict1 = {'neighbor':data.t1d1_ip_addr,'remote_as':'100','config_type_list':["neighbor","connect"],'connect':1, 'local_as':'10'}
    dict2 = {'neighbor':data.t1d2_ip_addr,'remote_as':'200','config_type_list':["neighbor","connect"],'connect':1, 'local_as':'20'}
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg(" \n####### STEP-7.4: Verify all BGP neighbors are up.  ##############\n")
    ############################################################################################
    if not retry_api(verify_bgp_nbr_count, dut1, expected_count=data.max_ecmp, retry_count=4,delay=5):
        st.report_fail("bgp_ip_peer_establish_fail",data.max_ecmp)

    ############################################################################################
    hdrMsg(" \n####### STEP-7.5: Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,\
            vlan_id=data.vlan,vlan='1', \
            gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1',netmask = '255.255.255.0')
    h1.update(h11)
    st.log("INTFCONF: "+str(h1))

    h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,\
            vlan_id=data.vlan, vlan='1',\
            gateway=data.d2t1_ip_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1',netmask = '255.255.255.0')
    h2.update(h22)
    st.log("INTFCONF: "+str(h2))

    ############################################################################################
    hdrMsg(" \n####### STEP-7.6: Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################

    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '100',
                 'remote_as'             : '10',
                 'remote_ip_addr'        : data.d1t1_ip_addr
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' : num_routes,
                  'as_path'    : 'as_seq:100',
                  'prefix'     : data.prefix1
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    conf_var2 = { 'mode'                 : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '20',
                 'remote_ip_addr'        : data.d2t1_ip_addr
                }

    route_var2 = { 'mode'       : 'add',
                  'num_routes' : num_routes,
                   'as_path'    : 'as_seq:200',
                  'prefix'     : data.prefix2
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}
    # Configuring the BGP router.
    bgp_rtr2 = tg_bgp_config(tg = tg2,
        handle    = h2['handle'],
        conf_var  = conf_var2,
        route_var = route_var2,
        ctrl_var  = ctrl_start)
    # Configuring the BGP router.
    bgp_rtr1 = tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    ############################################################################################
    hdrMsg("\n####### STEP-7.7: Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", neighbor=data.t1d1_ip_addr, state='Established', retry_count=retry_time,delay=delay_time):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d1_ip_addr)

    if not retry_api(bgp_obj.verify_bgp_summary, dut2, shell="vtysh", neighbor=data.t1d2_ip_addr, state='Established', retry_count=retry_time,delay=delay_time):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d2_ip_addr)

    ############################################################################################
    hdrMsg("\n########## STEP-7.8: Configure raw stream ############\n")
    ############################################################################################

    # configuring bound stream host_to_routeHandle.
    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr11 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ip_dst_mode='increment', ip_dst_count=200,ip_dst_step='0.0.0.1',ip_src_addr=data.prefix1,ip_dst_addr=data.prefix2,   l3_protocol='ipv4', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan,vlan='enable', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='1')

    ############################################################################################
    hdrMsg("\n########## STEP-7.9: Start the traffic ############\n")
    ############################################################################################

    c = check_ecmp()
    if c!=6:
        st.report_fail('ip_traffic_fail')
    else:
        st.log('PASS:Traffic is being load balanced as expected.')

    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')

    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, '1', [vars.D2D1P1], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, '1', [vars.D1D2P1], tagging_mode=True)

    ############################################################################################
    hdrMsg("\n########## STEP-7.10: Configure bound stream ############\n")
    ############################################################################################

    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1['handle'], emulation_dst_handle=bgp_rtr2['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')

    ############################################################################################
    hdrMsg("\n########## STEP-7.11: Start and stop the traffic ############\n")
    ############################################################################################

    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP-7.12: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n####### STEP-7.13: Shutdown 1 interface and verify all traffic flows via the other interfaces ##############\n")
    ############################################################################################
    st.log("Flap the NH intf")
    port.shutdown(vars.D2,[vars.D2D1P2])
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP-7.14: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(4)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP-7.15: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## STEP-7.16: Unshut the interface ############\n")
    ############################################################################################
    port.noshutdown(vars.D2,[vars.D2D1P2])
    #BGP_triggers(scl_num=num_routes,ecmp=1)
    st.report_pass('test_case_passed')

@pytest.mark.functionality
def test_L3Scl_ECMP_008(L3Scl_fixture_008):
    global h3
    global h4
    global bgp_conf
    global bgp_conf2
    global tr11
    global tr1
    global tr2
    hdrMsg("TC ID: FtRtPerfFn011; TC SUMMARY : Verify 1D Scale of Max ipv6 routes with 64 ECMP paths on default-vrf.")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes = data.ipv6_scale_ecmp/2
    wait_time = 2
    ##
    ############################################################################################
    hdrMsg("\n############# STEP-8.1: Assign IPv6 address to Vlan interfaces ##############\n")
    ############################################################################################
    for i,vlan,ipv6_1,ipv6_2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,'Vlan'+vlan,ipv6_1,'64','ipv6'],[ipfeature.config_ip_addr_interface,dut2,'Vlan'+vlan,ipv6_2,'64','ipv6']])

    #utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,data.vlan1,data.d1t1_ipv6_addr,'64','ipv6'],[ipfeature.config_ip_addr_interface,dut2, data.vlan1, data.d2t1_ipv6_addr, '64','ipv6']])

    ############################################################################################
    hdrMsg("\n########## STEP-8.2: Configure EBGP between Dut1 and Dut2 for all interfaces ##########\n")
    ############################################################################################

    dict1 = {'local_as':'10','router_id':data.rtrid1, 'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp,'addr_family':'ipv6'}
    dict2 = {'local_as':'20','router_id':data.rtrid2, 'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp,'addr_family':'ipv6'}
    parallel.exec_parallel(True, [dut1, dut2], bgp_obj.config_bgp, [dict1, dict2])

    #config_route_map(dut2, 'UseGlobal' ,type = 'next_hop_v6')
    #config_route_map(dut1, 'UseGlobal' ,type = 'next_hop_v6')
    ipfeature.config_route_map_global_nexthop(dut1,route_map='UseGlobal')
    ipfeature.config_route_map_global_nexthop(dut2, route_map='UseGlobal')

    for i,ip1,ip2 in zip(range(0,data.max_ecmp+2),data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        dict1 = {'neighbor':ip2,'local_as':'10','remote_as':'20','config_type_list':["neighbor","activate","connect"],'connect':1,'addr_family':'ipv6'}
        dict2 = {'neighbor':ip1,'local_as':'20','remote_as':'10','config_type_list':["neighbor","activate","connect"],'connect':1,'addr_family':'ipv6'}
        parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])
        dict1 = {'neighbor':ip2,'local_as':'10','remote_as':'20','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
        dict2 = {'neighbor':ip1,'local_as':'20','remote_as':'10','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
        parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    dict1 = {'neighbor':data.t1d1_ipv6_addr,'local_as':'10','remote_as':'100','config_type_list':["neighbor","activate","connect"],'connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.t1d2_ipv6_addr,'local_as':'20','remote_as':'200','config_type_list':["neighbor","activate","connect"],'connect':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    dict1 = {'neighbor':data.t1d1_ipv6_addr,'local_as':'10','remote_as':'100','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.t1d2_ipv6_addr,'local_as':'20','remote_as':'200','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal', 'diRection':'in','connect':1,'addr_family':'ipv6' }
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])
    ############################################################################################
    hdrMsg(" \n####### STEP-8.3: Verify all BGP neighbors are up.  ##############\n")
    ############################################################################################

    if not retry_api(verify_ipv6_bgp_nbr_count, dut1, expected_count=data.max_ecmp, retry_count=retry_time,delay=delay_time):
        st.report_fail("bgp_ip_peer_establish_fail",data.max_ecmp)

    ############################################################################################
    hdrMsg(" \n####### STEP-8.4: Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    h3 = {}
    h4 = {}
    h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,\
            vlan_id=data.vlan, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d1t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h3.update(h11)
    st.log("INTFCONF: "+str(h3))

    h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t1d2_ipv6_addr,\
            vlan_id=data.vlan, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d2t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
    h4.update(h22)
    st.log("INTFCONF: "+str(h4))

    ############################################################################################
    hdrMsg(" \n####### STEP-8.5: Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################
    # Configuring BGP device on top of interface.
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h3['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='100', remote_as='10', remote_ipv6_addr=data.d1t1_ipv6_addr)
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route1=tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix_ipv6,as_path = 'as_seq:100')
    st.log("BGPROUTE: "+str(bgp_route1))

    # Starting the BGP device.
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    #bgp_ctrl2=tg1.tg_emulation_bgp_control(handle=bgp_route1['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.

    # Configuring BGP device on top of interface.
    bgp_conf2 = tg2.tg_emulation_bgp_config(handle=h4['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.vlan, remote_as='20', remote_ipv6_addr=data.d2t1_ipv6_addr)
    st.log("BGPCONF: "+str(bgp_conf2))

    # Adding routes to BGP device.
    bgp_route2=tg2.tg_emulation_bgp_route_config(handle=bgp_conf2['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix2_ipv6,as_path = 'as_seq:200')
    st.log("BGPROUTE: "+str(bgp_route2))

    # Starting the BGP device.
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='start')
    #bgp_ctrl2=tg2.tg_emulation_bgp_control(handle=bgp_route2['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    ############################################################################################
    hdrMsg("\n####### STEP-8.6: Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", neighbor=data.t1d1_ipv6_addr, state='Established', retry_count=4,delay=5,family='ipv6'):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d1_ipv6_addr)

    if not retry_api(bgp_obj.verify_bgp_summary, dut2, shell="vtysh", neighbor=data.t1d2_ipv6_addr, state='Established', retry_count=4,delay=5,family='ipv6'):
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d2_ipv6_addr)

    ############################################################################################
    hdrMsg("\n########## STEP-8.7: Configure raw stream ############\n")
    ############################################################################################
    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr11 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ipv6_dst_mode='increment', ipv6_dst_count=200,ipv6_dst_step='::1',ipv6_src_addr=data.prefix_ipv6,ipv6_dst_addr=data.prefix2_ipv6,  l3_protocol='ipv6', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan,vlan='enable', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='1',high_speed_result_analysis=0)

    ############################################################################################
    hdrMsg("\n########## STEP-8.8: Start the traffic ############\n")
    ############################################################################################

    c = check_ecmp()
    if c!=6:
        st.report_fail('ip_traffic_fail')
    else:
        st.log('PASS:Traffic is being load balanced as expected.')

    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')

    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, '1', [vars.D2D1P1], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, '1', [vars.D1D2P1], tagging_mode=True)

    ############################################################################################
    hdrMsg("\n########## STEP-8.9: Configure bound stream ############\n")
    ############################################################################################
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h4['handle'], emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0',high_speed_result_analysis=0)
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h3['handle'], emulation_dst_handle=bgp_route2['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0',high_speed_result_analysis=0)
    st.log("BOUND_STREAM: "+str(tr1))
    st.log("BOUND_STREAM: "+str(tr2))

    ############################################################################################
    hdrMsg("\n########## STEP-8.10: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(4)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP-8.11: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    #BGP_triggers(scl_num=num_routes,ecmp=1)
    st.report_pass('test_case_passed')


@pytest.fixture(scope="function")
def L3Scl_fixture_007(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    ############################################################################################
    hdrMsg("Remove ip address from Physical Interface\n")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_1_ip_addr,data.mask],[ipfeature.delete_ip_interface,dut2, vars.D2D1P1,data.d2d1_1_ip_addr,data.mask]])
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_ipv6_addr,data.maskv6,'ipv6'],[ipfeature.delete_ip_interface,dut2,vars.D2D1P1,data.d2d1_ipv6_addr,data.maskv6,'ipv6']])

    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    intf_list1 = [int(data.dut1_vlan_scl[0])]
    intf_list2 = [x for x in range(int(data.dut1_vlan_scl[1]),int(data.dut1_vlan_scl[data.max_ecmp+2]))]
    vlan = intf_list1[0]
    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp+2), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True)

    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp+2), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, vlan, [vars.D2D1P1], tagging_mode=True)
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True)
    '''
    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    vlan_obj.create_vlan(dut1, data.vlan)
    vlan_obj.add_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.create_vlan(dut2, data.vlan)
    vlan_obj.add_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)
    '''

    yield

    ############################################################################################
    hdrMsg("### CLEANUP for TC7 ###")
    ############################################################################################
    hdrMsg("Delete router bgp on dut1 and dut2")
    ############################################################################################
    #
    bgp_obj.config_router_bgp_mode(vars.D1,'10',config_mode='disable')
    bgp_obj.config_router_bgp_mode(vars.D2,'20',config_mode='disable')

    ############################################################################################
    hdrMsg("\n############# Delete IP address to Vlan interfaces ##############\n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        utils.exec_all(True,[[ipfeature.delete_ip_interface,dut1,'Vlan'+vlan,ip1,'24'],[ipfeature.delete_ip_interface,dut2,'Vlan'+vlan,ip2,'24']])
    #utils.exec_all(True,[[ipfeature.delete_ip_interface,dut1,data.vlan1,data.d1t1_ip_addr,'24'],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ip_addr, '24']])
    port.noshutdown(vars.D2,[vars.D2D1P2])

    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')

    #vlan_obj.delete_vlan_member(dut1, data.vlan, [vars.D1T1P1])
    #vlan_obj.delete_vlan_member(dut2, data.vlan, [vars.D2T1P1])

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    #vlan_obj.delete_vlan(dut1,data.vlan)
    #vlan_obj.delete_vlan(dut2,data.vlan)
    global h1,h2
    #
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    if bgp_rtr1 and bgp_rtr2:
        bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_rtr1['conf']['handle'], mode='stop')
        bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_rtr2['conf']['handle'], mode='stop')
        st.wait(5)
    if h1 and h2:
        tg1.tg_interface_config(port_handle = tg_ph_1, handle=h1['handle'],mode='destroy')
        tg2.tg_interface_config(port_handle = tg_ph_2, handle=h2['handle'],mode='destroy')

@pytest.fixture(scope="function")
def L3Scl_fixture_008(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    ##
    ############################################################################################
    hdrMsg("Remove ip address %s on dut1 and %s on dut2 for Physical Interface"\
           % (data.d2t1_ip_addr, data.mask))
    ############################################################################################

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_1_ip_addr,data.mask, 'ipv4', True],[ipfeature.delete_ip_interface,dut2, vars.D2D1P1,data.d2d1_1_ip_addr,data.mask, 'ipv4', True]])
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_ipv6_addr,data.maskv6,'ipv6', True],[ipfeature.delete_ip_interface,dut2,vars.D2D1P1,data.d2d1_ipv6_addr,data.maskv6,'ipv6', True]])

    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    intf_list1 = [int(data.dut1_vlan_scl[0])]
    intf_list2 = [x for x in range(int(data.dut1_vlan_scl[1]),int(data.dut1_vlan_scl[data.max_ecmp+2]))]
    vlan = intf_list1[0]
    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp+2), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True)

    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp+2), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, vlan, [vars.D2D1P1], tagging_mode=True)
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True)

    '''
    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    vlan_obj.create_vlan(dut1, data.vlan)
    vlan_obj.add_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.create_vlan(dut2, data.vlan)
    vlan_obj.add_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)
    '''

    yield

    ############################################################################################
    hdrMsg("### CLEANUP for TC8 ###")
    ############################################################################################
    hdrMsg("Delete router bgp on dut1 and dut2")
    ############################################################################################
    ##
    bgp_obj.config_router_bgp_mode(vars.D1,'10',config_mode='disable')
    bgp_obj.config_router_bgp_mode(vars.D2,'20',config_mode='disable')

    ############################################################################################
    hdrMsg("\n############# Delete IP address to Vlan interfaces ##############\n")
    ############################################################################################
    for i,vlan,ipv6_1,ipv6_2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        utils.exec_all(True,[[ipfeature.delete_ip_interface,dut1,'Vlan'+vlan,ipv6_1,'64','ipv6'],[ipfeature.delete_ip_interface,dut2,'Vlan'+vlan,ipv6_2,'64','ipv6']])
    port.noshutdown(vars.D2,[vars.D2D1P2])
    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True,
                                       config='del', skip_error=True)
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True,
                                       config='del', skip_error=True)
    ###vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del', skip_error=True)
    ###vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del', skip_error=True)

    #vlan_obj.delete_vlan_member(dut1, data.vlan, [vars.D1T1P1])
    #vlan_obj.delete_vlan_member(dut2, data.vlan, [vars.D2T1P1])

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    #vlan_obj.delete_vlan(dut1,data.vlan)
    #vlan_obj.delete_vlan(dut2,data.vlan)
    #
    global h3,h4
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='stop')
    st.wait(5)
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h3['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h4['handle'],mode='destroy')

@pytest.mark.functionality
def test_L3Scl_ECMP_009(L3Scl_ECMP_fixture_009):
    global src1
    global src2
    global tr1
    global tr2
    hdrMsg("TC ID: FtRtPerfFn011; TC SUMMARY : Verify 1D Scale of Max ipv4 static routes with 64 ECMP paths on default-vrf.")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes = data.ipv4_scale_static-1
    wait_time = 2

    intf_list = [x for x in range(int(data.dut1_vlan_scl[0]),int(data.dut1_vlan_scl[data.max_ecmp_static]))]

    ############################################################################################
    hdrMsg("\n########## Configure Ve interfaces with ipv4 address ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp_static),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'24'],[ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'24']])

    ############################################################################################
    hdrMsg("\n########## Configure DUT-TG router port ########## \n")
    ############################################################################################
    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,vars.D1T1P1,data.d1t1_ip_addr,'24'],[ipfeature.config_ip_addr_interface,dut2, vars.D2T1P1, data.d2t1_ip_addr, '24']])

    ############################################################################################
    hdrMsg("\n########## Configure static route on DUT1 and DUT2 to reach TG1 and TG2 ########## \n")
    ############################################################################################
    ipfeature.create_static_route(vars.D1, data.t1d1_ip_addr, '121.1.0.0/16', shell="vtysh", family='ipv4')
    ipfeature.create_static_route(vars.D2, data.t1d2_ip_addr, '221.1.0.0/16', shell="vtysh", family='ipv4')

    #ipfeature.config_static_route_vrf(vars.D1, '121.1.0.0', '16', data.t1d1_ip_addr, family='ipv4')
    #ipfeature.config_static_route_vrf(vars.D2, '221.1.0.0', '16', data.t1d2_ip_addr, family='ipv4')
    ############################################################################################
    hdrMsg("\n########## Configure static route on DUT1 and DUT2  ########## \n")
    ############################################################################################
    '''
    frr_path = os.getcwd()
    apply_file = True
    res1 = True
    frr_apply_path = frr_path+"/routing/frr.conf"
    st.apply_files(vars.D1, [frr_apply_path])
    '''
    config_static_rt_scl(vars.D1,t=30)

    ############################################################################################
    hdrMsg("\n ########## Configure Interface hosts in TGEN1 and TGEN2 ########## \n")
    ############################################################################################
    src_handle1 = tg1.tg_interface_config(port_handle=tg_ph_1,mode='config',intf_ip_addr=data.t1d1_ip_addr,gateway=data.d1t1_ip_addr, netmask='255.255.255.0')
    src1 = src_handle1['handle']
    res1=tg1.tg_arp_control(handle=src1, arp_target='all')
    src_handle2 = tg1.tg_interface_config(port_handle=tg_ph_2,mode='config',intf_ip_addr=data.t1d2_ip_addr,gateway=data.d2t1_ip_addr,  netmask='255.255.255.0')
    src2 = src_handle2['handle']
    res2=tg2.tg_arp_control(handle=src2, arp_target='all')

    ############################################################################################
    hdrMsg("\n########## Configure raw streams on TGEN1 and TGEN2 ########## \n")
    ############################################################################################

    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ip_dst_mode='increment', ip_dst_count=num_routes,ip_dst_step='0.0.1.0',ip_src_addr=data.prefix1, ip_dst_addr=data.prefix2,   l3_protocol='ipv4',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=51200, enable_stream_only_gen='1')

    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_2, mac_src='00:21:01:00:00:01', mac_dst=mac2, ip_dst_mode='increment', ip_dst_count=num_routes,ip_dst_step='0.0.1.0',ip_src_addr=data.prefix2, ip_dst_addr=data.prefix1,   l3_protocol='ipv4',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=51200, enable_stream_only_gen='1')

    '''
    ############################################################################################
    #("\n Delete and Reconfigure static route on DUT1 and DUT2 as workaround for 8904 \n")
    ############################################################################################
    ipfeature.delete_static_route(vars.D1, data.t1d1_ip_addr, '121.1.0.0/16', shell="vtysh", family='ipv4')
    ipfeature.delete_static_route(vars.D2, data.t1d2_ip_addr, '221.1.0.0/16', shell="vtysh", family='ipv4')
    ipfeature.create_static_route(vars.D1, data.t1d1_ip_addr, '121.1.0.0/16', shell="vtysh", family='ipv4')
    ipfeature.create_static_route(vars.D2, data.t1d2_ip_addr, '221.1.0.0/16', shell="vtysh", family='ipv4')
    st.wait(5)
    '''
    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################
    arp_api.show_arp(vars.D1)
    arp_api.show_arp(vars.D2)

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    #BGP_triggers(scl_num=num_routes,ecmp=1)
    #BGP_triggers(scl_num=num_routes)

    ############################################################################################
    hdrMsg("\n####### Shutdown 1 interface and verify all traffic flows via the other interfaces ##############\n")
    ############################################################################################
    st.log("Flap the NH intf")
    port.shutdown(vars.D2,[vars.D2D1P2])
    st.wait(5)

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################
    arp_api.show_arp(vars.D1)
    arp_api.show_arp(vars.D2)

    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## Unshut the interface ############\n")
    ############################################################################################
    port.noshutdown(vars.D2,[vars.D2D1P2])
    ecmp = 0
    ############################################################################################
    hdrMsg("\n########## Clear arp table in Dut1 ############\n")
    ############################################################################################
    arp_api.clear_arp_table(vars.D1)
    st.wait(2)
    ############################################################################################
    hdrMsg("\n########## Verify routes in Dut1 ############\n")
    ############################################################################################
    if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
        debug_cmds()
        st.report_fail('fib_failure_route_fail',"count")
    else:
        st.log("Traffic test passed.\n")

    if ecmp==1:
        verify_ecmp()
    if all_triggers_flag:
        ############################################################################################
        hdrMsg("\n########## Clear the mac table in Dut1 ############\n")
        ############################################################################################

        mac_obj.clear_mac(dut1)
        st.wait(4)

        ############################################################################################
        hdrMsg("\n########## Verify routes in Dut1 ############\n")
        ############################################################################################
        if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            ##
            st.report_fail('fib_failure_route_fail',"count")
        else:
            st.log("Traffic test passed.\n")

        if ecmp==1:
            verify_ecmp()

    if all_triggers_flag:
            ############################################################################################
            hdrMsg("\n########## Verify routes after rebooting Dut1 ############\n")
            ############################################################################################
            st.log("Verification of routes after a reboot.")
            bgp_obj.enable_docker_routing_config_mode(vars.D1)
            reboot_api.config_save(vars.D1)
            reboot_api.config_save(vars.D1,shell='vtysh')
            st.reboot(vars.D1,'fast')
            st.wait(3)
            ports = port_obj.get_interfaces_all(vars.D1)
            if not ports:
                st.report_fail("operation_failed")
            else:
                st.report_pass("operation_successful")

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                ##
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

            if ecmp==1:
                verify_ecmp()
            ###########################################################################################
            hdrMsg("Step  Stop and Start the BGP container" )
            ###########################################################################################
            reboot_api.config_save(dut1)
            reboot_api.config_save(dut1,shell='vtysh')
            basic_obj.service_operations_by_systemctl(dut1, operation='stop', service='bgp')
            basic_obj.service_operations_by_systemctl(dut1, operation='restart', service='bgp')

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            st.log("Verification of number of IPv4 route entries in hardware")
            if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.log("FAIL - Expected routes not found")
                st.report_fail('fib_failure_route_fail',"Route count")
            if ecmp==1:
                verify_ecmp()
    #BGP_triggers(scl_num=num_routes,ecmp=1)

    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def L3Scl_ECMP_fixture_009(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    ############################################################################################
    hdrMsg("Remove ip address from Physical Interface\n")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_1_ip_addr,data.mask, "ipv4", True],[ipfeature.delete_ip_interface,dut2, vars.D2D1P1,data.d2d1_1_ip_addr,data.mask, "ipv4", True]])
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_ipv6_addr,data.maskv6,'ipv6', True],[ipfeature.delete_ip_interface,dut2,vars.D2D1P1,data.d2d1_ipv6_addr,data.maskv6,'ipv6', True]])

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan1,data.d1t1_ip_addr, data.mask, "ipv4", True],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ip_addr, data.mask, "ipv4", True]])
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan1,data.d1t1_ipv6_addr, data.maskv6, 'ipv6', True],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ipv6_addr, data.maskv6, 'ipv6', True]])

    ############################################################################################
    hdrMsg("Delete VLAN member and vlan from DUT-TG port \n")
    ############################################################################################
    vlan_obj.delete_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)
    vlan_obj.delete_vlan(dut1,data.vlan)
    vlan_obj.delete_vlan(dut2,data.vlan)

    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    vlan = int(data.dut1_vlan_scl[0])
    intf_list2 = [x for x in range(int(data.dut1_vlan_scl[1]),int(data.dut1_vlan_scl[data.max_ecmp_static]))]
    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp_static), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P2, skip_verify=True)
    #vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P1, skip_verify=True)

    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp_static), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, vlan, [vars.D2D1P1], tagging_mode=True)
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P2, skip_verify=True)
    #vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P1, skip_verify=True)

    yield

    hdrMsg("### CLEANUP for TC9 ###")
    port.noshutdown(vars.D2,[vars.D2D1P2])

    ############################################################################################
    hdrMsg("\n########## Unconfigure Ve interfaces with ipv4 address ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp_static),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        utils.exec_all(True,[[ipfeature.delete_ip_interface,vars.D1,'Vlan'+vlan,ip1,'24'],[ipfeature.delete_ip_interface,vars.D2,'Vlan'+vlan,ip2,'24']])

    ############################################################################################
    hdrMsg("\n########## Configure DUT-TG router port ########## \n")
    ############################################################################################
    utils.exec_all(True,[[ipfeature.delete_ip_interface,dut1,vars.D1T1P1,data.d1t1_ip_addr,'24'],[ipfeature.delete_ip_interface,dut2, vars.D2T1P1, data.d2t1_ip_addr, '24']])

    ############################################################################################
    hdrMsg("Delete static routes on dut1 and dut2")
    ############################################################################################
    ##
    config_static_rt_scl(vars.D1,t=30,config='no')

    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P2, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P1, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P1, skip_verify=True, config='del')

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')
    #vlan_obj.delete_vlan(dut1,data.vlan)
    #vlan_obj.delete_vlan(dut2,data.vlan)
    #
    global src1,src2
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    #st.wait(5)
    #
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=src1,mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=src2,mode='destroy')


@pytest.mark.functionality
def test_L3Scl_ECMP_010(L3Scl_ECMP_fixture_010):
    global src1
    global src2
    global tr1
    global tr2
    hdrMsg("TC ID: FtRtPerfFn012; TC SUMMARY : Verify 1D Scale of Max ipv6 static routes with 64 ECMP paths on default-vrf.")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes = data.ipv6_scale_static-1
    wait_time = 2

    intf_list = [x for x in range(int(data.dut1_vlan_scl[0]),int(data.dut1_vlan_scl[data.max_ecmp_static]))]

    ############################################################################################
    hdrMsg("\n########## Configure Ve interfaces with ipv6 address and vrf binding ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp_static),data.dut1_vlan_scl,data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'64','ipv6'],[ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'64','ipv6']])

    ############################################################################################
    hdrMsg("\n########## Configure DUT-TG router port ########## \n")
    ############################################################################################
    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,vars.D1T1P1,data.d1t1_ipv6_addr,'64','ipv6'],[ipfeature.config_ip_addr_interface,dut2, vars.D2T1P1, data.d2t1_ipv6_addr, '64','ipv6']])

    ############################################################################################
    hdrMsg("\n########## Configure static route on DUT1 and DUT2 to reach TG1 and TG2 ########## \n")
    ############################################################################################
    #ipfeature.config_static_route_vrf(vars.D1,'::', '0', data.t1d1_ipv6_addr, family='ipv6')
    #ipfeature.config_static_route_vrf(vars.D2,'::', '0', data.t1d2_ipv6_addr, family='ipv6')
    ipfeature.create_static_route(vars.D1, data.t1d1_ipv6_addr, '::/0', shell="vtysh", family='ipv6')
    ipfeature.create_static_route(vars.D2, data.t1d2_ipv6_addr, '::/0', shell="vtysh", family='ipv6')

    ############################################################################################
    hdrMsg("\n########## Configure static route on DUT1 and DUT2 by uploading FRR file ########## \n")
    ############################################################################################
    '''
    frr_path = os.getcwd()
    apply_file = True
    res1 = True
    frr_apply_path = frr_path+"/routing/frr.conf"
    st.apply_files(vars.D1, [frr_apply_path])
    '''
    ##
    config_static_rt_scl(vars.D1,t=30,prefix1='1121:',prefix2='3121:',family='ipv6')

    ############################################################################################
    hdrMsg("\n########## Configure Interface hosts in TGEN1 and TGEN2 ########## \n")
    ############################################################################################
    arp_api.set_ndp_ageout_time(vars.D1, 3600)
    src_handle1 = tg1.tg_interface_config(port_handle=tg_ph_1,mode='config',ipv6_intf_addr=data.t1d1_ipv6_addr,ipv6_gateway=data.d1t1_ipv6_addr, ipv6_prefix_length='64',arp_send_req='1')
    src1 = src_handle1['handle']
    res1=tg1.tg_arp_control(handle=src1, arp_target='all')
    src_handle2 = tg1.tg_interface_config(port_handle=tg_ph_2,mode='config',ipv6_intf_addr=data.t1d2_ipv6_addr,ipv6_gateway=data.d2t1_ipv6_addr, ipv6_prefix_length='64',arp_send_req='1')
    src2 = src_handle2['handle']
    res2=tg2.tg_arp_control(handle=src2, arp_target='all')
    ############################################################################################
    hdrMsg("\n########## Configure raw streams on TGEN1 and TGEN2 ########## \n")
    ############################################################################################
    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ipv6_dst_mode='increment', ipv6_dst_count=num_routes,ipv6_dst_step='0:1::',ipv6_src_addr = data.prefix_ipv6, ipv6_dst_addr=data.prefix2_ipv6,   l3_protocol='ipv6',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=51200, enable_stream_only_gen='1')

    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_2, mac_src='00:21:01:00:00:01', mac_dst=mac2, ipv6_dst_mode='increment', ipv6_dst_count=num_routes,ipv6_dst_step='0:1::',ipv6_src_addr=data.prefix2_ipv6, ipv6_dst_addr=data.prefix_ipv6,   l3_protocol='ipv6',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=51200, enable_stream_only_gen='1')
    '''
    ############################################################################################
    #("\n########## Delete and Reconfigure static route as workaround for 8904 ########## \n")
    ############################################################################################
    ipfeature.delete_static_route(vars.D1, data.t1d1_ipv6_addr, '::/0', shell="vtysh", family='ipv6')
    ipfeature.delete_static_route(vars.D2, data.t1d2_ipv6_addr, '::/0', shell="vtysh", family='ipv6')
    ipfeature.create_static_route(vars.D1, data.t1d1_ipv6_addr, '::/0', shell="vtysh", family='ipv6')
    ipfeature.create_static_route(vars.D2, data.t1d2_ipv6_addr, '::/0', shell="vtysh", family='ipv6')

    st.wait(5)
    '''
    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################
    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    #BGP_triggers(scl_num=num_routes,ecmp=1,family='ipv6')
    #BGP_triggers(scl_num=num_routes,family='ipv6')
    ############################################################################################
    hdrMsg("\n####### Shutdown 1 interface and verify all traffic flows via the other interfaces ##############\n")
    ############################################################################################
    st.log("Flap the NH intf")
    port.shutdown(vars.D2,[vars.D2D1P2])
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## Unshut the interface ############\n")
    ############################################################################################
    port.noshutdown(vars.D2,[vars.D2D1P2])
    ecmp = 0

    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def L3Scl_ECMP_fixture_010(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    '''
    tg_vrf_bind(config='no')
    vrf_config(config = 'no')
    '''
    ############################################################################################
    hdrMsg("Remove ip address from Physical Interface\n")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_1_ip_addr,data.mask, "ipv4", True],[ipfeature.delete_ip_interface,dut2, vars.D2D1P1,data.d2d1_1_ip_addr,data.mask, "ipv4", True]])
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_ipv6_addr,data.maskv6,'ipv6', True],[ipfeature.delete_ip_interface,dut2,vars.D2D1P1,data.d2d1_ipv6_addr,data.maskv6,'ipv6', True]])

    '''
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan1,data.d1t1_ip_addr, data.mask],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ip_addr, data.mask]])
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan1,data.d1t1_ipv6_addr, data.maskv6, 'ipv6'],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ipv6_addr, data.maskv6, 'ipv6']])

    ############################################################################################
    hdrMsg("Delete VLAN member and vlan from DUT-TG port \n")
    ############################################################################################
    vlan_obj.delete_vlan_member(dut1, data.vlan, [vars.D1T1P1])
    vlan_obj.delete_vlan_member(dut2, data.vlan, [vars.D2T1P1])
    vlan_obj.delete_vlan(dut1,data.vlan)
    vlan_obj.delete_vlan(dut2,data.vlan)
    '''
    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    vlan = int(data.dut1_vlan_scl[0])
    intf_list2 = [x for x in range(int(data.dut1_vlan_scl[1]),int(data.dut1_vlan_scl[data.max_ecmp_static]))]
    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp_static), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D1, vlan, [vars.D1D2P1], tagging_mode=True)
    #vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P2, skip_verify=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P1, skip_verify=True)

    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp_static), skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, vlan, [vars.D2D1P1], tagging_mode=True)
    #vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P2, skip_verify=True)
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P1, skip_verify=True)

    yield

    hdrMsg("### CLEANUP for TC10 ###")
    port.noshutdown(vars.D2,[vars.D2D1P2])

    ############################################################################################
    hdrMsg("\n########## Unconfigure Ve interfaces with ipv6 address ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp_static),data.dut1_vlan_scl,data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        utils.exec_all(True,[[ipfeature.delete_ip_interface,vars.D1,'Vlan'+vlan,ip1,'64','ipv6'],[ipfeature.delete_ip_interface,vars.D2,'Vlan'+vlan,ip2,'64','ipv6']])

    ############################################################################################
    hdrMsg("\n########## Unconfigure DUT-TG router port ########## \n")
    ############################################################################################
    utils.exec_all(True,[[ipfeature.delete_ip_interface,dut1,vars.D1T1P1,data.d1t1_ipv6_addr,'64','ipv6'],[ipfeature.delete_ip_interface,dut2, vars.D2T1P1, data.d2t1_ipv6_addr, '64','ipv6']])

    ############################################################################################
    hdrMsg("Delete static routes on dut1 and dut2")
    ############################################################################################
    ##
    config_static_rt_scl(vars.D1,t=30,prefix1='1121:',prefix2='3121:',family='ipv6',config='no')
    ipfeature.config_static_route_vrf(vars.D1,'::', '0',data.t1d1_ipv6_addr, family='ipv6', config='no')
    ipfeature.config_static_route_vrf(vars.D1,'::', '0',data.t1d2_ipv6_addr, family='ipv6', config='no')

    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    ###vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P2, skip_verify=True, config='del')
    ###vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P1, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P1, skip_verify=True, config='del')

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')

    vlan_obj.add_vlan_member(vars.D1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D2, data.vlan, [vars.D2T1P1], tagging_mode=True)
    #vlan_obj.delete_vlan(dut1,data.vlan)
    #vlan_obj.delete_vlan(dut2,data.vlan)
    #
    global src1,src2
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.wait(5)
    #
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=src1,mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=src2,mode='destroy')


def create_l3_host(tg, tg_ph, host_count,src_ip,vlan,dest_ip,mac,dst_mac=None,cfg='yes'):
    stream_list = list()
    tg.tg_traffic_control(action='reset',port_handle=tg_ph)
    trf1 = tg.tg_traffic_config(mac_dst='ff:ff:ff:ff:ff:ff',rate_pps='2000',mode='create',
        port_handle=tg_ph, transmit_mode='continuous', l3_protocol='arp',
        arp_src_hw_addr=mac, arp_src_hw_mode='increment', arp_src_hw_count=host_count,
        arp_dst_hw_mode='fixed', arp_operation='arpRequest',mac_src=mac,mac_src_mode='increment', mac_src_count=host_count,mac_src_step='00.00.00.00.00.01',
        ip_src_addr=src_ip, ip_dst_addr=dest_ip, length_mode='fixed', enable_stream_only_gen='0',
        ip_src_step='0.0.0.1', ip_src_count=host_count, ip_src_mode='increment',vlan_id=vlan,vlan_id_step='0',high_speed_result_analysis=0)
    stream_list.append(trf1['stream_id'])
    if dst_mac != None:
        trf1b=tg.tg_traffic_config(mac_dst=dst_mac,rate_pps='2000',mode='create', port_handle=tg_ph, transmit_mode='continuous', l3_protocol='arp', arp_dst_hw_addr=dst_mac, arp_src_hw_addr=mac, arp_src_hw_mode='increment', arp_src_hw_count=host_count, arp_dst_hw_mode='fixed', arp_operation='arpReply',mac_src=mac,mac_src_mode='increment', mac_src_count=host_count,mac_src_step='00.00.00.00.00.01', ip_src_addr=src_ip, ip_dst_addr=dest_ip, length_mode='fixed', enable_stream_only_gen='0', ip_src_step='0.0.0.1', ip_src_count=host_count, ip_src_mode='increment',vlan_id=vlan,vlan_id_step='0',high_speed_result_analysis=0)
        stream_list.append(trf1b['stream_id'])

    tg.tg_traffic_control(action='run', handle=stream_list)
    st.wait(10)
    return stream_list

def create_ipv6_host(tg, tg_ph, host_count,src_ipv6,vlan,dest_ipv6,mac):
    tg.tg_traffic_control(action='reset',port_handle=tg_ph)
    trf1=tg.tg_traffic_config(mac_dst='ff:ff:ff:ff:ff:ff',rate_pps='1000',mode='create',
        port_handle=tg_ph, transmit_mode='continuous', l3_protocol='arp',
        arp_src_hw_addr=mac, arp_src_hw_mode='increment', arp_src_hw_count=host_count,
        arp_dst_hw_mode='fixed', arp_operation='arpRequest',
        ipv6_src_addr=src_ipv6, ipv6_dst_addr=dest_ipv6, length_mode='fixed', enable_stream_only_gen='0',
        ipv6_src_step='0000:0::1', ipv6_src_count=host_count, ipv6_src_mode='increment',vlan_id=vlan,vlan_id_step='0')

    tg.tg_traffic_control(action='run', handle=trf1['stream_id'])

    return trf1

def measure_arp_learn_time(dut1, default_arp, max_arp):
    #(tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    sleep_time = 10
    st.log("Number of ARP's in the beginning %d" %(default_arp))
    curr_arp = default_arp
    arp_in_this_poll = default_arp
    prev_poll_count = 0
    record_start_time = 0
    #initialize for error handling
    #tg1.tg_traffic_control(action='run', handle=trf1['stream_id'])
    start_time = datetime.datetime.now()

    while(curr_arp < max_arp):
        now = datetime.datetime.now()
        prev_poll_count = arp_in_this_poll
        n = arp_api.get_arp_count(vars.D1)
        arp_in_this_poll = n - curr_arp
        #no more entries learnt, break!
        if (prev_poll_count == arp_in_this_poll):
          break

        if arp_in_this_poll > 0 and record_start_time == 0:
            start_time = now
            st.log("Time when the first arp was installed %s " %(str(start_time)))
            sleep_time = 5
            record_start_time =1
        #st.log start_time
        curr_arp = curr_arp + arp_in_this_poll
        after = datetime.datetime.now()
        st.log(" [%s]: increment %d curr_arp %d " %(str(after), arp_in_this_poll, curr_arp))
        if curr_arp == max_arp:
            break
        st.wait(sleep_time)

    end_time = datetime.datetime.now()
    st.log("Time when all the arp's were installed %s" %(str(end_time)))
    #tg1.tg_traffic_control(action='stop', handle=trf1['stream_id'])
    #st.log end_time
    diff = (end_time - start_time).total_seconds()
    st.log("total time is %d" %(int(diff)))
    return int(diff)

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
            sleep_time=5
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


def BGP_triggers(family = 'ipv4',scl_num=25000,ecmp=0):

    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    if family == 'ipv4':
        ipv4_scale = scl_num
        wait_time = ipv4_scale/10000*perf_time
        t = wait_time/4
        ############################################################################################
        hdrMsg("\n########## Clear bgp neighbor ############\n")
        ############################################################################################

        st.log("clear bgp neighbors")
        bgp_obj.clear_ip_bgp_vtysh(vars.D1)

        ############################################################################################
        hdrMsg("\n########## Verify routes in Dut1 ############\n")
        ############################################################################################
        st.wait(t)
        st.log("Verification of number of IPv4 route entries in hardware")
        retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time)
        if ecmp==1:
            verify_ecmp()

        ############################################################################################
        hdrMsg("\n########## Flap the interface in Dut1 ############\n")
        ############################################################################################
        st.log("Flap the NH intf")
        port.shutdown(dut2,[vars.D2D1P1])
        st.wait(2)

        port.noshutdown(dut2,[vars.D2D1P1])
        st.wait(15)
        ############################################################################################
        hdrMsg("\n########## Verify routes in Dut1 ############\n")
        ############################################################################################
        st.log("Verification of number of IPv4 route entries in hardware")
        retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time)
        if ecmp==1:
            verify_ecmp()

        if all_triggers_flag:
            ############################################################################################
            hdrMsg("\n########## Clear the mac table in Dut1 ############\n")
            ############################################################################################

            mac_obj.clear_mac(dut1)

            ############################################################################################
            hdrMsg("\n########## Clear arp table in Dut1 ############\n")
            ############################################################################################

            arp_api.clear_arp_table(vars.D1)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            st.log("Verification of number of IPv4 route entries in hardware")
            retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time)

            if ecmp==1:
                verify_ecmp()

            ############################################################################################
            hdrMsg("\n########## Delete router bgp in Dut1 ############\n")
            ############################################################################################

            bgp_obj.config_router_bgp_mode(dut1,10,config_mode='disable')

            ############################################################################################
            hdrMsg("\n########## Reconfigure router bgp in Dut1 ############\n")
            ############################################################################################

            bgp_obj.enable_router_bgp_mode(dut1, local_asn=10)
            bgp_obj.create_bgp_router(dut1,"10",data.rtrid1,"60","180")

            dict1 = {'local_as':'10','router_id':data.rtrid1, 'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp}
            dict2 = {'local_as':'20','router_id':data.rtrid2,'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp}
            parallel.exec_parallel(True, [dut1, dut2], bgp_obj.config_bgp, [dict1, dict2])

            bgp_obj.create_bgp_neighbor(dut1,"10",data.d2d1_1_ip_addr,"20",keep_alive="60",hold="180",family="ipv4")
            bgp_obj.create_bgp_neighbor(dut1,"10",data.t1d1_ip_addr,"100",keep_alive="60",hold="180",family="ipv4")
            bgp_obj.create_bgp_neighbor(dut1,"10",data.t1d1_ipv6_addr,"100",keep_alive="60",hold="180",family="ipv6")
            bgp_obj.create_bgp_neighbor(dut1,"10",data.d2d1_ipv6_addr,"20",keep_alive="60",hold="180",family="ipv6")

            ############################################################################################
            hdrMsg("\n########## Verify BGP neighbors in Dut1 ############\n")
            ############################################################################################
            if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", neighbor=data.d2d1_1_ip_addr, state='Established', retry_count=4,delay=5):
                st.report_fail("bgp_ip_peer_establish_fail",data.d2d1_1_ip_addr)

            if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", neighbor=data.t1d1_ip_addr, state='Established', retry_count=4,delay=5):
                st.report_fail("bgp_ip_peer_establish_fail",data.t1d1_ip_addr)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

        if all_triggers_flag:
            ############################################################################################
            hdrMsg("\n########## Verify routes after rebooting Dut1 ############\n")
            ############################################################################################

            st.log("Verification of routes after a reboot.")
            bgp_obj.enable_docker_routing_config_mode(vars.D1)
            reboot_api.config_save(vars.D1)
            reboot_api.config_save(vars.D1,shell='vtysh')
            st.reboot(vars.D1,'fast')
            st.wait(t)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")
            if ecmp==1:
                verify_ecmp()

            ###########################################################################################
            hdrMsg("Step  Stop and Start the BGP container" )
            ###########################################################################################
            reboot_api.config_save(dut1)
            reboot_api.config_save(dut1,shell='vtysh')
            basic_obj.service_operations_by_systemctl(dut1, operation='stop', service='bgp')
            basic_obj.service_operations_by_systemctl(dut1, operation='restart', service='bgp')

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            if not retry_api(verify_traffic,2,port_set = 1, retry_count=4,delay=5):
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

            if ecmp==1:
                verify_ecmp()
    else:
        ipv6_scale = scl_num
        wait_time = ipv6_scale/10000*perf_time
        t = wait_time/4
        ############################################################################################
        hdrMsg("\n########## Clear bgp neighbor ############\n")
        ############################################################################################

        st.log("clear ipv6 bgp neighbors")
        bgp_obj.clear_ipv6_bgp_vtysh(vars.D1)

        ############################################################################################
        hdrMsg("\n########## Verify routes in Dut1 ############\n")
        ############################################################################################
        if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            ##
            st.report_fail('fib_failure_route_fail',"count")
        else:
            st.log("Traffic test passed.\n")

        '''
        if ecmp==1:
            verify_ecmp()
        '''
        ############################################################################################
        hdrMsg("\n########## Flap the interface in Dut1 ############\n")
        ############################################################################################

        st.log("Flap the NH intf")
        port.shutdown(dut2,[vars.D2D1P1])
        st.wait(2)

        port.noshutdown(dut2,[vars.D2D1P1])
        st.wait(15)
        ############################################################################################
        hdrMsg("\n########## Verify BGP neighbors in Dut1 ############\n")
        ############################################################################################
        if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", family='ipv6',neighbor=data.d2d1_ipv6_addr, state='Established', retry_count=retry_time,delay=delay_time):
            st.report_fail("bgp_ip_peer_establish_fail",data.d2d1_ipv6_addr)

        ############################################################################################
        hdrMsg("\n########## Verify routes in Dut1 ############\n")
        ############################################################################################

        if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            ##
            st.report_fail('fib_failure_route_fail',"count")
        else:
            st.log("Traffic test passed.\n")

        if ecmp==1:
            verify_ecmp()

        ############################################################################################
        hdrMsg("\n########## Start and stop the traffic ############\n")
        ############################################################################################

        (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
        st.log("BOUND_STREAM: " + str(tr1))
        st.log("BOUND_STREAM: " + str(tr2))
        res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
        st.log("TrafControl: " + str(res))
        st.wait(5)
        res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
        st.log("TR_CTRL: " + str(res))
        st.wait(2)

        ############################################################################################
        hdrMsg("\n########## Verify traffic ############\n")
        ############################################################################################
        traffic_params = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D2P1],
                'rx_obj' : [tg2]
                }
        }
        aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
        if aggrResult:
            st.log('Traffic verification passed for mode aggregate')
        else:
            debug_cmds()
            st.report_fail('ip_traffic_fail')
            st.log('Traffic verification failed for mode aggregate')

        traffic_params = {
            '1': {
                'tx_ports' : [vars.T1D2P1],
                'tx_obj' : [tg2],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P1],
                'rx_obj' : [tg1]
                }
        }

        aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
        if aggrResult:
            st.log('Traffic verification passed for mode aggregate')
        else:
            debug_cmds()
            st.report_fail('ip_traffic_fail')
            st.log('Traffic verification failed for mode aggregate')
        '''
        if ecmp==1:
            verify_ecmp()
        '''
        if all_triggers_flag:
            ############################################################################################
            hdrMsg("\n########## Clear the mac table in Dut1 ############\n")
            ############################################################################################

            mac_obj.clear_mac(dut1)

            ############################################################################################
            hdrMsg("\n########## Clear ND table in Dut1 ############\n")
            ############################################################################################
            arp_api.clear_ndp_table(vars.D1)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################

            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                ##
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

            ############################################################################################
            hdrMsg("\n########## Start and stop the traffic ############\n")
            ############################################################################################

            (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
            st.log("BOUND_STREAM: " + str(tr1))
            st.log("BOUND_STREAM: " + str(tr2))
            res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
            st.log("TrafControl: " + str(res))
            st.wait(5)
            res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
            st.log("TR_CTRL: " + str(res))
            st.wait(2)

            ############################################################################################
            hdrMsg("\n########## Verify traffic ############\n")
            ############################################################################################
            traffic_params = {
                '1': {
                    'tx_ports' : [vars.T1D1P1],
                    'tx_obj' : [tg1],
                    'exp_ratio' : [1],
                    'rx_ports' : [vars.T1D2P1],
                    'rx_obj' : [tg2]
                     }
            }
            aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
            if aggrResult:
                st.log('Traffic verification passed for mode aggregate')
            else:
                debug_cmds()
                st.report_fail('ip_traffic_fail')
                st.log('Traffic verification failed for mode aggregate')

            traffic_params = {
                '1': {
                    'tx_ports' : [vars.T1D2P1],
                    'tx_obj' : [tg2],
                    'exp_ratio' : [1],
                    'rx_ports' : [vars.T1D1P1],
                    'rx_obj' : [tg1]
                     }
            }

            aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
            if aggrResult:
                st.log('Traffic verification passed for mode aggregate')
            else:
                debug_cmds()
                st.report_fail('ip_traffic_fail')
                st.log('Traffic verification failed for mode aggregate')
            '''
            if ecmp==1:
                verify_ecmp()
            '''
        if all_triggers_flag:
            ############################################################################################
            hdrMsg("\n########## Delete router bgp in Dut1 ############\n")
            ############################################################################################

            bgp_obj.config_router_bgp_mode(dut1,10,config_mode='disable')

            ############################################################################################
            hdrMsg("\n########## Reconfigure router bgp in Dut1 ############\n")
            ############################################################################################

            bgp_obj.enable_router_bgp_mode(dut1, local_asn=10)
            bgp_obj.create_bgp_router(dut1,"10",data.rtrid1,"60","180")

            bgp_obj.create_bgp_neighbor(dut1,"10",data.d2d1_ipv6_addr,"20",keep_alive="60",hold="180",family="ipv6")
            bgp_obj.create_bgp_neighbor(dut1,"10",data.t1d1_ipv6_addr,"100",keep_alive="60",hold="180",family="ipv6")

            #config_route_map(dut1, 'UseGlobal' ,type = 'next_hop_v6')
            ipfeature.config_route_map_global_nexthop(dut1,route_map='UseGlobal')

            bgp_obj.config_bgp(dut = dut1, local_as = '10', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.t1d1_ipv6_addr)
            bgp_obj.config_bgp(dut = dut1, local_as = '10', addr_family ='ipv6', config_type_list=["routeMap"], routeMap='UseGlobal', diRection='in', neighbor=data.d2d1_ipv6_addr)

            ############################################################################################
            hdrMsg(" \n####### Verify BGP neighborship on DUT1 ##############\n")
            ############################################################################################
            if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", family='ipv6', neighbor=data.t1d1_ipv6_addr, state='Established', retry_count=retry_time,delay=delay_time):
                st.report_fail('bgp_ip_peer_establish_fail',data.t1d1_ipv6_addr)

            if not retry_api(bgp_obj.verify_bgp_summary, dut1, shell="vtysh", family='ipv6', neighbor=data.d2d1_ipv6_addr, state='Established', retry_count=retry_time,delay=delay_time):
                st.report_fail("bgp_ip_peer_establish_fail",data.d2d1_ipv6_addr)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################

            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

        if all_triggers_flag:
            ############################################################################################
            hdrMsg("\n########## Verify routes after rebooting Dut1 ############\n")
            ############################################################################################

            bgp_obj.enable_docker_routing_config_mode(vars.D1)
            st.log("Verification of routes after a reboot.")
            reboot_api.config_save(vars.D1)
            reboot_api.config_save(vars.D1,shell='vtysh')
            st.reboot(vars.D1,'fast')
            st.wait(30)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################

            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")
            if ecmp==1:
                verify_ecmp()

            ###########################################################################################
            hdrMsg("Step  Stop and Start the BGP container" )
            ###########################################################################################
            reboot_api.config_save(dut1)
            reboot_api.config_save(dut1,shell='vtysh')
            basic_obj.service_operations_by_systemctl(dut1, operation='stop', service='bgp')
            basic_obj.service_operations_by_systemctl(dut1, operation='restart', service='bgp')

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################

            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

def verify_traffic(t,port_set=1):

    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    global tr1,tr2
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)

    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))

    '''
    if port_set==2:
        global tr3,tr4
        st.log("BOUND_STREAM: "+str(tr3))
        res=tg3.tg_traffic_control(action='run', handle=tr3['stream_id'])
        st.log("BOUND_STREAM: "+str(tr4))
        res=tg4.tg_traffic_control(action='run', handle=tr4['stream_id'])
        st.log("TrafControl: "+str(res))
    '''

    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    '''
    if port_set==2:
        global tr3,tr4
        res=tg3.tg_traffic_control(action='stop', handle=tr3['stream_id'])
        res=tg4.tg_traffic_control(action='stop', handle=tr4['stream_id'])
        st.log("TR_CTRL: "+str(res))
    '''
    st.wait(2)

    result = True
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        result = True
    else:
        result = False

    return result

def base_uncfg():
    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    ipfeature.delete_static_route(dut2, data.d2d1_1_ip_addr, '0.0.0.0/0', shell="vtysh", family='ipv4')
    ipfeature.delete_static_route(dut2, data.d2d1_ipv6_addr, '::/0', shell="vtysh", family='ipv6')

    ############################################################################################
    hdrMsg("Remove ip address %s on dut1 and %s on dut2 for vlan %s"\
           % (data.d2t1_ip_addr, data.mask, data.vlan1))
    ############################################################################################

    #ipfeature.delete_ip_interface(dut1, data.vlan1,data.d1t1_ip_addr, data.mask)
    #ipfeature.delete_ip_interface(dut2, data.vlan1, data.d2t1_ip_addr, data.mask)
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan1,data.d1t1_ip_addr, data.mask, "ipv4", True],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ip_addr, data.mask, True]])

    ############################################################################################
    hdrMsg("Remove ipv6 address on vlan interface")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan1,data.d1t1_ipv6_addr, data.maskv6, 'ipv6'],[ipfeature.delete_ip_interface,dut2, data.vlan1, data.d2t1_ipv6_addr, data.maskv6, 'ipv6']])
    #ipfeature.delete_ip_interface(dut1, data.vlan1, data.d1t1_ipv6_addr, data.maskv6, 'ipv6')
    #ipfeature.delete_ip_interface(dut2, data.vlan1, data.d2t1_ipv6_addr, data.maskv6, 'ipv6')
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, data.vlan201_1, data.d1t1_ipv6_addr2, data.maskv6, 'ipv6'],[ipfeature.delete_ip_interface,dut2, data.vlan201_1, data.d2t1_ipv6_addr2, data.maskv6, 'ipv6' ]])
    #ipfeature.delete_ip_interface(dut1, data.vlan201_1, data.d1t1_ipv6_addr2, data.maskv6, 'ipv6')
    #ipfeature.delete_ip_interface(dut2, data.vlan201_1, data.d2t1_ipv6_addr2, data.maskv6, 'ipv6')

    ############################################################################################
    hdrMsg("Remove ip address on dut1 and dut2 for link1")
    ############################################################################################

    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_1_ip_addr,data.mask, "ipv4", True],[ipfeature.delete_ip_interface,dut2, vars.D2D1P1,data.d2d1_1_ip_addr,data.mask, "ipv4", True]])
    utils.exec_all(True, [[ipfeature.delete_ip_interface,dut1, vars.D1D2P1,data.d1d2_ipv6_addr,data.maskv6,'ipv6', True],[ipfeature.delete_ip_interface,dut2,vars.D2D1P1,data.d2d1_ipv6_addr,data.maskv6,'ipv6', True]])
    #ipfeature.delete_ip_interface(dut1,vars.D1D2P1,data.d1d2_1_ip_addr,data.mask)
    #ipfeature.delete_ip_interface(dut1,vars.D1D2P1,data.d1d2_ipv6_addr,data.maskv6,'ipv6')

    #ipfeature.delete_ip_interface(dut2,vars.D2D1P1,data.d2d1_1_ip_addr,data.mask)
    #ipfeature.delete_ip_interface(dut2,vars.D2D1P1,data.d2d1_ipv6_addr,data.maskv6,'ipv6')

    ############################################################################################
    hdrMsg("Delete vlan member configuration")
    ############################################################################################
    utils.exec_all(True,[[vlan_obj.delete_vlan_member,dut1,data.vlan,[vars.D1T1P1],True],
                             [vlan_obj.delete_vlan_member,dut2,data.vlan,[vars.D2T1P1],True]])
    utils.exec_all(True,[[vlan_obj.delete_vlan_member,dut1,data.vlan201,[vars.D1T1P2],True],
                             [vlan_obj.delete_vlan_member,dut2,data.vlan201,[vars.D2T1P2],True]])
    #vlan_obj.delete_vlan_member(dut1, data.vlan, [vars.D1T1P1])
    #vlan_obj.delete_vlan_member(dut2, data.vlan, [vars.D2T1P1])
    vlan_obj.delete_vlan_member(dut2, data.vlan201, [vars.D2T1P2], tagging_mode=True)
    #vlan_obj.delete_vlan_member(dut1, data.vlan201, [vars.D1T1P2])
    ############################################################################################
    hdrMsg("Remove Vlan %s on dut1 ,dut2"%data.vlan1)
    ############################################################################################
    vlan_obj.delete_vlan(dut1,data.vlan)
    vlan_obj.delete_vlan(dut2,data.vlan)
    vlan_obj.delete_vlan(dut1,data.vlan201)
    vlan_obj.delete_vlan(dut2,data.vlan201)

    ############################################################################################
    hdrMsg("Delete router bgp on dut1 and dut2")
    ############################################################################################
    dict1 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
    dict2 = {'config_type_list': ["removeBGP"], 'removeBGP': 'yes', 'config': 'no'}
    parallel.exec_parallel(True, [dut1, dut2], bgp_obj.config_bgp, [dict1, dict2])

    ############################################################################################
    hdrMsg("Reset TGEN ports")
    ############################################################################################
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

def enable_debugs():
    global vars
    cmd = "debug zebra rib detailed \n  debug zebra nht detailed \n debug vrf \n debug zebra fpm \n debug zebra events \n debug zebra dplane detailed\n"
    utils.exec_all(True,[[st.vtysh_config,vars.D1,cmd],[st.vtysh_config,vars.D2,cmd]])

def debug_cmds():
    global vars
    ipfeature.show_ip_route(vars.D1,summary_routes='yes')
    ipfeature.show_ip_route(vars.D1,summary_routes='yes',family='ipv6')
    c=asicapi.bcmcmd_route_count_hardware(vars.D1)
    st.log("Hardware count on DUT1:{}".format(c))
    c=asicapi.bcmcmd_route_count_hardware(vars.D2)
    st.log("Hardware count on DUT2:{}".format(c))
    c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D1)
    c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D2)
    bgp_obj.show_bgp_ipv4_summary_vtysh(vars.D1)
    bgp_obj.show_bgp_ipv6_summary_vtysh(vars.D1)
    parallel.exec_all(True, [[asicapi.dump_l3_alpm, vars.D1], [asicapi.dump_l3_alpm, vars.D2]])


def verify_ecmp():
    global vars
    ############################################################################################
    hdrMsg("\n########## Verify ECMP Traffic ############\n")
    ############################################################################################
    c = check_ecmp()
    if c!=6:
        st.report_fail('ip_traffic_fail')
    else:
        st.log('PASS:Traffic is being load balanced as expected.')

    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True)
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, '1', [vars.D2D1P1], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, '1', [vars.D1D2P1], tagging_mode=True)

def check_ecmp():
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    res=tg1.tg_traffic_control(action='run', handle=tr11['stream_id'])
    st.log("TrafControl: "+str(res))
    st.wait(2)
    DUT_tx_value = port_obj.get_interface_counters(vars.D1, vars.D1D2P1,"tx_bps")
    st.log(DUT_tx_value)
    counter = 0
    vlan = 1

    intf_list = [x for x in range(int(data.dut1_vlan_scl[1]),int(data.dut1_vlan_scl[data.max_ecmp]))]
    random.shuffle(intf_list)
    intf_lst = [intf_list[x] for x in range(0,6)]
    intf_lst[0] = 1
    st.log(intf_lst)

    for i in range(0,6):
        DUT_tx_value[0]['tx_bps'] = DUT_tx_value[0]['tx_bps'].replace(" KB/s","")
        n = re.search(r"\d+",DUT_tx_value[0]['tx_bps'])
        DUT_tx_value[0]['tx_bps'] = int(n.group())
        if int(DUT_tx_value[0]['tx_bps']) >= 0:
            st.log("PASS:Traffic is flowing through Vlan {}".format(vlan))
            counter+=1
            st.log(counter)
        else:
            st.log("FAIL:Traffic is not flowing through Vlan {}".format(vlan))
            return counter

        if int(i) != 5:
            utils.exec_all(True,[[vlan_obj.delete_vlan_member,vars.D1,intf_lst[i],[vars.D1D2P1],True],[vlan_obj.delete_vlan_member,vars.D2,intf_lst[i],[vars.D2D1P1],True]])
            vlan=intf_lst[i]
            vlan_obj.add_vlan_member(vars.D1, vlan, [vars.D1D2P2], tagging_mode=True)
            vlan_obj.add_vlan_member(vars.D2, vlan, [vars.D2D1P2], tagging_mode=True)
            vlan = intf_lst[i+1]
            utils.exec_all(True,[[vlan_obj.delete_vlan_member,vars.D1,vlan,[vars.D1D2P2],True],[vlan_obj.delete_vlan_member,vars.D2,vlan,[vars.D2D1P2],True]])
            vlan_obj.add_vlan_member(vars.D1, vlan, [vars.D1D2P1], tagging_mode=True)
            vlan_obj.add_vlan_member(vars.D2, vlan, [vars.D2D1P1], tagging_mode=True)
            port_obj.clear_interface_counters(vars.D1)
            st.wait(2)
            DUT_tx_value = port_obj.get_interface_counters(vars.D1, vars.D1D2P1,"tx_bps")
        else:
            res=tg1.tg_traffic_control(action='stop', handle=tr11['stream_id'])
    return counter


def config_static_rt_scl(dut,t=140,**kwargs):
    st.log('Config Ve API')
    config = kwargs.get('config', '')
    pref1 = kwargs.get('prefix1', data.prefix1)
    pref2 = kwargs.get('prefix2', data.prefix2)
    family = kwargs.get('family', 'ipv4')

    def static_route_d1():
        count = 0
        if family == 'ipv4':
            ip_list2 = ip_range(data.dut2_ecmp_ip[0],2,data.max_ecmp_static-1)
            ip_pref2 = ip_range(pref2,2,data.ipv4_scale_static)
            for prefix in ip_pref2:
                for nh_ip in ip_list2:
                    nw = prefix+"/24"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D1, static_ip=nw, next_hop=nh_ip)
                    else:
                        ipfeature.create_static_route(vars.D1, static_ip=nw, next_hop=nh_ip)
                count += 1
        else:
            ipv6_list2 = ['9000:%s::2'%x for x in range (1,data.max_ecmp_static+1)]
            ipv6_pref2 = ipv6_list(pref2,data.ipv6_scale_static)
            for prefix in ipv6_pref2:
                for nh_ip in ipv6_list2:
                    nw = prefix+"/64"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D1, static_ip=nw, next_hop=nh_ip, family='ipv6')
                    else:
                        ipfeature.create_static_route(vars.D1, static_ip=nw, next_hop=nh_ip, family='ipv6')
                count += 1


    def static_route_d2():
        count = 0
        if family == 'ipv4':
            ip_list = ip_range(data.dut1_ecmp_ip[0],2,data.max_ecmp_static-1)
            ip_pref = ip_range(pref1,2,data.ipv4_scale_static)
            for prefix in ip_pref:
                for nh_ip in ip_list:
                    nw = prefix+"/24"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D2, static_ip=nw, next_hop=nh_ip)
                    else:
                        ipfeature.create_static_route(vars.D2, static_ip=nw, next_hop=nh_ip)
                count += 1

        else:
            ipv6_list1 = ['9000:%s::1'%x for x in range (1,data.max_ecmp_static+1)]
            ipv6_pref = ipv6_list(pref1,data.ipv6_scale_static)
            for prefix in ipv6_pref:
                for nh_ip in ipv6_list1:
                    nw = prefix+"/64"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D2, static_ip=nw, next_hop=nh_ip, family='ipv6')
                    else:
                        ipfeature.create_static_route(vars.D2, static_ip=nw, next_hop=nh_ip, family='ipv6')
                count += 1

    st.exec_all([[static_route_d1],[static_route_d2]])
    return True

