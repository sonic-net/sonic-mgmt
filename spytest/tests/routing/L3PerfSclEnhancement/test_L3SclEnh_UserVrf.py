#############################################################################
#Script Title : L3 Scale Enhancement
#Author       : Meenal Annamalai
#Mail-id      : meenal.annamalai@broadcom.com
#############################################################################

import random
import re
import pytest

from spytest import utils
from spytest.tgen.tg import *
from spytest.tgen.tgen_utils import *
from utilities import parallel

import apis.routing.ip as ipfeature
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.system.port as port_obj
import apis.system.basic as basic_obj
import apis.routing.bgp as bgp_obj
import apis.routing.vrf as vrf_api
import apis.routing.arp as arp_api
from apis.system import port
import apis.system.reboot as reboot_api
import apis.common.asic_bcm as asicapi
from L3SclEnhancement_vars import *
from L3SclEnhancement_lib import *

vars = dict()

@pytest.fixture(scope='module', autouse = True)
def L3ScaleEnhancement_Prologue_Epilogue():
    global tg1
    global tg2
    global tg3
    global tg4
    global tg_ph_1
    global tg_ph_2
    global tg_ph_3
    global tg_ph_4
    global plat_name
    global trigger_flag
    global vars
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:2")
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg3 = tgen_obj_dict[vars['tgen_list'][0]]
    tg4 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg1.get_port_handle(vars.T1D2P1)
    tg_ph_3 = tg2.get_port_handle(vars.T1D1P2)
    tg_ph_4 = tg2.get_port_handle(vars.T1D2P2)
    plat_name = basic_obj.get_hwsku(vars.D1)
    trigger_flag = 0
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    ############################################################################################
    hdrMsg("\n########## BASE CONFIGS ############\n")
    ############################################################################################

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

    st.log("Platform is {}".format(plat_name))

    ############################################################################################
    hdrMsg("\n########## Enable debugs ############\n")
    ############################################################################################
    enable_debugs()
    ############################################################################################
    hdrMsg("\n########## Configure VRFs globally ############\n")
    ############################################################################################
    vrf_config()

    ############################################################################################
    hdrMsg("\n########## Configure Routemap ############\n")
    ############################################################################################

    #config_route_map(dut1, 'UseGlobal' ,type = 'next_hop_v6', config = 'yes')
    #config_route_map(dut2, 'UseGlobal' ,type = 'next_hop_v6', config = 'yes')
    ipfeature.config_route_map_global_nexthop(dut1,route_map='UseGlobal')
    ipfeature.config_route_map_global_nexthop(dut2, route_map='UseGlobal')

    ############################################################################################
    hdrMsg("\n########## Configure Dut-TG ports with L3 ############\n")
    ############################################################################################

    tg_vrf_bind()

    ############################################################################################
    hdrMsg("\n########## Configure Dut-Dut ports with L3 ############\n")
    ############################################################################################

    dut_vrf_bind()
    #vrf_static_rt_cfg()
    for i,vrf in zip(range(0,3),data.vrf_name[0:3]):
        ipfeature.config_static_route_vrf(vars.D2, '0.0.0.0', '0', data.dut1_dut2_vrf_ip[i], family='ipv4', vrf_name=vrf)
        ipfeature.config_static_route_vrf(vars.D2, '::', '0', data.dut1_dut2_vrf_ipv6[i], family='ipv6', vrf_name=vrf, config = '')

    ############################################################################################
    hdrMsg("\n########## Configure BGP on Dut1 and Dut2 ############\n")
    ############################################################################################

    dut_vrf_bgp()

    yield

    vrf_base_unconfig()

def vrf_config(**kwargs):
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = ''
    if config == '':
        st.log('######------Configure vrfs ------######')
        for vrf in data.vrf_name[0:3]:
            dict1 = {'vrf_name':vrf,'skip_error':True}
            parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])
    else:
        st.log('######------Unconfigure vrfs ------######')
        for vrf in data.vrf_name[0:3]:
            dict1 = {'vrf_name':vrf,'skip_error':True,'config':'no'}
            parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])


def vrf_static_rt_cfg():
    for i,vrf in zip(range(0,3),data.vrf_name[0:3]):
        my_cmd="ip route 0.0.0.0/0 {} vrf {}".format(data.dut1_dut2_vrf_ip[i],vrf)
        #my_cmd = "ip route 0.0.0.0/0 +'+data.dut1_dut2_vrf_ip[i]+' vrf '+vrf + '\n'
        st.vtysh_config(vars.D2, my_cmd)

def vrf_static_rt_uncfg():
    for i,vrf in zip(range(0,3),data.vrf_name[0:3]):
        my_cmd="no ip route 0.0.0.0/0 {} vrf {}".format(data.dut1_dut2_vrf_ip[i],vrf)
        #my_cmd = "ip route 0.0.0.0/0 +'+data.dut1_dut2_vrf_ip[i]+' vrf '+vrf + '\n'
        st.vtysh_config(vars.D2, my_cmd)


@pytest.fixture(scope="function")
def L3Scl_fixture_004(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global h1,h2,h3,h4
    hdrMsg("### CLEANUP for TC4 ###")
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    tg_vrf_bind2(config='no')
    #
    for i in range(0,data.num_of_vrfs):
        bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_rtr1[i]['conf']['handle'], mode='stop')
        bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_rtr2[i]['conf']['handle'], mode='stop')
        bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf_3['handle'], mode='stop')
        bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf_4['handle'], mode='stop')
        st.wait(5)
        tg1.tg_interface_config(port_handle = tg_ph_1, handle=h1[i]['handle'],mode='destroy')
        tg2.tg_interface_config(port_handle = tg_ph_2, handle=h2[i]['handle'],mode='destroy')
        tg3.tg_interface_config(port_handle = tg_ph_3, handle=h3[i]['handle'],mode='destroy')
        tg4.tg_interface_config(port_handle = tg_ph_4, handle=h4[i]['handle'],mode='destroy')

@pytest.fixture(scope="function")
def L3Scl_fixture_005(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    vars = st.get_testbed_vars()
    yield
    hdrMsg("### CLEANUP for TC5 ###")
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    num_loops = max_arp_count/8000
    vlan='Vlan'+str(data.dut1_tg1_vlan[0])
    for i in range(0,num_loops+1):
        ipfeature.delete_ip_interface(vars.D1, vlan, data.ip_list_2[i], data.mask, is_secondary_ip='yes')

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
    hdrMsg("### CLEANUP for TC6 ###")
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    global h1,h2
    #tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    st.wait(5)
    tg2.tg_interface_config(port_handle=tg_ph_1, handle=h2['handle'], mode='destroy')
    st.wait(5)
    #ipfeature.delete_ip_interface(vars.D1,'Vlan'+data.dut1_tg1_vlan[0] , data.gw_ipv6, data.maskv6,family='ipv6')

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
def L3Scl_fixture_002(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global h3,h4
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    hdrMsg("### CLEANUP for TC2 ###")
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='stop')
    st.wait(5)
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h3['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h4['handle'],mode='destroy')


@pytest.fixture(scope="function")
def L3Scl_fixture_003(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global h5,h6
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    hdrMsg("### CLEANUP for TC3 ###")
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='stop')
    st.wait(5)
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h5['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h6['handle'],mode='destroy')



@pytest.mark.functionality
def test_L3Scl_vrf_002(L3Scl_fixture_002):
    global h3
    global h4
    global bgp_conf
    global bgp_conf2
    global tr1
    global tr2

    hdrMsg("TC ID: FtRtPerfFn004; TC SUMMARY : Verify 1D Scale of Max ipv6 routes with prefix <=64 on user-vrf")

    global vars
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:2")
    #vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    num_routes = ipv6_scale/2
    wait_time = ipv6_scale/10000*perf_time
    h3 = {}
    h4 = {}
    for i in range(1,2):
        h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.tg1_dut1_vrf_ipv6[i],\
            vlan_id=data.dut1_tg1_vlan[i], vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.dut1_tg1_vrf_ipv6[i], src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
        h3.update(h11)
        st.log("INTFCONF: "+str(h3))

        h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.tg1_dut2_vrf_ipv6[i],\
            vlan_id=data.dut2_tg1_vlan[i], vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.dut2_tg1_vrf_ipv6[i], src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
        h4.update(h22)
        st.log("INTFCONF: "+str(h4))

    ############################################################################################
    hdrMsg(" \n########### Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv6',shell="sonic",neighbor=data.dut2_dut1_vrf_ipv6[1], state='Established', vrf = data.vrf_name[1],delay=5,retry_count=5):
        st.log('BGP neighbor is not up ')
    else:
        st.log('BGP neighbor is up ')

    #shutdown Dut2 - Dut1 interface to allow Dut2 to populate TG2 routes first before routes received from Dut1
    port.shutdown(vars.D2,[vars.D2D1P1])
    st.wait(2)

    # Configuring BGP device on top of interface.
    i = 1
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h3['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.dut1_tg_as[i], remote_as='102', remote_ipv6_addr=data.dut1_tg1_vrf_ipv6[i])
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route1=tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix_ipv6,as_path = 'as_seq:'+data.dut1_tg_as[i])
    st.log("BGPROUTE: "+str(bgp_route1))

    # Starting the BGP device #1.
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    #bgp_ctrl2=tg1.tg_emulation_bgp_control(handle=bgp_route1['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    # Configuring BGP device on top of interface.
    bgp_conf2 = tg2.tg_emulation_bgp_config(handle=h4['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.dut2_tg_as[i], remote_as='102', remote_ipv6_addr=data.dut2_tg1_vrf_ipv6[i])
    st.log("BGPCONF: "+str(bgp_conf2))

    # Adding routes to BGP device.
    bgp_route2=tg2.tg_emulation_bgp_route_config(handle=bgp_conf2['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix2_ipv6,as_path = 'as_seq:'+data.dut2_tg_as[i])
    st.log("BGPROUTE: "+str(bgp_route2))

    # Starting the BGP device.
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='start')
    #bgp_ctrl2=tg2.tg_emulation_bgp_control(handle=bgp_route2['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    tg_vrf_bgp()

    port.noshutdown(vars.D2,[vars.D2D1P1])
    st.wait(15)
    ############################################################################################
    hdrMsg("\n########## Configure bound stream ############\n")
    ############################################################################################

    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h4['handle'], emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h3['handle'], emulation_dst_handle=bgp_route2['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)

    ############################################################################################
    hdrMsg("\n########## Verify routes are installed in the hardware ############\n")
    ############################################################################################
    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
         st.report_fail('fib_failure_route_fail',"count")
         st.log('Expected number of routes not found')
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

    BGP_triggers(family = 'ipv6',scl_num=ipv6_scale)

    st.log('Verified Platform {} for IPv6 max scale {} in user-vrf'.format(plat_name,ipv6_scale))
    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_L3Scl_vrf_003(L3Scl_fixture_003):
    global h5
    global h6
    global bgp_conf
    global bgp_conf2

    hdrMsg("TC ID: FtRtPerfFn006; TC SUMMARY : Verify 1D Scale of Max ipv6 routes with prefix >64 on user-vrf")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    num_routes = ipv6_scale_abv_64/2
    wait_time = ipv6_scale_abv_64/10000*perf_time

    h5 = {}
    h6 = {}

    for i in range(1,2):
        h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.tg1_dut1_vrf_ipv6[i],\
            vlan_id=data.dut1_tg1_vlan[i],vlan='1', \
            ipv6_prefix_length='64', ipv6_gateway=data.dut1_tg1_vrf_ipv6[i], src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
        h5.update(h11)
        st.log("INTFCONF: "+str(h5))

        h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.tg1_dut2_vrf_ipv6[i],\
            vlan_id=data.dut2_tg1_vlan[i], vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.dut2_tg1_vrf_ipv6[i], src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
        h6.update(h22)
        st.log("INTFCONF: "+str(h6))

    ############################################################################################
    hdrMsg(" \n####### STEP 3.1: Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv6',shell="sonic",neighbor=data.dut2_dut1_vrf_ipv6[1], state='Established', vrf = data.vrf_name[1],delay=5,retry_count=5):
        st.log('BGP neighbor is not up ')
    else:
        st.log('BGP neighbor is up ')

    # Shutdown Dut2 - Dut1 interface to allow Dut2 to populate TG2 routes first before routes received from Dut1
    port.shutdown(vars.D2,[vars.D2D1P1])
    st.wait(2)

    # Configuring BGP device on top of interface.
    i = 1
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h5['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.dut1_tg_as[i], remote_as='102', remote_ipv6_addr=data.dut1_tg1_vrf_ipv6[i])
    st.log("BGPCONF: "+str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route1=tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix_ipv6,as_path = 'as_seq:'+data.dut1_tg_as[i],ipv6_prefix_length='72')
    st.log("BGPROUTE: "+str(bgp_route1))


    # Starting the BGP device.
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    #bgp_ctrl2=tg1.tg_emulation_bgp_control(handle=bgp_route1['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    # Configuring BGP device on top of interface.
    bgp_conf2 = tg2.tg_emulation_bgp_config(handle=h6['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.dut2_tg_as[i], remote_as='102', remote_ipv6_addr=data.dut2_tg1_vrf_ipv6[i])
    st.log("BGPCONF: "+str(bgp_conf2))
    # Adding routes to BGP device.
    bgp_route2=tg2.tg_emulation_bgp_route_config(handle=bgp_conf2['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix2_ipv6,as_path = 'as_seq:'+data.dut2_tg_as[i],ipv6_prefix_length='72')
    st.log("BGPROUTE: "+str(bgp_route2))

    # Starting the BGP device.
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    tg_vrf_bgp()

    port.noshutdown(vars.D2,[vars.D2D1P1])
    st.wait(15)
    ############################################################################################
    hdrMsg("\n########## STEP 3.2: Verify routes are installed in the hardware ############\n")
    ############################################################################################
    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale_abv_64, retry_count=retry_time,delay=5):
        debug_cmds()
        st.log("FAIL - Expected routes not found")
        st.report_fail('fib_failure_route_fail',"Route count")

    ############################################################################################
    hdrMsg("\n########## STEP 3.3: Configure bound stream ############\n")
    ############################################################################################
    tr1=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h6['handle'], emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)
    tr2=tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h5['handle'], emulation_dst_handle=bgp_route2['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)
    st.log("BOUND_STREAM: "+str(tr1))
    st.log("BOUND_STREAM: "+str(tr2))

    ############################################################################################
    hdrMsg("\n########## STEP 3.4: Start and stop the traffic ############\n")
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
    hdrMsg("\n########## STEP 3.5: Verify traffic ############\n")
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

    ipv6_scale=ipv6_scale_abv_64
    BGP_triggers(family='ipv6',scl_num=ipv6_scale)

    st.log('Verified Platform {} for IPv6 >/64 max scale {} in user-vrf'.format(plat_name,ipv6_scale))
    st.report_pass('test_case_passed')

@pytest.mark.functionality
def test_L3Scl_vrf_004(L3Scl_fixture_004):
    global h1
    global h2
    global h3
    global h4
    global bgp_rtr1
    global bgp_rtr2
    global bgp_route1
    global bgp_route2
    global bgp_conf_3
    global bgp_conf_4
    global tr1
    global tr2
    global tr3
    global tr4

    hdrMsg("TC ID: FtRtPerfFn004; TC SUMMARY : Verify 1D Scale of Max ipv4+ipv6 routes with different prefix ranges on user-vrf")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes_v4 =ipv4_scale_ipv4ipv6/2
    num_routes_v6 =ipv6_scale_ipv4ipv6/2
    total = ipv4_scale_ipv4ipv6 + ipv6_scale_ipv4ipv6
    wait_time = total/10000*perf_time

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    h1 = {}
    h2 = {}
    h3 = {}
    h4 = {}
    for i,mac in zip(range(0,data.num_of_vrfs),data.src_mac_list):
       h1[i]=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.tg1_dut1_vrf_ip[i],\
            vlan_id=data.dut1_tg1_vlan[i], vlan='1',\
            gateway=data.dut1_tg1_vrf_ip[i], src_mac_addr=mac, arp_send_req='1')
       st.log("INTFCONF: "+str(h1[i]))

    for i,mac in zip(range(0,data.num_of_vrfs),data.src_mac_list2):
       h2[i]=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.tg1_dut2_vrf_ip[i],\
            vlan_id=data.dut2_tg1_vlan[i], vlan='1',\
            gateway=data.dut2_tg1_vrf_ip[i], src_mac_addr=mac, arp_send_req='1')
       st.log("INTFCONF: "+str(h2[i]))

    st.wait(5)
    tg3.tg_traffic_control(action='reset',port_handle=tg_ph_3)
    tg4.tg_traffic_control(action='reset',port_handle=tg_ph_4)
    for i,mac in zip(range(0,data.num_of_vrfs),data.src_mac_list):
        h3[i]=tg3.tg_interface_config(port_handle=tg_ph_3, mode='config', ipv6_intf_addr=data.tg1_dut1_vrf_ipv6_2[i],\
            vlan_id=data.dut1_tg1_vlan2[i],vlan='1', \
            ipv6_prefix_length='64', ipv6_gateway=data.dut1_tg1_vrf_ipv6_2[i], src_mac_addr=mac, arp_send_req='1')
        st.log("INTFCONF: "+str(h3[i]))
    st.wait(5)
    for i,mac in zip(range(0,data.num_of_vrfs),data.src_mac_list2):
        h4[i]=tg4.tg_interface_config(port_handle=tg_ph_4, mode='config', ipv6_intf_addr=data.tg1_dut2_vrf_ipv6_2[i],\
            vlan_id=data.dut1_tg1_vlan2[i], vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.dut2_tg1_vrf_ipv6_2[i], src_mac_addr=mac, arp_send_req='1')
        st.log("INTFCONF: "+str(h4[i]))
    st.wait(5)
    tg_vrf_bind2()

    ############################################################################################
    hdrMsg(" \n####### Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################
    num_routes_v4 =ipv4_scale_ipv4ipv6/2
    num_routes_v6 =ipv6_scale_ipv4ipv6/2
    wait_time = ipv4_scale_ipv4ipv6/10000*perf_time
    route_count_v4 = int(num_routes_v4)/data.num_of_vrfs
    route_count_v6 = int(num_routes_v6)/data.num_of_vrfs

    bgp_rtr1 = dict()
    bgp_rtr2 = dict()
    bgp_route1 = dict()
    bgp_route2 = dict()

    for i in range(0,data.num_of_vrfs):
        conf_var = { 'mode'              : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : data.dut1_tg_as[i],
                 'remote_as'             : data.dut1_as[i],
                 'remote_ip_addr'        : data.dut1_tg1_vrf_ip[i]
               }
        route_var = { 'mode'       : 'add',
                  'num_routes' : route_count_v4,
                  'as_path'    : 'as_seq:'+data.dut1_tg_as[i],
                  'prefix'     : data.prefix_list_vrf[i]
                }
        ctrl_start = { 'mode' : 'start'}
        ctrl_stop = { 'mode' : 'stop'}
        # Configuring the BGP router.
        bgp_rtr1[i] = tg_bgp_config(tg = tg1,
            handle    = h1[i]['handle'],
            conf_var  = conf_var,
            route_var = route_var,
            ctrl_var  = ctrl_start)
        st.wait(5)

        conf_var2 = { 'mode'    : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'     : data.dut2_tg_as[i],
                 'remote_as'    : data.dut2_as[i],
                 'remote_ip_addr': data.dut2_tg1_vrf_ip[i]
               }
        route_var2 = { 'mode'  : 'add',
                  'num_routes' :  route_count_v4,
                  'as_path'    : 'as_seq:'+data.dut2_tg_as[i],
                  'prefix'     : data.prefix2_list_vrf[i]
                }
        ctrl_start = { 'mode' : 'start'}
        ctrl_stop = { 'mode' : 'stop'}

        # Configuring the BGP router.
        bgp_rtr2[i] = tg_bgp_config(tg = tg2,
            handle    = h2[i]['handle'],
            conf_var  = conf_var2,
            route_var = route_var2,
            ctrl_var  = ctrl_start)
    st.wait(5)

    for i in range(0,data.num_of_vrfs):
        # Configuring BGP device on top of interface.
        bgp_conf_3 = tg3.tg_emulation_bgp_config(handle=h3[i]['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.dut1_tg_as[i], remote_as=data.dut1_as[i], remote_ipv6_addr=data.dut1_tg1_vrf_ipv6_2[i])
        st.log("BGPCONF: "+str(bgp_conf_3))

        # Adding routes to BGP device.
        bgp_route1[i]=tg3.tg_emulation_bgp_route_config(handle=bgp_conf_3['handle'], mode='add', ip_version='6', num_routes=route_count_v6, prefix=data.prefix_list_ipv6_vrf[i],as_path = 'as_seq:'+data.dut1_tg_as[i])
        st.log("BGPROUTE: "+str(bgp_route1))

        # Starting the BGP device.
        bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf_3['handle'], mode='start')
        st.log("BGPCTRL: "+str(bgp_ctrl))
        st.wait(10)
        # Configuring BGP device on top of interface.
        bgp_conf_4 = tg4.tg_emulation_bgp_config(handle=h4[i]['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as=data.dut2_tg_as[i], remote_as=data.dut2_as[i], remote_ipv6_addr=data.dut2_tg1_vrf_ipv6_2[i])
        st.log("BGPCONF: "+str(bgp_conf_4))

        # Adding routes to BGP device.
        bgp_route2[i]=tg4.tg_emulation_bgp_route_config(handle=bgp_conf_4['handle'], mode='add', ip_version='6', num_routes=route_count_v6, prefix=data.prefix2_list_ipv6_vrf[i],as_path = 'as_seq:'+data.dut2_tg_as[i])
        st.log("BGPROUTE: "+str(bgp_route2))
        # Starting the BGP device.
        bgp_ctrl=tg4.tg_emulation_bgp_control(handle=bgp_conf_4['handle'], mode='start')
        st.log("BGPCTRL: "+str(bgp_ctrl))
        # Verified at neighbor.

        tg_vrf_bgp()
        tg_vrf_bgp2()

        if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv6',shell="sonic",neighbor=data.dut2_dut1_vrf_ipv6[i], state='Established', vrf = data.vrf_name[i],delay=5,retry_count=5):
            st.log('BGP neighbor is not up ')
        else:
            st.log('BGP neighbor is up ')

        if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv4',shell="sonic",neighbor=data.dut2_dut1_vrf_ip[i], state='Established', vrf = data.vrf_name[i],delay=5,retry_count=5):
            st.log('BGP neighbor is down ')
        else:
            st.log('PASS - BGP neighbor is up ')

    ############################################################################################
    hdrMsg("\n########## Verify BGP routes in the routing table ############\n")
    ############################################################################################
    st.log("Verification of number of IPv4 route entries in hardware")
    if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale_ipv4ipv6, retry_count=retry_time,delay=delay_time):
        debug_cmds()
        st.log('FAIL - Expected routes not found in hardware')
        st.report_fail('fib_failure_route_fail',"Route count")

    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale_ipv4ipv6, retry_count=retry_time,delay=delay_time):
         debug_cmds()
         st.report_fail('fib_failure_route_fail',"count")
         st.log('Expected number of routes not found')

    ############################################################################################
    hdrMsg("\n########## Configure bound stream ############\n")
    ############################################################################################
    # Configuring bound stream host_to_routeHandle.
    tr1 = {}
    tr2 = {}
    tr3 = {}
    tr4 = {}
    for i in range(0,data.num_of_vrfs):
        tr1[i]=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2[i]['handle'], emulation_dst_handle=bgp_rtr1[i]['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
        tr2[i]=tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1[i]['handle'], emulation_dst_handle=bgp_rtr2[i]['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
        tr3[i]=tg3.tg_traffic_config(port_handle=tg_ph_3,emulation_src_handle=h3[i]['handle'], emulation_dst_handle=bgp_route2[i]['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
        tr4[i]=tg4.tg_traffic_config(port_handle=tg_ph_4,emulation_src_handle=h4[i]['handle'], emulation_dst_handle=bgp_route1[i]['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_1)
    tg2.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_2)
    for i in range(0,data.num_of_vrfs):
        st.log("BOUND_STREAM: " + str(tr1[i]))
        st.log("BOUND_STREAM: " + str(tr2[i]))
        st.log("BOUND_STREAM: " + str(tr3[i]))
        st.log("BOUND_STREAM: " + str(tr4[i]))
        res=tg1.tg_traffic_control(action='run', handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'], tr4[i]['stream_id']])
        st.log("TrafControl: "+str(res))
    st.wait(3)
    # Verified at the DUT.
    for i in range(0,data.num_of_vrfs):
        res=tg1.tg_traffic_control(action='stop', handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'], tr4[i]['stream_id']])
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

    ipv4_scale = ipv4_scale_ipv4ipv6
    ipv6_scale = ipv6_scale_ipv4ipv6

    wait_time = ipv4_scale_ipv4ipv6/10000*perf_time
    t = wait_time/4

    ############################################################################################
    hdrMsg("\n########## Clear bgp neighbor ############\n")
    ############################################################################################

    st.log("clear bgp neighbors")
    bgp_obj.clear_ip_bgp_vrf_vtysh(vars.D1,data.vrf_name[1])

    ############################################################################################
    hdrMsg("\n########## Clear bgp neighbor ############\n")
    ############################################################################################

    st.log("clear ipv6 bgp neighbors")
    bgp_obj.clear_ip_bgp_vrf_vtysh(vars.D1,data.vrf_name[1],family='ipv6')

    ############################################################################################
    hdrMsg("\n########## Verify routes in Dut1 ############\n")
    ############################################################################################

    st.log("Verification of number of IPv4 route entries in hardware")
    if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
        debug_cmds()
        st.log('FAIL: Expected number of routes not found')
        st.report_fail('fib_failure_route_fail',"Route count")

    ############################################################################################
    hdrMsg("\n########## Verify IPv6 routes in Dut1 ############\n")
    ############################################################################################

    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
        debug_cmds()
        st.log("FAIL - Expected routes not found")
        st.report_fail('fib_failure_route_fail',"Route count")

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_1)
    tg2.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_2)
    for i in range(0,data.num_of_vrfs):
        st.log("BOUND_STREAM: " + str(tr1[i]))
        st.log("BOUND_STREAM: " + str(tr2[i]))
        res=tg1.tg_traffic_control(action='run', handle=[tr1[i]['stream_id'], tr2[i]['stream_id']])
        st.log("TrafControl: "+str(res))
    st.wait(3)
    # Verified at the DUT.
    for i in range(0,data.num_of_vrfs):
        res=tg1.tg_traffic_control(action='stop', handle=[tr1[i]['stream_id'], tr2[i]['stream_id']])
        st.log("TR_CTRL: "+str(res))
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

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1],'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## Flap the interface in Dut1 ############\n")
    ############################################################################################

    st.log("Flap the NH intf")
    port.shutdown(dut2,[vars.D2D1P1])
    st.wait(2)

    port.noshutdown(dut2,[vars.D2D1P1])
    st.wait(15)
    ############################################################################################
    hdrMsg("\n########## Verify IPv4 routes in Dut1 ############\n")
    ############################################################################################
    if not retry_api(verify_route_count_hardware, vars.D1, exp_num_of_routes=ipv4_scale, retry_count=retry_time, delay=delay_time):
        debug_cmds()
        st.log("FAIL - Expected routes not found")
        st.report_fail('fib_failure_route_fail',"Route count")

    ############################################################################################
    hdrMsg("\n########## Verify IPv6 routes in Dut1 ############\n")
    ############################################################################################

    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
        debug_cmds()
        st.log("FAIL - Expected routes not found")
        st.report_fail('fib_failure_route_fail',"Route count")

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_1)
    tg2.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_2)
    for i in range(0, data.num_of_vrfs):
        st.log("BOUND_STREAM: " + str(tr1[i]))
        st.log("BOUND_STREAM: " + str(tr2[i]))
        st.log("BOUND_STREAM: " + str(tr3[i]))
        st.log("BOUND_STREAM: " + str(tr4[i]))
        res = tg1.tg_traffic_control(action='run', handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'], tr4[i]['stream_id']])
        st.log("TrafControl: " + str(res))
    st.wait(3)
    # Verified at the DUT.
    for i in range(0, data.num_of_vrfs):
        res = tg1.tg_traffic_control(action='stop', handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'], tr4[i]['stream_id']])
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

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1],'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    if trigger_flag:
        ############################################################################################
        hdrMsg("\n########## Clear the mac table in Dut1 ############\n")
        ############################################################################################
        mac_obj.clear_mac(dut1)
        st.wait(4)
        ############################################################################################
        hdrMsg("\n########## Clear arp table in Dut1 ############\n")
        ############################################################################################
        arp_api.clear_arp_table(vars.D1)

        ############################################################################################
        hdrMsg("\n########## Verify IPv4 routes in Dut1 ############\n")
        ############################################################################################
        if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            st.log("FAIL - Expected routes not found")
            st.report_fail('fib_failure_route_fail',"Route count")

        ############################################################################################
        hdrMsg("\n########## Verify IPv6 routes in Dut1 ############\n")
        ############################################################################################

        st.log("Verification of number of IPv6 route entries in hardware")
        if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            st.log("FAIL - Expected routes not found")
            st.report_fail('fib_failure_route_fail',"Route count")

        ############################################################################################
        hdrMsg("\n########## Start and stop the traffic ############\n")
        ############################################################################################

        tg1.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_1)
        tg2.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_2)
        for i in range(0, data.num_of_vrfs):
            st.log("BOUND_STREAM: " + str(tr1[i]))
            st.log("BOUND_STREAM: " + str(tr2[i]))
            st.log("BOUND_STREAM: " + str(tr3[i]))
            st.log("BOUND_STREAM: " + str(tr4[i]))
            res = tg1.tg_traffic_control(action='run',
                                         handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'],
                                                 tr4[i]['stream_id']])
            st.log("TrafControl: " + str(res))
        st.wait(3)
        # Verified at the DUT.
        for i in range(0, data.num_of_vrfs):
            res = tg1.tg_traffic_control(action='stop',
                                         handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'],
                                                 tr4[i]['stream_id']])
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

        traffic_params = {'1': {'tx_ports' : [vars.T1D2P1],'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
        aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

        if aggrResult:
            st.log('Traffic verification passed for mode aggregate')
        else:
            debug_cmds()
            st.report_fail('ip_traffic_fail')
            st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## Verify routes after rebooting Dut1 ############\n")
    ############################################################################################
    st.log("Verification of routes after a reboot.")
    bgp_obj.enable_docker_routing_config_mode(vars.D1)
    reboot_api.config_save(vars.D1)
    st.vtysh(vars.D1,"copy running-config startup-config")
    st.reboot(vars.D1,'fast')
    #reboot_frc(vars.D1)
    st.wait(5)
    ports = port_obj.get_interfaces_all(vars.D1)
    if not ports:
        debug_cmds()
        st.report_fail("operation_failed")
    else:
        st.report_pass("operation_successful")

    ############################################################################################
    hdrMsg("\n########## Verify IPv4 routes in Dut1 ############\n")
    ############################################################################################
    if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
        debug_cmds()
        st.log("FAIL - Expected routes not found")
        st.report_fail('fib_failure_route_fail',"Route count")

    ############################################################################################
    hdrMsg("\n########## Verify IPv6 routes in Dut1 ############\n")
    ############################################################################################

    st.log("Verification of number of IPv6 route entries in hardware")
    if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
        debug_cmds()
        st.log("FAIL - Expected routes not found")
        st.report_fail('fib_failure_route_fail',"Route count")

    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_1)
    tg2.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_2)
    for i in range(0, data.num_of_vrfs):
        st.log("BOUND_STREAM: " + str(tr1[i]))
        st.log("BOUND_STREAM: " + str(tr2[i]))
        st.log("BOUND_STREAM: " + str(tr3[i]))
        st.log("BOUND_STREAM: " + str(tr4[i]))
        res = tg1.tg_traffic_control(action='run',
                                     handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'],
                                             tr4[i]['stream_id']])
        st.log("TrafControl: " + str(res))
    st.wait(3)
    # Verified at the DUT.
    for i in range(0, data.num_of_vrfs):
        res = tg1.tg_traffic_control(action='stop',
                                     handle=[tr1[i]['stream_id'], tr2[i]['stream_id'], tr3[i]['stream_id'],
                                             tr4[i]['stream_id']])
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

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1],'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    st.log('Verified Platform {} for IPv4+IPv6  max scale {} and {} in user-vrf'.format(plat_name,ipv4_scale,ipv6_scale))
    st.report_pass('test_case_passed')

@pytest.mark.functionality
def test_L3Scl_vrf_001(L3Scl_fixture_001):
    global h1
    global h2
    global bgp_rtr1
    global bgp_rtr2
    global tr1
    global tr2

    hdrMsg("TC ID: FtRtPerfFn002; TC SUMMARY : Verify 1D Scale of Max ipv4 routes with different prefix ranges on user-vrf")

    global vars
    #vars = st.get_testbed_vars()
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:2")

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    h1 = {}
    h2 = {}
    for i,mac in zip(range(0,data.num_of_vrfs),data.src_mac_list):
       h1[i]=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.tg1_dut1_vrf_ip[i],\
            vlan_id=data.dut1_tg1_vlan[i], vlan='1',\
            gateway=data.dut1_tg1_vrf_ip[i], src_mac_addr=mac, arp_send_req='1')
       st.log("INTFCONF: "+str(h1[i]))

    for i,mac in zip(range(0,data.num_of_vrfs),data.src_mac_list2):
       h2[i]=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.tg1_dut2_vrf_ip[i],\
            vlan_id=data.dut2_tg1_vlan[i], vlan='1',\
            gateway=data.dut2_tg1_vrf_ip[i], src_mac_addr=mac, arp_send_req='1')
       st.log("INTFCONF: "+str(h2[i]))

    ############################################################################################
    hdrMsg(" \n####### Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################

    num_routes = ipv4_scale/2
    route_count = int(num_routes)/data.num_of_vrfs
    bgp_rtr1 = dict()
    bgp_rtr2 = dict()
    for i in range(0,data.num_of_vrfs):
        conf_var = { 'mode'              : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : data.dut1_tg_as[i],
                 'remote_as'             : data.dut1_as[i],
                 'remote_ip_addr'        : data.dut1_tg1_vrf_ip[i]
               }
        route_var = { 'mode'       : 'add',
                  'num_routes' : route_count,
                  'as_path'    : 'as_seq:'+data.dut1_tg_as[i],
                  'prefix'     : data.prefix_list_vrf[i]
                }
        ctrl_start = { 'mode' : 'start'}
        ctrl_stop = { 'mode' : 'stop'}

        conf_var2 = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : data.dut2_tg_as[i],
                 'remote_as'             : data.dut2_as[i],
                 'remote_ip_addr'        : data.dut2_tg1_vrf_ip[i]
               }
        route_var2 = { 'mode'  : 'add',
                  'num_routes' :  route_count,
                  'as_path'    : 'as_seq:'+data.dut2_tg_as[i],
                  'prefix'     : data.prefix2_list_vrf[i]
                }
        ctrl_start = { 'mode' : 'start'}
        ctrl_stop = { 'mode' : 'stop'}

        # Configuring the BGP router.
        bgp_rtr2[i] = tg_bgp_config(tg = tg2,
            handle    = h2[i]['handle'],
            conf_var  = conf_var2,
            route_var = route_var2,
            ctrl_var  = ctrl_start)
        st.wait(5)

        # Configuring the BGP router #1.
        bgp_rtr1[i] = tg_bgp_config(tg = tg1,
            handle    = h1[i]['handle'],
            conf_var  = conf_var,
            route_var = route_var,
            ctrl_var  = ctrl_start)

    tg_vrf_bgp()
    #
    if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv4',shell="sonic",neighbor=data.dut2_dut1_vrf_ip[1], state='Established', vrf = data.vrf_name[1],delay=5,retry_count=5):
        st.log('BGP neighbor is down ')
    else:
        st.log('PASS - BGP neighbor is up ')

    ############################################################################################
    hdrMsg("\n########## Configure bound stream ############\n")
    ############################################################################################
    # Configuring bound stream host_to_routeHandle.
    #globals()['tr1']={}
    #globals()['tr2']={}
    for i in range(0,data.num_of_vrfs):
        tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2[i]['handle'], emulation_dst_handle=bgp_rtr1[i]['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)
        tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1[i]['handle'], emulation_dst_handle=bgp_rtr2[i]['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0',high_speed_result_analysis=0)

    ############################################################################################
    hdrMsg("\n########## Verify BGP routes in the routing table ############\n")
    ############################################################################################
    st.log("Verification of number of IPv4 route entries in hardware")
    if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
        st.log('FAIL - Expected routes not found in hardware')
        st.report_fail('fib_failure_route_fail',"Route count")
    ############################################################################################
    hdrMsg("\n########## Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_1)
    tg2.tg_traffic_control(action = 'clear_stats',port_handle = tg_ph_2)
    for i in range(0,data.num_of_vrfs):
        st.log("BOUND_STREAM: " + str(tr1))
        st.log("BOUND_STREAM: " + str(tr2))
        res=tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
        st.log("TrafControl: "+str(res))
    st.wait(3)
    # Verified at the DUT.
    for i in range(0,data.num_of_vrfs):
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

    BGP_triggers(scl_num=ipv4_scale)

    st.log('Verified Platform {} for IPv4 max scale {} in user-vrf'.format(plat_name,ipv4_scale))
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def L3Scl_fixture_001(request,L3ScaleEnhancement_Prologue_Epilogue):
    yield
    global h1,h2
    hdrMsg("### CLEANUP for TC1 ###")
    #
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    for i in range(0,data.num_of_vrfs):
        bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_rtr1[i]['conf']['handle'], mode='stop')
        bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_rtr2[i]['conf']['handle'], mode='stop')
        st.wait(4)
        tg1.tg_interface_config(port_handle = tg_ph_1, handle=h1[i]['handle'],mode='destroy')
        tg2.tg_interface_config(port_handle = tg_ph_2, handle=h2[i]['handle'],mode='destroy')

def create_l3_host(tg, tg_ph, host_count, src_ip, vlan, dest_ip, mac, dst_mac=None, cfg='yes'):
    tg.tg_traffic_control(action='reset', port_handle=tg_ph)
    '''
    trf1=tg.tg_traffic_config(mac_dst='ff:ff:ff:ff:ff:ff',rate_pps='1000',mode='create',
        port_handle=tg_ph, transmit_mode='continuous', l3_protocol='arp',
        arp_src_hw_addr=mac, arp_src_hw_mode='increment', arp_src_hw_count=host_count,
        arp_dst_hw_mode='fixed', arp_operation='arpRequest',
        ip_src_addr=src_ip, ip_dst_addr=dest_ip, length_mode='fixed', enable_stream_only_gen='0',
        ip_src_step='0.0.0.1', ip_src_count=host_count, ip_src_mode='increment',vlan_id=vlan,vlan_id_step='0',high_speed_result_analysis=0)
    tg.tg_traffic_control(action='run', handle=trf1['stream_id'])
    '''
    stream_list = list()
    trf1 = tg.tg_traffic_config(mac_dst='ff:ff:ff:ff:ff:ff', rate_pps='2000', mode='create',
                                port_handle=tg_ph, transmit_mode='continuous', l3_protocol='arp',
                                arp_src_hw_addr=mac, arp_src_hw_mode='increment', arp_src_hw_count=host_count,
                                arp_dst_hw_mode='fixed', arp_operation='arpRequest', mac_src=mac,
                                mac_src_mode='increment', mac_src_count=host_count, mac_src_step='00.00.00.00.00.01',
                                ip_src_addr=src_ip, ip_dst_addr=dest_ip, length_mode='fixed',
                                enable_stream_only_gen='0',
                                ip_src_step='0.0.0.1', ip_src_count=host_count, ip_src_mode='increment', vlan_id=vlan,
                                vlan_id_step='0', high_speed_result_analysis=0)
    stream_list.append(trf1['stream_id'])
    if dst_mac != None:
        trf1b = tg.tg_traffic_config(mac_dst=dst_mac, rate_pps='2000', mode='create', port_handle=tg_ph,
                                     transmit_mode='continuous', l3_protocol='arp', arp_dst_hw_addr=dst_mac,
                                     arp_src_hw_addr=mac, arp_src_hw_mode='increment', arp_src_hw_count=host_count,
                                     arp_dst_hw_mode='fixed', arp_operation='arpReply', mac_src=mac,
                                     mac_src_mode='increment', mac_src_count=host_count,
                                     mac_src_step='00.00.00.00.00.01', ip_src_addr=src_ip, ip_dst_addr=dest_ip,
                                     length_mode='fixed', enable_stream_only_gen='0', ip_src_step='0.0.0.1',
                                     ip_src_count=host_count, ip_src_mode='increment', vlan_id=vlan, vlan_id_step='0',
                                     high_speed_result_analysis=0)
        stream_list.append(trf1b['stream_id'])

    tg.tg_traffic_control(action='run', handle=stream_list)
    st.wait(10)
    tg.tg_traffic_control(action='stop', handle=stream_list)

    return stream_list

def create_l3_host_v6(tg, tg_ph, host_count):
    tg.tg_traffic_control(action='reset',port_handle=tg_ph)
    tr1 = tg.tg_traffic_config(mac_src = '00.00.00.00.00.01',mac_dst='00.00.00.00.00.02',rate_pps='1000',mode='create',\
          port_handle=tg_ph, transmit_mode='continuous',\
          frame_size='128', l3_protocol='ipv6', ipv6_src_addr=data.src_ipv6,
          ipv6_dst_addr=data.gw_ipv6, l4_protocol='udp', udp_src_port='32222', udp_dst_port='33333',\
          length_mode='fixed', enable_stream_only_gen='0',
          ipv6_src_step='::1', ipv6_src_count=host_count, ipv6_src_mode='increment',vlan_id=data.dut1_tg1_vlan[0],vlan_id_step='0',vlan='1',high_speed_result_analysis=0)

    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])

    return tr1


@pytest.mark.functionality
def test_L3Scl_vrf_005(L3Scl_fixture_005):

    hdrMsg("TC ID: FtRtPerfFn020; TC SUMMARY : Verify 1D scale of ipv4 host routes in user-vrf ")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    arp_api.get_arp_ageout_time(vars.D1)
    arp_api.set_arp_ageout_time(vars.D1, 3600)
    tr = {}
    vlan='Vlan'+str(data.dut1_tg1_vlan[0])
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    mac_list = ['00:0a:00:00:01:01','00:0b:00:00:01:01','00:0c:00:00:01:01','00:0d:00:00:01:01','00:0e:00:00:01:01','00:0f:00:00:01:01','00:aa:00:00:01:01','00:bb:00:00:01:01','00:cc:00:00:01:01','00:dd:00:00:01:01','00:ee:00:00:01:01']
    ipfeature.config_ip_addr_interface(dut1, vlan, data.ip_list_2[0], data.mask, is_secondary_ip='yes')
    mac_dst=str(mac_obj.get_sbin_intf_mac(dut1, vlan))
    tr[0] = create_l3_host(tg1, tg_ph_1, 2000,data.ip_list_3[0], '401', data.ip_list_2[0],mac_list[0],mac_dst)
    if not retry_api(verify_arp_count, vars.D1, expected_count=2000, vrf=data.vrf_name[0], retry_count=3, delay=5):
        st.log('Expected ARP entries not found')
    arp_api.clear_arp_table(vars.D1)
    st.wait(5)
    tr[0] = create_l3_host(tg1, tg_ph_1, 2000,data.ip_list_3[0], '401', data.ip_list_2[0],mac_list[0],mac_dst)
    retry_api(verify_arp_count, vars.D1, expected_count=2000, vrf=data.vrf_name[0], retry_count=3, delay=5)
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    arp_api.clear_arp_table(vars.D1)

    #total = show_arp_count(vars.D1)
    total = arp_api.get_arp_count(vars.D1)
    st.log("ARP COUNT:"+str(total))
    cnt = 0
    host_count = 8000
    wait_time = 15
    tr = {}
    num_loops = max_arp_count/host_count
    mac_list = ['00:0a:00:00:01:01','00:0b:00:00:01:01','00:0c:00:00:01:01','00:0d:00:00:01:01','00:0e:00:00:01:01','00:0f:00:00:01:01','00:aa:00:00:01:01','00:bb:00:00:01:01','00:cc:00:00:01:01','00:dd:00:00:01:01','00:ee:00:00:01:01']
    for i in range(1,num_loops+1):
        ipfeature.config_ip_addr_interface(dut1, vlan, data.ip_list_2[i], data.mask, is_secondary_ip='yes')
        tr[i] = create_l3_host(tg1, tg_ph_1, host_count,data.ip_list_3[i], '401', data.ip_list_2[i],mac_list[i],mac_dst)
        st.wait(1)

    ############################################################################################
    hdrMsg("\n########## Verify ARP total count in Dut1 ############\n")
    ############################################################################################
    # Verify ARP and counters at the DUT.
    if not retry_api(verify_arp_count, vars.D1, expected_count=max_arp_count-5, retry_count=6, delay=5):
        st.log('Expected ARP entries not found')
        st.report_fail('ARP_scale_fail',max_arp_count-5)

    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_L3Scl_vrf_006(L3Scl_fixture_006):
    global h1
    global h2
    hdrMsg("TC ID: FtRtPerfFn020; TC SUMMARY : Verify 1D scale of ipv6 host routes in default-vrf ")
    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()

    #total = arp_api.get_ndp_count(vars.D1)
    default_nd = arp_api.get_ndp_count(vars.D1)
    st.log("ND COUNT:"+str(default_nd))

    ############################################################################################
    hdrMsg("\n########## STEP 6.1 - Configure Hosts in TG1 ############\n")
    ############################################################################################

    nd_cnt = 8000
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.tg1_dut1_vrf_ipv6[0] ,  ipv6_gateway=data.dut1_tg1_vrf_ipv6[0], src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id=data.dut1_tg1_vlan[0], count='8000', arp_send_req='1', ipv6_gateway_step='::', ipv6_intf_addr_step='::1', ipv6_prefix_length = '64')

    h2 = tg2.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.tg1_dut1_vrf_ipv6[1] ,  ipv6_gateway=data.dut1_tg1_vrf_ipv6[1], src_mac_addr='00:0b:01:00:00:01', vlan='1', vlan_id=data.dut1_tg1_vlan[1], count='8000', arp_send_req='1', ipv6_gateway_step='::', ipv6_intf_addr_step='::1', ipv6_prefix_length = '64')
    ############################################################################################
    hdrMsg("\n########## STEP 6.2 - Start ARP/ND from all hosts in TGEN ############\n")
    ############################################################################################
    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    res2=tg2.tg_arp_control(handle=h2['handle'], arp_target='all')

    nd_install_time = measure_nd_learn_time(dut1, default_nd, max_nd_count)

    ############################################################################################
    hdrMsg("\n########## STEP 6.3 - Verify ND total count in Dut1 ############\n")
    ############################################################################################
    # Verify ND and counters at the DUT.
    if not retry_api(verify_ndp_count, vars.D1, expected_count=max_nd_count/2-1, vrf=data.vrf_name[0], retry_count=5, delay=3):
        st.log('Expected ND entries not found')
        st.report_fail('ND_entry_count_fail',max_nd_count)
    if not retry_api(verify_ndp_count, vars.D1, expected_count=max_nd_count/2-1, vrf=data.vrf_name[1], retry_count=5, delay=3):
        st.log('Expected ND entries not found')
        st.report_fail('ND_entry_count_fail',max_nd_count)

    """
    ############################################################################################
    hdrMsg("\n########## STEP 6.4 - Verify ND total count after clear all ND ############\n")
    ############################################################################################
    st.log('Clear ipv6 nd table.')
    arp_api.clear_ndp_table(vars.D1)
    st.wait(18)
    '''
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(4)
    port.noshutdown(vars.D1,[vars.D1T1P1])
    st.wait(2)

    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(4)
    port.noshutdown(vars.D1,[vars.D1T1P1])
    st.wait(2)
    '''
    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')

    if not retry_api(verify_ndp_count, vars.D1, expected_count=max_nd_count,retry_count=5, delay=3):
        st.log('Expected ND entries not found')
        st.report_fail('ND_entry_count_fail',max_nd_count)

    ############################################################################################
    hdrMsg("\n########## STEP 6.5 - Flap the link and verify ND Performance ############\n")
    ############################################################################################
    st.log('Flap DUT-TG interface.')
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(5)
    port.noshutdown(vars.D1,[vars.D1T1P1])
    st.wait(2)
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(5)

    default_nd = arp_api.get_ndp_count(vars.D1)

    st.log('Unshut DUT_TG interface.')
    port.noshutdown(vars.D1,[vars.D1T1P1])
    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    res1=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    nd_install_time = measure_nd_learn_time(dut1, default_nd, max_nd_count)
    """

    st.log("ND Performance - Installation time for {} ND entries - {}".format(max_nd_count,nd_install_time))
    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_L3Scl_ECMP_vrf_007(L3Scl_ECMP_fixture_007):
    global bgp_rtr1
    global bgp_rtr2
    global h1
    global h2
    global h1
    global h2
    global bgp_rtr2
    global bgp_rtr1
    global tr11
    global tr1
    global tr2
    hdrMsg("TC ID: FtRtPerfFn010; TC SUMMARY : Verify 1D Scale of Max ipv4 routes with 64 ECMP paths on user vrf.")

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
    dict1 = {'vrf_name':"Vrf1",'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])
    intf_list = [x for x in range(int(data.dut1_vlan_scl[0]),int(data.dut1_vlan_scl[data.max_ecmp]))]

    ############################################################################################
    hdrMsg("\n########## STEP 7.1: Configure Vlan interfaces with ipv4 address and vrf binding ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        dict1 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        dict2 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'24'],[ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'24']])

    #utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,data.vlan1,data.d1t1_ip_addr,'24'],[ipfeature.config_ip_addr_interface,dut2, data.vlan1, data.d2t1_ip_addr, '24']])

    ############################################################################################
    hdrMsg("\n########## STEP 7.2: Configure EBGP between Dut1 and Dut2 for all interfaces ##########\n")
    ############################################################################################
    dict1 = {'local_as':'10','vrf_name':"Vrf1",'router_id':data.rtrid1,'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp}
    dict2 = {'local_as':'20','vrf_name':"Vrf1",'router_id':data.rtrid2,'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp}
    parallel.exec_parallel(True, [dut1, dut2], bgp_obj.config_bgp, [dict1, dict2])

    for i,ip1,ip2 in zip(range(0,data.max_ecmp+2),data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        dict1 = {'neighbor':ip2,'remote_as':'20','vrf_name':"Vrf1",'local_as':'10','config_type_list':["neighbor","connect"],'connect':1}
        dict2 = {'neighbor':ip1,'remote_as':'10','vrf_name':"Vrf1",'local_as':'20','config_type_list':["neighbor","connect"],'connect':1}
        parallel.exec_parallel(True,[vars.D1,vars.D2],bgp_obj.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg("\n########## STEP 7.3: Configure ports connected from DUTs to TG ##########\n")
    ############################################################################################
    # Configuring vlan 200
    dict1 = {'vrf_name':"Vrf1", 'intf_name':data.vlan1,'skip_error':True}
    dict2 = {'vrf_name':"Vrf1", 'intf_name':data.vlan1,'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,data.vlan1,data.d1t1_ip_addr,"16",'ipv4'], [ipfeature.config_ip_addr_interface,vars.D2,data.vlan1,data.d2t1_ip_addr,"16", 'ipv4']])

    ############################################################################################
    hdrMsg("\n########## STEP 7.4: Configure BGP between DUTs and TG ##########\n")
    ############################################################################################
    dict1 = {'neighbor':data.t1d1_ip_addr,'remote_as':'100','vrf_name':"Vrf1",'local_as':'10','config_type_list':["neighbor","connect"],'connect':1}
    dict2 = {'neighbor':data.t1d2_ip_addr,'remote_as':'200','vrf_name':"Vrf1",'local_as':'20','config_type_list':["neighbor","connect"],'connect':1}
    parallel.exec_parallel(True,[vars.D1,vars.D2],bgp_obj.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg(" \n####### STEP 7.5: Verify all BGP neighbors are up.  ##############\n")
    ############################################################################################
    if not retry_api(verify_bgp_nbr_count, dut1, expected_count=data.max_ecmp,vrf='Vrf1', retry_count=retry_time,delay=delay_time):
        st.report_fail("bgp_ip_peer_establish_fail",data.max_ecmp)

    ############################################################################################
    hdrMsg(" \n####### STEP 7.6: Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    h1 = {}
    h2 = {}
    h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,\
            vlan_id=data.vlan, vlan='1',\
            gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1',netmask = '255.255.0.0')
    h1.update(h11)
    st.log("INTFCONF: "+str(h1))

    h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,\
            vlan_id=data.vlan, vlan='1',\
            gateway=data.d2t1_ip_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1',netmask = '255.255.0.0')
    h2.update(h22)
    st.log("INTFCONF: "+str(h2))

    ############################################################################################
    hdrMsg(" \n####### STEP 7.7: Configure BGP and emulate routes on TG1 and TG2 ##############\n")
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

    st.log("Flap the NH intf")
    port.shutdown(vars.D1,[vars.D1T1P1])
    st.wait(2)

    port.noshutdown(vars.D1,[vars.D1T1P1])
    st.wait(15)

    ############################################################################################
    hdrMsg("\n####### STEP 7.8: Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv4',shell="sonic",neighbor=data.t1d1_ip_addr, state='Established', vrf = "Vrf1",delay=5,retry_count=5):
        st.log('BGP neighbor is down ')
    else:
        st.log('PASS - BGP neighbor is up ')

    ############################################################################################
    hdrMsg("\n########## STEP 7.9: Configure raw stream ############\n")
    ############################################################################################

    # configuring bound stream host_to_routeHandle.
    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr11 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ip_dst_mode='increment', ip_dst_count=200,ip_dst_step='0.0.0.1',ip_src_addr=data.prefix1,ip_dst_addr=data.prefix2,   l3_protocol='ipv4', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan,vlan='enable', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='1')

    ############################################################################################
    hdrMsg("\n########## STEP 7.10: Start the traffic ############\n")
    ############################################################################################

    c = check_ecmp()
    if c!=6:
        #
        st.report_fail('ip_traffic_fail')
    else:
        st.log('PASS:Traffic is being load balanced as expected.')

    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')


    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, '1', [vars.D2D1P1], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, '1', [vars.D1D2P1], tagging_mode=True)

    ############################################################################################
    hdrMsg("\n########## STEP 7.11: Configure bound stream ############\n")
    ############################################################################################

    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_rtr1['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
    st.wait(5)
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1['handle'], emulation_dst_handle=bgp_rtr2['route'][0]['handle'],  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500,enable_stream_only_gen='0')
    st.wait(5)

    ############################################################################################
    hdrMsg("\n########## STEP 7.12: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.wait(5)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res=tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: "+str(res))
    # Verified at the DUT.
    st.wait(3)
    res=tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: "+str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 7.13: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')

    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        utils.exec_all(True,[[st.generate_tech_support,vars.D1,'dut1'],[st.generate_tech_support,vars.D2,'dut2']])
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n####### STEP 7.14: Shutdown 1 interface and verify all traffic flows via the other interfaces ##############\n")
    ############################################################################################

    st.log("Flap the NH intf")
    port.shutdown(vars.D2,[vars.D2D1P2])
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 7.15: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    # Verified at the DUT.
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 7.16: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## STEP 7.17: Unshut the interface ############\n")
    ############################################################################################
    port.noshutdown(vars.D2,[vars.D2D1P2])

    BGP_triggers(scl_num=num_routes,ecmp=0)
    st.report_pass('test_case_passed')


@pytest.mark.functionality
def test_L3Scl_ECMP_vrf_008(L3Scl_ECMP_fixture_008):
    global h1
    global h2
    global bgp_conf
    global bgp_conf2
    global tr11
    global tr1
    global tr2
    hdrMsg("TC ID: FtRtPerfFn012; TC SUMMARY : Verify 1D Scale of Max ipv6 routes with 64 ECMP paths on user-vrf.")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes = data.ipv6_scale_ecmp/2
    wait_time = 2
    ##
    dict1 = {'vrf_name':"Vrf1",'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])
    intf_list = [x for x in range(int(data.dut1_vlan_scl[0]),int(data.dut1_vlan_scl[data.max_ecmp]))]

    ############################################################################################
    hdrMsg("\n########## STEP 8.1: Configure Vlan interfaces with ipv4 address and vrf binding ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        dict1 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        dict2 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'64','ipv6'],     [ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'64','ipv6']])

    dict1 = {'vrf_name':"Vrf1", 'intf_name':data.vlan1,'skip_error':True}
    dict2 = {'vrf_name':"Vrf1", 'intf_name':data.vlan1,'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,data.vlan1,data.d1t1_ipv6_addr,'64','ipv6'],[ipfeature.config_ip_addr_interface,dut2, data.vlan1, data.d2t1_ipv6_addr, '64','ipv6']])

    ############################################################################################
    hdrMsg("\n########## STEP 8.2: Configure EBGP between Dut1 and Dut2 for all interfaces ##########\n")
    ############################################################################################

    dict1 = {'local_as':'10','router_id':data.rtrid1, 'vrf_name':"Vrf1",'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp,'addr_family':'ipv6'}
    dict2 = {'local_as':'20','router_id':data.rtrid2,'vrf_name':"Vrf1",'config_type_list':['router_id',"max_path_ebgp"],'max_path_ebgp':data.max_ecmp_bgp,'addr_family':'ipv6'}
    parallel.exec_parallel(True, [dut1, dut2], bgp_obj.config_bgp, [dict1, dict2])

    ipfeature.config_route_map_global_nexthop(dut1,route_map='UseGlobal')
    ipfeature.config_route_map_global_nexthop(dut2, route_map='UseGlobal')

    for i,ip1,ip2 in zip(range(0,data.max_ecmp+2),data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        dict1 = {'neighbor':ip2,'remote_as':'20','vrf_name':"Vrf1",'local_as':'10','config_type_list':["neighbor","connect"],'connect':1,'addr_family':'ipv6'}
        dict2 = {'neighbor':ip1,'remote_as':'10','vrf_name':"Vrf1",'local_as':'20','config_type_list':["neighbor","connect"],'connect':1,'addr_family':'ipv6'}
        parallel.exec_parallel(True,[vars.D1,vars.D2],bgp_obj.config_bgp,[dict1,dict2])
        dict1 = {'neighbor':ip2,'local_as':'10','remote_as':'20','vrf_name':"Vrf1",'config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
        dict2 = {'neighbor':ip1,'local_as':'20','remote_as':'10','vrf_name':"Vrf1",'config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
        parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg(" \n####### STEP 8.3: Verify all BGP neighbors are up.  ##############\n")
    ############################################################################################

    if not retry_api(verify_ipv6_bgp_nbr_count, dut1, expected_count=data.max_ecmp, vrf='Vrf1',retry_count=retry_time,delay=delay_time):
        st.report_fail("bgp_ip_peer_establish_fail",data.max_ecmp)

    ############################################################################################
    hdrMsg("\n########## STEP 8.4: Configure BGP between DUTs and TG ##########\n")
    ############################################################################################

    dict1 = {'neighbor':data.t1d1_ipv6_addr,'remote_as':'100','vrf_name':"Vrf1",'local_as':'10','config_type_list':["neighbor","connect"],'connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.t1d2_ipv6_addr,'remote_as':'200','vrf_name':"Vrf1",'local_as':'20','config_type_list':["neighbor","connect"],'connect':1,'addr_family':'ipv6'}
    parallel.exec_parallel(True,[vars.D1,vars.D2],bgp_obj.config_bgp,[dict1,dict2])

    dict1 = {'neighbor':data.t1d1_ipv6_addr,'local_as':'10','vrf_name':"Vrf1",'remote_as':'100','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal','diRection':'in','connect':1,'addr_family':'ipv6'}
    dict2 = {'neighbor':data.t1d2_ipv6_addr,'local_as':'20','vrf_name':"Vrf1",'remote_as':'200','config_type_list':["neighbor","connect",'activate','routeMap'],'routeMap':'UseGlobal', 'diRection':'in','connect':1,'addr_family':'ipv6' }
    parallel.exec_parallel(True,[dut1,dut2],bgp_obj.config_bgp,[dict1,dict2])

    ############################################################################################
    hdrMsg(" \n####### STEP 8.5: Configure Devices on TG1 and TG2 ##############\n")
    ############################################################################################

    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    h1 = {}
    h2 = {}
    h11=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,\
            vlan_id=data.vlan, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d1t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h1.update(h11)
    st.log("INTFCONF: "+str(h1))

    h22=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.t1d2_ipv6_addr,\
            vlan_id=data.vlan, vlan='1',\
            ipv6_prefix_length='64', ipv6_gateway=data.d2t1_ipv6_addr, src_mac_addr='00:0a:01:00:00:02', arp_send_req='1')
    h2.update(h22)
    st.log("INTFCONF: "+str(h2))

    ############################################################################################
    hdrMsg(" \n####### STEP 8.6: Configure BGP and emulate routes on TG1 and TG2 ##############\n")
    ############################################################################################
    # Configuring BGP device on top of interface.
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='100', remote_as='10', remote_ipv6_addr=data.d1t1_ipv6_addr)
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
    bgp_conf2 = tg2.tg_emulation_bgp_config(handle=h2['handle'], mode='enable', ip_version='6', active_connect_enable='1', local_as='200', remote_as='20', remote_ipv6_addr=data.d2t1_ipv6_addr)
    st.log("BGPCONF: "+str(bgp_conf2))

    # Adding routes to BGP device.
    bgp_route2=tg2.tg_emulation_bgp_route_config(handle=bgp_conf2['handle'], mode='add', ip_version='6', num_routes=num_routes, prefix=data.prefix2_ipv6,as_path = 'as_seq:200')
    st.log("BGPROUTE: "+str(bgp_route2))

    # Starting the BGP device.
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='start')
    #bgp_ctrl2=tg2.tg_emulation_bgp_control(handle=bgp_route2['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.wait(5)

    ############################################################################################
    hdrMsg("\n########### STEP 8.7: Verify BGP neighborships between DUTs and TG1,TG2 ##############\n")
    ############################################################################################
    if not retry_api(bgp_obj.verify_bgp_summary,dut1,family='ipv6',shell="sonic",neighbor=data.t1d1_ipv6_addr,vrf='Vrf1', state='Established', delay=5,retry_count=5):
        debug_cmds2()
        st.log('BGP neighbor is not up ')
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d1_ipv6_addr)
    else:
        st.log('BGP neighbor is up ')

    if not retry_api(bgp_obj.verify_bgp_summary, dut2, family='ipv6',shell="sonic", neighbor=data.t1d2_ipv6_addr, vrf='Vrf1',state='Established',  retry_count=4,delay=5):
        debug_cmds2()
        st.log('BGP neighbor is not up ')
        st.report_fail("bgp_ip_peer_establish_fail",data.t1d2_ipv6_addr)

    ############################################################################################
    hdrMsg("\n########## STEP 8.8: Configure raw stream ############\n")
    ############################################################################################
    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr11 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ipv6_dst_mode='increment', ipv6_dst_count=200,ipv6_dst_step='::1',ipv6_src_addr=data.prefix_ipv6,ipv6_dst_addr=data.prefix2_ipv6,  l3_protocol='ipv6', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan,vlan='enable', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='1',high_speed_result_analysis=0)

    ############################################################################################
    hdrMsg("\n########## STEP 8.9: Start the traffic ############\n")
    ############################################################################################

    c = check_ecmp()
    if c!=6:
        #
        st.report_fail('ip_traffic_fail')
    else:
        st.log('PASS:Traffic is being load balanced as expected.')

    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D1, "1 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "1 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')

    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True)
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True)
    vlan_obj.add_vlan_member(vars.D2, '1', [vars.D2D1P1], tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, '1', [vars.D1D2P1], tagging_mode=True)

    ############################################################################################
    hdrMsg("\n########## STEP 8.10: Configure bound stream ############\n")
    ############################################################################################
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'], emulation_dst_handle=bgp_route1['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0',high_speed_result_analysis=0)
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1['handle'], emulation_dst_handle=bgp_route2['handle'], circuit_endpoint_type='ipv6', mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500, enable_stream_only_gen='0',high_speed_result_analysis=0)
    st.log("BOUND_STREAM: "+str(tr1))
    st.log("BOUND_STREAM: "+str(tr2))

    ############################################################################################
    hdrMsg("\n########## STEP 8.11: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    # Verified at the DUT.
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 8.12: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    #BGP_triggers(scl_num=num_routes,ecmp=1,family='ipv6')
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def L3Scl_ECMP_fixture_007(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    tg_vrf_bind(config='no')
    #vrf_config(config = 'no')

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

    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    vlan_obj.create_vlan(dut1, data.vlan)
    vlan_obj.add_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.create_vlan(dut2, data.vlan)
    vlan_obj.add_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)

    yield

    hdrMsg("### CLEANUP for TC7 ###")
    port.noshutdown(vars.D2,[vars.D2D1P2])
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'24','ipv4','remove'],[ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'24','ipv4','remove']])
        dict1 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
    ############################################################################################
    hdrMsg("Delete router bgp on dut1 and dut2")
    ############################################################################################
    bgp_obj.config_bgp(dut = vars.D1, local_as = "10", vrf_name = "Vrf1" ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])
    bgp_obj.config_bgp(dut = vars.D2, local_as = "20", vrf_name = "Vrf1" ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])

    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')

    vlan_obj.delete_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    vlan_obj.delete_vlan(dut1,data.vlan)
    vlan_obj.delete_vlan(dut2,data.vlan)
    ############################################################################################
    hdrMsg("Delete VRF on dut1 and dut2")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1",'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])
    debug_cmds()

    global h1,h2
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    if bgp_rtr1 and bgp_rtr2:
        bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_rtr1['conf']['handle'], mode='stop')
        bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_rtr2['conf']['handle'], mode='stop')
    if h1 and h2:
        tg1.tg_interface_config(port_handle = tg_ph_1, handle=h1['handle'],mode='destroy')
        tg2.tg_interface_config(port_handle = tg_ph_2, handle=h2['handle'],mode='destroy')


@pytest.fixture(scope="function")
def L3Scl_ECMP_fixture_008(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    #vrf_config(config = 'no')

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

    ############################################################################################
    hdrMsg("\n####### Create vlans and assign to member ports on DUT1 and DUT2 ##############\n")
    ############################################################################################
    vlan_obj.create_vlan(dut1, data.vlan)
    vlan_obj.add_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.create_vlan(dut2, data.vlan)
    vlan_obj.add_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)

    yield
    debug_cmds()
    hdrMsg("### CLEANUP for TC8 ###")
    port.noshutdown(vars.D2,[vars.D2D1P2])
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp),data.dut1_vlan_scl,data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'64','ipv6','remove'],[ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'64','ipv6','remove']])
        dict1 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True,'config':'no'}
        dict2 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True,'config':'no'}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,data.vlan1,data.d1t1_ipv6_addr,'64','ipv6','remove'],[ipfeature.config_ip_addr_interface,dut2, data.vlan1, data.d2t1_ipv6_addr, '64','ipv6','remove']])
    dict1 = {'vrf_name':"Vrf1", 'intf_name':data.vlan1,'skip_error':True,'config':'no'}
    dict2 = {'vrf_name':"Vrf1", 'intf_name':data.vlan1,'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
    ############################################################################################
    hdrMsg("Delete router bgp on dut1 and dut2")
    ############################################################################################
    bgp_obj.config_bgp(dut = vars.D1, local_as = "10", vrf_name = "Vrf1" ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])
    bgp_obj.config_bgp(dut = vars.D2, local_as = "20", vrf_name = "Vrf1" ,config = 'no', removeBGP = 'yes', config_type_list = ["removeBGP"])

    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P2, skip_verify=True, config='del')
    #vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp+2), vars.D1D2P1, skip_verify=True, config='del')
    #vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp+2), vars.D2D1P1, skip_verify=True, config='del')

    vlan_obj.delete_vlan_member(dut1, data.vlan, [vars.D1T1P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, data.vlan, [vars.D2T1P1], tagging_mode=True)

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp+2), skip_verify=True, config='del')
    vlan_obj.delete_vlan(dut1,data.vlan)
    vlan_obj.delete_vlan(dut2,data.vlan)
    ############################################################################################
    hdrMsg("Delete VRF on dut1 and dut2")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1",'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])

    ############################################################################################
    hdrMsg(" \n####### Reset and destroy TGEN handles #############\n")
    ############################################################################################

    global h1,h2
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    bgp_ctrl=tg2.tg_emulation_bgp_control(handle=bgp_conf2['handle'], mode='stop')
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=h1['handle'],mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=h2['handle'],mode='destroy')


@pytest.mark.functionality
def test_L3Scl_ECMP_vrf_009(L3Scl_ECMP_fixture_009):
    global src1
    global src2
    global tr1
    global tr2
    hdrMsg("TC ID: FtRtPerfFn011; TC SUMMARY : Verify 1D Scale of Max ipv4 static routes with 64 ECMP paths on user-vrf.")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes = data.ipv4_scale_static-1
    wait_time = 2

    ############################################################################################
    hdrMsg("\n########## STEP 9.1: Configure VRFs globally ############\n")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1",'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])

    intf_list = [x for x in range(int(data.dut1_vlan_scl[0]),int(data.dut1_vlan_scl[data.max_ecmp_static]))]

    ############################################################################################
    hdrMsg("\n########## STEP 9.2: Configure Ve interfaces with ipv4 address and vrf binding ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp_static),data.dut1_vlan_scl,data.dut1_ecmp_ip,data.dut2_ecmp_ip):
        dict1 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        dict2 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'24'],[ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'24']])
    #
    ############################################################################################
    hdrMsg("\n########## STEP 9.3: Configure DUT-TG router port ########## \n")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1", 'intf_name':vars.D1T1P1,'skip_error':True}
    dict2 = {'vrf_name':"Vrf1", 'intf_name':vars.D2T1P1,'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,vars.D1T1P1,data.d1t1_ip_addr,'24'],[ipfeature.config_ip_addr_interface,dut2, vars.D2T1P1, data.d2t1_ip_addr, '24']])

    ############################################################################################
    hdrMsg("\n########## STEP 9.4: Configure static route on DUT1 and DUT2 to reach TG1 and TG2 ########## \n")
    ############################################################################################
    ipfeature.config_static_route_vrf(vars.D1, '121.1.0.0', '16', data.t1d1_ip_addr, family='ipv4', vrf_name='Vrf1')
    ipfeature.config_static_route_vrf(vars.D2, '221.1.0.0', '16', data.t1d2_ip_addr, family='ipv4', vrf_name='Vrf1')

    ############################################################################################
    hdrMsg("\n########## STEP 9.5: Configure static route on DUT1 and DUT2 by uploading FRR file ########## \n")
    ############################################################################################
    """

    frr_path = os.getcwd()
    apply_file = True
    res1 = True
    frr_apply_path = frr_path+"/routing/frr.conf"
    result = st.apply_files(vars.D1, [frr_apply_path])
    """
    #ipv4_scl = data.ipv4_scale_static
    config_static_rt_scl(vars.D1,t=30,scale_num=data.ipv4_scale_static)
    ############################################################################################
    hdrMsg("\n ########## STEP 9.6: Configure Interface hosts in TGEN1 and TGEN2 ########## \n")
    ############################################################################################
    src_handle1 = tg1.tg_interface_config(port_handle=tg_ph_1,mode='config',intf_ip_addr=data.t1d1_ip_addr,gateway=data.d1t1_ip_addr, netmask='255.255.255.0')
    src1 = src_handle1['handle']
    res1=tg1.tg_arp_control(handle=src1, arp_target='all')
    src_handle2 = tg1.tg_interface_config(port_handle=tg_ph_2,mode='config',intf_ip_addr=data.t1d2_ip_addr,gateway=data.d2t1_ip_addr,  netmask='255.255.255.0')
    src2 = src_handle2['handle']
    res2=tg2.tg_arp_control(handle=src2, arp_target='all')

    ############################################################################################
    hdrMsg("\n########## STEP 9.7: Configure raw streams on TGEN1 and TGEN2 ########## \n")
    ############################################################################################
    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ip_dst_mode='increment', ip_dst_count=num_routes,ip_dst_step='0.0.1.0',ip_src_addr=data.prefix1, ip_dst_addr=data.prefix2,   l3_protocol='ipv4',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=5120, enable_stream_only_gen='1')
    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_2, mac_src='00:21:01:00:00:01', mac_dst=mac2, ip_dst_mode='increment', ip_dst_count=num_routes,ip_dst_step='0.0.1.0',ip_src_addr=data.prefix2, ip_dst_addr=data.prefix1,   l3_protocol='ipv4',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=5120, enable_stream_only_gen='1')

    st.wait(5)
    ############################################################################################
    ## ("\nDeleting and reconfiguring static route as a workaround for 8904\n")
    ############################################################################################
    ipfeature.config_static_route_vrf(vars.D1, '121.1.0.0', '16', data.t1d1_ip_addr, family='ipv4', vrf_name='Vrf1',config='no')
    ipfeature.config_static_route_vrf(vars.D2, '221.1.0.0', '16', data.t1d2_ip_addr, family='ipv4', vrf_name='Vrf1',config='no')

    ipfeature.config_static_route_vrf(vars.D1, '121.1.0.0', '16', data.t1d1_ip_addr, family='ipv4', vrf_name='Vrf1')
    ipfeature.config_static_route_vrf(vars.D2, '221.1.0.0', '16', data.t1d2_ip_addr, family='ipv4', vrf_name='Vrf1')

    ############################################################################################
    hdrMsg("\n########## STEP 9.8: Start and stop the traffic ############\n")
    ############################################################################################
    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    # Verified at the DUT.
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 9.9: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')


    ############################################################################################
    hdrMsg("\n####### STEP 9.10: Shutdown 1 interface and verify all traffic flows via the other interfaces ##############\n")
    ############################################################################################

    st.log("Flap the NH intf")
    port.shutdown(vars.D2,[vars.D2D1P2])
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 9.11: Start and stop the traffic ############\n")
    ############################################################################################

    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    # Verified at the DUT.
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 9.12: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    ############################################################################################
    hdrMsg("\n########## STEP 9.13: Unshut the interface ############\n")
    ############################################################################################
    port.noshutdown(vars.D2,[vars.D2D1P2])
    ecmp = 0
    ############################################################################################
    hdrMsg("\n########## STEP 9.14: Clear the mac table in Dut1 ############\n")
    ############################################################################################

    mac_obj.clear_mac(dut1)
    st.wait(4)

    ############################################################################################
    hdrMsg("\n########## STEP 9.15: Clear arp table in Dut1 ############\n")
    ############################################################################################
    arp_api.clear_arp_table(vars.D1)
    st.wait(2)
    ############################################################################################
    hdrMsg("\n########## STEP 9.16: Verify routes in Dut1 ############\n")
    ############################################################################################
    if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
        debug_cmds2()
        ##
        st.report_fail('fib_failure_route_fail',"count")
    else:
        st.log("Traffic test passed.\n")

    if ecmp==1:
        verify_ecmp()

    if trigger_flag:
            ############################################################################################
            hdrMsg("\n########## STEP 9.17: Verify routes after rebooting Dut1 ############\n")
            ############################################################################################
            st.log("Verification of routes after a reboot.")
            bgp_obj.enable_docker_routing_config_mode(vars.D1)
            reboot_api.config_save(vars.D1)
            st.vtysh(vars.D1,"copy running-config startup-config")
            st.reboot(vars.D1,'fast')
            st.wait(3)
            ports = port_obj.get_interfaces_all(vars.D1)
            if not ports:
                st.report_fail("operation_failed")
            else:
                st.report_pass("operation_successful")

            ############################################################################################
            hdrMsg("\n########## STEP 9.18: Verify routes in Dut1 ############\n")
            ############################################################################################
            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):

                debug_cmds2()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

            if ecmp==1:
                verify_ecmp()

    #BGP_triggers(scl_num=num_routes,ecmp=1)
    #BGP_triggers(scl_num=num_routes)
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def L3Scl_ECMP_fixture_009(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]
    """
    tg_vrf_bind(config='no')
    vrf_config(config = 'no')
    """
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

    hdrMsg("### CLEANUP for TC9 ###")
    port.noshutdown(vars.D2,[vars.D2D1P2])
    dict1 = {'vrf_name':"Vrf1", 'intf_name':vars.D1T1P1,'skip_error':True,'config':'no'}
    dict2 = {'vrf_name':"Vrf1", 'intf_name':vars.D2T1P1,'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])

    ############################################################################################
    hdrMsg("Delete static routes on dut1 and dut2")
    ############################################################################################
    ##
    config_static_rt_scl(vars.D1,t=30,config='no')

    ############################################################################################
    hdrMsg("Delete VRF on dut1 and dut2")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1",'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])

    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P1, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P1, skip_verify=True, config='del')

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')
    vlan_obj.delete_vlan(dut1,data.vlan)
    vlan_obj.delete_vlan(dut2,data.vlan)
    debug_cmds2()
    global src1,src2
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.wait(5)
    #
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=src1,mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=src2,mode='destroy')

@pytest.mark.functionality
def test_L3Scl_ECMP_vrf_010(L3Scl_ECMP_fixture_010):
    global src1
    global src2
    global tr1
    global tr2
    hdrMsg("TC ID: FtRtPerfFn012; TC SUMMARY : Verify 1D Scale of Max ipv6 static routes with 64 ECMP paths on user-vrf.")

    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    num_routes = data.ipv6_scale_static
    wait_time = 2
    ############################################################################################
    hdrMsg("\n########## STEP 10.1: Configure VRFs globally ############\n")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1",'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])

    intf_list = [x for x in range(int(data.dut1_vlan_scl[0]),int(data.dut1_vlan_scl[data.max_ecmp_static]))]

    ############################################################################################
    hdrMsg("\n########## STEP 10.2: Configure Ve interfaces with ipv6 address and vrf binding ########## \n")
    ############################################################################################
    for i,vlan,ip1,ip2 in zip(range(0,data.max_ecmp_static),data.dut1_vlan_scl,data.dut1_ecmp_ipv6,data.dut2_ecmp_ipv6):
        dict1 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        dict2 = {'vrf_name':"Vrf1", 'intf_name':'Vlan'+vlan,'skip_error':True}
        parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])
        utils.exec_all(True,[[ipfeature.config_ip_addr_interface,vars.D1,'Vlan'+vlan,ip1,'64','ipv6'],[ipfeature.config_ip_addr_interface,vars.D2,'Vlan'+vlan,ip2,'64','ipv6']])
    #
    ############################################################################################
    hdrMsg("\n########## STEP 10.3: Configure DUT-TG router port ########## \n")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1", 'intf_name':vars.D1T1P1,'skip_error':True}
    dict2 = {'vrf_name':"Vrf1", 'intf_name':vars.D2T1P1,'skip_error':True}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])

    utils.exec_all(True,[[ipfeature.config_ip_addr_interface,dut1,vars.D1T1P1,data.d1t1_ipv6_addr,'64','ipv6'],[ipfeature.config_ip_addr_interface,dut2, vars.D2T1P1, data.d2t1_ipv6_addr, '64','ipv6']])

    ############################################################################################
    hdrMsg("\n########## STEP 10.4: Configure static route on DUT1 and DUT2 to reach TG1 and TG2 ########## \n")
    ############################################################################################
    ipfeature.config_static_route_vrf(vars.D1,'::', '0', data.t1d1_ipv6_addr, family='ipv6', vrf_name='Vrf1')
    ipfeature.config_static_route_vrf(vars.D2,'::', '0', data.t1d2_ipv6_addr, family='ipv6', vrf_name='Vrf1')
    st.wait(5)

    ############################################################################################
    hdrMsg("\n########## STEP 10.5: Configure static route on DUT1 and DUT2 by uploading FRR file ########## \n")
    ############################################################################################
    """
    frr_path = os.getcwd()
    apply_file = True
    res1 = True
    frr_apply_path = frr_path+"/routing/frr.conf"
    st.apply_files(vars.D1, [frr_apply_path])
    """
    ##
    config_static_rt_scl(vars.D1,t=30,prefix1='1121:',prefix2='3121:',family='ipv6')
    ############################################################################################
    hdrMsg("\n########## STEP 10.6: Configure Interface hosts in TGEN1 and TGEN2 ########## \n")
    ############################################################################################
    arp_api.set_ndp_ageout_time(vars.D1, 3600)
    src_handle1 = tg1.tg_interface_config(port_handle=tg_ph_1,mode='config',ipv6_intf_addr=data.t1d1_ipv6_addr,ipv6_gateway=data.d1t1_ipv6_addr, ipv6_prefix_length='64',arp_send_req='1')
    src1 = src_handle1['handle']
    res1=tg1.tg_arp_control(handle=src1, arp_target='all')
    src_handle2 = tg1.tg_interface_config(port_handle=tg_ph_2,mode='config',ipv6_intf_addr=data.t1d2_ipv6_addr,ipv6_gateway=data.d2t1_ipv6_addr, ipv6_prefix_length='64',arp_send_req='1')
    src2 = src_handle2['handle']
    res2=tg2.tg_arp_control(handle=src2, arp_target='all')
    #

    ############################################################################################
    hdrMsg("\n########## STEP 10.7: Configure raw streams on TGEN1 and TGEN2 ########## \n")
    ############################################################################################
    mac1=mac_obj.get_sbin_intf_mac(vars.D1,'eth0')
    mac2=mac_obj.get_sbin_intf_mac(vars.D2,'eth0')
    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mac_src='00:11:01:00:00:01', mac_dst=mac1, ipv6_dst_mode='increment', ipv6_dst_count=num_routes,ipv6_dst_step='0:1::',ipv6_src_addr = data.prefix_ipv6, ipv6_dst_addr=data.prefix2_ipv6,   l3_protocol='ipv6',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=5120, enable_stream_only_gen='1')

    tr2 = tg1.tg_traffic_config(port_handle=tg_ph_2, mac_src='00:21:01:00:00:01', mac_dst=mac2, ipv6_dst_mode='increment', ipv6_dst_count=num_routes,ipv6_dst_step='0:1::',ipv6_src_addr=data.prefix2_ipv6, ipv6_dst_addr=data.prefix_ipv6,   l3_protocol='ipv6',  mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=5120, enable_stream_only_gen='1')

    ############################################################################################
    ###("\n Delete and Reconfigure static route as a workaround for defect 8904 \n")
    ############################################################################################
    ipfeature.config_static_route_vrf(vars.D1,'::', '0', data.t1d1_ipv6_addr, family='ipv6', vrf_name='Vrf1',config='no')
    ipfeature.config_static_route_vrf(vars.D2,'::', '0', data.t1d2_ipv6_addr, family='ipv6', vrf_name='Vrf1',config='no')
    ipfeature.config_static_route_vrf(vars.D1,'::', '0', data.t1d1_ipv6_addr, family='ipv6', vrf_name='Vrf1')
    ipfeature.config_static_route_vrf(vars.D2,'::', '0', data.t1d2_ipv6_addr, family='ipv6', vrf_name='Vrf1')
    st.wait(5)
    ############################################################################################
    hdrMsg("\n########## STEP 10.8: Start and stop the traffic ############\n")
    ############################################################################################
    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    # Verified at the DUT.
    st.wait(3)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    ############################################################################################
    hdrMsg("\n########## STEP 10.9: Verify traffic ############\n")
    ############################################################################################
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    traffic_params = {'1': {'tx_ports' : [vars.T1D2P1], 'tx_obj' : [tg2],'exp_ratio' : [1],'rx_ports' : [vars.T1D1P1], 'rx_obj' : [tg1]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        st.log('Traffic verification passed for mode aggregate')
    else:
        debug_cmds2()
        st.report_fail('ip_traffic_fail')
        st.log('Traffic verification failed for mode aggregate')

    BGP_triggers(scl_num=num_routes,ecmp=0,family='ipv6')
    #BGP_triggers(scl_num=num_routes,family='ipv6')
    st.report_pass('test_case_passed')

@pytest.fixture(scope="function")
def L3Scl_ECMP_fixture_010(request,L3ScaleEnhancement_Prologue_Epilogue):
    global vars
    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    """
    tg_vrf_bind(config='no')
    vrf_config(config = 'no')
    """
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
    dict1 = {'vrf_name':"Vrf1", 'intf_name':vars.D1T1P1,'skip_error':True,'config':'no'}
    dict2 = {'vrf_name':"Vrf1", 'intf_name':vars.D2T1P1,'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.bind_vrf_interface, [dict1, dict2])

    ############################################################################################
    hdrMsg("Delete static routes on dut1 and dut2")
    ############################################################################################

    config_static_rt_scl(vars.D1,t=30,prefix1='1121:',prefix2='3121:',family='ipv6',config='no')
    ipfeature.config_static_route_vrf(vars.D1,'::', '0',data.t1d1_ipv6_addr, family='ipv6', vrf_name='Vrf1',config='no')
    ipfeature.config_static_route_vrf(vars.D1,'::', '0',data.t1d2_ipv6_addr, family='ipv6', vrf_name='Vrf1',config='no')

    ############################################################################################
    hdrMsg("Delete VRF on dut1 and dut2")
    ############################################################################################
    dict1 = {'vrf_name':"Vrf1",'skip_error':True,'config':'no'}
    parallel.exec_parallel(True, [vars.D1, vars.D2], vrf_api.config_vrf, [dict1, dict1])

    ############################################################################################
    hdrMsg(" \n####### Delete vlan port member in Dut1 #############\n")
    ############################################################################################

    intf_list1 = [int(data.dut1_vlan_scl[0])]
    vlan = intf_list1[0]
    vlan_obj.delete_vlan_member(dut1, vlan, [vars.D1D2P1], tagging_mode=True)
    vlan_obj.delete_vlan_member(dut2, vlan, [vars.D2D1P1], tagging_mode=True)

    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P2, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D1, "2 {}".format(data.max_ecmp_static), vars.D1D2P1, skip_verify=True, config='del')
    vlan_obj.config_vlan_range_members(vars.D2, "2 {}".format(data.max_ecmp_static), vars.D2D1P1, skip_verify=True, config='del')

    ############################################################################################
    hdrMsg(" \n####### Delete vlans in Dut1 #############\n")
    ############################################################################################

    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')
    vlan_obj.config_vlan_range(vars.D2, "1 {}".format(data.max_ecmp_static+2), skip_verify=True, config='del')
    vlan_obj.delete_vlan(dut1,data.vlan)
    vlan_obj.delete_vlan(dut2,data.vlan)
    debug_cmds2()
    global src1,src2
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.wait(5)
    #
    tg1.tg_interface_config(port_handle = tg_ph_1, handle=src1,mode='destroy')
    tg2.tg_interface_config(port_handle = tg_ph_2, handle=src2,mode='destroy')

    ############################################################################################
    hdrMsg(" \n####### Reconfigure  VRFs #############\n")
    ############################################################################################
    #vrf_config()
    #tg_vrf_bind()

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
        bgp_obj.clear_ip_bgp_vrf_vtysh(vars.D1,data.vrf_name[1])

        ############################################################################################
        hdrMsg("\n########## Verify routes in Dut1 ############\n")
        ############################################################################################
        st.log("Verification of number of IPv4 route entries in hardware")
        if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
            st.log('FAIL: Expected number of routes not found')
            st.report_fail('fib_failure_route_fail',"Route count")

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
        if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            st.report_fail('fib_failure_route_fail',"count")
        else:
            st.log("Traffic test passed.\n")

        if ecmp==1:
            verify_ecmp()
        if trigger_flag:
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
            if not retry_api(verify_traffic,2,port_set = 1, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.report_fail('fib_failure_route_fail',"count")
            else:
                st.log("Traffic test passed.\n")

            '''
            if ecmp==1:
                verify_ecmp()
            '''
        if trigger_flag:
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
                debug_cmds()
                st.report_fail("operation_failed")
            else:
                st.report_pass("operation_successful")

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
            st.log("Verification of number of IPv4 route entries in hardware")
            if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.log("FAIL - Expected routes not found")
                st.report_fail('fib_failure_route_fail',"Route count")

            if ecmp==1:
                verify_ecmp()

            ############################################################################################
            hdrMsg("\n########## Verify after warm reboot ############\n")
            ############################################################################################
            #perform warm rebot command
            st.log ("WARM REBOOT")
            st.reboot(vars.D1, "warm")
            ports = port_obj.get_interfaces_all(vars.D1)
            if not ports:
                debug_cmds()
                st.report_fail("operation_failed")
            else:
                st.report_pass("operation_successful")

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            st.log("Verification of number of IPv4 route entries in hardware")
            if not retry_api(verify_route_count_hardware,vars.D1,exp_num_of_routes=ipv4_scale, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.log("FAIL - Expected routes not found")
                st.report_fail('fib_failure_route_fail',"Route count")

    else:
        ipv6_scale = scl_num
        wait_time = ipv6_scale/10000*perf_time
        t = wait_time/4
        ############################################################################################
        hdrMsg("\n########## Clear bgp neighbor ############\n")
        ############################################################################################

        st.log("clear ipv6 bgp neighbors")
        bgp_obj.clear_ip_bgp_vrf_vtysh(vars.D1,data.vrf_name[1],family='ipv6')

        ############################################################################################
        hdrMsg("\n########## Verify routes in Dut1 ############\n")
        ############################################################################################

        st.log("Verification of number of IPv6 route entries in hardware")
        ipv6_scale = ipv6_scale-700
        if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            st.log("FAIL - Expected routes not found")
            st.report_fail('fib_failure_route_fail',"Route count")

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
        st.log("Verification of number of IPv6 route entries in hardware")
        if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
            debug_cmds()
            st.log("FAIL - Expected routes not found")
            st.report_fail('fib_failure_route_fail',"Route count")
        '''
        if ecmp==1:
            verify_ecmp()
        '''
        if trigger_flag:
            ############################################################################################
            hdrMsg("\n########## Clear the mac table in Dut1 ############\n")
            ############################################################################################

            mac_obj.clear_mac(dut1)
            st.wait(4)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            st.log("Verification of number of IPv6 route entries in hardware")
            if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.log("FAIL - Expected routes not found")
                st.report_fail('fib_failure_route_fail',"Route count")
            '''
            if ecmp==1:
                verify_ecmp()
            '''

            ############################################################################################
            hdrMsg("\n########## Clear IPv6 ND table ############\n")
            ############################################################################################
            arp_api.clear_ndp_table(vars.D1)
            st.wait(14)

            ############################################################################################
            hdrMsg("\n########## Verify routes in Dut1 ############\n")
            ############################################################################################
            st.log("Verification of number of IPv6 route entries in hardware")
            if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.log("FAIL - Expected routes not found")
                st.report_fail('fib_failure_route_fail',"Route count")
            '''
            if ecmp==1:
                verify_ecmp()
            '''

        if trigger_flag:
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
            st.log("Verification of number of IPv6 route entries in hardware")
            retry_api(verify_ipv6_route_count_hardware, vars.D1, exp_num_of_routes=ipv6_scale, retry_count=retry_time, delay=delay_time)

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
            st.log("Verification of number of IPv6 route entries in hardware")
            if not retry_api(verify_ipv6_route_count_hardware,vars.D1,exp_num_of_routes=ipv6_scale, retry_count=retry_time,delay=delay_time):
                debug_cmds()
                st.log("FAIL - Expected routes not found")
                st.report_fail('fib_failure_route_fail',"Route count")


def vrf_base_unconfig():

    ############################################################################################
    hdrMsg("\n########## VRF Cleanup ############\n")
    ############################################################################################
    global vars
    vars = st.get_testbed_vars()

    dut1 = st.get_dut_names()[0]
    dut2 = st.get_dut_names()[1]

    for i,vrf in zip(range(0,3),data.vrf_name[0:3]):
        ipfeature.config_static_route_vrf(vars.D2, '0.0.0.0', '0', data.dut1_dut2_vrf_ip[i], family='ipv4', vrf_name=vrf, config='no')
        ipfeature.config_static_route_vrf(vars.D2, '::', '0', data.dut1_dut2_vrf_ipv6[i], family='ipv6', vrf_name=vrf, config = 'no')

    #config_route_map(dut1, 'UseGlobal', type = 'next_hop_v6', config = 'no')
    #config_route_map(dut2, 'UseGlobal', type = 'next_hop_v6', config = 'no')
    ipfeature.config_route_map_global_nexthop(dut1,route_map='UseGlobal')
    ipfeature.config_route_map_global_nexthop(dut2, route_map='UseGlobal')

    tg_vrf_bgp(config = 'no')
    dut_vrf_bgp(config = 'no')
    dut_vrf_bind(config = 'no')
    #tg_vrf_bind(config = 'no')
    vrf_config(config = 'no')

def check_ecmp():
    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    res=tg1.tg_traffic_control(action='run', handle=tr11['stream_id'])
    st.log("TrafControl: "+str(res))
    st.wait(2)
    DUT_tx_value = port_obj.get_interface_counters(vars.D1, vars.D1D2P1,"tx_bps")
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



def config_static_rt_scl(dut,t=70,**kwargs):
    st.log('Config Ve API')
    config = kwargs.get('config', '')
    pref1 = kwargs.get('prefix1', data.prefix1)
    pref2 = kwargs.get('prefix2', data.prefix2)
    family = kwargs.get('family', 'ipv4')
    rt_scale = kwargs.get('scale_num', 10)

    def static_route_d1():
        count = 0
        if family == 'ipv4':
            ip_list2 = ip_range(data.dut2_ecmp_ip[0],2,data.max_ecmp_static-1)
            ip_pref2 = ip_range(pref2,2,rt_scale)
            for prefix in ip_pref2:
                for nh_ip in ip_list2:
                    nw = prefix+"/24"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D1, static_ip=nw, next_hop=nh_ip, vrf='Vrf1')
                    else:
                        ipfeature.create_static_route(vars.D1, static_ip=nw, next_hop=nh_ip, vrf='Vrf1')
                count += 1
        else:
            ipv6_list2 = ['9000:%s::2'%x for x in range (1,data.max_ecmp_static+1)]
            ipv6_pref2 = ipv6_list(pref2,rt_scale)
            for prefix in ipv6_pref2:
                for nh_ip in ipv6_list2:
                    nw = prefix+"/64"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D1, static_ip=nw, next_hop=nh_ip, family='ipv6', vrf='Vrf1')
                    else:
                        ipfeature.create_static_route(vars.D1, static_ip=nw, next_hop=nh_ip, family='ipv6', vrf='Vrf1')
                count += 1


    def static_route_d2():
        count = 0
        if family == 'ipv4':
            ip_list = ip_range(data.dut1_ecmp_ip[0],2,data.max_ecmp_static-1)
            ip_pref = ip_range(pref1,2,rt_scale)
            for prefix in ip_pref:
                for nh_ip in ip_list:
                    nw = prefix+"/24"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D2, static_ip=nw, next_hop=nh_ip, vrf='Vrf1')
                    else:
                        ipfeature.create_static_route(vars.D2, static_ip=nw, next_hop=nh_ip, vrf='Vrf1')
                count += 1

        else:
            ipv6_list1 = ['9000:%s::1'%x for x in range (1,data.max_ecmp_static+1)]
            ipv6_pref = ipv6_list(pref1,rt_scale)
            for prefix in ipv6_pref:
                for nh_ip in ipv6_list1:
                    nw = prefix+"/64"
                    if config == 'no':
                        ipfeature.delete_static_route(vars.D2, static_ip=nw, next_hop=nh_ip, family='ipv6', vrf='Vrf1')
                    else:
                        ipfeature.create_static_route(vars.D2, static_ip=nw, next_hop=nh_ip, family='ipv6',  vrf='Vrf1')
                count += 1

    st.exec_all([[static_route_d1],[static_route_d2]])
    return True




def enable_debugs():
    global vars
    cmd = "debug zebra rib detailed \n  debug zebra nht detailed \n debug vrf \n debug zebra fpm \n debug zebra events \n debug zebra dplane detailed\n"
    utils.exec_all(True,[[st.vtysh_config,vars.D1,cmd],[st.vtysh_config,vars.D2,cmd]])

def debug_cmds():
    global vars
    for i in range(0,3):
        ipfeature.show_ip_route(vars.D1, summary_routes='yes', vrf_name=data.vrf_name[i])
        ipfeature.show_ip_route(vars.D1, summary_routes='yes', vrf_name=data.vrf_name[i], family='ipv6')
        bgp_obj.show_bgp_ipv4_summary_vtysh(vars.D1, vrf=data.vrf_name[i])
        bgp_obj.show_bgp_ipv6_summary_vtysh(vars.D1, vrf=data.vrf_name[i])
        ipfeature.show_ip_route(vars.D2, summary_routes='yes', vrf_name=data.vrf_name[i])
        ipfeature.show_ip_route(vars.D2, summary_routes='yes', vrf_name=data.vrf_name[i], family='ipv6')
        bgp_obj.show_bgp_ipv4_summary_vtysh(vars.D2, vrf=data.vrf_name[i])
        bgp_obj.show_bgp_ipv6_summary_vtysh(vars.D2, vrf=data.vrf_name[i])
    st.vtysh_show(vars.D1, "show zebra client",skip_tmpl=True)
    st.vtysh_show(vars.D2, "show zebra fpm stats",skip_tmpl=True)
    c=asicapi.bcmcmd_route_count_hardware(vars.D1)
    st.log("Hardware count on DUT1:{}".format(c))
    c=asicapi.bcmcmd_route_count_hardware(vars.D2)
    st.log("Hardware count on DUT1:{}".format(c))
    c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D1)
    c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D2)

def debug_cmds2():
    global vars
    vrf_name = 'Vrf1'
    ipfeature.show_ip_route(vars.D1, summary_routes='yes', vrf_name=vrf_name)
    ipfeature.show_ip_route(vars.D1, summary_routes='yes', vrf_name=vrf_name,  family='ipv6')
    ipfeature.show_ip_route(vars.D2, summary_routes='yes', vrf_name=vrf_name)
    ipfeature.show_ip_route(vars.D2, summary_routes='yes', vrf_name=vrf_name,  family='ipv6')
    ipfeature.show_ip_route(vars.D1, vrf_name=vrf_name)
    ipfeature.show_ip_route(vars.D1, vrf_name=vrf_name,  family='ipv6')
    ipfeature.show_ip_route(vars.D2, vrf_name=vrf_name)
    ipfeature.show_ip_route(vars.D2, vrf_name=vrf_name,  family='ipv6')
    arp_api.show_arp(vars.D1)
    arp_api.show_arp(vars.D2)
    arp_api.show_ndp(vars.D1)
    arp_api.show_ndp(vars.D2)
    st.vtysh_show(vars.D1, "show zebra client",skip_tmpl=True)
    st.vtysh_show(vars.D2, "show zebra fpm stats",skip_tmpl=True)
    c=asicapi.bcmcmd_route_count_hardware(vars.D1)
    st.log("Hardware count on DUT1:{}".format(c))
    c=asicapi.bcmcmd_route_count_hardware(vars.D2)
    st.log("Hardware count on DUT1:{}".format(c))
    c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D1)
    c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D2)

def verify_traffic(t,port_set=1):

    (tg1, tg2, tg3, tg4, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4) = get_handles()
    global tr1,tr2
    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    st.log("BOUND_STREAM: " + str(tr1))
    st.log("BOUND_STREAM: " + str(tr2))
    res = tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TrafControl: " + str(res))
    # Verified at the DUT.
    st.wait(t)
    res = tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])
    st.log("TR_CTRL: " + str(res))
    st.wait(2)

    result = True
    traffic_params = {'1': {'tx_ports' : [vars.T1D1P1], 'tx_obj' : [tg1],'exp_ratio' : [1],'rx_ports' : [vars.T1D2P1], 'rx_obj' : [tg2]}}
    aggrResult = validate_tgen_traffic(traffic_details = traffic_params, mode = 'aggregate', comp_type = 'packet_count')
    if aggrResult:
        result = True
    else:
        result = False
        c=asicapi.bcmcmd_route_count_hardware(vars.D1)
        st.log("Hardware count on DUT1:{}".format(c))
        c=asicapi.bcmcmd_route_count_hardware(vars.D2)
        st.log("Hardware count on DUT1:{}".format(c))
        c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D1)
        c=asicapi.bcmcmd_ipv6_route_count_hardware(vars.D2)

    return result
