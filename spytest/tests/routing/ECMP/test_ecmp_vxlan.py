# This file contains the list of ECMP Hashing tests.
# Author: Sunil Rajendra (sunil.rajendra@broadcom.com)

import pytest
#from spytest import st
from spytest import st,utils,tgapi
#from ecmp_vars_vxlan import data
#from ecmp_utils_vxlan import *
#from ecmp_utils import *
#import apis.system.reboot as reboot
import apis.routing.ip as ip
#import apis.routing.bgp as bgp
#import apis.switching.mac as mac
import apis.system.interface as intf
from ecmp_utils import *

def initialize_topology_vars():
    global vars, tg, d3_tg_ph1, d3_tg_ph2, d4_tg_ph1, d4_tg_ph2, d5_tg_ph1, d5_tg_ph2, tg_all, dut_list
    #global d4_tg_port1, d5_tg_port1,d6_tg_port1,d7_tg_port1, d7_tg_ph1, d7_tg_ph2, d5_tg_port2, d6_tg_port2, d7_tg_port2, d3_tg_port1, d3_tg_port2
    
    #vars = st.ensure_min_topology("D1D3:3","D1D4:3","D1D5:3","D1D6:3","D2D3:3","D2D4:3","D2D5:3","D2D6:4","D4D7:4","D3T1:2","D6T1:1","D3CHIP=TD3","D4CHIP=TD3","D5CHIP=TD3","D6CHIP=TD3")
    vars = st.ensure_min_topology("D1D3:3", "D1D4:3", "D1D5:3", "D2D3:3", "D2D4:3", "D2D5:3", "D3T1:2", "D4T1:2", "D5T1:2", "D3CHIP=TD3","D4CHIP=TD3","D5CHIP=TD3")
    #vars = st.ensure_min_topology("D1D2:2", "D1D3:2", "D1D4:2", "D2T1:2", "D3T1:2", "D4T1:2", "D2CHIP=TD3", "D3CHIP=TD3", "D4CHIP=TD3")
    #create_glob_vars()
    vars = st.get_testbed_vars()
    if st.get_ui_type() == 'click':
        st.report_unsupported("test_execution_skipped", "Skipping cli mode CLICK")
    
    data.dut_list = st.get_dut_names()
    data.rtr_list = data.dut_list[0:]
    data.leaf_list = data.rtr_list[2:]
    data.dut1 = data.dut_list[0]
    data.dut2 = data.dut_list[1]
    data.dut3 = data.dut_list[2]
    data.dut4 = data.dut_list[3]
    data.dut5 = data.dut_list[4]
    dut_list = [data.dut1, data.dut2, data.dut3, data.dut4, data.dut5]
    
    data.d1d3_ports = [vars.D1D3P1, vars.D1D3P2, vars.D1D3P3]
    data.d3d1_ports = [vars.D3D1P1, vars.D3D1P2, vars.D3D1P3]
    data.d1d4_ports = [vars.D1D4P1, vars.D1D4P2, vars.D1D4P3]
    data.d4d1_ports = [vars.D4D1P1, vars.D4D1P2, vars.D4D1P3]
    data.d1d5_ports = [vars.D1D5P1, vars.D1D5P2, vars.D1D5P3]
    data.d5d1_ports = [vars.D5D1P1, vars.D5D1P2, vars.D5D1P3]
    data.d2d3_ports = [vars.D2D3P1, vars.D2D3P2, vars.D2D3P3]
    data.d3d2_ports = [vars.D3D2P1, vars.D3D2P2, vars.D3D2P3]
    data.d2d4_ports = [vars.D2D4P1, vars.D2D4P2, vars.D2D4P3]
    data.d4d2_ports = [vars.D4D2P1, vars.D4D2P2, vars.D4D2P3]
    data.d2d5_ports = [vars.D2D5P1, vars.D2D5P2, vars.D2D5P3]
    data.d5d2_ports = [vars.D5D2P1, vars.D5D2P2, vars.D5D2P3]
    data.t1d3_ports = [vars.T1D3P1, vars.T1D3P2]
    data.t1d4_ports = [vars.T1D4P1, vars.T1D4P2]
    data.t1d5_ports = [vars.T1D5P1, vars.T1D5P2]
    data.d3t1_ports = [vars.D3T1P1, vars.D3T1P2]
    data.d4t1_ports = [vars.D4T1P1, vars.D4T1P2]
    data.d5t1_ports = [vars.D5T1P1, vars.D5T1P2]
    
    tg = tgapi.get_chassis(vars)
    d3_tg_ph1, d3_tg_ph2 = tg.get_port_handle(vars.T1D3P1), tg.get_port_handle(vars.T1D3P2)
    d4_tg_ph1, d4_tg_ph2 = tg.get_port_handle(vars.T1D4P1), tg.get_port_handle(vars.T1D4P2)
    d5_tg_ph1, d5_tg_ph2 = tg.get_port_handle(vars.T1D5P1), tg.get_port_handle(vars.T1D5P2)
    tg_all = [d3_tg_ph1, d3_tg_ph2, d4_tg_ph1, d4_tg_ph2, d5_tg_ph1, d5_tg_ph2]
    
    #d4_tg_port1,d5_tg_port1,d6_tg_port1,d7_tg_port1,d3_tg_port1,d3_tg_port2 = vars.T1D4P1, vars.T1D5P1, vars.T1D6P1, vars.T1D7P1,vars.T1D3P1,vars.T1D3P2
    #d5_tg_port2,d6_tg_port2,d7_tg_port2 = vars.T1D5P2, vars.T1D6P2, vars.T1D7P2

def create_tg_hosts():
    #global tg, d3_tg_ph1, stream_dict
    global tg_l1_h1, tg_l1_h2, tg_l2_h1, tg_l2_h2, tg_l3_h1, tg_l1_h1_6, tg_l1_h2_6, tg_l2_h1_6, tg_l2_h2_6, tg_l3_h1_6
    global tg_l3l1_1, tg_l3l1_6_1
    # Configuring hosts.
    tg_l1_h1 = tg.tg_interface_config(port_handle=d3_tg_ph1, mode='config', intf_ip_addr=data.leaf1_dict["tenant_v4_ip"][0], gateway=data.leaf1_dict["tenant_ip_list"][0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf1_dict["tenant_mac_v4"][0], vlan='1', vlan_id=data.leaf1_dict["tenant_vlan_list"][0])
    tg_l1_h2 = tg.tg_interface_config(port_handle=d3_tg_ph2, mode='config', intf_ip_addr=data.leaf1_dict["tenant_v4_ip"][1], gateway=data.leaf1_dict["tenant_ip_list"][1], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf1_dict["tenant_mac_v4"][1], vlan='1', vlan_id=data.leaf1_dict["tenant_vlan_list"][1])
    tg_l2_h1 = tg.tg_interface_config(port_handle=d4_tg_ph1, mode='config', intf_ip_addr=data.leaf2_dict["tenant_v4_ip"][0], gateway=data.leaf2_dict["tenant_ip_list"][0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf2_dict["tenant_mac_v4"][0], vlan='1', vlan_id=data.leaf2_dict["tenant_vlan_list"][0])
    tg_l2_h2 = tg.tg_interface_config(port_handle=d4_tg_ph2, mode='config', intf_ip_addr=data.leaf2_dict["tenant_v4_ip"][1], gateway=data.leaf2_dict["tenant_ip_list"][1], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf2_dict["tenant_mac_v4"][1], vlan='1', vlan_id=data.leaf2_dict["tenant_vlan_list"][1])
    tg_l3_h1 = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config', intf_ip_addr=data.leaf3_dict["tenant_v4_ip"][0], gateway=data.leaf3_dict["tenant_ip_list"][0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf3_dict["tenant_mac_v4"][0], vlan='1', vlan_id=data.leaf3_dict["tenant_vlan_list"][0])
    tg_l1_h1_6 = tg.tg_interface_config(port_handle=d3_tg_ph1, mode='config', ipv6_intf_addr=data.leaf1_dict["tenant_v6_ip"][0], ipv6_prefix_length=mask6, ipv6_gateway=data.leaf1_dict["tenant_ipv6_list"][0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf1_dict["tenant_mac_v6"][0], vlan='1', vlan_id=data.leaf1_dict["tenant_vlan_list"][0])
    tg_l1_h2_6 = tg.tg_interface_config(port_handle=d3_tg_ph2, mode='config', ipv6_intf_addr=data.leaf1_dict["tenant_v6_ip"][1], ipv6_prefix_length=mask6, ipv6_gateway=data.leaf1_dict["tenant_ipv6_list"][1], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf1_dict["tenant_mac_v6"][1], vlan='1', vlan_id=data.leaf1_dict["tenant_vlan_list"][1])
    tg_l2_h1_6 = tg.tg_interface_config(port_handle=d4_tg_ph1, mode='config', ipv6_intf_addr=data.leaf2_dict["tenant_v6_ip"][0], ipv6_prefix_length=mask6, ipv6_gateway=data.leaf2_dict["tenant_ipv6_list"][0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf2_dict["tenant_mac_v6"][0], vlan='1', vlan_id=data.leaf2_dict["tenant_vlan_list"][0])
    tg_l2_h2_6 = tg.tg_interface_config(port_handle=d4_tg_ph2, mode='config', ipv6_intf_addr=data.leaf2_dict["tenant_v6_ip"][1], ipv6_prefix_length=mask6, ipv6_gateway=data.leaf2_dict["tenant_ipv6_list"][1], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf2_dict["tenant_mac_v6"][1], vlan='1', vlan_id=data.leaf2_dict["tenant_vlan_list"][1])
    tg_l3_h1_6 = tg.tg_interface_config(port_handle=d5_tg_ph1, mode='config', ipv6_intf_addr=data.leaf3_dict["tenant_v6_ip"][0], ipv6_prefix_length=mask6, ipv6_gateway=data.leaf3_dict["tenant_ipv6_list"][0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.leaf3_dict["tenant_mac_v6"][0], vlan='1', vlan_id=data.leaf3_dict["tenant_vlan_list"][0])

def create_tg_streams():
    global tg_l3l1_1, tg_l3l1_6_1
    # Configuring streams.
    tg_l3l1_1=tg.tg_traffic_config(port_handle=d5_tg_ph1, mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, mac_src=data.leaf3_dict["tenant_mac_v4"][0], mac_dst=data.dut5_gw_mac, l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=data.leaf3_dict["tenant_vlan_list"][0], l3_protocol=ipv4var, ip_src_addr=data.leaf3_dict["tenant_v4_ip"][0], ip_dst_addr=data.st_ip_1[2], ip_dst_count=data.tg_count, ip_dst_mode='increment', ip_dst_step=data.tg_step, frame_size=data.tg_framesize, ip_ttl=data.tg_ipttl)
    tg_l3l1_6_1=tg.tg_traffic_config(port_handle=d5_tg_ph1, mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, mac_src=data.leaf3_dict["tenant_mac_v6"][0], mac_discovery_gw=data.leaf3_dict["tenant_ipv6_list"][0], l2_encap='ethernet_ii_vlan', vlan="enable", vlan_id=data.leaf3_dict["tenant_vlan_list"][0], l3_protocol='ipv6', ipv6_src_addr=data.leaf3_dict["tenant_v6_ip"][0], ipv6_dst_addr=data.st_ip6_1[2], ipv6_dst_count=data.tg_count, ipv6_dst_mode='increment', ipv6_dst_step=data.tg_step6, frame_size=data.tg_framesize)

@pytest.fixture(scope='module', autouse=True)
def prologue_epilogue(request):
    initialize_topology_vars()
    #result = ecmp_base_config()
    [res, exceptions] = utils.exec_all(True, [[create_tg_hosts], [ecmp_base_config]], True)
    create_tg_streams()
    if res[1] is False:
        more_debugs(duts=dut_list)
        st.report_fail("module_config_verification_failed")
    yield
    ecmp_base_unconfig()


def test_ecmp_vxlan_func003():
    tc_list = ['FtOpSoRoLBFunc004', 'FtOpSoRoLBFunc008', 'FtOpSoRoLBFunc010']
    st.banner("Testcase: Verify IPv4 and IPv6 ECMP Loadbalance and Hash polarization in VxLAN topology.\n TCs:{}.".format(tc_list))
    retvar = True
    fail_msgs = ''
    tc_res={}
    for tc in tc_list: tc_res[tc] = True
    
    spine1=data.dut1
    spine2=data.dut2
    leaf1=data.dut3
    leaf2=data.dut4
    leaf3=data.dut5
    
    st.banner("Step T1: Verify default show cli.")
    def f3_t1_1():
        res1=ip.verify_ip_loadshare(spine1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on spine1."
            st.log(fail_msg)
            return False
        return True
    def f3_t1_2():
        res1=ip.verify_ip_loadshare(spine2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on spine2."
            st.log(fail_msg)
            return False
        return True
    def f3_t1_3():
        res1=ip.verify_ip_loadshare(leaf1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on leaf1."
            st.log(fail_msg)
            return False
        return True
    def f3_t1_4():
        res1=ip.verify_ip_loadshare(leaf2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on leaf2."
            st.log(fail_msg)
            return False
        return True
    def f3_t1_5():
        res1=ip.verify_ip_loadshare(leaf3, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on leaf3."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f3_t1_1], [f3_t1_2], [f3_t1_3], [f3_t1_4], [f3_t1_5]])
    if False in set(res):
        fail_msg = "ERROR: Step T1 show cli for default values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]]=False
        retvar = False
    
    '''
    st.log("Step T1a: Fine tuning the config and verification.")
    f3_f2_1=lambda x: intf.interface_shutdown(spine1, [vars.D1D3P2, vars.D1D4P2, vars.D1D5P2])
    f3_f2_2=lambda x: intf.interface_shutdown(spine2, [vars.D2D3P2, vars.D2D4P2, vars.D2D5P2])
    [res, exceptions] = utils.exec_all(True, [[f3_f2_1, 1], [f3_f2_2, 1]])
    st.wait(waitvar)
    '''
    st.banner("Step T2: Start all IPv4 and IPv6 Streams.")
    tg_v4s = [tg_l3l1_1['stream_id']]
    tg_v6s = [tg_l3l1_6_1['stream_id']]
    tg_strs = tg_v4s + tg_v6s
    f3_f1_1 = lambda x: intf.clear_interface_counters(spine1)
    f3_f1_2 = lambda x: intf.clear_interface_counters(spine2)
    f3_f1_3 = lambda x: intf.clear_interface_counters(leaf1)
    f3_f1_4 = lambda x: intf.clear_interface_counters(leaf2)
    f3_f1_5 = lambda x: intf.clear_interface_counters(leaf3)
    [res, exceptions] = utils.exec_all(True, [[f3_f1_1, 1], [f3_f1_2, 1], [f3_f1_3, 1], [f3_f1_4, 1], [f3_f1_5, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T3: Verify ECMP.")
    leaf_tg_ports = [[leaf1, vars.D3T1P1], [leaf1, vars.D3T1P2], [leaf2, vars.D4T1P1], [leaf2, vars.D4T1P2]]
    l3_spine_ports = [[leaf3, vars.D5D1P1], [leaf3, vars.D5D1P2], [leaf3, vars.D5D2P1], [leaf3, vars.D5D2P2]]
    spine_leaf_ports = [[spine1, vars.D1D3P1], [spine1, vars.D1D3P2], [spine1, vars.D1D4P1], [spine1, vars.D1D4P2], [spine2, vars.D2D3P1], [spine2, vars.D2D3P2], [spine2, vars.D2D4P1], [spine2, vars.D2D4P2]]
    res1=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=leaf_tg_ports, ratio = [[1], [0.25, 0.25, 0.25, 0.25]], clear_save=True)
    res2=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=l3_spine_ports, ratio = [[1], [0.25, 0.25, 0.25, 0.25]], saved_flag=True)
    #res3=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=spine_leaf_ports, ratio = [[1], [0.25, 0.25, 0.25, 0.25, 0, 0, 0, 0]], saved_flag=True)
    res3=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=spine_leaf_ports, ratio = [[1], [0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125]], saved_flag=True, tolerance=25)
    st.log("Step T12: res1={}, res2={}, res3={} - all should be True".format(res1, res2, res3))
    if res1 is False or res2 is False or res3 is False:
        fail_msg = "ERROR: Step T3 Initial ECMP failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[1]] = False
        retvar = False
        gen_tech_supp(filename='f3_t3_')
        more_debugs(duts=dut_list)
    
    st.banner("Step T4: Remove dst-ip on leaf3, src-l4-port from other duts.")
    def f3_t4_1():
        ip.config_ip_loadshare_hash(spine1, key='ip', val=ecmpv4[3], config='no')
        ip.config_ip_loadshare_hash(spine1, key='ipv6', val=ecmpv6[3], config='no')
        res1=ip.verify_ip_loadshare(spine1, ip=ecmpv4[3], ipv6=ecmpv6[3])
        if res1 is True:
            fail_msg = "ERROR: Step T4 show failed on spine1."
            st.log(fail_msg)
            return False
        return True
    def f3_t4_2():
        ip.config_ip_loadshare_hash(spine2, key='ip', val=ecmpv4[3], config='no')
        ip.config_ip_loadshare_hash(spine2, key='ipv6', val=ecmpv6[3], config='no')
        res1=ip.verify_ip_loadshare(spine2, ip=ecmpv4[3], ipv6=ecmpv6[3])
        if res1 is True:
            fail_msg = "ERROR: Step T4 show failed on spine2."
            st.log(fail_msg)
            return False
        return True
    def f3_t4_3():
        ip.config_ip_loadshare_hash(leaf1, key='ip', val=ecmpv4[3], config='no')
        ip.config_ip_loadshare_hash(leaf1, key='ipv6', val=ecmpv6[3], config='no')
        res1=ip.verify_ip_loadshare(leaf1, ip=ecmpv4[3], ipv6=ecmpv6[3])
        if res1 is True:
            fail_msg = "ERROR: Step T4 show failed on leaf1."
            st.log(fail_msg)
            return False
        return True
    def f3_t4_4():
        ip.config_ip_loadshare_hash(leaf2, key='ip', val=ecmpv4[3], config='no')
        ip.config_ip_loadshare_hash(leaf2, key='ipv6', val=ecmpv6[3], config='no')
        res1=ip.verify_ip_loadshare(leaf2, ip=ecmpv4[3], ipv6=ecmpv6[3])
        if res1 is True:
            fail_msg = "ERROR: Step T4 show failed on leaf2."
            st.log(fail_msg)
            return False
        return True
    def f3_t4_5():
        ip.config_ip_loadshare_hash(leaf3, key='ip', val=ecmpv4[1], config='no')
        ip.config_ip_loadshare_hash(leaf3, key='ipv6', val=ecmpv6[1], config='no')
        res1=ip.verify_ip_loadshare(leaf3, ip=ecmpv4[1], ipv6=ecmpv6[1])
        if res1 is True:
            fail_msg = "ERROR: Step T4 show failed on leaf3."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f3_t4_1], [f3_t4_2], [f3_t4_3], [f3_t4_4], [f3_t4_5]])
    if False in set(res):
        fail_msg = "ERROR: Step T4 show cli failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[1]] = False
        retvar = False
    
    st.banner("Step T5: Start the Streams.")
    [res, exceptions] = utils.exec_all(True, [[f3_f1_1, 1], [f3_f1_2, 1], [f3_f1_3, 1], [f3_f1_4, 1], [f3_f1_5, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T6: Verify no ECMP at leaf1 and leaf2.")
    res1a=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=leaf_tg_ports, ratio = [[1], [1, 0, 0, 0]], clear_save=True)
    res1b=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=leaf_tg_ports, ratio = [[1], [0, 1, 0, 0]], saved_flag=True)
    res1c=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=leaf_tg_ports, ratio = [[1], [0, 0, 1, 0]], saved_flag=True)
    res1d=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=leaf_tg_ports, ratio = [[1], [0, 0, 0, 1]], saved_flag=True)
    st.log("Step T6: tx11={}, tx12={}, tx21={}, tx22={} - only one of these should be True".format(res1a, res1b, res1c, res1d))
    res2a=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=l3_spine_ports, ratio = [[1], [0.5, 0.5, 0, 0]], saved_flag=True)
    res2b=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=l3_spine_ports, ratio = [[1], [0, 0, 0.5, 0.5]], saved_flag=True)
    st.log("Step T6: L3S1={}, L3S2={} - only one of these should be True".format(res2a, res2b))
    res3a=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=spine_leaf_ports, ratio = [[1], [0.5, 0.5, 0, 0, 0, 0, 0, 0]], saved_flag=True, tolerance=25)
    res3b=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=spine_leaf_ports, ratio = [[1], [0, 0, 0.5, 0.5, 0, 0, 0, 0]], saved_flag=True, tolerance=25)
    res3c=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=spine_leaf_ports, ratio = [[1], [0, 0, 0, 0, 0.5, 0.5, 0, 0]], saved_flag=True, tolerance=25)
    res3d=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=spine_leaf_ports, ratio = [[1], [0, 0, 0, 0, 0, 0, 0.5, 0.5]], saved_flag=True, tolerance=25)
    st.log("Step T6: S1L1={}, S1L2={}, S2L1={}, S2L2={} - only one of these should be True".format(res3a, res3b, res3c, res3d))
    res1= len([r for r in [res1a, res1b, res1c, res1d] if r is True])
    res2= len([r for r in [res2a, res2b] if r is True])
    res3= len([r for r in [res3a, res3b, res3c, res3d] if r is True])
    if res1 != 1 or res2 != 1 or res3 != 1:
        st.log("Step T6: res1={}, res2={}, res3={} - all should be 1".format(res1, res2, res3))
        st.log("Step T6: tx11={}, tx12={}, tx21={}, tx22={} - only one of these should be True".format(res1a, res1b, res1c, res1d))
        st.log("Step T6: L3S1={}, L3S2={} - only one of these should be True".format(res2a, res2b))
        st.log("Step T6: S1L1={}, S1L2={}, S2L1={}, S2L2={} - only one of these should be True".format(res3a, res3b, res3c, res3d))
        fail_msg = "ERROR: Step T6 ECMP still working even after disabling."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[1]] = False
        retvar = False
        gen_tech_supp(filename='f3_t5_')
        more_debugs(duts=dut_list)
    
    st.banner("Step T10: Reconfigure the ECMP params.")
    def f3_t10_1():
        ip.config_ip_loadshare_hash(spine1, key='ip', val=ecmpv4[3])
        ip.config_ip_loadshare_hash(spine1, key='ipv6', val=ecmpv6[3])
        res1=ip.verify_ip_loadshare(spine1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T10 show failed on spine1."
            st.log(fail_msg)
            return False
        return True
    def f3_t10_2():
        ip.config_ip_loadshare_hash(spine2, key='ip', val=ecmpv4[3])
        ip.config_ip_loadshare_hash(spine2, key='ipv6', val=ecmpv6[3])
        res1=ip.verify_ip_loadshare(spine2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T10 show failed on spine2."
            st.log(fail_msg)
            return False
        return True
    def f3_t10_3():
        ip.config_ip_loadshare_hash(leaf1, key='ip', val=ecmpv4[3])
        ip.config_ip_loadshare_hash(leaf1, key='ipv6', val=ecmpv6[3])
        res1=ip.verify_ip_loadshare(leaf1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T10 show failed on leaf1."
            st.log(fail_msg)
            return False
        return True
    def f3_t10_4():
        ip.config_ip_loadshare_hash(leaf2, key='ip', val=ecmpv4[3])
        ip.config_ip_loadshare_hash(leaf2, key='ipv6', val=ecmpv6[3])
        res1=ip.verify_ip_loadshare(leaf2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T10 show failed on leaf2."
            st.log(fail_msg)
            return False
        return True
    def f3_t10_5():
        ip.config_ip_loadshare_hash(leaf3, key='ip', val=ecmpv4[1])
        ip.config_ip_loadshare_hash(leaf3, key='ipv6', val=ecmpv6[1])
        res1=ip.verify_ip_loadshare(leaf3, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T10 show failed on leaf3."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f3_t10_1], [f3_t10_2], [f3_t10_3], [f3_t10_4], [f3_t10_5]])
    if False in set(res):
        fail_msg = "ERROR: Step T10 show cli failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[1]] = tc_res[tc_list[2]] = False
        retvar = False
    
    st.banner("Step T11: Start the Streams.")
    [res, exceptions] = utils.exec_all(True, [[f3_f1_1, 1], [f3_f1_2, 1], [f3_f1_3, 1], [f3_f1_4, 1], [f3_f1_5, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T12: Verify ECMP is restored.")
    res1=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=leaf_tg_ports, ratio = [[1], [0.25, 0.25, 0.25, 0.25]], clear_save=True)
    res2=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=l3_spine_ports, ratio = [[1], [0.25, 0.25, 0.25, 0.25]], saved_flag=True)
    res3=verify_intf_counters(rx=[[leaf3, vars.D5T1P1]], tx=spine_leaf_ports, ratio = [[1], [0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125, 0.125]], saved_flag=True, tolerance=25)
    st.log("Step T12: res1={}, res2={}, res3={} - all should be True".format(res1, res2, res3))
    if res1 is False or res2 is False or res3 is False:
        fail_msg = "ERROR: Step T12 ECMP restoration failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[1]] = tc_res[tc_list[2]] = False
        retvar = False
        gen_tech_supp(filename='f3_t12_')
        more_debugs(duts=dut_list)
    
    for tc in tc_list:
        if tc_res[tc]:
            st.report_tc_pass(tc, "tc_passed")
    
    if retvar is False:
        st.report_fail("test_case_failure_message", fail_msgs)
    
    st.report_pass("test_case_passed")
