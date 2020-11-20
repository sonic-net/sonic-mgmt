# This file contains the list of ECMP Hashing tests
# Author: Sunil Rajendra (sunil.rajendra@broadcom.com)
import pytest

from spytest import st, utils

import apis.routing.ip as ip
import apis.system.basic as basic
import apis.system.interface as intf
import apis.qos.acl as acl
from apis.system import basic
from utilities.utils import retry_api

from ecmp_utils import *

def initialize_topology():
    global vars, dut_list, dut1, dut2
    global tg, tg_1, tg_2, tg_3, tg_4, tg_all
    global saved_output
    
    # Verify Minimum topology requirement is met
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1T1:2", "D2T1:2", "D1D2:2")
    st.banner("Start Test with topology D1T1:2, D2T1:2, D1D2:2")
    if st.get_ui_type() == 'click':
        st.report_unsupported("test_execution_skipped","Skipping cli mode CLICK")
    
    # Initialize DUT variables and ports
    dut_list = st.get_dut_names()
    dut1 = vars.D1
    dut2 = vars.D2
    tg = tgen_obj_dict[vars['tgen_list'][0]]
    tg_1 = tg.get_port_handle(vars.T1D1P1)
    tg_2 = tg.get_port_handle(vars.T1D2P1)
    tg_3 = tg.get_port_handle(vars.T1D1P2)
    tg_4 = tg.get_port_handle(vars.T1D2P2)
    tg_all = [tg_1, tg_2, tg_3, tg_4]
    saved_output = {}
    data.dut1_mac = basic.get_ifconfig_ether(dut1, vars.D1T1P1)
    data.dut2_mac = basic.get_ifconfig_ether(dut2, vars.D2T1P1)

def config_base_all():
    st.log("Within config_base_all...")
    def config_base_dut1():
        st.log("Within config_base_dut1...")
        ip.config_ip_addr_interface(dut1, vars['D1T1P1'], data.ip_1[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut1, vars['D1T1P1'], data.ip6_1[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P1'], data.ip_12_1[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P1'], data.ip6_12_1[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P2'], data.ip_12_2[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P2'], data.ip6_12_2[0], mask6, ipv6var, addvar)
        ip.create_static_route(dut1, data.ip_12_1[1], data.st_ip_2[1])
        ip.create_static_route(dut1, data.ip_12_2[1], data.st_ip_2[1])
        ip.create_static_route(dut1, data.ip_1[1], data.st_ip_1[1])
        ip.create_static_route(dut1, data.ip6_12_1[1], data.st_ip6_2[1], family='ipv6')
        ip.create_static_route(dut1, data.ip6_12_2[1], data.st_ip6_2[1], family='ipv6')
        ip.create_static_route(dut1, data.ip6_1[1], data.st_ip6_1[1], family='ipv6')
    def config_base_dut2():
        st.log("Within config_base_dut2...")
        ip.config_ip_addr_interface(dut2, vars['D2T1P1'], data.ip_2[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut2, vars['D2T1P1'], data.ip6_2[0], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P1'], data.ip_12_1[1], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P1'], data.ip6_12_1[1], mask6, ipv6var, addvar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P2'], data.ip_12_2[1], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P2'], data.ip6_12_2[1], mask6, ipv6var, addvar)
        ip.create_static_route(dut2, data.ip_12_1[0], data.st_ip_1[1])
        ip.create_static_route(dut2, data.ip_12_2[0], data.st_ip_1[1])
        ip.create_static_route(dut2, data.ip_2[1], data.st_ip_2[1])
        ip.create_static_route(dut2, data.ip6_12_1[0], data.st_ip6_1[1], family='ipv6')
        ip.create_static_route(dut2, data.ip6_12_2[0], data.st_ip6_1[1], family='ipv6')
        ip.create_static_route(dut2, data.ip6_2[1], data.st_ip6_2[1], family='ipv6')
    [res, exceptions] = utils.exec_all(True, [[config_base_dut1], [config_base_dut2]])
    # Verify Static routes.
    st.wait(waitvar)
    res=retry_api(verify_config_base_all, retry_count=2, delay=5)
    return res

def verify_config_base_all():
    st.log("Within verify_config_base_all...")
    def verify_config_base_dut1():
        st.log("Within verify_config_base_dut1...")
        res1=ip.verify_multiple_routes(dut1, ip_address=[data.st_ip_2[1]]*2+[data.st_ip_1[1]], nexthop=[data.ip_12_1[1], data.ip_12_2[1], data.ip_1[1]])
        res2=ip.verify_multiple_routes(dut1, ip_address=[data.st_ip6_2[1]]*2+[data.st_ip6_1[1]], nexthop=[data.ip6_12_1[1], data.ip6_12_2[1], data.ip6_1[1]], family='ipv6')
        out1=ip.show_ip_route(dut1, summary_routes='summary')
        res3=True if (out1[0]['fib_static'] == '2' and int(out1[0]['fib_total']) >= 5) else False
        out2=ip.show_ip_route(dut1, summary_routes='summary', family='ipv6', vrf_name='default')
        res4=True if (out2[0]['fib_static'] == '2' and int(out2[0]['fib_total']) >= 8) else False
        res = list(set([res1, res2, res3, res4]))
        st.log("verify_config_base_dut1: res1={}, res2={}, res3={}, res4={}.".format(res1, res2, res3, res4))
        return res[0] if len(res)==1 else False
    def verify_config_base_dut2():
        st.log("Within verify_config_base_dut2...")
        res1=ip.verify_multiple_routes(dut2, ip_address=[data.st_ip_1[1]]*2+[data.st_ip_2[1]], nexthop=[data.ip_12_1[0], data.ip_12_2[0], data.ip_2[1]])
        res2=ip.verify_multiple_routes(dut2, ip_address=[data.st_ip6_1[1]]*2+[data.st_ip6_2[1]], nexthop=[data.ip6_12_1[0], data.ip6_12_2[0], data.ip6_2[1]], family='ipv6')
        out1=ip.show_ip_route(dut2, summary_routes='summary')
        res3=True if (out1[0]['fib_static'] == '2' and int(out1[0]['fib_total']) >= 5) else False
        out2=ip.show_ip_route(dut2, summary_routes='summary', family='ipv6', vrf_name='default')
        res4=True if (out2[0]['fib_static'] == '2' and int(out2[0]['fib_total']) >= 8) else False
        res = list(set([res1, res2, res3, res4]))
        st.log("verify_config_base_dut2: res1={}, res2={}, res3={}, res4={}.".format(res1, res2, res3, res4))
        return res[0] if len(res)==1 else False
    [res, exceptions] = utils.exec_all(True, [[verify_config_base_dut1], [verify_config_base_dut2]])
    return False if False in set(res) else True

def deconfig_base_all():
    st.log("Within deconfig_base_all...")
    def deconfig_base_dut1():
        st.log("Within deconfig_base_dut1...")
        ip.delete_static_route(dut1, data.ip_12_1[1], data.st_ip_2[1])
        ip.delete_static_route(dut1, data.ip_12_2[1], data.st_ip_2[1])
        ip.delete_static_route(dut1, data.ip_1[1], data.st_ip_1[1])
        ip.delete_static_route(dut1, data.ip6_12_1[1], data.st_ip6_2[1], family='ipv6')
        ip.delete_static_route(dut1, data.ip6_12_2[1], data.st_ip6_2[1], family='ipv6')
        ip.delete_static_route(dut1, data.ip6_1[1], data.st_ip6_1[1], family='ipv6')
        ip.config_ip_addr_interface(dut1, vars['D1T1P1'], data.ip_1[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut1, vars['D1T1P1'], data.ip6_1[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P1'], data.ip_12_1[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P1'], data.ip6_12_1[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P2'], data.ip_12_2[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut1, vars['D1D2P2'], data.ip6_12_2[0], mask6, ipv6var, removevar)
    def deconfig_base_dut2():
        st.log("Within deconfig_base_dut2...")
        ip.delete_static_route(dut2, data.ip_12_1[0], data.st_ip_1[1])
        ip.delete_static_route(dut2, data.ip_12_2[0], data.st_ip_1[1])
        ip.delete_static_route(dut2, data.ip_2[1], data.st_ip_2[1])
        ip.delete_static_route(dut2, data.ip6_12_1[0], data.st_ip6_1[1], family='ipv6')
        ip.delete_static_route(dut2, data.ip6_12_2[0], data.st_ip6_1[1], family='ipv6')
        ip.delete_static_route(dut2, data.ip6_2[1], data.st_ip6_2[1], family='ipv6')
        ip.config_ip_addr_interface(dut2, vars['D2T1P1'], data.ip_2[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut2, vars['D2T1P1'], data.ip6_2[0], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P1'], data.ip_12_1[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P1'], data.ip6_12_1[1], mask6, ipv6var, removevar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P2'], data.ip_12_2[1], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut2, vars['D2D1P2'], data.ip6_12_2[1], mask6, ipv6var, removevar)
    [res, exceptions] = utils.exec_all(True, [[deconfig_base_dut1], [deconfig_base_dut2]])
    return False if False in set(res) else True

def config_base_tg():
    global tg_h1, tg_h2, tg_h3, tg_h4
    global tg_h1_6, tg_h2_6, tg_h3_6, tg_h4_6
    global tg_tr12, tg_tr21
    global tg_tr12_6, tg_tr21_6
    
    st.log("Within config_base_tg...")
    # Configuring hosts.
    tg_h1 = tg.tg_interface_config(port_handle=tg_1, mode='config', intf_ip_addr=data.ip_1[1], gateway=data.ip_1[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[0])
    tg_h2 = tg.tg_interface_config(port_handle=tg_2, mode='config', intf_ip_addr=data.ip_2[1], gateway=data.ip_2[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[1])
    tg_h3 = tg.tg_interface_config(port_handle=tg_3, mode='config', intf_ip_addr=data.ip_1_2[1], gateway=data.ip_1_2[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[2])
    tg_h4 = tg.tg_interface_config(port_handle=tg_4, mode='config', intf_ip_addr=data.ip_2_2[1], gateway=data.ip_2_2[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[3])
    tg_h1_6 = tg.tg_interface_config(port_handle=tg_1, mode='config', ipv6_intf_addr=data.ip6_1[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_1[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[0])
    tg_h2_6 = tg.tg_interface_config(port_handle=tg_2, mode='config', ipv6_intf_addr=data.ip6_2[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_2[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[1])
    tg_h3_6 = tg.tg_interface_config(port_handle=tg_3, mode='config', ipv6_intf_addr=data.ip6_1_2[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_1_2[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[2])
    tg_h4_6 = tg.tg_interface_config(port_handle=tg_4, mode='config', ipv6_intf_addr=data.ip6_2_2[1], ipv6_prefix_length=mask6, ipv6_gateway=data.ip6_2_2[0], arp_send_req='1', enable_ping_response=1, src_mac_addr=data.tg_macs[3])
    
    # Configuring streams.
    tg_tr12=tg.tg_traffic_config(port_handle=tg_1, mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, mac_src=data.tg_macs[0], mac_dst=data.dut1_mac, l3_protocol=ipv4var, ip_src_addr=data.ip_1[1], ip_dst_addr=data.st_ip_2[2], ip_dst_count=data.tg_count, ip_dst_mode='increment', ip_dst_step=data.tg_step, frame_size=data.tg_framesize, ip_ttl=data.tg_ipttl)
    tg_tr21=tg.tg_traffic_config(port_handle=tg_2, mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, mac_src=data.tg_macs[1], mac_dst=data.dut2_mac, l3_protocol=ipv4var, ip_src_addr=data.ip_2[1], ip_dst_addr=data.st_ip_1[2], l4_protocol='tcp', tcp_src_port=data.src_port, tcp_dst_port=data.dst_port, tcp_dst_port_count=data.tg_count, tcp_dst_port_step=1, tcp_dst_port_mode='increment', frame_size=data.tg_framesize, ip_ttl=data.tg_ipttl)
    tg_tr12_6=tg.tg_traffic_config(port_handle=tg_1, mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, l3_protocol='ipv6', mac_src=data.tg_macs[0], mac_discovery_gw=data.ip6_1[0], ipv6_src_addr=data.ip6_1[1], ipv6_dst_addr=data.st_ip6_2[2], ipv6_dst_count=data.tg_count, ipv6_dst_mode='increment', ipv6_dst_step=data.tg_step6, frame_size=data.tg_framesize)
    tg_tr21_6=tg.tg_traffic_config(port_handle=tg_2, mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=data.tg_rate, l3_protocol='ipv6', mac_src=data.tg_macs[1], mac_discovery_gw=data.ip6_2[0], ipv6_src_addr=data.ip6_2[1], ipv6_dst_addr=data.st_ip6_1[2], l4_protocol='tcp', tcp_src_port=data.src_port, tcp_dst_port=data.dst_port, tcp_dst_port_count=data.tg_count, tcp_dst_port_step=1, tcp_dst_port_mode='increment', frame_size=data.tg_framesize)

def deconfig_base_tg():
    tg.tg_traffic_control(action='reset', port_handle=tg_all)

@pytest.fixture(scope="module",autouse=True)
def prologue_epilogue():
    st.banner("Start of PROLOGUE.")
    st.log("Starting to initialize and validate topology...")
    initialize_topology()
    [res, exceptions] = utils.exec_all(True, [[config_base_tg], [config_base_all]], True)
    if res[1] is False:
        more_debugs(duts=dut_list)
        st.report_fail("module_config_verification_failed")
    st.banner("End of PROLOGUE.")
    yield
    [res, exceptions] = utils.exec_all(True, [[deconfig_base_tg], [deconfig_base_all]], True)

def test_ecmp_cli001():
    tc_list = ['FtOpSoRoLBCli001', 'FtOpSoRoLBCli002', 'FtOpSoRoLBCli003', 'FtOpSoRoLBCli004']
    st.banner("Testcase: Verify ECMP Loadbalance CLIs.\n TCs:{}.".format(tc_list))
    retvar = True
    fail_msgs = ''
    tc_res={}
    for tc in tc_list: tc_res[tc] = True
    
    st.banner("Step T1: Verify default show cli.")
    def c1_t1_1():
        res1=ip.verify_ip_loadshare(dut1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on dut1."
            st.log(fail_msg)
            return False
        return True
    def c1_t1_2():
        res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on dut2."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t1_1], [c1_t1_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T1 show cli for default values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]]=False
        retvar = False
    
    st.banner("Step T1a: Remove all ipv4 and ipv6 ECMP params.")
    def c1_t1a_1():
        res1=ip.config_ip_loadshare_hash(dut1, key='ip', val=ecmpv4, config='no')
        res2=ip.config_ip_loadshare_hash(dut1, key='ipv6', val=ecmpv6, config='no')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T1a Removing ipv4 and ipv6 ECMP params failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[0]]=False
            return False
        return True
    def c1_t1a_2():
        res1=ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4, config='no')
        res2=ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6, config='no')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T1a Removing ipv4 and ipv6 ECMP params failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[1]]=False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t1a_1], [c1_t1a_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T1a Removing ipv4 and ipv6 ECMP params failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
    
    st.log("Step T1b: Verify show cli.")
    def c1_t1b_1():
        res1=ip.verify_ip_loadshare(dut1, seed=data.seed_def)
        res2=ip.verify_ip_loadshare(dut1, ip=ecmpv4, ipv6=ecmpv6)
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T1b show failed on dut1."
            st.log(fail_msg)
            return False
        return True
    def c1_t1b_2():
        res1=ip.verify_ip_loadshare(dut2, seed=data.seed_def)
        res2=ip.verify_ip_loadshare(dut2, ip=ecmpv4, ipv6=ecmpv6)
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T1b show failed on dut2."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t1b_1], [c1_t1b_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T1b show cli after removing ipv4 and ipv6 params failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]]=False
        retvar = False
    
    st.banner("Step T2: Config ipv4 and ipv6 ECMP params.")
    def c1_t2_1():
        res1=ip.config_ip_loadshare_hash(dut1, key='ip', val=ecmpv4[0])
        if res1 is False:
            fail_msg = "ERROR: Step T2 ipv4 ECMP param failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[0]]=False
            return False
        return True
    def c1_t2_2():
        res1=ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6[0:4])
        if res1 is False:
            fail_msg = "ERROR: Step T2 ipv6 ECMP param failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[1]]=False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t2_1], [c1_t2_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T2 ipv4 and ipv6 ECMP params failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
    
    st.banner("Step T3: Verify show cli for configured ipv4 and ipv6 params.")
    st.wait(waitvar/2)
    def c1_t3_1():
        res1=ip.verify_ip_loadshare(dut1, ip=ecmpv4[0], seed=data.seed_def)
        res2=ip.verify_ip_loadshare(dut1, ipv6=ecmpv6)
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T3 show failed on dut1."
            st.log(fail_msg)
            return False
        return True
    def c1_t3_2():
        res1=ip.verify_ip_loadshare(dut2, ipv6=ecmpv6[0:4], seed=data.seed_def)
        res2=ip.verify_ip_loadshare(dut2, ip=ecmpv4)
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T3 show failed on dut2."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t3_1], [c1_t3_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T3 show cli for configured values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]]=False
        retvar = False
    
    st.banner("Step T4: Unconfig ipv4 and ipv6 ECMP params.")
    def c1_t4_1():
        res1=ip.config_ip_loadshare_hash(dut1, key='ip', val=ecmpv4[0], config='no')
        if res1 is False:
            fail_msg = "ERROR: Step T4 ipv4 ECMP param unconfig failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[0]]=False
            return False
        return True
    def c1_t4_2():
        res1=ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6[0:4], config='no')
        if res1 is False:
            fail_msg = "ERROR: Step T4 ipv6 ECMP param unconfig failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[1]]=False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t4_1], [c1_t4_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T4 ipv4 and ipv6 ECMP params unconfig failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
    
    st.banner("Step T5: Verify show cli after unconfig.")
    st.wait(waitvar/2)
    [res, exceptions] = utils.exec_all(True, [[c1_t1b_1], [c1_t1b_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T5 show cli failed after unconfig."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]]=False
        retvar = False
    
    st.banner("Step T6: Config seed with different ipv4 and ipv6 ECMP params.")
    def c1_t6_1():
        res1=ip.config_ip_loadshare_hash(dut1, key='ipv6', val=ecmpv6[-1])
        res2=ip.config_ip_loadshare_hash(dut1, key='seed', val=data.seed_range[0])
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T6 ECMP seed config failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[1]] = tc_res[tc_list[2]] = False
            return False
        return True
    def c1_t6_2():
        res1=ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4[1:])
        res2=ip.config_ip_loadshare_hash(dut2, key='seed', val=data.seed_range[1])
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T6 ECMP seed config failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t6_1], [c1_t6_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T6 ECMP seed config failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
    
    st.banner("Step T7: Verify show cli for configured seed value.")
    st.wait(waitvar/2)
    def c1_t7_1():
        res1=ip.verify_ip_loadshare(dut1, ipv6=ecmpv6[-1], seed=data.seed_range[0])
        res2=ip.verify_ip_loadshare(dut1, ip=ecmpv4)
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T7 show failed on dut1."
            st.log(fail_msg)
            return False
        return True
    def c1_t7_2():
        res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4[1:], seed=data.seed_range[1])
        res2=ip.verify_ip_loadshare(dut2, ipv6=ecmpv6)
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T7 show failed on dut2."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t7_1], [c1_t7_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T7 show cli for configured values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]]=False
        retvar = False
        gen_tech_supp(filename='c1_t7_')
    
    st.banner("Step T8: Unconfig all ECMP params.")
    def c1_t8_1():
        res1=ip.config_ip_loadshare_hash(dut1, key='ipv6', val=ecmpv6[-1], config='no')
        res2=ip.config_ip_loadshare_hash(dut1, key='seed', val=data.seed_range[0], config='no')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T8 unconfig failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[1]] = tc_res[tc_list[2]] = False
            return False
        return True
    def c1_t8_2():
        res1=ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4[1:], config='no')
        res2=ip.config_ip_loadshare_hash(dut2, key='seed', val=data.seed_range[1], config='no')
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T8 unconfig failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t8_1], [c1_t8_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T8 ECMP params unconfig failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False

    st.banner("Step T9: Verify show cli after remove all configs.")
    st.wait(waitvar/2)
    [res, exceptions] = utils.exec_all(True, [[c1_t1b_1], [c1_t1b_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T9 show cli failed after removing all configs."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]]=False
        retvar = False
    
    st.banner("Step T12: Reconfig all ipv4 and ipv6 ECMP params to match the default config.")
    def c1_t12_1():
        res1=ip.config_ip_loadshare_hash(dut1, key='ip', val=ecmpv4)
        res2=ip.config_ip_loadshare_hash(dut1, key='ipv6', val=ecmpv6)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T12 Reconfig all ipv4 and ipv6 ECMP params failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[1]] = tc_res[tc_list[2]] = False
            return False
        return True
    def c1_t12_2():
        res1=ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4)
        res2=ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6)
        if res1 is False or res2 is False:
            fail_msg = "ERROR: Step T12 Reconfig all ipv4 and ipv6 ECMP params failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[c1_t12_1], [c1_t12_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T12 Reconfig all ipv4 and ipv6 ECMP params failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
    
    st.banner("Step T13: Verify show cli after configuring all IPv4 and IPv6 ECMP params.")
    st.wait(waitvar/2)
    [res, exceptions] = utils.exec_all(True, [[c1_t1_1], [c1_t1_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T13 show cli failed after configuring all IPv4 and IPv6 ECMP params."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]]=False
        retvar = False
    
    for tc in tc_list:
        if tc_res[tc]:
            st.report_tc_pass(tc, "tc_passed")
    
    if retvar is False:
        st.report_fail("test_case_failure_message", fail_msgs)
    
    st.report_pass("test_case_passed")

def test_ecmp_basic_func001():
    tc_list = ['FtOpSoRoLBFunc001', 'FtOpSoRoLBFunc002', 'FtOpSoRoLBFunc005', 'FtOpSoRoLBFunc006']
    st.banner("Testcase: Verify IPv4 and IPv6 ECMP Loadbalance basic functionality.\n TCs:{}.".format(tc_list))
    retvar = True
    fail_msgs = ''
    tc_res={}
    for tc in tc_list: tc_res[tc] = True
    
    st.banner("Step T1: Verify default show cli.")
    def f1_t1_1():
        res1=ip.verify_ip_loadshare(dut1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on dut1."
            st.log(fail_msg)
            return False
        return True
    def f1_t1_2():
        res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T1 Default show failed on dut2."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f1_t1_1], [f1_t1_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T1 show cli for default values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]]=False
        retvar = False
    
    st.banner("Step T2: Start all IPv4 and IPv6 Streams.")
    tg_v4s = [tg_tr12['stream_id'], tg_tr21['stream_id']]
    tg_v6s = [tg_tr12_6['stream_id'], tg_tr21_6['stream_id']]
    tg_strs = tg_v4s + tg_v6s
    f1_f1_1 = lambda x: intf.clear_interface_counters(dut1)
    f1_f1_2 = lambda x: intf.clear_interface_counters(dut2)
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T3: Verify ECMP.")
    res1=verify_intf_counters(rx=[[dut1, vars.D1T1P1], [dut2, vars.D2D1P1], [dut2, vars.D2D1P2]],
        tx=[[dut1, vars.D1D2P1], [dut1, vars.D1D2P2], [dut2, vars.D2T1P1]],
        ratio = [[1, 0.5, 0.5], [0.5, 0.5, 1]], clear_save=True)
    res2=verify_intf_counters(rx=[[dut2, vars.D2T1P1], [dut1, vars.D1D2P1], [dut1, vars.D1D2P2]],
        tx=[[dut2, vars.D2D1P1], [dut2, vars.D2D1P2], [dut1, vars.D1T1P1]],
        ratio = [[1, 0.5, 0.5], [0.5, 0.5, 1]], saved_flag=True)
    if res1 is False:
        fail_msg = "ERROR: Step T3 ECMP failed from dut1 to dut2."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
        retvar = False
        gen_tech_supp(filename='f1_t3a_')
        more_debugs(duts=dut_list)
    if res2 is False:
        fail_msg = "ERROR: Step T3 ECMP failed from dut2 to dut1."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[1]] = tc_res[tc_list[3]] = False
        retvar = False
        if res1 is not False:
            gen_tech_supp(filename='f1_t3b_')
            more_debugs(duts=dut_list)
    
    st.banner("Step T4: Configure non-matching user ECMP params.")
    def f1_t4_1():
        ip.config_ip_loadshare_hash(dut1, key='ip', val=ecmpv4[1:], config='no')
        ip.config_ip_loadshare_hash(dut1, key='ipv6', val=ecmpv6[1:], config='no')
        res1=ip.verify_ip_loadshare(dut1, ip=ecmpv4[0], ipv6=ecmpv6[0], seed=data.seed_def)
        res2=ip.verify_ip_loadshare(dut1, ip=ecmpv4[1:], ipv6=ecmpv6[1:])
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T4 non-matching ECMP params failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
            return False
        return True
    def f1_t4_2():
        ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4[:2]+[ecmpv4[4]], config='no')
        ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6[:2]+[ecmpv6[4]], config='no')
        res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4[2:4], ipv6=ecmpv6[2:4], seed=data.seed_def)
        res2=ip.verify_ip_loadshare(dut2, ip=ecmpv4[:2]+[ecmpv4[4]], ipv6=ecmpv6[:2]+[ecmpv6[4]])
        if res1 is False or res2 is True:
            fail_msg = "ERROR: Step T4 non-matching ECMP params failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[1]] = tc_res[tc_list[3]] = False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f1_t4_1], [f1_t4_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T4 non-matching ECMP params failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
        gen_tech_supp(filename='f1_t4_')
    
    st.banner("Step T5: Resend ipv4 traffic and verify ECMP.")
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_v4s)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_v4s)
    st.wait(waitvar/2)
    res1=verify_intf_counters(rx=[[dut1, vars.D1T1P1], [dut2, vars.D2D1P1], [dut2, vars.D2D1P2]], ratio = [[1, 0, 1]], clear_save=True)
    res2=verify_intf_counters(rx=[[dut1, vars.D1T1P1]], tx=[[dut1, vars.D1D2P1], [dut1, vars.D1D2P2], [dut2, vars.D2T1P1]], ratio = [[1], [1, 0, 1]], saved_flag=True)
    if (res1 is False and res2 is False) or (res1 is True and res2 is True):
        fail_msg = "ERROR: Step T5 IPv4 ECMP failed on dut1."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = False
        retvar = False
    res1=verify_intf_counters(rx=[[dut2, vars.D2T1P1], [dut1, vars.D1D2P1], [dut1, vars.D1D2P2]], ratio = [[1, 0, 1]], saved_flag=True)
    res2=verify_intf_counters(rx=[[dut2, vars.D2T1P1]], tx=[[dut2, vars.D2D1P1], [dut2, vars.D2D1P2], [dut1, vars.D1T1P1]], ratio = [[1], [1, 0, 1]], saved_flag=True)
    if (res1 is False and res2 is False) or (res1 is True and res2 is True):
        fail_msg = "ERROR: Step T5 IPv4 ECMP failed on dut2."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[1]] = False
        retvar = False
        gen_tech_supp(filename='f1_t5_')
        more_debugs(duts=dut_list)
    
    st.banner("Step T6: Resend ipv6 traffic and verify ECMP.")
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_v6s)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_v6s)
    st.wait(waitvar/2)
    res1=verify_intf_counters(rx=[[dut1, vars.D1T1P1], [dut2, vars.D2D1P1], [dut2, vars.D2D1P2]], ratio = [[1, 0, 1]], clear_save=True)
    res2=verify_intf_counters(rx=[[dut1, vars.D1T1P1]], tx=[[dut1, vars.D1D2P1], [dut1, vars.D1D2P2], [dut2, vars.D2T1P1]], ratio = [[1], [1, 0, 1]], saved_flag=True)
    if (res1 is False and res2 is False) or (res1 is True and res2 is True):
        fail_msg = "ERROR: Step T6 IPv6 ECMP failed on dut1."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[2]] = False
        retvar = False
    res1=verify_intf_counters(rx=[[dut2, vars.D2T1P1], [dut1, vars.D1D2P1], [dut1, vars.D1D2P2]], ratio = [[1, 0, 1]], saved_flag=True)
    res2=verify_intf_counters(rx=[[dut2, vars.D2T1P1]], tx=[[dut2, vars.D2D1P1], [dut2, vars.D2D1P2], [dut1, vars.D1T1P1]], ratio = [[1], [1, 0, 1]], saved_flag=True)
    if (res1 is False and res2 is False) or (res1 is True and res2 is True):
        fail_msg = "ERROR: Step T6 IPv6 ECMP failed on dut2."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[3]] = False
        retvar = False
        gen_tech_supp(filename='f1_t6_')
        more_debugs(duts=dut_list)
    
    st.banner("Step T7: Configure traffic matching ECMP params.")
    def f1_t7_1():
        ip.config_ip_loadshare_hash(dut1, key='ip', val=ecmpv4[0], config='no')
        ip.config_ip_loadshare_hash(dut1, key='ipv6', val=ecmpv6[0], config='no')
        ip.config_ip_loadshare_hash(dut1, key='ip', val=ecmpv4[1:4])
        ip.config_ip_loadshare_hash(dut1, key='ipv6', val=ecmpv6[1:4])
        res1=ip.verify_ip_loadshare(dut1, ip=ecmpv4[0], ipv6=ecmpv6[0])
        res2=ip.verify_ip_loadshare(dut1, ip=ecmpv4[1:4], ipv6=ecmpv6[1:4], seed=data.seed_def)
        if res1 is True or res2 is False:
            fail_msg = "ERROR: Step T7 show failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
            return False
        return True
    def f1_t7_2():
        ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4[2:4], config='no')
        ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6[2:4], config='no')
        ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4[4])
        ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6[4])
        res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4[2:4], ipv6=ecmpv6[2:4])
        res2=ip.verify_ip_loadshare(dut2, ip=ecmpv4[4], ipv6=ecmpv6[4], seed=data.seed_def)
        if res1 is True or res2 is False:
            fail_msg = "ERROR: Step T7 show failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[1]] = tc_res[tc_list[3]] = False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f1_t7_1], [f1_t7_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T7 show cli for matching ECMP params failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
    
    st.banner("Step T8: Resend traffic.")
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T9: Verify ECMP.")
    res1=verify_intf_counters(rx=[[dut1, vars.D1T1P1], [dut2, vars.D2D1P1], [dut2, vars.D2D1P2]],
        tx=[[dut1, vars.D1D2P1], [dut1, vars.D1D2P2], [dut2, vars.D2T1P1]],
        ratio = [[1, 0.5, 0.5], [0.5, 0.5, 1]], clear_save=True)
    res2=verify_intf_counters(rx=[[dut2, vars.D2T1P1], [dut1, vars.D1D2P1], [dut1, vars.D1D2P2]],
        tx=[[dut2, vars.D2D1P1], [dut2, vars.D2D1P2], [dut1, vars.D1T1P1]],
        ratio = [[1, 0.5, 0.5], [0.5, 0.5, 1]], saved_flag=True)
    if res1 is False:
        fail_msg = "ERROR: Step T9 ECMP failed from dut1 to dut2."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
        retvar = False
        gen_tech_supp(filename='f1_t9a_')
        more_debugs(duts=dut_list)
    if res2 is False:
        fail_msg = "ERROR: Step T9 ECMP failed from dut2 to dut1."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[1]] = tc_res[tc_list[3]] = False
        retvar = False
        if res1 is not False:
            gen_tech_supp(filename='f1_t9b_')
            more_debugs(duts=dut_list)
    
    st.banner("Step T10: Shut ECMP link1.")
    intf.interface_shutdown(dut1, vars['D1D2P1'])
    st.wait(waitvar)
    
    st.banner("Step T11: Resend traffic.")
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T12: Verify traffic takes single link.")
    res1=verify_intf_counters(rx=[[dut1, vars.D1T1P1], [dut2, vars.D2D1P1], [dut2, vars.D2D1P2]],
        tx=[[dut1, vars.D1D2P1], [dut1, vars.D1D2P2], [dut2, vars.D2T1P1]],
        ratio = [[1, 0, 1], [0, 1, 1]], clear_save=True)
    res2=verify_intf_counters(rx=[[dut2, vars.D2T1P1], [dut1, vars.D1D2P1], [dut1, vars.D1D2P2]],
        tx=[[dut2, vars.D2D1P1], [dut2, vars.D2D1P2], [dut1, vars.D1T1P1]],
        ratio = [[1, 0, 1], [0, 1, 1]], saved_flag=True)
    if res1 is False or res2 is False:
        fail_msg = "ERROR: Step T12 single link traffic failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
        retvar = False
        gen_tech_supp(filename='f1_t12_')
        more_debugs(duts=dut_list)
    
    st.banner("Step T13: NoShut ECMP link1.")
    intf.interface_noshutdown(dut1, vars['D1D2P1'])
    st.wait(waitvar)
    
    st.banner("Step T14: Resend traffic.")
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T15: Verify ECMP.")
    res1=verify_intf_counters(rx=[[dut1, vars.D1T1P1], [dut2, vars.D2D1P1], [dut2, vars.D2D1P2]],
        tx=[[dut1, vars.D1D2P1], [dut1, vars.D1D2P2], [dut2, vars.D2T1P1]],
        ratio = [[1, 0.5, 0.5], [0.5, 0.5, 1]], clear_save=True)
    res2=verify_intf_counters(rx=[[dut2, vars.D2T1P1], [dut1, vars.D1D2P1], [dut1, vars.D1D2P2]],
        tx=[[dut2, vars.D2D1P1], [dut2, vars.D2D1P2], [dut1, vars.D1T1P1]],
        ratio = [[1, 0.5, 0.5], [0.5, 0.5, 1]], saved_flag=True)
    if res1 is False or res2 is False:
        fail_msg = "ERROR: Step T15 ECMP failed after noshut."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
        retvar = False
        gen_tech_supp(filename='f1_t15_')
        more_debugs(duts=dut_list)
    
    st.banner("Step T16: Config all ECMP params.")
    def f1_t16_1():
        ip.config_ip_loadshare_hash(dut1, key='ip', val=[ecmpv4[0], ecmpv4[4]])
        ip.config_ip_loadshare_hash(dut1, key='ipv6', val=[ecmpv6[0], ecmpv6[4]])
        res1=ip.verify_ip_loadshare(dut1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T16 Default show failed on dut1."
            st.log(fail_msg)
            tc_res[tc_list[0]] = tc_res[tc_list[2]] = False
            return False
        return True
    def f1_t16_2():
        ip.config_ip_loadshare_hash(dut2, key='ip', val=ecmpv4[:-1])
        ip.config_ip_loadshare_hash(dut2, key='ipv6', val=ecmpv6[:-1])
        res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T16 Default show failed on dut2."
            st.log(fail_msg)
            tc_res[tc_list[1]] = tc_res[tc_list[3]] = False
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f1_t16_1], [f1_t16_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T16 show cli for default values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        retvar = False
    
    for tc in tc_list:
        if tc_res[tc]:
            st.report_tc_pass(tc, "tc_passed")
    
    if retvar is False:
        st.report_fail("test_case_failure_message", fail_msgs)
    
    st.report_pass("test_case_passed")

def test_ecmp_clos_func002():
    tc_list = ['FtOpSoRoLBFunc003', 'FtOpSoRoLBFunc007', 'FtOpSoRoLBFunc009']
    st.banner("Testcase: Verify IPv4 and IPv6 ECMP Loadbalance and Hash polarization in CLOS topology.\n TCs:{}.".format(tc_list))
    retvar = True
    fail_msgs = ''
    tc_res={}
    for tc in tc_list: tc_res[tc] = True
    
    st.banner("Step T1: Config required for this testcase.")
    def f2_t1_1():
        ip.config_ip_addr_interface(dut1, vars['D1T1P2'], data.ip_1_2[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut1, vars['D1T1P2'], data.ip6_1_2[0], mask6, ipv6var, addvar)
        ip.create_static_route(dut1, data.ip_1_2[1], data.st_ip_1[1])
        ip.create_static_route(dut1, data.ip6_1_2[1], data.st_ip6_1[1], family='ipv6')
    def f2_t1_2():
        ip.config_ip_addr_interface(dut2, vars['D2T1P2'], data.ip_2_2[0], mask4, ipv4var, addvar)
        ip.config_ip_addr_interface(dut2, vars['D2T1P2'], data.ip6_2_2[0], mask6, ipv6var, addvar)
        ip.create_static_route(dut2, data.ip_2_2[1], data.st_ip_2[1])
        ip.create_static_route(dut2, data.ip6_2_2[1], data.st_ip6_2[1], family='ipv6')
    utils.exec_all(True, [[f2_t1_1], [f2_t1_2]])
    
    st.banner("Step T2: Verify static routes.")
    st.wait(waitvar)
    def f2_t2_1():
        res1=ip.verify_multiple_routes(dut1, ip_address=[data.st_ip_2[1]]*2+[data.st_ip_1[1]]*2, nexthop=[data.ip_12_1[1], data.ip_12_2[1], data.ip_1[1], data.ip_1_2[1]])
        res2=ip.verify_multiple_routes(dut1, ip_address=[data.st_ip6_2[1]]*2+[data.st_ip6_1[1]]*2, nexthop=[data.ip6_12_1[1], data.ip6_12_2[1], data.ip6_1[1], data.ip6_1_2[1]], family='ipv6')
        res = list(set([res1, res2]))
        st.log("f2_t2_1: res1={}, res2={}.".format(res1, res2))
        return res[0] if len(res)==1 else False
    def f2_t2_2():
        res1=ip.verify_multiple_routes(dut2, ip_address=[data.st_ip_1[1]]*2+[data.st_ip_2[1]]*2, nexthop=[data.ip_12_1[0], data.ip_12_2[0], data.ip_2[1], data.ip_2_2[1]])
        res2=ip.verify_multiple_routes(dut2, ip_address=[data.st_ip6_1[1]]*2+[data.st_ip6_2[1]]*2, nexthop=[data.ip6_12_1[0], data.ip6_12_2[0], data.ip6_2[1], data.ip6_2_2[1]], family='ipv6')
        res = list(set([res1, res2]))
        st.log("f2_t2_2: res1={}, res2={}.".format(res1, res2))
        return res[0] if len(res)==1 else False
    [res, exceptions] = utils.exec_all(True, [[f2_t2_1], [f2_t2_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T2 static routes failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]]=False
        retvar = False
        more_debugs(duts=dut_list)
    
    st.banner("Step T3: Verify default show cli.")
    def f2_t3_1():
        res1=ip.verify_ip_loadshare(dut1, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T3 Default show failed on dut1."
            st.log(fail_msg)
            return False
        return True
    def f2_t3_2():
        res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_def)
        if res1 is False:
            fail_msg = "ERROR: Step T3 Default show failed on dut2."
            st.log(fail_msg)
            return False
        return True
    [res, exceptions] = utils.exec_all(True, [[f2_t3_1], [f2_t3_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T3 show cli for default values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]]=False
        retvar = False
    
    st.banner("Step T4: Start all Streams.")
    tg_v4s = [tg_tr12['stream_id'], tg_tr21['stream_id']]
    tg_v6s = [tg_tr12_6['stream_id'], tg_tr21_6['stream_id']]
    tg_strs = tg_v4s + tg_v6s
    f1_f1_1 = lambda x: intf.clear_interface_counters(dut1)
    f1_f1_2 = lambda x: intf.clear_interface_counters(dut2)
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    st.wait(waitvar/2)
    
    st.banner("Step T5: Verify IPv4 and IPv6 ECMP.")
    rx_ports = [[dut1, vars.D1T1P1], [dut1, vars.D1T1P2], [dut2, vars.D2D1P1], [dut2, vars.D2D1P2]]
    tx_ports = [[dut2, vars.D2T1P1], [dut2, vars.D2T1P2], [dut1, vars.D1D2P1], [dut1, vars.D1D2P2]]
    res1=verify_intf_counters(rx=rx_ports, tx=tx_ports, ratio = [[1, 0, 0.5, 0.5], [0.5, 0.5, 0.5, 0.5]], clear_save=True)
    res2=verify_intf_counters(rx=tx_ports, tx=rx_ports, ratio = [[1, 0, 0.5, 0.5], [0.5, 0.5, 0.5, 0.5]], saved_flag=True)
    st.log("Step T5: tx12={}, tx21={}".format(res1, res2))
    if res1 is False or res2 is False:
        fail_msg = "ERROR: Step T5 IPv4 and IPv6 ECMP failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[1]] = False
        retvar = False
        more_debugs(duts=dut_list)
    
    st.banner("Step T6: Configure ACLs link1=in, link2=out.")
    acl.create_acl_table(dut1, name=data.acl_names[0], stage = "INGRESS", type="ip", ports=[vars.D1D2P1])
    acl.create_acl_rule(dut1, type="ip", table_name=data.acl_names[0], rule_name="5", packet_action="deny", ip_protocol="ip")
    acl.create_acl_table(dut1, name=data.acl_names6[0], stage = "INGRESS", type="ipv6", ports=[vars.D1D2P1])
    acl.create_acl_rule(dut1, type="ipv6", table_name=data.acl_names6[0], rule_name="5", packet_action="deny", ip_protocol="ipv6")
    acl.create_acl_table(dut1, name=data.acl_names[1], stage = "EGRESS", type="ip", ports=[vars.D1D2P2])
    acl.create_acl_rule(dut1, type="ip", table_name=data.acl_names[1], rule_name="5", packet_action="deny", ip_protocol="ip")
    acl.create_acl_table(dut1, name=data.acl_names6[1], stage = "EGRESS", type="ipv6", ports=[vars.D1D2P2])
    acl.create_acl_rule(dut1, type="ipv6", table_name=data.acl_names6[1], rule_name="5", packet_action="deny", ip_protocol="ipv6")
    
    st.banner("Step T7: Start all Streams again.")
    #TODO: Using only ipv4 now, as seeing issue with acl_out in ipv6.
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    '''
    res=tg.tg_traffic_control(action='run', handle=tg_strs)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_strs)
    '''
    res=tg.tg_traffic_control(action='run', handle=tg_v4s)
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=tg_v4s)
    st.wait(waitvar/2)
    
    st.banner("Step T8: Verify IPv4 and IPv6 hash polarization.")
    res1a=verify_intf_counters(rx=rx_ports, tx=tx_ports, ratio = [[1, 0, 0.5, 0], [0.5, 0, 0.5, 0]], clear_save=True)
    res1b=verify_intf_counters(rx=rx_ports, tx=tx_ports, ratio = [[1, 0, 0.5, 0], [0, 0.5, 0.5, 0]], saved_flag=True)
    res2a=verify_intf_counters(rx=tx_ports, tx=rx_ports, ratio = [[1, 0, 0.5, 0.5], [0.5, 0, 0.5, 0.5]], saved_flag=True)
    res2b=verify_intf_counters(rx=tx_ports, tx=rx_ports, ratio = [[1, 0, 0.5, 0.5], [0, 0.5, 0.5, 0.5]], saved_flag=True)
    st.log("Step T8: tx21={}, tx22={}, tx11={}, tx12={}".format(res1a, res1b, res2a, res2b))
    if (res1a is False and res1b is False) or (res1a is True and res1b is True) or (res2a is False and res2b is False) or (res2a is True and res2b is True):
        fail_msg = "ERROR: Step T8 IPv4 and IPv6 hash polarization failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[0]] = tc_res[tc_list[1]] = False
        retvar = False
        gen_tech_supp(filename='f1_t8_')
        more_debugs(duts=dut_list)
    else:
        st.log("Step T8: IPv4 and IPv6 hash polarization passed.")
    
    st.banner("Step T9: Change the hash seed value on dut2.")
    ip.config_ip_loadshare_hash(dut2, key='seed', val=data.seed_val[1])
    st.wait(waitvar/2)
    
    st.banner("Step T10: Verify the show cli with new seed value.")
    res1=ip.verify_ip_loadshare(dut2, ip=ecmpv4, ipv6=ecmpv6, seed=data.seed_val[1])
    if res1 is False:
        fail_msg = "ERROR: Step T10 show cli for user seed value failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[2]]=False
        retvar = False
    
    st.banner("Step T11: Start dut1 to dut2 Streams.")
    #TODO: Staring only IPv4 stream due to bug in IPv6 ACL out.
    [res, exceptions] = utils.exec_all(True, [[f1_f1_1, 1], [f1_f1_2, 1]])
    tg.tg_traffic_control(action='clear_stats', port_handle=tg_all)
    '''
    res=tg.tg_traffic_control(action='run', handle=[tg_v4s[0],tg_v6s[0]])
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=[tg_v4s[0],tg_v6s[0]])
    '''
    res=tg.tg_traffic_control(action='run', handle=[tg_v4s[0]])
    st.wait(waitvar)
    res=tg.tg_traffic_control(action='stop', handle=[tg_v4s[0]])
    st.wait(waitvar/2)
    
    st.banner("Step T12: Verify IPv4 and IPv6 hash polarization is not seen.")
    res1=verify_intf_counters(rx=rx_ports, tx=tx_ports, ratio = [[1, 0, 0.5, 0], [0.25, 0.25, 0.5, 0]], clear_save=True)
    if res1 is False:
        fail_msg = "ERROR: Step T12 IPv4 and IPv6 hash polarization is still seen."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[2]] = False
        retvar = False
        gen_tech_supp(filename='f1_t12_')
        more_debugs(duts=dut_list)
    else:
        st.log("Step T12: Passed: IPv4 and IPv6 hash polarization is no longer seen.")
    
    st.banner("Step T20: Cleanup.")
    ip.config_ip_loadshare_hash(dut2, key='seed', val=data.seed_val[1], config='no')
    acl.delete_acl_table(dut1, acl_table_name=data.acl_names, acl_type="ip")
    acl.delete_acl_table(dut1, acl_table_name=data.acl_names6, acl_type="ipv6")
    def f2_t20_1():
        ip.config_ip_addr_interface(dut1, vars['D1T1P2'], data.ip_1_2[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut1, vars['D1T1P2'], data.ip6_1_2[0], mask6, ipv6var, removevar)
        ip.delete_static_route(dut1, data.ip_1_2[1], data.st_ip_1[1])
        ip.delete_static_route(dut1, data.ip6_1_2[1], data.st_ip6_1[1], family='ipv6')
    def f2_t20_2():
        ip.config_ip_addr_interface(dut2, vars['D2T1P2'], data.ip_2_2[0], mask4, ipv4var, removevar)
        ip.config_ip_addr_interface(dut2, vars['D2T1P2'], data.ip6_2_2[0], mask6, ipv6var, removevar)
        ip.delete_static_route(dut2, data.ip_2_2[1], data.st_ip_2[1])
        ip.delete_static_route(dut2, data.ip6_2_2[1], data.st_ip6_2[1], family='ipv6')
    utils.exec_all(True, [[f2_t20_1], [f2_t20_2]])
    
    st.banner("Step T21: Verify.")
    [res, exceptions] = utils.exec_all(True, [[f2_t3_1], [f2_t3_2]])
    if False in set(res):
        fail_msg = "ERROR: Step T21 show cli for default values failed."
        fail_msgs += fail_msg
        st.log(fail_msg)
        tc_res[tc_list[2]]=False
        retvar = False
    
    for tc in tc_list:
        if tc_res[tc]:
            st.report_tc_pass(tc, "tc_passed")
    
    if retvar is False:
        st.report_fail("test_case_failure_message", fail_msgs)
    
    st.report_pass("test_case_passed")
