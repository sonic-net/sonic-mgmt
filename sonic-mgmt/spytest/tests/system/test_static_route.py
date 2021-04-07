import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ipfeature
import apis.switching.vlan as vapi
import apis.system.port as papi
import apis.system.interface as intapi
import apis.routing.ip as ip_obj
import apis.switching.portchannel as portchannel_obj
import apis.switching.vlan as vlan_obj
import apis.system.basic as basic_obj
import apis.routing.bgp as bgpapi

data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 20
data.clear_parallel = True
data.port_channel = "PortChannel100"
data.loopback_d1 = "Loopback11"
data.loopback_d2 = "Loopback12"
data.dut1_as = "65100"
data.dut2_as = "65200"

data.d1t1_ip_addr = "192.168.11.1"
data.d1d2_ip_addr = "192.168.12.1"
data.d2d1_ip_addr = "192.168.12.2"
data.d2t1_ip_addr = "192.168.13.1"
data.t1d1_ip_addr = "192.168.11.2"
data.t1d2_ip_addr = "192.168.13.2"
data.loopback_d1_addr = "192.168.14.1"
data.loopback_d2_addr = "192.168.15.1"
data.static_ip_list = ["192.168.11.0/24","192.168.13.0/24", "192.168.14.0/24","192.168.15.0/24"]

data.d1t1_ip_addr_v6 = "2011::1"
data.d1d2_ip_addr_v6 = "2012::1"
data.d2d1_ip_addr_v6 = "2012::2"
data.d2t1_ip_addr_v6 = "2013::1"
data.loopback_d1_addr_v6 = "2014::1"
data.loopback_d2_addr_v6 = "2015::1"
data.static_ipv6_list = ["2011::0/64","2013::0/64","2014::0/64","2015::0/64"]
data.mask_v6 = "64"

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

@pytest.fixture(scope="module", autouse=True)
def platform_tcs_module_hooks(request):
    yield

def verifyPortStatus():
    data.my_dut_list = st.get_dut_names()
    intapi.interface_noshutdown(vars.D1, [vars.D1T1P1,vars.D1D2P1])
    intapi.interface_noshutdown(vars.D2, [vars.D2T1P1,vars.D2D1P1])
    st.wait(5)
    for dut,portList in zip(data.my_dut_list,[[vars.D1T1P1,vars.D1D2P1] ,[vars.D2T1P1,vars.D2D1P1]]):
        for port in portList:
            if not intapi.verify_interface_status(dut,port,'oper', 'up'):
                return False
    return True

def config_static_route():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    # if not verifyPortStatus():
    #     st.report_fail("operation_failed")
    #Config ipv4 address of the interface 
    ipfeature.config_ip_addr_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr,data.mask)
    #Config static route for ipv4 interface
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
    ipfeature.create_static_route(dut2, data.d1d2_ip_addr, data.static_ip_list[0])
    #Config ipv6 address of the interface 
    ipfeature.config_ip_addr_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.config_ip_addr_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr_v6,data.mask_v6,family='ipv6')
    #Config static route for ipv6 interface
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family = 'ipv6')
    ipfeature.create_static_route(dut2, data.d1d2_ip_addr_v6, data.static_ipv6_list[0], family = 'ipv6')
    st.log("checking show ip routes")
    st.show(dut1, "show ip route")
    #Verify ping to static route
    st.log("Verifying ping after creatic static route ")
    verify_ping()
    
def verify_ping():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]

    #Verifying ping of ipv4 address 
    ipv4_result = ipfeature.ping(dut2, data.d1t1_ip_addr, timeout=7)
    if ipv4_result:
        st.log("Ping ipv4 succeeded")
        st.report_pass("test_case_passed")
    else:
        st.log("Ping ipv4 failed")
        st.report_fail("test_case_failed")
    #Verifying ping of ipv6 address
    ipv6_result = ipfeature.ping(dut2, data.d1t1_ip_addr_v6, family="ipv6", timeout=7)
    if ipv6_result:
        st.log("Ping ipv6 succeeded")
        st.report_pass("test_case_passed")
    else:
        st.log("Ping ipv6 failed")
        st.report_fail("test_case_failed")


def unconfig_static_route():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    
    #Removing the static route 
    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
    ipfeature.delete_static_route(dut2, data.d1d2_ip_addr, data.static_ip_list[0])
    ipfeature.delete_ip_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr,data.mask)

    #Removing ip configuration
    ipfeature.delete_ip_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.delete_ip_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr_v6,data.mask_v6,family='ipv6')

    st.log("Verifying ping after cleaning up")

    ipv4_result = ipfeature.ping(dut2, data.d1t1_ip_addr, timeout=7)
    if ipv4_result:
        st.log("Ping ipv4 succeeded after clean up")
        st.report_fail("test_case_failed")
    else:
        st.log("Ping ipv4 failed after clean up")
        st.report_pass("test_case_passed")

    ipv6_result = ipfeature.ping(dut2, data.d1t1_ip_addr_v6, family="ipv6", timeout=7)
    if ipv6_result:
        st.log("Ping ipv6 succeeded after clean up")
        st.report_fail("test_case_failed")
    else:
        st.log("Ping ipv6 failed after clean up ")
        st.report_pass("test_case_passed")
    

def traffic_allow():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]

    dut1 = vars.D1
    dut2 = vars.D2
    st.show(dut1, "show ip interfaces")
    st.show(dut1, "show ipv6 interfaces")
    st.show(dut1, "show ip route")

    # L3 traffic streams
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()

    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    res=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
    gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:11:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res))
    handle1 = res['handle']

    res=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,
    gateway=data.d2t1_ip_addr, src_mac_addr='00:0a:01:00:12:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res))
    handle2 = res['handle']

    tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
    l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle1, emulation_dst_handle=handle2)
    tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='continuous', length_mode='fixed',
    l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle2, emulation_dst_handle=handle1)

    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')

    tg1.tg_traffic_control(action='clear_stats', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats', port_handle=tg_ph_2)
    papi.clear_interface_counters(dut1)
    tg1.tg_traffic_control(action='run', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='run', port_handle=tg_ph_2)
    st.wait(data.traffic_run_time)

    st.log("Verifying ping after traffic enabled")
    verify_ping()

    tg1.tg_traffic_control(action='stop', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='stop', port_handle=tg_ph_2)

    st.wait(5)
    tg1.tg_packet_control(port_handle=tg_ph_1, action='stop')
    tg2.tg_packet_control(port_handle=tg_ph_2, action='stop')

    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_ph_1,mode='aggregate')
    total_tg1_tx = stats_tg1[tg_ph_1]['aggregate']['tx']['total_pkts']
    total_tg1_rx = stats_tg1[tg_ph_1]['aggregate']['rx']['total_pkts']

    stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_ph_2,mode='aggregate')
    total_tg2_tx = stats_tg2[tg_ph_2]['aggregate']['tx']['total_pkts']
    total_tg2_rx = stats_tg2[tg_ph_2]['aggregate']['rx']['total_pkts']
    st.log("Tgen Sent Packets on D1T1P1: {} and Received Packets on D2T1P1: {}".format(total_tg1_tx, total_tg2_rx))
    st.log("Tgen Sent Packets on D2T1P1: {} and Received Packets on D1T1P1: {}".format(total_tg2_tx, total_tg1_rx))

    if (int(total_tg1_tx) == 0) | (int(total_tg2_tx) == 0):
        st.log("Traffic Validation Failed")
        st.report_fail("operation_failed")
    elif (abs(int(total_tg1_tx)-int(total_tg2_rx)) > data.tgen_stats_threshold):
        st.log("Traffic Validation Failed")
        st.report_fail("operation_failed")
    elif (abs(int(total_tg2_tx)-int(total_tg1_rx)) > data.tgen_stats_threshold):
        st.log("Traffic Validation Failed")
        st.report_fail("operation_failed")
    #Getting interfaces counter values on DUT
    DUT_rx_value = papi.get_interface_counters(dut1, vars.D1T1P1, "rx_ok")
    DUT_tx_value = papi.get_interface_counters(dut1, vars.D1D2P1, "tx_ok")

    for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

    for i in DUT_tx_value:
        p2_txmt = i['tx_ok']
        p2_txmt = p2_txmt.replace(",","")

    st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))
    st.log("Verify ping after traffic is disabled")
    verify_ping()
    


@pytest.fixture(scope="module", autouse=True)
def platform_tcs_func_hooks(request):
    # add things at the start every test case
    # use 'request.function.func_name' to compare
    # if any thing specific a particular test case
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D1T1:1", "D2T1:1")
    # add things at the end every test case
    # use 'request.function.func_name' to compare
    # if any thing specific a particular test case


def test_platform_static_route_config():
    #Verifying the port are up
    verifyPortStatus()
    #Verifying static route 
    config_static_route()
    #Verifying traffic 
    traffic_allow()
    #Unconfiguring the static route 
    unconfig_static_route()
    


