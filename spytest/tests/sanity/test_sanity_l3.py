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

data.d1t1_ip_addr = "192.168.11.1"
data.d1d2_ip_addr = "192.168.12.1"
data.d2d1_ip_addr = "192.168.12.2"
data.d2t1_ip_addr = "192.168.13.1"
data.t1d1_ip_addr = "192.168.11.2"
data.t1d2_ip_addr = "192.168.13.2"
data.static_ip_list = ["192.168.11.0/24","192.168.13.0/24"]

data.d1t1_ip_addr_v6 = "2011::1"
data.d1d2_ip_addr_v6 = "2012::1"
data.d2d1_ip_addr_v6 = "2012::2"
data.d2t1_ip_addr_v6 = "2013::1"
data.static_ipv6_list = ["2011::0/64","2013::0/64"]
data.mask_v6 = "64"

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

@pytest.fixture(scope="module", autouse=True)
def sanity_l3_module_hooks(request):
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


def pre_test_l3_fwding():
    # override from testbed
    data.my_dut_list = st.get_dut_names()
    if len(data.my_dut_list) < 2:
        st.report_fail("operation_failed")
        return
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]
    if not verifyPortStatus():
        st.report_fail("operation_failed")

    ipfeature.config_ip_addr_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr,data.mask)
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
    ipfeature.create_static_route(dut2, data.d1d2_ip_addr, data.static_ip_list[0])
    # ipv6
    ipfeature.config_ip_addr_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.config_ip_addr_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.config_ip_addr_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.create_static_route(dut1, data.d2d1_ip_addr_v6, data.static_ipv6_list[1], family = 'ipv6')
    ipfeature.create_static_route(dut2, data.d1d2_ip_addr_v6, data.static_ipv6_list[0], family = 'ipv6')

def post_test_l3_fwding():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    dut2 = data.my_dut_list[1]

    ipfeature.delete_static_route(dut1, data.d2d1_ip_addr, data.static_ip_list[1])
    ipfeature.delete_static_route(dut2, data.d1d2_ip_addr, data.static_ip_list[0])
    ipfeature.delete_ip_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr,data.mask)

    ipfeature.delete_ip_interface(dut1, vars.D1T1P1, data.d1t1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.delete_ip_interface(dut2, vars.D2D1P1, data.d2d1_ip_addr_v6,data.mask_v6,family='ipv6')
    ipfeature.delete_ip_interface(dut2, vars.D2T1P1, data.d2t1_ip_addr_v6,data.mask_v6,family='ipv6')
    st.show(dut1, "show vlan config")

@pytest.fixture(scope="module", autouse=True)
def sanity_l3_func_hooks(request):
    # add things at the start every test case
    # use 'request.function.func_name' to compare
    # if any thing specific a particular test case
    global vars
    vars = st.ensure_min_topology("D1D2:1", "D1T1:1", "D2T1:1")
    st.log("POST TEST : Cleanup call are started..")
    ip_obj.clear_ip_configuration(st.get_dut_names(),thread= data.clear_parallel)
    ip_obj.clear_ip_configuration(st.get_dut_names(),'ipv6',thread= data.clear_parallel)
    vlan_obj.clear_vlan_configuration(st.get_dut_names(),thread= data.clear_parallel)
    portchannel_obj.clear_portchannel_configuration(st.get_dut_names(),thread= data.clear_parallel)
    pre_test_l3_fwding()
    yield
    post_test_l3_fwding()
    # add things at the end every test case
    # use 'request.function.func_name' to compare
    # if any thing specific a particular test case

@pytest.mark.base_test_sanity
def test_l3_fwding():
    #pre_test_l3_fwding()
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

    if basic_obj.is_vsonic_device(vars.D1):
        result1 = ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
        result2 = ipfeature.ping(dut1, data.d2t1_ip_addr_v6,'ipv6', timeout=7)
    else:
        result1 = ipfeature.ping(dut1, data.d2t1_ip_addr)
        result2 = ipfeature.ping(dut1, data.d2t1_ip_addr_v6,'ipv6')

    if (abs(int(p1_rcvd)-int(p2_txmt)) > data.counters_threshold) | (p1_rcvd == '0') | (p2_txmt == '0') | (not result1) | (not result2):
        st.report_fail("operation_failed")
    else:
        st.report_pass("operation_successful")

@pytest.mark.base_test_sanity
def test_l2_to_l3_port():
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]
    data.vlan='10'
    data.vlan_int='Vlan'+'10'
    result_flag = 1

    # configure from L3 to L2 port
    vapi.create_vlan(dut1, data.vlan)
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')

    ipfeature.config_ip_addr_interface(dut1, data.vlan_int, data.d1d2_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut1, data.vlan_int, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')

    vapi.add_vlan_member(dut1, data.vlan, vars.D1D2P1, False)
    if not vapi.verify_vlan_config(dut1, str(data.vlan), None, vars.D1D2P1):
        result_flag = 0

    # for now using local ping function till qa branch is merged
    if basic_obj.is_vsonic_device(vars.D1):
        result1 = ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
        result2 = ipfeature.ping(dut1, data.d2t1_ip_addr_v6,'ipv6', timeout=7)
    else:
        result1 = ipfeature.ping(dut1, data.d2t1_ip_addr)
        result2 = ipfeature.ping(dut1, data.d2t1_ip_addr_v6,'ipv6')

    if not result1 or not result2:
        result_flag = 0

    # Revert back from L2 to L3 port
    vapi.delete_vlan_member(dut1,data.vlan,[vars.D1D2P1])
    ipfeature.delete_ip_interface(dut1, data.vlan_int, data.d1d2_ip_addr,data.mask)
    ipfeature.delete_ip_interface(dut1, data.vlan_int, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')
    vapi.delete_vlan(dut1, [data.vlan])

    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr,data.mask)
    ipfeature.config_ip_addr_interface(dut1, vars.D1D2P1, data.d1d2_ip_addr_v6,data.mask_v6,family='ipv6')
    if basic_obj.is_vsonic_device(vars.D1):
        st.wait(15)
        ping_result = ipfeature.ping(dut1, data.d2t1_ip_addr, timeout=7)
    else:
        ping_result = ipfeature.ping(dut1, data.d2t1_ip_addr)
    if ping_result and result_flag:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")

