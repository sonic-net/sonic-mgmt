import pytest
import apis.routing.ip as ipfeature
import apis.routing.arp as arpfeature
from spytest.tgen.tg import tgen_obj_dict
from spytest.dicts import SpyTestDict
from spytest import st
import apis.switching.vlan as vapi
from spytest.dicts import SpyTestDict
import apis.system.port as papi
import apis.system.interface as ifapi
from apis.common.asic import bcm_show

data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None
data.mask = "16"
data.counters_threshold = 10
data.tgen_stats_threshold = 10
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 30
data.max_host_1 = 8000
data.max_host_2 = 10000

data.d1t1_ip_addr = "12.0.0.1"
data.d1t2_ip_addr = "5.0.0.1"
data.t1d1_ip_addr = "12.0.0.10"
data.t1d2_ip_addr = "5.0.0.10"
data.ip_list_1 = ['12.0.0.1', '12.0.0.10']
data.ip_list_2 = ['11.0.0.10', '11.0.0.1']

def get_handles():
    vars = st.get_testbed_vars()

    st.log(vars)
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg2.get_port_handle(vars.T1D1P2)

    return (tg1, tg2, tg_ph_1, tg_ph_2)

@pytest.fixture(scope="module", autouse=True)
def l3fwd_module_hooks(request):
    yield

def pre_test_l3_fwding():
    # override from testbed
    vars = st.get_testbed_vars()
    data.my_dut_list = st.get_dut_names()

    dut1 = data.my_dut_list[0]

    st.log(vars)

    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')
    vapi.clear_vlan_configuration(st.get_dut_names())

    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.d1t1_ip_addr, data.mask)

    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.d1t2_ip_addr, data.mask)

def post_test_l3_fwding():
    vars = st.get_testbed_vars()
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]

    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P1, data.d1t1_ip_addr, data.mask)

def parse_output(output):
    lines = output.splitlines()
    line  = list(lines[0])
    cnt = 2
    total = ''
    while (line[-cnt] != ' '):
      total = line[-cnt] + total
      cnt += 1
    st.log(total)
    return int(total)

def parse_route_output(output):
    lines = output.splitlines()
    line  = lines[0]

    st.log(line)
    return int(line)

def flap_interface(intf_name):
    vars = st.get_testbed_vars()
    ifapi.interface_operation(vars.D1, intf_name, operation="shutdown")

    st.wait(5)

    ifapi.interface_operation(vars.D1, intf_name, operation="startup")

@pytest.fixture(scope="module", autouse=True)
def l3fwd_func_hooks(request):
    global vars
    vars = st.get_testbed_vars()
    st.log("PRE TSET : Cleanup call are started.")
    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')
    vapi.clear_vlan_configuration(st.get_dut_names())
    yield
    st.log("POST TSET : Cleanup call are started.")
    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')
    vapi.clear_vlan_configuration(st.get_dut_names())

def create_l3_host(tg, tg_ph, host_count, duration):
    tg.tg_traffic_control(action='reset',port_handle=tg_ph)

    tr1=tg.tg_traffic_config(mac_dst='ff:ff:ff:ff:ff:ff',rate_pps='5000',mode='create',
        port_handle=tg_ph, transmit_mode='continuous', l3_protocol='arp',
        arp_src_hw_addr='00.00.00.00.00.01', arp_src_hw_mode='increment', arp_src_hw_count=host_count,
        arp_dst_hw_mode='fixed', arp_operation='arpRequest',
        ip_src_addr=data.ip_list_1[1], ip_dst_addr=data.ip_list_1[0], length_mode='fixed', enable_stream_only_gen='0',
        ip_src_step='0.0.0.1', ip_src_count=host_count, ip_src_mode='increment')

    if (duration):
        tg.tg_traffic_control(action='run', handle=tr1['stream_id'], duration=duration)
    else:
        tg.tg_traffic_control(action='run', handle=tr1['stream_id'])

    return tr1


@pytest.mark.l3_scale_ut
def test_l3_host_scaling_tc5_1():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    ifapi.interface_status_show(dut1)

    tr1 = create_l3_host(tg1, tg_ph_1, 8000, 5)
    st.wait(15)

    # Verified ARP and counters at the DUT.
    total_in_sw = arpfeature.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(total_in_sw))
    #We expect all 8k host entries should be programmed in hw within 32secs
    st.wait(20)
    output = bcm_show(dut1, 'bcmcmd "l3 l3table show" | wc -l')
    total_in_hw = parse_route_output(output)

    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    post_test_l3_fwding()
    if (total_in_sw >= data.max_host_1 and total_in_hw >= data.max_host_1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_host_scaling_tc5_2():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1)

    cnt = 0
    pass_flag = True
    host_count = 32000
    curr_count = 8000
    wait_time = 15
    duration = 8

    #Send burst of 8k upto 32k max
    tr1 = create_l3_host(tg1, tg_ph_1, host_count, duration)
    while (cnt <= 3 and pass_flag):
        st.wait(wait_time)

        # Verified ARP and counters at the DUT.
        total = arpfeature.get_arp_count(dut1)
        st.log("Total ARP entries: {}".format(total))

        output = output = bcm_show(dut1, 'bcmcmd "l3 l3table show" | wc -l')
        st.log(output)
        if (total >= curr_count):
            curr_count += 8000
        else:
            pass_flag = False
        cnt += 1

    #Make sure all the entries programmed in the hw
    st.wait(90)
    output = output = bcm_show(dut1, 'bcmcmd "l3 l3table show" | wc -l')
    st.log(output)

    post_test_l3_fwding()
    if (pass_flag):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def check_intf_traffic_counters(dut1):
    papi.clear_interface_counters(dut1)
    st.wait(10)
    vars = st.get_testbed_vars()
    DUT_rx_value = papi.get_interface_counters(dut1, vars.D1T1P1, "rx_bps")
    DUT_tx_value = papi.get_interface_counters(dut1, vars.D1T1P2, "tx_bps")

    for i in DUT_rx_value:
        p1_rcvd = i['rx_bps']
        p1_rcvd = p1_rcvd.replace(" MB/s","")
        p1_rcvd = p1_rcvd.replace(" B/s","")

    for i in DUT_tx_value:
        p2_txmt = i['tx_bps']
        p2_txmt = p2_txmt.replace(" MB/s","")
        p2_txmt = p2_txmt.replace(" B/s","")

    st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))

    if (p1_rcvd and p2_txmt):
        return True
    else:
        return False

@pytest.mark.l3_scale_ut
def test_l3_host_scaling_tc5_3():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    ifapi.interface_status_show(dut1)

    tr1 = create_l3_host(tg1, tg_ph_1, data.max_host_1, 20)
    st.wait(15)

    # Verified ARP and counters at the DUT.
    total = arpfeature.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(total))
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    res=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
    gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:11:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res))
    handle1 = res['handle']
    #tg1.tg_test_control(action='sync')

    res=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,
    gateway=data.d1t2_ip_addr, src_mac_addr='00:0a:01:00:12:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res))
    handle2 = res['handle']
    #tg2.tg_test_control(action='sync')

    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
    l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle1, emulation_dst_handle=handle2)
    tr2 = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='continuous', length_mode='fixed',
    l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle2, emulation_dst_handle=handle1)

    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')

    tg1.tg_traffic_control(action='clear_stats', handle=tr1['stream_id'])
    tg2.tg_traffic_control(action='clear_stats', handle=tr2['stream_id'])
    papi.clear_interface_counters(dut1)
    tg1.tg_traffic_control(action='run', handle=tr1['stream_id'], duration=2)
    tg2.tg_traffic_control(action='run', handle=tr2['stream_id'], duration=2)
    st.wait(data.traffic_run_time)
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg2.tg_traffic_control(action='stop', handle=tr2['stream_id'])

    tg1.tg_packet_control(port_handle=tg_ph_1, action='stop')
    tg2.tg_packet_control(port_handle=tg_ph_2, action='stop')

    papi.clear_interface_counters(dut1)
    res=tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.wait(20)
    retval = check_intf_traffic_counters(dut1)

    post_test_l3_fwding()
    if (total >= data.max_host_1 and retval):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_host_scaling_tc5_4():
    pre_test_l3_fwding()
    vars = st.get_testbed_vars()
    data.my_dut_list = st.get_dut_names()

    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    ifapi.interface_status_show(dut1)

    # L3 traffic streams
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tr1 = create_l3_host(tg1, tg_ph_1, data.max_host_1, 20)
    st.wait(15)

    # Verified ARP and counters at the DUT.
    total = arpfeature.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(total))
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    res=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.t1d1_ip_addr,
    gateway=data.d1t1_ip_addr, src_mac_addr='00:0a:01:00:11:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res))
    handle1 = res['handle']
    #tg1.tg_test_control(action='sync')

    res=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.t1d2_ip_addr,
    gateway=data.d1t2_ip_addr, src_mac_addr='00:0a:01:00:12:01', arp_send_req='1')
    st.log("INTFCONF: "+str(res))
    handle2 = res['handle']
    #tg2.tg_test_control(action='sync')

    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
    l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle1, emulation_dst_handle=handle2)
    tr2 = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='continuous', length_mode='fixed',
    l3_length=data.tgen_l3_len, rate_pps=data.tgen_rate_pps, emulation_src_handle=handle2, emulation_dst_handle=handle1)

    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')

    tg1.tg_traffic_control(action='clear_stats', handle=tr1['stream_id'])
    tg2.tg_traffic_control(action='clear_stats', handle=tr2['stream_id'])
    papi.clear_interface_counters(dut1)
    tg1.tg_traffic_control(action='run', handle=tr1['stream_id'], duration=2)
    tg2.tg_traffic_control(action='run', handle=tr2['stream_id'], duration=2)
    st.wait(data.traffic_run_time)
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg2.tg_traffic_control(action='stop', handle=tr2['stream_id'])

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

    flap_interface(vars.D1T1P1)
    flap_interface(vars.D1T1P2)

    #Getting interfaces counter values on DUT
    DUT_rx_value = ifapi.get_interface_counters(dut1, vars.D1T1P1, "rx_ok")
    DUT_tx_value = ifapi.get_interface_counters(dut1, vars.D1T1P2, "tx_ok")

    for i in DUT_rx_value:
        p1_rcvd = i['rx_ok']
        p1_rcvd = p1_rcvd.replace(",","")

    for i in DUT_tx_value:
        p2_txmt = i['tx_ok']
        p2_txmt = p2_txmt.replace(",","")

    st.log("rx_ok counter value on DUT Ingress port: {} and tx_ok xounter value on DUT Egress port : {}".format(p1_rcvd, p2_txmt))

    post_test_l3_fwding()
    if (total >= data.max_host_1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_host_scaling_tc5_5():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    ifapi.interface_status_show(dut1)


    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tr1 = create_l3_host(tg1, tg_ph_1, 8000, 120)

    st.wait(15)
    # Verified ARP and counters at the DUT.
    total = arpfeature.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(total))
    
    if (total):
      arpfeature.clear_arp_table(vars.D1)

    st.wait(30)

    total = arpfeature.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(total))

    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    post_test_l3_fwding()
    if (total >= data.max_host_1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

