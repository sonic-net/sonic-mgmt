import pytest
import datetime

import apis.routing.ip as ipfeature
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen.tgen_utils import tg_bgp_config
from spytest.dicts import SpyTestDict
from spytest import st
import apis.switching.vlan as vapi
from spytest.dicts import SpyTestDict
from spytest.utils import filter_and_select
import apis.routing.bgp as bgpfeature
import apis.routing.arp as arpapi
from apis.system.interface import interface_status_show, interface_operation
from apis.common.asic import bcm_show

data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None
data.mask = "16"
data.v6_mask = "120"
data.counters_threshold = 10
data.tgen_stats_threshold = 10
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 30
data.max_host_1 = 8000
data.max_host_2 = 10000

data.d1t1_ip_addr = "12.0.0.1"
data.d1t2_ip_addr = "5.0.0.10"
data.t1d1_ip_addr = "12.0.0.10"
data.t1d2_ip_addr = "5.0.0.1"
data.ip_list_1 = ['12.0.0.1', '12.0.0.10']
data.d1t1_ipv6_addr = "2000::2"
data.d1t2_ipv6_addr = "2001::2"
data.t1d1_ipv6_addr = "2000::1"
data.t1d2_ipv6_addr = "2001::1"
data.ipv6_list_1 = ['2000::1', '2000::2']
data.oct1 = 10
data.oct2 = 0
data.oct3 = 1
data.oct4 = 1
data.intf_ip_addr = "20.20.20.1"
data.my_ip_addr = "10.10.10.1"
data.ip_prefixlen = "24"
data.as_num = 100
data.remote_as_num = 200
data.neigh_ip_addr = "10.10.10.2"
data.my_ipv6_addr = "2000::1"
data.neigh_ipv6_addr = "2000::2"
data.ipv6_prefixlen = "64"
data.routemap = "preferGlobal"
data.intf_ipv6_addr = "2200::1"
data.result = [0, 0, 0, 0, 0]
data.l3_intf = False
data.result_14_3 = False
data.tc6_xoct1 = 10
data.tc6_xoct2 = 0
data.tc6_xoct3 = 1
data.tc6_xoct4 = 1
data.intf_count = "160"
data.tc6_xt1d1_ip_addr = "10.0.220.10"
data.tc6_xd1t1_ip_addr = "10.0.220.1`"
data.tc6_xbase_vlan = 61
data.tc6_xresult = [False, False, False, False, False, False]
data.max_vlan_count = 160

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

    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P2, data.d1t2_ip_addr, data.mask)

def pre_test_l3_fwding_v6():
    # override from testbed
    vars = st.get_testbed_vars()
    data.my_dut_list = st.get_dut_names()
    st.log(vars)
    dut1 = data.my_dut_list[0]

    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')
    vapi.clear_vlan_configuration(st.get_dut_names())

    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.d1t1_ipv6_addr, data.v6_mask, family="ipv6")

    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.d1t2_ipv6_addr, data.v6_mask, family="ipv6")

def post_test_l3_fwding_v6():
    vars = st.get_testbed_vars()
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]

    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P1, data.d1t1_ipv6_addr, data.v6_mask, family="ipv6")

    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P2, data.d1t2_ipv6_addr, data.v6_mask, family="ipv6")

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

@pytest.fixture(scope="module", autouse=True)
def l3fwd_func_hooks(request):
    #global vars
    #vars = st.get_testbed_vars()
    #st.log("PRE TSET : Cleanup call are started.")
    #ipfeature.clear_ip_configuration(st.get_dut_names())
    #ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')
    #vapi.clear_vlan_configuration(st.get_dut_names())
    yield
    #st.log("POST TSET : Cleanup call are started.")
    #ipfeature.clear_ip_configuration(st.get_dut_names())
    #ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')
    #vapi.clear_vlan_configuration(st.get_dut_names())

def create_l3_host(tg, tg_ph, host_count):
    tg.tg_traffic_control(action='reset',port_handle=tg_ph)

    tr1=tg.tg_traffic_config(mac_dst='ff:ff:ff:ff:ff:ff',rate_pps='1000',mode='create',
        port_handle=tg_ph, transmit_mode='continuous', l3_protocol='arp',
        arp_src_hw_addr='00.00.00.00.00.01', arp_src_hw_mode='increment', arp_src_hw_count=host_count,
        arp_dst_hw_mode='fixed', arp_operation='arpRequest',
        ip_src_addr=data.ip_list_1[1], ip_dst_addr=data.ip_list_1[0], length_mode='fixed', enable_stream_only_gen='0',
        ip_src_step='0.0.0.1', ip_src_count=host_count, ip_src_mode='increment')

    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])

    return tr1

def create_l3_host_v6(tg, tg_ph, host_count):
    tg.tg_traffic_control(action='reset',port_handle=tg_ph)

    tr1 = tg.tg_traffic_config(mac_src = '00.00.00.00.00.01',mac_dst='00.00.00.00.00.02',rate_pps='1000',mode='create',\
          port_handle=tg_ph, transmit_mode='continuous',\
          frame_size='128', l3_protocol='ipv6', ipv6_src_addr=data.ipv6_list_1[0],
          ipv6_dst_addr=data.ipv6_list_1[1], l4_protocol='udp', udp_src_port='32222', udp_dst_port='33333',\
          length_mode='fixed', enable_stream_only_gen='0',
          ipv6_src_step='::1', ipv6_src_count=host_count, ipv6_src_mode='increment')

    tg.tg_traffic_control(action='run', handle=tr1['stream_id'])

    return tr1

def measure_arp_learn_time(dut1, default_arp, max_arp, cmd, hw):
    sleep_time = 10
    st.log("Number of ARP's in the beginning %d" %(default_arp))
    curr_arp = default_arp
    arp_in_this_poll = default_arp
    prev_poll_count = 0
    record_start_time = 0
    #initialize for error handling
    start_time = datetime.datetime.now()

    while(curr_arp < max_arp):
        now = datetime.datetime.now()
        output = bcm_show(dut1, cmd)
        prev_poll_count = arp_in_this_poll
        if (hw):
          arp_in_this_poll = parse_route_output(output) - curr_arp
        else:
          arp_in_this_poll = parse_output(output) - curr_arp

        #no more entries learnt, break!
        if (prev_poll_count == arp_in_this_poll):
          break

        if arp_in_this_poll > 0 and record_start_time == 0:
            start_time = now
            st.log("Time when the first arp was installed %s " %(str(start_time)))
            sleep_time = 10
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
    #st.log end_time
    diff = (end_time - start_time).total_seconds()
    st.log("total time is %d" %(int(diff)))

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
        output = arpapi.get_ndp_count(dut1)
        st.log("Total NDP entries are: {}".format(output))
        prev_poll_count = nd_in_this_poll
        nd_in_this_poll = output - curr_nd

        #no more entries learnt, break!
        if (prev_poll_count == nd_in_this_poll):
          break

        nd_in_this_poll = output - curr_nd
        if nd_in_this_poll > 0 and record_start_time == 0:
            start_time = now
            st.log("Time when the first arp was installed %s " %(str(start_time)))
            sleep_time=10
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

def measure_route_learn_time(dut1, default_route, max_route, cmd):
    sleep_time = 10
    st.log("Number of route's in the beginning %d" %(default_route))
    curr_route = default_route
    route_in_this_poll = default_route
    prev_poll_count = 0
    record_start_time = 0
    #initialize for error handling
    start_time = datetime.datetime.now()

    while(curr_route < max_route):
        now = datetime.datetime.now()
        output = bcm_show(dut1, cmd)
        prev_poll_count = route_in_this_poll
        route_in_this_poll = parse_route_output(output) - curr_route

        #no more entries learnt, break!
        if (prev_poll_count == route_in_this_poll):
          break

        if route_in_this_poll > 0 and record_start_time == 0:
            start_time = now
            st.log("Time when the first route was installed %s " %(str(start_time)))
            sleep_time = 10
            record_start_time =1
        #st.log start_time
        curr_route = curr_route + route_in_this_poll
        after = datetime.datetime.now()
        st.log(" [%s]: increment %d curr_route %d " %(str(after), route_in_this_poll, curr_route))
        if curr_route == max_route:
            break
        st.wait(sleep_time)

    end_time = datetime.datetime.now()
    st.log("Time when all the route's were installed %s" %(str(end_time)))
    #st.log end_time
    diff = (end_time - start_time).total_seconds()
    st.log("total time is %d" %(int(diff)))

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_12_1():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    port1 = vars.D1T1P1

    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    interface_status_show(dut1)

    tr1 = create_l3_host(tg1, tg_ph_1, 8000)

    # Verified ARP and counters at the DUT.
    cmd = "show arp | grep Total"
    default_arp = arpapi.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(default_arp))
    measure_arp_learn_time(dut1, default_arp, 8000, cmd, False)

    #shut the link and make sure all the entries deleted from the hw
    interface_operation(dut1, port1, operation="shutdown")
    st.wait(15)
    cmd = 'bcmcmd "l3 l3table show" | wc -l'
    output = bcm_show(dut1, cmd)
    st.log(output)
    curr_arp = parse_route_output(output)

    if (curr_arp != default_arp):
        st.log("cleaning up host entries from HW failed"+str(curr_arp)+str(default_arp))

    interface_operation(dut1, port1, operation="startup")

    #Now measure the hardware performance
    cmd = 'bcmcmd "l3 l3table show" | wc -l'
    output = bcm_show(dut1, cmd)
    st.log(output)
    default_arp = parse_route_output(output)
    measure_arp_learn_time(dut1, default_arp, 8000, cmd, True)

    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    post_test_l3_fwding()
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_12_2():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    interface_status_show(dut1)

    tr1 = create_l3_host(tg1, tg_ph_1, 16000)

    # Verified ARP and counters at the DUT.
    cmd = "show arp | grep Total"
    default_arp = arpapi.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(default_arp))
    measure_arp_learn_time(dut1, default_arp, 16000, cmd, False)
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'], max_wait_timer=10)
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    post_test_l3_fwding()
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_12_3():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    interface_status_show(dut1)

    tr1 = create_l3_host(tg1, tg_ph_1, 32000)

    # Verified ARP and counters at the DUT.
    cmd = "show arp | grep Total"
    default_arp = arpapi.get_arp_count(dut1)
    st.log("Total ARP entries: {}".format(default_arp))
    measure_arp_learn_time(dut1, default_arp, 32000, cmd, False)
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'], max_wait_timer=10)
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    post_test_l3_fwding()
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_12_4():
    pre_test_l3_fwding_v6()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    interface_status_show(dut1)

    tr1 = create_l3_host_v6(tg1, tg_ph_1, 8000)

    # Verified ARP and counters at the DUT.
    default_nd = arpapi.get_ndp_count(dut1)
    st.log("Total NDP entries are: {}".format(default_nd))
    measure_nd_learn_time(dut1, default_nd, 8000)
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'], max_wait_timer=10)
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    post_test_l3_fwding_v6()
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_12_5():
    pre_test_l3_fwding_v6()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    interface_status_show(dut1)

    tr1 = create_l3_host_v6(tg1, tg_ph_1, 16000)

    # Verified ARP and counters at the DUT.
    default_nd = arpapi.get_ndp_count(dut1)
    st.log("Total NDP entries are: {}".format(default_nd))
    measure_nd_learn_time(dut1, default_nd, 16000)
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'], max_wait_timer=10)
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    post_test_l3_fwding_v6()
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_14_1():
    pre_test_l3_fwding()

    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.show_ip_route(dut1)
    interface_status_show(dut1)

    tr1 = create_l3_host(tg1, tg_ph_1, 10000)

    st.wait(15)

    # Verified ARP and counters at the DUT.
    output = bcm_show(dut1, "time show arp")
    st.log(output)
    tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'], max_wait_timer=10)
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)

    post_test_l3_fwding()
    st.report_pass("test_case_passed")

def get_next_ip():
    data.oct3 += 1
    if (data.oct3 == 255):
        data.oct2 += 1
        data.oct3 = 0

    return str(data.oct1) +'.'+str(data.oct2)+'.'+str(data.oct3)+'.'+str(data.oct4)

def clear_arp_entries(dut):
    """
    This proc is to clear arp entries of the dut.
    :param dut: DUT Number
    :return:
    """
    arpapi.clear_arp_table(dut)

def verify_ip_from_vlan_interface(dut, port):
    """

    :param port:
    :type port:
    :param ipaddr:
    :type ipaddr:
    :param dut:
    :type dut:
    :return:
    :rtype:
    """
    output = vapi.show_vlan_brief(dut, cli_type='click')
    match = {"ports": port}
    entries = filter_and_select(output, ["ipadd"], match)
    return entries

def trigger_link_flap(dut, port):
    """

    :param dut:
    :type dut:
    :param port:
    :type port:
    :return:
    :rtype:
    """
    interface_operation(dut, port, operation="shutdown")
    st.wait(5)
    interface_operation(dut, port, operation="startup")
    st.wait(5)

def get_arp_entries(dut, ipaddr):
    """
    :param dut:
    :type dut:
    :return:
    """
    return arpapi.show_arp(dut, ipaddress=ipaddr)

def verify_arp_entry( dut, port,ipaddr):
    """

    :param port:
    :type port:
    :param ipaddr:
    :type ipaddr:
    :param dut:
    :type dut:
    :return:bool

    """
    result = False
    output = get_arp_entries(dut, ipaddr)
    entries = filter_and_select(output, None, {"address": ipaddr})
    if not filter_and_select(entries, None, {"address": ipaddr, "vlan": port}):
        result = False
    else:
        result = True

    #entries = filter_and_select(output, ['Address'], {'Vlan': port})
    #for addr in entries:
    #    if addr['Address'] == ipaddr:
     #       result = True
      #      break
    return result


def get_handles_1():
    vars = st.get_testbed_vars()

    st.log(vars)
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D2P3)
    tg_ph_2 = tg2.get_port_handle(vars.T1D2P4)

    return (tg1, tg_ph_1, tg2, tg_ph_2)


def verify_traffic_results(dut):
    vars = st.get_testbed_vars()
    count = 0
    tc_fail_flag = 0
    member3 = vars.D2T1P3
    member4 = vars.D2T1P4
    res1 = True
    dut1 = dut
    v_range_t = str(data.tc6_xbase_vlan) + " " + str(data.tc6_xbase_vlan + data.max_vlan_count - 1)
    vapi.config_vlan_range_members(dut1, v_range_t, member3)
    if (res1):
      data.result[0] = True
    (tg1, tg_ph_1, tg2, tg_ph_2) = get_handles_1()

    clear_arp_entries(dut)
    output = arpapi.show_arp(dut)

    st.wait(15)
    st.log("INTFCONF: "+str(member3))
    st.log("INTFCONF: "+str(member4))
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.0.62.10',  gateway='10.0.62.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='61', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')


    #pdb.set_trace()
    edit_vid = 219
    st.wait(15)
    output = arpapi.show_arp(dut)
    #END
    if res1:
        st.log("Interface Scaling Test Case 6.2 PASSED PING TEST")
    dut1 = dut
    # L3 INTF SCALING TEST CASE 1.2 START
    result1 = verify_arp_entry(dut, edit_vid, data.tc6_xt1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.2 PASSED ")
        data.tc6_xresult[0] = True
        data.tc6_xresult[1] = True
    else:
        tc_fail_flag = 1
        st.log("Ping operation_failed")
    #tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 1.2 END

    # L3 INTF SCALING TEST CASE 1.3 START
    clear_arp_entries(dut)
    st.wait(15)
    trigger_link_flap(dut1, member3)

    res=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    st.wait(30)
    output = arpapi.show_arp(dut)
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.0.62.10',  gateway='10.0.62.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='61', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')


    #st.wait(30)


    result1 = verify_arp_entry(dut, edit_vid, data.tc6_xt1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.3 PASSED ")
        data.tc6_xresult[2] = True
    else:
        tc_fail_flag = 1
        st.log("Ping operation_failed")

    #tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 6.3 END

    # L3 INTF SCALING TEST CASE 1.4 START
    trigger_link_flap(dut1, member3)
    st.wait(30)
    res=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.0.62.10',  gateway='10.0.62.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='61', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')


    st.wait(30)
    output = arpapi.show_arp(dut)
    ipfeature.ping(dut1, data.tc6_xt1d1_ip_addr)
    result1 = verify_arp_entry(dut, edit_vid, data.tc6_xt1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.4 PASSED ")
        data.tc6_xresult[3] = True
    else:
        st.log("Ping operation_failed")
        tc_fail_flag = 1
     #   st.report_fail("Ping operation_failed")


    #tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 1.4 END
    # L3 INTF SCALING TEST CASE 1.5 START
    intf_ip_addr3 = verify_ip_from_vlan_interface(dut1, edit_vid)
    ipfeature.delete_ip_interface(dut, 'Vlan'+str(edit_vid), data.tc6_xd1t1_ip_addr, subnet="24")
    ipfeature.config_ip_addr_interface(dut, 'Vlan'+str(edit_vid), data.tc6_xd1t1_ip_addr, data.ip_prefixlen, family="ipv4")
    res=tg1.tg_arp_control(handle=h1['handle'], arp_target='all')
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.0.62.10',  gateway='10.0.62.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='61', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')


    st.wait(30)
    output = arpapi.show_arp(dut)

    ipfeature.ping(dut1, data.tc6_xt1d1_ip_addr)
    result1 = verify_arp_entry(dut, edit_vid, data.tc6_xt1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.5 PASSED ")
        data.tc6_xresult[4] = True
    else:
        st.log("Ping operation_failed")
        tc_fail_flag = 1
     #   st.report_fail("Ping operation_failed")

    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    if tc_fail_flag == 0:
        st.log("Interface Scaling Test Case 6.1 6.2 6.3 6.4 6.5  PASSED")
        st.report_pass("test_case_passed")
    else:
        st.log("IPV4 Route Scaling Test Case FAILURE Seen");

    st.report_pass("operation_successful")






def create_l3_interface(dut, count, add, default_intf_count):
    #Remove conflicting ip config from loopback0
    #cmd = "config interface ip remove Loopback0 10.1.0.1/32"
    #st.log(cmd)

    if (add):
        vapi.config_vlan_range(dut, "1 {}".format(count))
        st.wait(10)

    start_time = datetime.datetime.now()
    for i in range(1, count+1):
        ip_addr = get_next_ip()
        #vapi.add_vlan_member(dut, i, vars.D1T1P1, tagging_mode=True)
        #st.log(ip_addr)
        if (add):
            ipfeature.config_ip_addr_interface(dut, "Vlan{}".format(i), ip_addr, 24)
        else:
            ipfeature.delete_ip_interface(dut, "Vlan{}".format(i), ip_addr, 24)
        # measure L3 interface create performance at various intervals
        if (i == 128):
            output = bcm_show(dut, 'bcmcmd "l3 intf show" | wc -l')
            st.log(output)
            curr_intf_count = parse_route_output(output)
            if (curr_intf_count + default_intf_count >= 128):
                end_time = datetime.datetime.now()
                if (add):
                    st.log("Time taken for creating 128 L3 interfaces =" +str(end_time - start_time))
                else:
                    st.log("Time taken for deleting 128 L3 interfaces =" +str(end_time - start_time))
                data.result[0] = 1
        elif (i == 256):
             output = bcm_show(dut, 'bcmcmd "l3 intf show" | wc -l')
             st.log(output)
             curr_intf_count = parse_route_output(output)
             if (curr_intf_count + default_intf_count >= 256):
                end_time = datetime.datetime.now()
                if (add):
                    st.log("Time taken for creating 256 L3 interfaces =" +str(end_time - start_time))
                else:
                    st.log("Time taken for deleting 256 L3 interfaces =" +str(end_time - start_time))
                data.result[1] = 1
        elif (i == 512):
             output = bcm_show(dut, 'bcmcmd "l3 intf show" | wc -l')
             st.log(output)
             curr_intf_count = parse_route_output(output)
             if (curr_intf_count + default_intf_count >= 512):
                end_time = datetime.datetime.now()
                if (add):
                    st.log("Time taken for creating 512 L3 interfaces =" +str(end_time - start_time))
                else:
                    st.log("Time taken for deleting 512 L3 interfaces =" +str(end_time - start_time))
                data.result[2] = 1
        elif (i == 1000):
             output = bcm_show(dut, 'bcmcmd "l3 intf show" | wc -l')
             st.log(output)
             curr_intf_count = parse_route_output(output)
             if (curr_intf_count + default_intf_count >= 1000):
                end_time = datetime.datetime.now()
                if (add):
                    st.log("Time taken for creating 1000 L3 interfaces =" +str(end_time - start_time))
                else:
                    st.log("Time taken for deleting 1000 L3 interfaces =" +str(end_time - start_time))
                data.result[3] = 1

    output = bcm_show(dut, "time show ip interface")
    st.log(output)
    data.result[4] = 1

def delete_bgp_router(dut, router_id, as_num):
    st.log("delete bgp router info")
    my_cmd = "router bgp {}".format(as_num)
    st.vtysh_config(dut, my_cmd)
    my_cmd = "no bgp router-id {}".format(router_id)

def create_bgp_neighbor_route_map_config(dut, local_asn, neighbor_ip, routemap):
    command = "route-map {} permit 10".format(routemap)
    st.vtysh_config(dut, command)
    command = "set ipv6 next-hop prefer-global"
    st.vtysh_config(dut, command)
    command = "router bgp {}".format(local_asn)
    st.vtysh_config(dut, command)
    command = "address-family ipv6 unicast"
    st.vtysh_config(dut, command)
    command = "neighbor {} route-map {} in".format(neighbor_ip, routemap)
    st.vtysh_config(dut, command)
    command = "neighbor {} route-map {} out".format(neighbor_ip, routemap)
    return
def measure_v4_route_scale_time(route_count, show_flag):
    vars = st.get_testbed_vars()
    dut = vars.D1
    default_route = 0
    #TG pumps 512k per sec so to make measure route install
    #time more accurate we start from 600k + route_count
    #base_route_count = 60000 + route_count
    base_route_count = route_count

    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')

    member3 = vars.D1T1P1
    member4 = vars.D1T1P2
    ipfeature.config_ip_addr_interface(dut, member3, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.config_ip_addr_interface(dut, member4, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")

    ipfeature.get_interface_ip_address(dut, family="ipv4")
    ipfeature.show_ip_route(dut)
    interface_status_show(dut)

    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)

    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.10.10.2',
            gateway='10.10.10.1', src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='20.20.20.2', gateway='20.20.20.1', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '100',
                 'remote_ip_addr'        : '10.10.10.1'
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' :  base_route_count,
                  'prefix'     : '121.1.1.0',
                  'as_path'    : 'as_seq:1'
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    # Configuring the BGP router.
    bgp_rtr1 = tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    st.log("BGP_HANDLE: "+str(bgp_rtr1))
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    st.wait(10)

    tr1=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
          emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4',
          mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')

    retval = bgpfeature.verify_bgp_summary(dut, neighbor=data.neigh_ip_addr, state='Established')

    if retval is True:
        output = bcm_show(dut, 'bcmcmd "l3 defip show" | wc -l')
        st.log(output)
        default_route = parse_route_output(output)

    route_count += default_route

    cmd = 'bcmcmd "l3 defip show" | wc -l'
    measure_route_learn_time(dut, default_route, route_count, cmd)

    if (show_flag):
        cmd = "time show ip route"
        bcm_show(dut, cmd)
        data.result_14_3 = True

    res=tg2.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    bgp_rtr2 = tg_bgp_config(tg = tg1,      handle    = bgp_rtr1['conf']['handle'],        ctrl_var  = ctrl_stop)
    ipfeature.delete_ip_interface(dut, member4, data.intf_ip_addr, data.ip_prefixlen, family="ipv4")
    ipfeature.delete_ip_interface(dut, member3, data.my_ip_addr, data.ip_prefixlen, family="ipv4")
    bgpfeature.delete_bgp_neighbor(dut, data.as_num, data.neigh_ip_addr, data.remote_as_num)
    delete_bgp_router(dut, '', data.as_num)

    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg2.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')
    st.wait(20)

@pytest.mark.l3_scale_ut_sp
def test_l3_perf_tc_11_1():
    measure_v4_route_scale_time(10000, False)
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut_sp
def test_l3_perf_tc_11_2():
    measure_v4_route_scale_time(30000, False)
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut_sp
def test_l3_perf_tc_11_3():
    measure_v4_route_scale_time(60000, False)
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_11_4():
    measure_v4_route_scale_time(90000, True)
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_14_3():
  if (data.result_14_3 is True):
    #measure_v4_route_scale_time(80000, True)
    st.report_pass("test_case_passed")

def measure_v6_route_learning_time(route_count):
    vars = st.get_testbed_vars()
    dut = vars.D1

    #TG pumps 512k per sec so to make measure route install
    #time more accurate we start from 600k + route_count
    base_route_count = 60000 + route_count

    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')

    member3 = vars.D1T1P1
    member4 = vars.D1T1P2
    ipfeature.config_ip_addr_interface(dut, member3, data.my_ipv6_addr, data.ipv6_prefixlen, family="ipv6")
    ipfeature.config_ip_addr_interface(dut, member4, data.intf_ipv6_addr, data.ipv6_prefixlen, family="ipv6")

    ipfeature.get_interface_ip_address(dut, family="ipv6")
    ipfeature.show_ip_route(dut, family="ipv6")

    bgpfeature.create_bgp_router(dut, data.as_num, '')
    bgpfeature.create_bgp_neighbor(dut, data.as_num, data.neigh_ipv6_addr, data.remote_as_num, family="ipv6")
    create_bgp_neighbor_route_map_config(dut, data.as_num, data.neigh_ipv6_addr, data.routemap)

    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr='2000::2',
        ipv6_prefix_length='64', ipv6_gateway='2000::1', src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr='2200::2',
        ipv6_prefix_length='64', ipv6_gateway='2200::1', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}
    bgp_conf=tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6',
        active_connect_enable='1', local_as='200', remote_as='100', remote_ipv6_addr='2000::1')

    bgp_route=tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6',
        num_routes=route_count, prefix='3300:1::', as_path='as_seq:1')
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')

    # Configuring the BGP router.
    st.log("BGP neighborship established.")

    tr2=tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
          emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6', mode='create',
          transmit_mode='continuous', length_mode='fixed', rate_pps=512000, enable_stream_only_gen='0')

    res=tg2.tg_traffic_control(action='run', handle=tr2['stream_id'])

    output = bcm_show(dut, 'bcmcmd "l3 ip6route show" | wc -l')
    st.log(output)
    default_route = parse_route_output(output)

    #Assume default route as current number of routes in the system
    #and measure route_count perforamnce on top of it
    route_count += default_route
    cmd = 'bcmcmd "l3 ip6route show" | wc -l'
    measure_route_learn_time(dut, default_route, route_count, cmd)

    res=tg2.tg_traffic_control(action='stop', handle=tr2['stream_id'])
    st.log("TR_CTRL: "+str(res))
    # Withdraw the routes.
    st.wait(10)
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.wait(50)

    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    tg2.tg_interface_config(port_handle=tg_ph_2, handle=h2['handle'], mode='destroy')

@pytest.mark.l3_scale_ut_sp
def test_l3_perf_tc_11_5():
    measure_v6_route_learning_time(10000)
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut_sp
def test_l3_perf_tc_11_6():
    measure_v6_route_learning_time(30000)
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut_sp
def test_l3_perf_tc_11_7():
    measure_v6_route_learning_time(60000)
    st.report_pass("test_case_passed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_13_1():
    vars = st.get_testbed_vars()
    dut2 = vars.D2
    if (data.l3_intf is False):
        output = bcm_show(dut2, 'bcmcmd "l3 intf show" | wc -l')
        st.log(output)
        default_intf_count = parse_route_output(output)

        create_l3_interface(dut2, 1000, 1, default_intf_count)
        data.l3_intf = True
        st.log(data.result)

        #data.oct1 = 10
        #data.oct2 = 0
        #data.oct3 = 1
        #data.oct4 = 1
        #create_l3_interface(dut1, 1000, 0, default_intf_count)
        #clean-up using range command
        #cmd = "config vlan range del 1 1000"

        if (data.result[0] == 1):
            st.report_pass("test_case_passed")
    else:
        if (data.result[0] == 1):
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_13_2():
    if (data.result[1] == 1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_13_3():
    if (data.result[2] == 1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_13_4():
    if (data.result[3] == 1):
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_perf_tc_14_2():
    vars = st.get_testbed_vars()
    dut2 = vars.D2

    if (data.l3_intf is False):
        output = bcm_show(dut2, 'bcmcmd "l3 intf show" | wc -l')
        st.log(output)
        default_intf_count = parse_route_output(output)

        create_l3_interface(dut2, 1000, 1, default_intf_count)
        data.l3_intf = True
        st.log(data.result)

        #data.oct1 = 10
        #data.oct2 = 0
        #data.oct3 = 1
        #data.oct4 = 1
        #create_l3_interface(dut1, 1000, 0, default_intf_count)
        #clean-up using range command
        #cmd = "config vlan range del 1 1000"

        st.report_pass("test_case_passed")
    else:
        if (data.result[4] == 1):
            st.report_pass("test_case_passed")
        else:
            st.report_pass("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_intf_scaling_tc_6_1():
    vars = st.get_testbed_vars()
    dut = vars.D2
    verify_traffic_results(dut)
    if data.tc6_xresult[0]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_intf_scaling_tc_6_2():
    if data.tc6_xresult[1]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_intf_scaling_tc_6_3():
    if data.tc6_xresult[2]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_intf_scaling_tc_6_4():
    if data.tc6_xresult[3]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut
def test_l3_intf_scaling_tc_6_5():
    if data.tc6_xresult[4]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")



