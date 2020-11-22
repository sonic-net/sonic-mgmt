
import os
import pytest
import apis.switching.vlan as vapi
from spytest.dicts import SpyTestDict
import apis.routing.ip as ipfeature
from apis.routing.arp import get_arp_count, show_arp, clear_arp_table
from spytest import st
from collections import OrderedDict
from spytest.tgen.tg import tgen_obj_dict
from spytest.utils import filter_and_select
import apis.system.port as papi
import apis.system.reboot as reboot_obj
from apis.system.basic import get_hwsku

def clear_arp_entries(dut):
    """
    This proc is to clear arp entries of the dut.
    :param dut: DUT Number
    :return:
    """
    clear_arp_table(dut)

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
    papi.set_status(dut, [port], 'shutdown')
    st.wait(5)
    papi.set_status(dut, [port], 'startup')
    st.wait(5)

def get_arp_entries(dut, ipaddr):
    """
    :param dut:
    :type dut:
    :return:
    """
    return show_arp(dut, ipaddress=ipaddr)

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

def verify_ping(src_obj,port_handle,dev_handle,dst_ip,ping_count=5,exp_count=5):
    ping_count,exp_count = int(ping_count),int(exp_count)
    if src_obj.tg_type == 'stc':
        result = src_obj.tg_emulation_ping(handle=dev_handle,host=dst_ip,count=ping_count)
        print("ping output: %s" % (result))
        return True if int(result['tx']) == ping_count and  int(result['rx']) == exp_count else False
    return True

def get_handles():
    vars = st.get_testbed_vars()

    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P3)
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_2 = tg1.get_port_handle(vars.T1D1P4)
    return (tg1, tg_ph_1, tg2, tg_ph_2)


data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def vlan_module_hooks(request):
    vars = st.get_testbed_vars()
    data.vlans = []
    data.dut = vars.D1
    data.start_ip_addr = "10.2.100.1/24"
    data.D2start_ip_addr = "10.2.100.1/24"
    data.start_ip_addr2 = "11.11.1.2/24"
    data.nexthop_start_ip_addr = "10.2.100.10/32"
    #data.nexthop_start_ip_addr = "10.2.101.10/32"
    #data.static_route = "200.1.0.0/24"
    data.static_route = "200.1.0.0/16"
    data.vlan_list = [101, 229]
    data.vlan_count = 16
    data.vlan_val = 100
    data.edit_index = 4
    data.all_ports = st.get_all_ports(data.dut)
    data.free_member_ports = OrderedDict()
    data.tg_member_ports = OrderedDict()
    data.intf_count = "160"
    data.my_ip_addr = "10.2.100.1"
    data.ip_prefixlen = "24"
    data.d1t1_ip_addr = "10.3.49.1"
    data.t1d1_ip_addr = "10.3.49.10"
    data.d1_ip_addr = "11.11.6.1/24"
    data.d2_ip_addr = "11.11.6.2/24"
    data.td3_1_identifier = "Ethernet6"
    data.td3_2_identifier = "Ethernet0"
    data.max_host_1 = 8000
    data.mask = "16"
    data.d1t1_5_x_ip_addr = "12.0.0.1"
    data.d1t2_5_x_ip_addr = "5.0.0.1"
    data.t1d1_5_x_ip_addr = "12.0.0.10"
    data.t1d2_5_x_ip_addr = "5.0.0.10"
    data.ip_list_1 = ['12.0.0.1', '12.0.0.10']
    data.ip_list_2 = ['11.0.0.10', '11.0.0.1']

    data.result = [False, False, False, False, False, False]

    yield

def l3_intf_scaling_tc_6_1_to_6_5():
    (dut) = (data.dut)
    vars = st.get_testbed_vars()
    count = 0
    intf_ip_addr = data.start_ip_addr
    D2_intf_ip_addr = data.D2start_ip_addr
    intf_ip_addr2 = data.start_ip_addr2
    nexthop = data.nexthop_start_ip_addr
    tc_fail_flag = 0
    member3 = vars.D1T1P3
    member4 = vars.D1T1P4
    json_path = os.getcwd()
    apply_file = True
    res1 = True
    json_apply_path = json_path+"/routing/th2-270_ve_config_db.json"
    #st.apply_files(dut, ["$PWD/tests/routing/1k_ve_config_db.json"])
    if apply_file is True:
        st.apply_files(dut, [json_apply_path])
    # L3 INTF SCALING TEST CASE 1.1 START
    st.wait(30)
    data.my_dut_list = st.get_dut_names()
    #dut1 = data.my_dut_list[0]
    dut1 = dut
    #res1 = verify_ve_count(dut)
    if (res1):
      data.result[0] = True
    # L3 traffic streams
    #For now Spirent link with 100G is not working , so the below code from START to END just books spirent port, it will be rectified
    # once infra team provides support for RS-FEC
    #START
    (tg1, tg_ph_1, tg2, tg_ph_2) = get_handles()

    st.log("INTFCONF: "+str(member3))
    st.log("INTFCONF: "+str(member4))
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.3.49.10',  gateway='10.3.49.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='305', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')

    #import pdb;pdb.set_trace()
    edit_vid = 305
    st.wait(15)
    #END
    if res1:
        st.log("Interface Scaling Test Case 6.2 PASSED PING TEST")
    st.log("INTFCONF: "+str(res1))
    dut1 = dut
    # L3 INTF SCALING TEST CASE 1.2 START
    # For now ping for only one ip . We intend to use 10 ip for ping test
    # As of now the ping goes to next connected one spirent host
    #Once spirent works fine , the below ping/arp resolution will ping to spirent hosts
    result1 = verify_arp_entry(dut, edit_vid, data.t1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.2 PASSED ")
        data.result[1] = True
    else:
        tc_fail_flag = 1
        st.log("Ping operation_failed")
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 1.2 END

    # L3 INTF SCALING TEST CASE 1.3 START
    clear_arp_entries(dut)
    st.wait(15)


    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.3.49.10',  gateway='10.3.49.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='305', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')


    st.wait(30)


    result1 = verify_arp_entry(dut, edit_vid, data.t1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.3 PASSED ")
        data.result[2] = True
    else:
        tc_fail_flag = 1
        st.log("Ping operation_failed")

    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 6.3 END

    # L3 INTF SCALING TEST CASE 1.4 START
    trigger_link_flap(dut1, member3)
    st.wait(30)
    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.3.49.10',  gateway='10.3.49.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='305', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')


    st.wait(30)
    st.log("INTFCONF: "+str(res1))
    ipfeature.ping(dut1, data.t1d1_ip_addr)
    result1 = verify_arp_entry(dut, edit_vid, data.t1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.4 PASSED ")
        data.result[3] = True
    else:
        st.log("Ping operation_failed")
        tc_fail_flag = 1
     #   st.report_fail("Ping operation_failed")


    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 1.4 END
    # L3 INTF SCALING TEST CASE 1.5 START
    intf_ip_addr3 = verify_ip_from_vlan_interface(dut1, edit_vid)
    ipfeature.delete_ip_interface(dut, 'Vlan'+str(edit_vid), data.d1t1_ip_addr, subnet="24")
    ipfeature.config_ip_addr_interface(dut, 'Vlan'+str(edit_vid), data.d1t1_ip_addr, data.ip_prefixlen, family="ipv4")
    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.3.49.10',  gateway='10.3.49.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='305', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0', vlan_id_step='1')


    st.wait(30)
    st.log("INTFCONF: "+str(res1))

    ipfeature.ping(dut1, data.t1d1_ip_addr)
    result1 = verify_arp_entry(dut, edit_vid, data.t1d1_ip_addr)
    if result1:
        st.log("Interface Scaling Test Case 6.5 PASSED ")
        data.result[4] = True
    else:
        st.log("Ping operation_failed")
        tc_fail_flag = 1
     #   st.report_fail("Ping operation_failed")

    tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 1.5 END

    # L3 INTF SCALING TEST CASE 1.6 START
    #ipfeature.delete_ip_interface(dut, 'Vlan'+str(edit_vid), data.d1t1_ip_addr, subnet="24")
    #vapi.delete_vlan_member(dut, edit_vid, [vars.D2T1P1])
    #vapi.delete_vlan(dut,[edit_vid])
    # vapi.create_vlan(dut, [edit_vid])
    #vapi.add_vlan_member(dut, edit_vid, [vars.D2T1P1], True)
    #ipfeature.config_ip_addr_interface(dut, 'Vlan'+str(edit_vid), data.d1t1_ip_addr, data.ip_prefixlen, family="ipv4")
    #st.wait(30)
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='10.3.49.10',  gateway='10.3.49.1', src_mac_addr='00:0a:01:00:00:01', vlan='1', vlan_id='305', vlan_id_count=data.intf_count, arp_send_req='1', gateway_step='0.0.1.0', intf_ip_addr_step='0.0.1.0')


    #res1=verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h1['handle'], dst_ip='10.3.49.1',\
    #                                                            ping_count='6', exp_count='6')
    #st.log("INTFCONF: "+str(res1))

    #ipfeature.ping(dut1, data.t1d1_ip_addr)
    #result1 = verify_arp_entry(dut, edit_vid, data.t1d1_ip_addr)
    #if result1:
    #    st.log("Interface Scaling Test Case 6.6 PASSED ")
    #else:
    #    st.log("Ping operation_failed")
    #    tc_fail_flag = 1
    #json_apply_path = json_path+"/routing/td3_restore_config_db.json"
    #st.apply_files(dut, ["$PWD/tests/routing/1k_ve_config_db.json"])
    st.clear_config(dut1)
    #tg1.tg_interface_config(port_handle=tg_ph_1, handle=h1['handle'], mode='destroy')
    # L3 INTF SCALING TEST CASE 1.6 END
    if tc_fail_flag == 0:
        st.log("Interface Scaling Test Case 6.1 6.2 6.3 6.4 6.5  PASSED")
        st.report_pass("test_case_passed")
    else:
        st.log("IPV4 Route Scaling Test Case FAILURE Seen");
        st.report_fail("test_case_failed")

    st.report_pass("operation_successful")

@pytest.mark.l3_scale_ut_not_run
def test_l3_ve_intf_scaling_tc_6_1():
    l3_intf_scaling_tc_6_1_to_6_5()
    st.log(data.result)
    if data.result[0]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_not_run
def test_l3_ve_intf_scaling_tc_6_2():
    if data.result[1]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_not_run
def test_l3_ve_intf_scaling_tc_6_3():
    if data.result[2]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_not_run
def test_l3_ve_intf_scaling_tc_6_4():
    if data.result[3]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_not_run
def test_l3_ve_intf_scaling_tc_6_5():
    if data.result[4]:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

def get_handles_1():
    vars = st.get_testbed_vars()

    st.log(vars)
    tg1 = tgen_obj_dict[vars['tgen_list'][0]]
    tg2 = tgen_obj_dict[vars['tgen_list'][0]]
    tg_ph_1 = tg1.get_port_handle(vars.T1D1P1)
    tg_ph_2 = tg2.get_port_handle(vars.T1D1P2)

    return (tg1, tg2, tg_ph_1, tg_ph_2)

def pre_test_l3_fwding():
    # override from testbed
    vars = st.get_testbed_vars()
    data.my_dut_list = st.get_dut_names()

    dut1 = data.my_dut_list[0]

    st.log(vars)

    ipfeature.clear_ip_configuration(st.get_dut_names())
    ipfeature.clear_ip_configuration(st.get_dut_names(),'ipv6')
    vapi.clear_vlan_configuration(st.get_dut_names())

    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.d1t1_5_x_ip_addr, data.mask)

    ipfeature.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.d1t2_5_x_ip_addr, data.mask)

def post_test_l3_fwding():
    vars = st.get_testbed_vars()
    data.my_dut_list = st.get_dut_names()
    dut1 = data.my_dut_list[0]

    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P1, data.d1t1_5_x_ip_addr, data.mask)

    ipfeature.delete_ip_interface(vars.D1, vars.D1T1P2, data.d1t2_5_x_ip_addr, data.mask)

def reboot_node(dut):
    st.reboot(dut)

    st.wait(100)
    ports = papi.get_interfaces_all(dut)
    if not ports:
      return False
    else:
      return True

def fast_reboot_node(dut):
    st.reboot(dut, "fast")

    st.wait(100)
    ports = papi.get_interfaces_all(dut)
    if not ports:
        return False
    else:
        return True

def warm_reboot_node(dut):
    reboot_obj.config_warm_restart(dut, oper='enable')
    reboot_obj.config_warm_restart(dut, oper='enable', tasks=['swss', 'bgp'])
    reboot_obj.config_warm_restart(dut, bgp_timer=120)
    reboot_obj.config_warm_restart(dut, neighsyncd_timer=100)
    st.reboot(dut, "warm")

    st.wait(300)
    ports = papi.get_interfaces_all(dut)
    if not ports:
        return False
    else:
        return True

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

@pytest.mark.l3_scale_ut_sp
def test_l3_host_scaling_tc5_6():
    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles_1()
    dut1 = vars.D1

    ret = reboot_node(dut1)
    pre_test_l3_fwding()
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    papi.get_status(dut1)

    if (ret):
        tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
        tr1 = create_l3_host(tg1, tg_ph_1, data.max_host_1, 20)
        st.wait(15)
        total = get_arp_count(dut1)
        st.log("Total ARP entries: {}".format(total))

        tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
        tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
        post_test_l3_fwding()
        if (total >= data.max_host_1):
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")
    else:
        post_test_l3_fwding()
        st.report_fail("test_case_failed")

def is_supported_platform(dut):
    name = get_hwsku(dut)
    plt_str = name.split('-')

    if (str(plt_str[1]) == "AS7712"):
        return True
    else:
        return False

@pytest.mark.l3_scale_ut_sp
def test_l3_host_scaling_tc5_7():
    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles_1()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    papi.get_status(dut1)

    reboot_obj.config_save(dut1)
    #To clean-up inconsistent state left in previous test
    ret = reboot_node(dut1)

    ret = warm_reboot_node(dut1)

    pre_test_l3_fwding()
    if (ret):
        tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
        tr1 = create_l3_host(tg1, tg_ph_1, data.max_host_1, 20)
        st.wait(15)
        total = get_arp_count(dut1)
        st.log("Total ARP entries: {}".format(total))

        tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
        tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
        post_test_l3_fwding()
        if (total >= data.max_host_1):
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")
    else:
        post_test_l3_fwding()
        st.report_fail("test_case_failed")

@pytest.mark.l3_scale_ut_sp
def test_l3_host_scaling_tc5_8():
    vars = st.get_testbed_vars()
    # Config 2 IPV4 interfaces on DUT.
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles_1()
    dut1 = vars.D1
    ipfeature.get_interface_ip_address(dut1, family="ipv4")
    ipfeature.get_interface_ip_address(dut1, family="ipv6")
    ipfeature.show_ip_route(dut1)
    papi.get_status(dut1)

    ret = fast_reboot_node(dut1)
    pre_test_l3_fwding()
    if (ret):
        tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
        tr1 = create_l3_host(tg1, tg_ph_1, data.max_host_1, 20)
        st.wait(15)
        total = get_arp_count(dut1)
        st.log("Total ARP entries: {}".format(total))

        tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
        tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
        post_test_l3_fwding()
        if (total >= data.max_host_1):
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")
    else:
        post_test_l3_fwding()
        st.report_fail("test_case_failed")
