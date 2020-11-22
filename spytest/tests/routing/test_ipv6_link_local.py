import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
import apis.system.switch_configuration as sc_obj
from apis.switching.mac import get_mac

import utilities.parallel as utils

def ipv6_link_initialize_variables():
    global data
    data = SpyTestDict()
    data.shell_sonic = "sonic"
    data.shell_vtysh = "vtysh"
    data.vlan_li = random_vlan_list(2)
    data.vlan_in_1 = "Vlan{}".format(str(data.vlan_li[0]))
    data.vlan_in_2 = "Vlan{}".format(str(data.vlan_li[1]))
    data.ip6_manual_ll_addr = ["fe80::1:1:1:11","fe80::2:2:2:22"]
    data.tg_ip6_addr_l = ["33f1::1", "8911:1::12"]
    data.tgd_ip6_addr_l = ["33f1::2", "8911:1::13"]
    data.tg_ip6_addr_mask_l = ["64", "64"]
    data.tg_ip6_addr_rt_l = ["33f1::", "8911:1::"]
    data.static_rt_ip = "7fe9::1"
    data.static_rt = "7fe9::/64"
    data.static_rt_manual = "8919::/78"
    data.static_rt_manual_ip = "8919::1"
    data.static_rt_mask = "64"
    data.prt_chnl = "PortChannel9"
    data.rate_traffic = "2000"
    data.tg1_src_mac_addr = "00:00:11:32:0B:C0"
    data.tg2_src_mac_addr = "00:00:01:AA:EF:11"
    data.vrf_name = "Vrf-LinkLocal"


@pytest.fixture(scope="module", autouse=True)
def ipv6_link_local_module_config(request):
    ipv6_link_initialize_variables()
    ipv6_link_local_pre_config()
    yield
    ipv6_link_local_post_config()


@pytest.fixture(scope="function", autouse=True)
def ipv6_link_local_func_hooks(request):
    utils.exec_all(True, [[ip_obj.show_ip_route, vars.D1, "ipv6"], [ip_obj.show_ip_route, vars.D2, "ipv6"]])
    yield
    if st.get_func_name(request) == 'test_ft_ipv6_link_local_warm_boot':
        ip_obj.create_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, "vtysh", 'ipv6', data.prt_chnl)
        tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    if st.get_func_name(request) == 'test_ft_ipv6_link_local_manual':
        utils.exec_all(True, [
            [ip_obj.delete_static_route, vars.D1, data.ip6_manual_ll_addr[1], data.static_rt_manual, 'ipv6', "vtysh",
             data.prt_chnl],
            [ip_obj.delete_static_route, vars.D2, data.tg_ip6_addr_l[1], data.static_rt_manual, 'ipv6', "vtysh", vars.D2T1P1]])
        utils.exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, data.prt_chnl, data.ip6_manual_ll_addr[0],
                               data.tg_ip6_addr_mask_l[0], "ipv6", 'remove'],
                              [ip_obj.config_ip_addr_interface, vars.D2, data.prt_chnl, data.ip6_manual_ll_addr[1],
                               data.tg_ip6_addr_mask_l[1], "ipv6", 'remove']])
        utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, data.prt_chnl, 'enable'],
                              [ip_obj.config_interface_ip6_link_local, vars.D2, data.prt_chnl, 'enable']])
        ip_obj.create_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, "vtysh", 'ipv6', data.prt_chnl)



@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_auto_generate():
    report_flag = 0
    if not d1_prt_link_local:
        st.log("Ipv6 link local address is not auto generated for port based routing interface {}".format(vars.D1D2P1))
        report_flag = 1
    d1_vlan_link_local = ip_obj.get_link_local_addresses(vars.D1, data.vlan_in_1)
    if not d1_vlan_link_local:
        st.log("Ipv6 link local address is not auto generated for vlan based routing interface {}".format(data.vlan_in_1))
        report_flag = 1
    d1_po_link_local = ip_obj.get_link_local_addresses(vars.D1, data.prt_chnl)
    if not d1_po_link_local:
        st.log(
            "Ipv6 link local address is not auto generated for Port Channel based routing interface PortChannel009")
        report_flag = 1
    if report_flag:
        st.report_fail("ip6_link_local_addr_auto_generation_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_ping():
    report_flag = 0
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = vars.D1D2P1):
        st.log("Ipv6 Ping over Link Local address via the Port based routing interface is failed.")
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = data.vlan_in_1):
        st.log("Ipv6 Ping over Link Local address via the Vlan  based routing interface is failed.")
        report_flag =1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = data.prt_chnl):
        st.log("Ipv6 Ping over Link Local address via the Port Channel based routing interface is failed.")
        report_flag =1
    # Get show ndp output
    utils.exec_all(True, [[arp_obj.show_ndp, vars.D1, None], [arp_obj.show_ndp, vars.D2, None]])
    d1_int_li = [vars.D2D1P1, vars.D2D1P2, data.prt_chnl]
    intf_obj.interface_operation(vars.D2, [vars.D2D1P1, vars.D2D1P2, data.prt_chnl], operation="shutdown", skip_verify=True)
    st.log("Waiting for 10 sec after shutdown the interfaces")
    st.wait(10)
    intf_obj.interface_status_show(vars.D1, [vars.D2D1P1, vars.D2D1P2, data.prt_chnl])
    intf_obj.interface_operation(vars.D2, [vars.D2D1P1, vars.D2D1P2, data.prt_chnl], operation="startup",
                                 skip_verify=True)
    st.log("Polling for interface status after no shutdown")
    for intf in d1_int_li:
        if not intf_obj.poll_for_interface_status(vars.D2, intf, "oper", "up", iteration=5, delay=1):
            st.error("Failed to startup interface {} on the DUT {}".format(intf, vars.D2))
            report_flag = 0

    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = vars.D1D2P1):
        st.log("After shut no shut, Ipv6 Ping over Link Local address via the Port based routing interface is failed.")
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface=data.vlan_in_1):
        st.log("After shut no shut, Ipv6 Ping over Link Local address via the Vlan  based routing interface is failed.")
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface=data.prt_chnl):
        st.log("After shut no shut, Ipv6 Ping over Link Local address via the Port Channel based routing interface is failed.")
        report_flag = 1
    if report_flag:
        st.report_fail("ip6_ping_fail_over_link_local_addr")
    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_ndp():
    report_flag=0
    if not arp_obj.verify_ndp(vars.D1, d2_prt_link_local[0], interface=vars.D1D2P1):
        st.log("NDP table not updated for Ipv6 Link Local address over Port based routing interface")
        report_flag = 1
    if not arp_obj.verify_ndp(vars.D1, d2_prt_link_local[0], vlan=data.vlan_li[0]):
        st.log("NDP table not updated for Ipv6 Link Local address over Vlan based routing interface")
        report_flag = 1
    if not arp_obj.verify_ndp(vars.D1, d2_prt_link_local[0], interface=data.prt_chnl):
        st.log("NDP table not updated for Ipv6 Link Local address over Port Channel based routing interface")
        report_flag = 1
    if report_flag:
        st.report_fail("ndp_entry_ip6_link_local_create_fail")
    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_ip6_disable():
    report_flag = 0
    ip_obj.config_ipv6(vars.D1, action='disable')
    if ip_obj.get_link_local_addresses(vars.D1, vars.D1D2P1):
        st.error("Auto generated ipv6 link local addr is not removed when ipv6 is disabled globally")
        report_flag = 1
    ip_obj.config_interface_ip6_link_local(vars.D1, d1_int_ipv6_list, 'enable')
    if not ip_obj.get_link_local_addresses(vars.D1, vars.D1D2P1):
        st.error("ipv6 link local addr is not auto generated when ipv6 is disabled and enabled globally")
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = vars.D1D2P1):
        st.log("Ipv6 Ping over Link Local address via the Port based routing interface is failed.")
        report_flag=1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = data.vlan_in_1):
        st.log("Ipv6 Ping over Link Local address via the Vlan  based routing interface is failed.")
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = data.vlan_in_2):
        st.log("Ipv6 Ping over Link Local address via the Vlan  based routing interface is failed.")
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = data.prt_chnl):
        st.log("Ipv6 Ping over Link Local address via the Port Channel based routing interface is failed.")
        report_flag = 1
    if report_flag:
        st.report_fail("ip6_link_local_addr_auto_generation_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_static_rt_ecmp():
    result_flag=0
    st.log("Clearing all interface counters")
    utils.exec_all(True, [[intf_obj.clear_interface_counters, vars.D1], [intf_obj.clear_interface_counters, vars.D2]])
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    st.wait(2)
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    verify_traffic_hash(vars.D1,[vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 200)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg2],
        }
    }

    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        st.log("Traffic loss observed for ipv6 traffic forwarded via ipv6 link local next hop")
        result_flag = 1
    if result_flag:
        st.report_fail("ip6_traffic_over_link_local_nh_fail")
    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_nh_change():
    report_flag = 0
    st.log("Clearing all interface counters")
    utils.exec_all(True, [[intf_obj.clear_interface_counters, vars.D1], [intf_obj.clear_interface_counters, vars.D2]])
    st.log("clearing TG stats")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    st.log("Remove the vlan participation to bring down the Vlan routing intf")
    vlan_obj.delete_vlan_member(vars.D1, data.vlan_li[0], vars.D1D2P2, tagging_mode=True)
    vlan_obj.add_vlan_member(vars.D1, data.vlan_li[0], vars.D1D2P2, tagging_mode=True)
    if not ip_obj.get_link_local_addresses(vars.D1, data.vlan_in_1):
        st.error("ipv6 link local addr is not auto generated after remove and re add of vlan routing intf")
        report_flag = 1
    pc_obj.add_del_portchannel_member(vars.D1, data.prt_chnl, [vars.D1D2P3, vars.D1D2P4], flag="del", skip_verify=True)
    pc_obj.add_del_portchannel_member(vars.D1, data.prt_chnl, [vars.D1D2P3, vars.D1D2P4], flag="add", skip_verify=True)
    if not ip_obj.get_link_local_addresses(vars.D1, data.prt_chnl):
        st.error("ipv6 link local addr is not auto generated for {} after remove and re add of members".format(data.prt_chnl))
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = vars.D1D2P1):
        st.log("Ipv6 Ping over Link Local address via the Port based routing interface is failed.")
        report_flag = 1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = data.vlan_in_1):
        st.log("Ipv6 Ping over Link Local address via the Vlan  based routing interface is failed.")
        report_flag =1
    if not ip_obj.ping(vars.D1, d2_prt_link_local[0], family='ipv6', interface = data.prt_chnl):
        st.log("Ipv6 Ping over Link Local address via the Port Channel based routing interface is failed.")
        report_flag =1
    utils.exec_all(True, [[get_mac, vars.D1] ,[get_mac, vars.D2]])
    st.log("Checking the IPv6 traffic forwarding over ECMP next hops after remove and re adding of next hop interfaces")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    st.wait(2)
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    ecmp_cntrs = verify_traffic_hash(vars.D1, [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4], 200)
    st.log("Counter stats on next hop interfaces - {}".format(ecmp_cntrs))
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg2],
        }
    }
    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        st.log("After flap in next hop interfaces, traffic loss observed for ipv6 traffic forwarded via ipv6 link local next hop")
        report_flag = 1
    if report_flag:
        st.report_fail("ip6_traffic_over_link_local_nh_fail")
    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_vrf():
    report_flag = 0
    st.log("Clearing all interface counters")
    utils.exec_all(True, [[intf_obj.clear_interface_counters, vars.D1], [intf_obj.clear_interface_counters, vars.D2]])
    st.log("clearing TG stats")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    st.log("Check the auto configured ipv6 link local address for VRF interface")
    if not ip_obj.get_link_local_addresses(vars.D1, data.vlan_in_2):
        st.log(
            "Ipv6 link local address is not auto generated for VRF binded vlan based routing interface {}".format(data.vlan_in_2))
        report_flag = 1
    ip_obj.show_ip_route(vars.D1, "ipv6", "sonic", data.vrf_name)
    st.log("binding the TG connected interface to VRF {}".format(data.vrf_name))
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.tgd_ip6_addr_l[0], data.tg_ip6_addr_mask_l[0], "ipv6",
                                    'remove')
    vrf_obj.bind_vrf_interface(vars.D1, vrf_name=data.vrf_name, intf_name=vars.D1T1P1, config='yes', skip_error=True)
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.tgd_ip6_addr_l[0],data.tg_ip6_addr_mask_l[0], "ipv6", 'add')
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    st.wait(2)
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    # Show command for debugging purpose in case of failures.
    utils.exec_all(True, [[intf_obj.show_interface_counters_all, vars.D1],
                          [intf_obj.show_interface_counters_all, vars.D2]])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg2],
        }
    }

    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        st.log(
            "After flap in next hop interfaces, traffic loss observed for ipv6 traffic forwarded via ipv6 link local next hop")
        report_flag = 1
    if report_flag:
        vrf_obj.bind_vrf_interface(vars.D1, vrf_name=data.vrf_name, intf_name=vars.D1T1P1, config='no', skip_error=True)
        ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.tgd_ip6_addr_l[0], data.tg_ip6_addr_mask_l[0],
                                        "ipv6", 'add')
        st.report_fail("ip6_traffic_over_link_local_nh_fail_vrf")
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.tgd_ip6_addr_l[0], data.tg_ip6_addr_mask_l[0], "ipv6",
                                    'remove')
    vrf_obj.bind_vrf_interface(vars.D1, vrf_name=data.vrf_name, intf_name=vars.D1T1P1, config='no', skip_error=True)
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.tgd_ip6_addr_l[0],data.tg_ip6_addr_mask_l[0], "ipv6", 'add')
    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression
def test_ft_ipv6_link_local_manual():
    result_flag = 0
    st.log("Clearing all interface counters")
    utils.exec_all(True, [[intf_obj.clear_interface_counters, vars.D1], [intf_obj.clear_interface_counters, vars.D2]])
    st.log("clearing TG stats")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    ip_obj.delete_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, 'ipv6', "vtysh", data.prt_chnl)
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local,vars.D1, data.prt_chnl, 'disable'],
                          [ip_obj.config_interface_ip6_link_local,vars.D2, data.prt_chnl, 'disable']])
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, data.prt_chnl, data.ip6_manual_ll_addr[0], data.tg_ip6_addr_mask_l[0], "ipv6", 'add'],
                          [ip_obj.config_ip_addr_interface, vars.D2, data.prt_chnl, data.ip6_manual_ll_addr[1], data.tg_ip6_addr_mask_l[1], "ipv6", 'add']])
    utils.exec_all(True, [
        [ip_obj.create_static_route, vars.D1, data.ip6_manual_ll_addr[1], data.static_rt_manual, "vtysh", 'ipv6', data.prt_chnl],
        [ip_obj.create_static_route, vars.D2, data.tg_ip6_addr_l[1], data.static_rt_manual, "vtysh", 'ipv6', vars.D2T1P1]])
    utils.exec_all(True, [[ip_obj.get_interface_ip_address, vars.D1, None, "ipv6"],
                          [ip_obj.get_interface_ip_address, vars.D2, None, "ipv6"]])
    st.log("Get show ipv6 route output")
    utils.exec_all(True, [[ip_obj.show_ip_route, vars.D1, "ipv6", "sonic", None],
                          [ip_obj.show_ip_route, vars.D2, "ipv6", "sonic", None]])
    tg1.tg_traffic_config(mode='modify', stream_id=tg_str_data[1]["tg1_ipv6_data_str_id_1"],
                          ipv6_dst_addr=data.static_rt_manual_ip)
    if not poll_verify_interface_ip_address(vars.D1, data.prt_chnl, ["{}%{}/64".format(data.ip6_manual_ll_addr[0], data.prt_chnl), "{}/64".format(data.ip6_manual_ll_addr[0])],10):
        result_flag = 1
    if not ip_obj.ping(vars.D1, data.ip6_manual_ll_addr[1], family='ipv6', interface = data.prt_chnl):
        st.log("Ipv6 Ping over manual ipv6 Link Local address via the Port Channel based routing interface is failed.")
        result_flag =1
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    st.wait(1)
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    st.wait(2)
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg2],
        }
    }

    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        st.log("traffic loss observed for ipv6 traffic forwarded via ipv6 link local next hop")
        result_flag = 1
    if result_flag:
        st.log("Show command for debugging purpose in case of failures")
        utils.exec_all(True, [[intf_obj.show_interface_counters_all, vars.D1],
                              [intf_obj.show_interface_counters_all, vars.D2]])
        st.report_fail("ip6_traffic_over_link_local_nh_fail_manual")

    st.report_pass("test_case_passed")


@pytest.mark.ipv6_link_local_regression_wb
def test_ft_ipv6_link_local_warm_boot():
    result_flag=0
    ip_obj.delete_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, 'ipv6', "vtysh", data.prt_chnl)
    st.log("Clearing all interface counters")
    utils.exec_all(True, [[intf_obj.clear_interface_counters, vars.D1], [intf_obj.clear_interface_counters, vars.D2]])
    utils.exec_all(True, [[ip_obj.show_ip_route, vars.D1, "ipv6", "sonic", None],
                          [ip_obj.show_ip_route, vars.D2, "ipv6", "sonic", None]])
    tg1.tg_traffic_config(mode='modify', stream_id=tg_str_data[1]["tg1_ipv6_data_str_id_1"],
                          ipv6_dst_addr=data.static_rt_ip)
    st.log("clearing TG stats")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    st.log("Performing warm-reboot, while ipv6 traffic is forwarding via link local next hops ")
    st.reboot(vars.D1, 'warm')
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_ipv6_data_str_id_1"])
    verify_traffic_hash(vars.D1,[vars.D1D2P1, vars.D1D2P2], 200)
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg2],
        }
    }

    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        st.log("During Warm boot, traffic loss observed for ipv6 traffic forwarded via ipv6 link local next hop")
        result_flag = 1
    if result_flag:
        utils.exec_all(True, [[ip_obj.get_interface_ip_address, vars.D1, None, "ipv6"],
                              [ip_obj.get_interface_ip_address, vars.D2, None, "ipv6"]])
        utils.exec_all(True, [[ip_obj.show_ip_route, vars.D1, "ipv6", "sonic", None],
                              [ip_obj.show_ip_route, vars.D2, "ipv6", "sonic", None]])
        utils.exec_all(True, [[intf_obj.show_interface_counters_all, vars.D1],
                              [intf_obj.show_interface_counters_all, vars.D2]])
        st.report_fail("ip6_traffic_over_link_local_nh_fail")
    st.report_pass("test_case_passed")


def ipv6_link_local_pre_config():
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:1", "D2T1:1")
    global tg_handler, tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data, dut1_rt_int_mac, dut2_rt_int_mac, \
        tg_rt_int_handle, d1_prt_link_local, d2_prt_link_local, d1_int_ipv6_list, d2_int_ipv6_list
    tg_handler = util_tg_init(vars, [vars.T1D1P1, vars.T1D2P1])
    tg1 = tg_handler["tg"]
    tg2 = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]

    st.log("For debugging purpose, checking 'running config' before proceeding for module config")
    utils.exec_all(True, [[sc_obj.get_running_config, vars.D1], [sc_obj.get_running_config, vars.D2]])

    st.log("For debugging purpose, checking 'routing interfaces' before proceeding for module config")
    utils.exec_all(True, [[ip_obj.get_interface_ip_address, vars.D1, None, "ipv6"], [ip_obj.get_interface_ip_address, vars.D2, None, "ipv6"]])
    pc_obj.config_portchannel(vars.D1, vars.D2, data.prt_chnl, [vars.D1D2P3, vars.D1D2P4],
                              [vars.D2D1P3, vars.D2D1P4], config='add', thread=True)

    st.log("Vlan config")
    utils.exec_all(True, [[vlan_obj.create_vlan, vars.D1, [data.vlan_li[0], data.vlan_li[1]]],
                          [vlan_obj.create_vlan, vars.D2, [data.vlan_li[0], data.vlan_li[1]]]])
    utils.exec_all(True, [
        [vlan_mem_cfg, vars.D1, [[data.vlan_li[0], vars.D1D2P2, True], [data.vlan_li[1], vars.D1D2P2, True]]],
        [vlan_mem_cfg, vars.D2, [[data.vlan_li[0], vars.D2D1P2, True], [data.vlan_li[1], vars.D2D1P2, True]]]])
    st.log("VRF Config and binding 2nd vlan routing interface to that VRF")
    vrf_obj.config_vrf(vars.D1, vrf_name=data.vrf_name, config='yes')
    vrf_obj.bind_vrf_interface(vars.D1, vrf_name=data.vrf_name, intf_name=data.vlan_in_2, config='yes', skip_error=True)
    st.log("Enabling ipv6 link local")
    d1_int_ipv6_list =[vars.D1D2P1, data.vlan_in_1, data.vlan_in_2,data.prt_chnl]
    d2_int_ipv6_list = [vars.D2D1P1, data.vlan_in_1, data.vlan_in_2, data.prt_chnl]
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1,d1_int_ipv6_list, 'enable'],
                          [ip_obj.config_interface_ip6_link_local, vars.D2,d2_int_ipv6_list, 'enable']])

    st.log("TG connected int ipv6 address config")
    utils.exec_all(True, [[ip_obj.config_ip_addr_interface, vars.D1, vars.D1T1P1, data.tgd_ip6_addr_l[0],
                           data.tg_ip6_addr_mask_l[0],"ipv6",'add'], [ip_obj.config_ip_addr_interface, vars.D2,
                                                                      vars.D2T1P1, data.tgd_ip6_addr_l[1],
                           data.tg_ip6_addr_mask_l[1],"ipv6",'add']])

    st.log("Get DUT mac address")
    [rt_int_mac, exceptions] = utils.exec_all(True, [[basic_obj.get_ifconfig_ether, vars.D1, vars.D1D2P1],
                                                     [basic_obj.get_ifconfig_ether, vars.D2, vars.D2D1P1]])
    utils.ensure_no_exception(exceptions)
    dut1_rt_int_mac = rt_int_mac[0]
    dut2_rt_int_mac = rt_int_mac[1]


    st.log("Get DUT link local addresses")
    [rt_link_local_addr, exceptions] = utils.exec_all(True, [[ip_obj.get_link_local_addresses, vars.D1, vars.D1D2P1],
                                                     [ip_obj.get_link_local_addresses, vars.D2, vars.D2D1P1]])
    utils.ensure_no_exception(exceptions)
    d1_prt_link_local = rt_link_local_addr[0]
    d2_prt_link_local = rt_link_local_addr[1]

    if not d1_prt_link_local or not d2_prt_link_local:
        st.log("DUT Link Local Address are empty")
        st.report_fail("link_local_address_not_found")

    st.log("Routing interface config in TG")
    tg_rt_int_handle = util_tg_routing_int_config(vars, tg1, tg2, tg_ph_1, tg_ph_2)

    st.log("Doing ping to the TG ipv6 address to resolve the next hop")
    utils.exec_all(True, [[ip_obj.ping, vars.D1, data.tgd_ip6_addr_l[0], 'ipv6'],[ip_obj.ping, vars.D2, data.tgd_ip6_addr_l[1], 'ipv6']])

    st.log("Get show ndp output")
    utils.exec_all(True, [[arp_obj.show_ndp, vars.D1, None],[arp_obj.show_ndp, vars.D2, None]])

    st.log("Static route config")
    utils.exec_all(True, [[ip_obj.create_static_route, vars.D1, d2_prt_link_local[0], data.static_rt, "vtysh", 'ipv6', vars.D1D2P1],
                          [ip_obj.create_static_route, vars.D2, data.tg_ip6_addr_l[1], data.static_rt, "vtysh", 'ipv6', vars.D2T1P1]])
    ip_obj.create_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, "vtysh", 'ipv6', data.vlan_in_1)
    ip_obj.create_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, "vtysh", 'ipv6', data.prt_chnl)
    ip_obj.create_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, "vtysh", 'ipv6', data.vlan_in_2, vrf=data.vrf_name)
    st.log("Get show ipv6 route output")
    utils.exec_all(True, [[ip_obj.show_ip_route, vars.D1, "ipv6", "sonic", None],[ip_obj.show_ip_route, vars.D2, "ipv6", "sonic", None]])
    ip_obj.show_ip_route(vars.D1, "ipv6", "sonic", data.vrf_name)

    st.log("TG Stream config")
    tg_str_data = util_tg_stream_config(tg1, tg2, tg_ph_1, tg_ph_2)

    st.log("Clearing all interface counters for debugging purpose")
    utils.exec_all(True, [[intf_obj.clear_interface_counters, vars.D1], [intf_obj.clear_interface_counters, vars.D2]])


def ipv6_link_local_post_config():
    vars = st.get_testbed_vars()
    st.log("Static route cleanup")
    utils.exec_all(True, [
        [ip_obj.delete_static_route, vars.D1, d2_prt_link_local[0], data.static_rt, 'ipv6', "vtysh", vars.D1D2P1],
        [ip_obj.delete_static_route, vars.D2, data.tg_ip6_addr_l[1], data.static_rt, 'ipv6', "vtysh", vars.D2T1P1]])
    ip_obj.delete_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, 'ipv6',"vtysh",  data.vlan_in_1)
    ip_obj.delete_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, 'ipv6',"vtysh", data.prt_chnl)
    ip_obj.delete_static_route(vars.D1, d2_prt_link_local[0], data.static_rt, 'ipv6', "vtysh", data.vlan_in_2, vrf=data.vrf_name)
    vrf_obj.config_vrf(vars.D1, vrf_name=data.vrf_name, config='no')
    st.log("Disabling ipv6 link local")
    utils.exec_all(True, [[ip_obj.config_interface_ip6_link_local, vars.D1, d1_int_ipv6_list, 'disable'],
                          [ip_obj.config_interface_ip6_link_local, vars.D2, d2_int_ipv6_list, 'disable']])
    ip_obj.clear_ip_configuration(st.get_dut_names(), family = 'ipv6')
    st.log("Vlan and Port Channel clean up")
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    pc_obj.clear_portchannel_configuration(st.get_dut_names())
    st.log("Cleaning up routing interfaces configured on TG")
    st.log("Stopping the TG traffic again, if in case of any failures in test function misses the stop operation")
    tgapi.traffic_action_control(tg_handler, actions=['reset'])
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_rt_int_handle[0]['handle'], mode='destroy')
    tg2.tg_interface_config(port_handle=tg_ph_2, handle=tg_rt_int_handle[1]['handle'], mode='destroy')


def util_tg_init(vars, tg_port_list):
    tg_port_list = list(tg_port_list) if isinstance(tg_port_list, list) else [tg_port_list]
    tg_handler = tgapi.get_handles(vars, tg_port_list)
    tgapi.traffic_action_control(tg_handler, actions=['reset', 'clear_stats'])
    return tg_handler


def util_tg_routing_int_config(vars, tg1, tg2,tg_ph_1, tg_ph_2,):

    st.log("TG1 {} IPv6 address {} config".format(vars.T1D1P1, data.tg_ip6_addr_l[0]))
    tg1_rt_int_handle = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.tg_ip6_addr_l[0],
                                 ipv6_prefix_length='64', ipv6_gateway=data.tgd_ip6_addr_l[0], arp_send_req='1')
    st.log("TG2 {} IPv6 address {} config".format(vars.T1D2P1, data.tg_ip6_addr_l[1]))
    tg2_rt_int_handle = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.tg_ip6_addr_l[1],
                                 ipv6_prefix_length='64', ipv6_gateway=data.tgd_ip6_addr_l[1], arp_send_req='1')
    return tg1_rt_int_handle,tg2_rt_int_handle


def util_tg_stream_config(tg1, tg2, tg_ph_1, tg_ph_2):
    result = {1:{},2:{}}
    tg1_ipv6_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',
                                                     length_mode='fixed', rate_pps=data.rate_traffic,
                                                     l3_protocol='ipv6', mac_src=data.tg1_src_mac_addr, mac_dst=dut1_rt_int_mac,
                                                     ipv6_src_addr=data.tg_ip6_addr_l[0],ipv6_dst_addr=data.static_rt_ip,
                                                     ipv6_dst_mode='increment', ipv6_dst_step='::1',ipv6_dst_count=1000)
    result[1]["tg1_ipv6_data_str_id_1"] = tg1_ipv6_data_str['stream_id']
    return result


def vlan_mem_cfg(dut, data):
    if type(data)== list and len(data)>0:
        for vlan, port, mode in data:
            vlan_obj.add_vlan_member(dut, vlan, port, tagging_mode=mode)
        return True
    return False


def verify_traffic_hash(dut, port_list, pkts_per_port, traffic_loss_verify=False, rx_port = '',
                                 tx_port = '', dut2 =''):
    if traffic_loss_verify:
        sub_list = []
        sub_list.append([intf_obj.show_interface_counters_all, dut])
        sub_list.append([intf_obj.show_interface_counters_all, dut2])
        [output, exceptions] = utils.exec_all(True, sub_list)
        utils.ensure_no_exception(exceptions)
        data.int_cntr_1, data.int_cntr_2 = output
    else:
        data.int_cntr_1 = intf_obj.show_interface_counters_all(dut)
    data.intf_count_dict = {}
    for port in port_list:
        for counter_dict in data.int_cntr_1:
            if counter_dict['iface'] == port:
                try:
                    data.intf_count_dict[port] = int(counter_dict['tx_ok'].replace(',',''))
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                if not (data.intf_count_dict[port] >= pkts_per_port):
                    intf_obj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
                    st.report_fail("traffic_not_hashed", dut)
    if traffic_loss_verify:
        for counter_dict in data.int_cntr_1:
            if counter_dict['iface'] == rx_port:
                try:
                    data.rx_traffic = int(counter_dict['rx_ok'].replace(',', ''))
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        for counter_dict in data.int_cntr_2:
            if counter_dict['iface'] == tx_port:
                try:
                    data.tx_traffic = int(counter_dict['tx_ok'].replace(',', ''))
                except Exception:
                    st.report_fail('invalid_traffic_stats')
                break
        if not (data.tx_traffic >= 0.95* data.rx_traffic):
            st.log("data.tx_traffic:{}".format(data.tx_traffic))
            st.log("data.rx_traffic:{}".format(data.rx_traffic))
            intf_obj.show_interface_counters_detailed(vars.D1, vars.D1T1P1)
            st.report_fail('traffic_loss_observed')
    return data.intf_count_dict


def poll_verify_interface_ip_address(dut, interface_name, ip_address, loopCnt):
    iter = 1
    while True:
        out = ip_obj.get_interface_ip_address(dut, interface_name=interface_name, family="ipv6")
        st.debug("The ipv6 interface output is: {}".format(out))
        if out and out[0]['ipaddr'] in ip_address:
            return True
        if iter > loopCnt:
            return False
        iter = iter + 1
