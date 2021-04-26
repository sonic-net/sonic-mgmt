# ################ Author Details ################
# Name: Kesava Swamy Karedla ; Kiran Vedula
# Email: kesava-swamy.karedla@broadcom.com ; kiran-kumar.vedula@broadcom.com
# ################################################
#
# 1. test_ft_static_nat - Verify static NAT establishes a one-to-one mapping between the inside local address and an
# inside global address.
# 2. test_ft_static_nat_snat - Verify static NAT establishes a one-to-one mapping between the inside local address and
# an inside global address with nat type as snat
# 3. test_ft_static_napt - Verify static NAPT functionality for TCP traffic
# 4. test_ft_static_napt_snat - Verify static NAPT functionality for UDP traffic with nat type as snat
# 5. test_ft_static_napt_entry_remove_reapply - Verify static NAPT functionality after NAT entries are removed
# and re applied
# 6. test_ft_static_napt_same_zone - Verify that if zones are same traffic should get forwarded as per L3 table
# 7. test_ft_static_twicenat - Verify static twicenat functionality
# 8. test_ft_dynamic_napt_without_acl_bind_udp - Verify dynamic NAT establishes a mapping between an inside local
# address and an inside global address dynamically selected from a pool of global addresses. Also verifies udp entry
# time out.
# 9. test_ft_nat_docker_restart - Verify nat translation table after nat docket restart
# 10. test_ft_dynamic_nat - Verify basic dynamic nat translation
#
###################################################

import pytest

from socket import inet_aton
from binascii import hexlify

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ipapi
import apis.routing.nat as natapi
import apis.routing.arp as arpapi
import apis.switching.vlan as vlanapi
import apis.system.basic as basicapi
import apis.system.interface as intfapi

from utilities.parallel import exec_all, ensure_no_exception

data = SpyTestDict()
dut1_rt_int_mac = None


def nat_initialize_variables():
    data.in1_ip_addr = "12.12.0.1"
    data.in1_ip_addr_h = ["12.12.0.2", "12.12.0.3", "12.12.0.4","12.12.0.5", "12.12.0.6", "12.12.0.7","12.12.0.8",
                          "12.12.0.9", "12.12.0.10", "12.12.0.11"]
    data.in1_ip_addr_rt = "12.12.0.0"
    data.in1_ip_addr_mask = "16"
    data.in2_ip_addr = "13.13.13.1"
    data.in2_ip_addr_h = ["13.13.13.2", "13.13.13.3", "13.13.13.4"]
    data.in2_ip_addr_rt = "13.13.13.0"
    data.in2_ip_addr_mask = "16"
    data.out_ip_addr = "125.56.90.11"
    data.out_ip_addr_l = ["125.56.90.12", "125.56.90.13", "125.56.90.14", "125.56.90.15"]
    data.out_ip_addr_h = "125.56.90.1"
    data.out_ip_range = "125.56.90.23-125.56.90.24"
    data.out_ip_pool = ["125.56.90.23", "125.56.90.24"]
    data.out_ip_addr_rt = "125.56.90.0"
    data.out_ip_addr_mask = "24"
    data.global_ip_addr_h = "129.2.30.13"
    data.global_ip_addr = "129.2.30.12"
    data.global_ip_addr_rt = "129.2.30.0"
    data.global_ip_addr_mask = "24"
    data.tw_global_ip_addr = "99.99.99.1"
    data.tw_global_ip_addr_rt = "99.99.99.0"
    data.tw_global_ip_addr_mask = "24"
    data.test_ip_addr = "22.22.22.1"
    data.test_ip_addr_mask = "16"
    data.test_ip_addr_rt = "22.22.0.0"
    data.tw_test_ip_addr = "15.15.0.1"
    data.tw_test_ip_addr_mask = "16"
    data.tw_test_ip_addr_rt = "15.15.0.0"
    data.s_local_ip = "11.11.11.2"
    data.s_local_ip_route = "11.11.0.0"
    data.s_local_ip_mask = "16"
    data.s_global_ip = "88.98.128.2"
    data.s_global_ip_rt = "88.98.128.0"
    data.s_global_ip_mask = "24"
    data.proto_all = "all"
    data.proto_tcp = "tcp"
    data.proto_udp = "udp"
    data.zone_1 = "0"
    data.zone_2 = "1"
    data.zone_3 = "2"
    data.zone_4 = "3"
    data.pool_name = ["pool_123_nat", "88912_pool", "123Pool"]
    data.bind_name = ["bind_1", "7812_bind", "bind11"]
    data.global_port_range = "333-334"
    data.local_src_port = ["251", "252"]
    data.local_dst_port = ["444", "8991"]
    data.global_src_port = ["12001", "7781"]
    data.global_dst_port = ["333", "334"]
    data.tcp_src_local_port = 1002
    data.tcp_dst_local_port = 3345
    data.udp_src_local_port = 7781
    data.udp_dst_local_port = 8812
    data.tcp_src_global_port = 100
    data.tcp_dst_global_port = 345
    data.udp_src_global_port = 7811
    data.udp_dst_global_port = 5516
    data.af_ipv4 = "ipv4"
    data.nat_type_snat = "snat"
    data.nat_type_dnat = "dnat"
    data.shell_sonic = "sonic"
    data.shell_vtysh = "vtysh"
    data.rate_traffic = '10'
    data.pkt_count = '10'
    data.host_mask = '32'
    data.packet_forward_action = 'FORWARD'
    data.packet_do_not_nat_action = 'DO_NOT_NAT'
    data.packet_drop_action = 'DROP'
    data.stage_Ing = 'INGRESS'
    data.stage_Egr = 'EGRESS'
    data.acl_table_nat = 'NAT_ACL'
    data.acl_table_in_nat_eg = 'in_nat_eg'
    data.acl_table_out_nat_eg = 'out_nat_eg'
    data.acl_table_nat = 'NAT_ACL'
    data.type = 'L3'
    data.acl_drop_all_rule = 'INGRESS_FORWARD_L3_DROP_ALL_RULE'
    data.ipv4_type = 'ipv4any'
    data.tg1_src_mac_addr = '00:00:23:11:14:08'
    data.tg2_src_mac_addr = '00:00:43:32:1A:01'
    data.wait_time_traffic_run_to_pkt_cap = 1
    data.wait_time_traffic_run = 1
    data.wait_nat_udp_timeout = 60
    data.wait_nat_stats = 7
    data.config_add='add'
    data.config_del='del'
    data.twice_nat_id_1 = '100'
    data.twice_nat_id_2 = '1100'
    data.wait_time_after_docker_restart = 10
    data.mask = '32'

    if not st.is_feature_supported("klish"):
        data.natcli_type = "click"
        data.nat_pkt_cap_enable = True
    else:
        data.natcli_type = "klish"
        data.nat_pkt_cap_enable = False

    if st.is_vsonic():
        data.nat_pkt_cap_enable = True
        data.wait_nat_stats = data.wait_nat_stats + 10


@pytest.fixture(scope="module", autouse=True)
def nat_module_config(request):
    nat_initialize_variables()
    nat_prolog()
    yield
    nat_epilog()


@pytest.fixture(scope="function", autouse=True)
def nat_func_hooks(request):
    intfapi.clear_interface_counters(vars.D1)
    natapi.clear_nat(vars.D1, statistics=True)
    yield
    if st.get_func_name(request) == 'test_ft_dynamic_napt_without_acl_bind_udp':
        natapi.config_nat_timeout(vars.D1, udp_timeout=300, config='set')


@pytest.mark.nat_regression
def test_ft_static_nat():
    # ################################################
    # Objective - Verify static NAT establishes a one-to-one mapping between the inside local address and an
    # inside global address.
    # #################################################
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_st_nat_dnat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_st_nat_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_st_nat_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='stop',  handle=tg_str_data["tg2"]["tg2_st_nat_dnat_data_str_id_1"])
    st.wait(data.wait_nat_stats)
    nat_stats = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[0])
    if not nat_stats:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet", data.in1_ip_addr_h[0], data.out_ip_addr_l[0])
    if not (int(nat_stats[0]['packets']) == (int(data.pkt_count))):
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet",data.in1_ip_addr_h[0],data.out_ip_addr_l[0])
    nat_stats = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_all, dst_ip=data.out_ip_addr_l[0])
    if not nat_stats:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[0], data.in1_ip_addr_h[0])
    if not (int(nat_stats[0]['packets']) == (int(data.pkt_count))):
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[0], data.in1_ip_addr_h[0])
    if data.nat_pkt_cap_enable:
        st.log("Validation through Packet Capture")
        s_ip_addr_h = util_ip_addr_to_hexa_conv(data.out_ip_addr_l[0])
        if not util_pkt_cap(tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data["tg1"]["tg1_st_nat_dnat_data_str_id_1"], offset_list=[26], value_list=[s_ip_addr_h]):
            util_nat_debug_fun()
            st.report_fail("snat_translation_failed_in_packet",data.in1_ip_addr_h[0],data.out_ip_addr_l[0])
        d_ip_addr_h = util_ip_addr_to_hexa_conv(data.in1_ip_addr_h[0])
        if not util_pkt_cap(tg2, tg1, tg_ph_2, tg_ph_1, tg_str_data["tg2"]["tg2_st_nat_dnat_data_str_id_1"], offset_list=[30], value_list=[d_ip_addr_h]):
            util_nat_debug_fun()
            st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[0], data.in1_ip_addr_h[0])
    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_static_nat_snat():
    # ################################################
    # Objective - Verify static NAT establishes a one-to-one mapping between the inside local address and an
    # inside global address with nat type as snat
    # #################################################
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_st_nat_snat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop',  handle=tg_str_data["tg1"]["tg1_st_nat_snat_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_st_nat_snat_data_str_id_1"])
    tg2.tg_traffic_control(action='stop',  handle=tg_str_data["tg2"]["tg2_st_nat_snat_data_str_id_1"])
    st.wait(data.wait_nat_stats)
    result = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_all, src_ip=data.s_global_ip)
    if not result:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet", data.s_global_ip, data.s_local_ip)
    if not int(result[0]['packets']) == (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet", data.s_global_ip,data.s_local_ip)
    nat_stats = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_all, dst_ip=data.s_local_ip)
    if not nat_stats:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.s_local_ip,data.s_global_ip)
    if not int(nat_stats[0]['packets']) == (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.s_local_ip,data.s_global_ip)

    if data.nat_pkt_cap_enable:
        st.log("Validation through Packet Capture")
        s_ip_addr_h = util_ip_addr_to_hexa_conv(data.s_local_ip)
        if not util_pkt_cap(tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data["tg1"]["tg1_st_nat_snat_data_str_id_1"], offset_list=[26], value_list=[s_ip_addr_h]):
            util_nat_debug_fun()
            st.report_fail("snat_translation_failed_in_packet", data.s_global_ip, data.s_local_ip)
        d_ip_addr_h = util_ip_addr_to_hexa_conv(data.s_global_ip)
        if not util_pkt_cap(tg2, tg1, tg_ph_2, tg_ph_1, tg_str_data["tg2"]["tg2_st_nat_snat_data_str_id_1"], offset_list=[30], value_list=[d_ip_addr_h]):
            util_nat_debug_fun()
            st.report_fail("dnat_translation_fail_in_packet", data.s_local_ip,data.s_global_ip)

    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_static_napt():
    # ################################################
    # Objective - Verify static NAPT functionality for TCP traffic
    # #################################################
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_st_napt_tcp_dnat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_st_napt_tcp_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_st_napt_tcp_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='stop',  handle=tg_str_data["tg2"]["tg2_st_napt_tcp_dnat_data_str_id_1"])
    st.wait(data.wait_nat_stats)
    result = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_tcp, src_ip=data.in1_ip_addr_h[1], src_ip_port= data.tcp_src_local_port)
    if not result:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet", data.in1_ip_addr_h[1], data.out_ip_addr_l[1])
    if not (int(result[0]['packets']) == (int(data.pkt_count))):
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet",data.in1_ip_addr_h[1],data.out_ip_addr_l[1])
    nat_stats = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_tcp, dst_ip=data.out_ip_addr_l[1], dst_ip_port=data.tcp_src_global_port)
    if not nat_stats:
        st.error("Received empty list, acl counters not updated")
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[1], data.in1_ip_addr_h[1])
    if not (int(nat_stats[0]['packets']) == (int(data.pkt_count))):
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[1], data.in1_ip_addr_h[1])

    if data.nat_pkt_cap_enable:
        st.log("Validation through Packet Capture")
        s_ip_addr_h = util_ip_addr_to_hexa_conv(data.out_ip_addr_l[1])
        s_port_h = util_int_to_hexa_conv(data.tcp_src_global_port)
        if not util_pkt_cap(tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data["tg1"]["tg1_st_napt_tcp_dnat_data_str_id_1"], offset_list=[23, 26, 34], value_list=['06', s_ip_addr_h, s_port_h]):
            util_nat_debug_fun()
            st.report_fail("snat_translation_failed_in_packet",data.in1_ip_addr_h[1],data.out_ip_addr_l[1])
        d_ip_addr_h = util_ip_addr_to_hexa_conv(data.in1_ip_addr_h[1])
        d_port_h = util_int_to_hexa_conv(data.tcp_src_local_port)
        if not util_pkt_cap(tg2, tg1, tg_ph_2, tg_ph_1, tg_str_data["tg2"]["tg2_st_napt_tcp_dnat_data_str_id_1"], offset_list=[23, 30, 36], value_list=['06', d_ip_addr_h, d_port_h]):
            util_nat_debug_fun()
            st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[1], data.in1_ip_addr_h[1])
    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_static_napt_snat():
    # ################################################
    # Objective - Verify static NAPT functionality for UDP traffic with nat type as snat
    # #################################################
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_st_napt_udp_dnat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_st_napt_udp_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_st_napt_udp_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='stop',  handle=tg_str_data["tg2"]["tg2_st_napt_udp_dnat_data_str_id_1"])
    st.wait(data.wait_nat_stats)
    result = natapi.poll_for_nat_statistics(vars.D1, protocol=(data.proto_udp), src_ip=data.in1_ip_addr_h[2], src_ip_port=data.udp_src_local_port)
    if not result:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet", data.out_ip_addr_l[2], data.in1_ip_addr_h[2])
    if not int(result[0]['packets']) == (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet",data.out_ip_addr_l[2],data.in1_ip_addr_h[2])
    nat_stats = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=data.out_ip_addr_l[2], dst_ip_port=data.udp_src_global_port)
    if not nat_stats:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.in1_ip_addr_h[2],data.out_ip_addr_l[0])
    if not int(nat_stats[0]['packets']) == (int(data.pkt_count)):
        st.report_fail("dnat_translation_fail_in_packet", data.in1_ip_addr_h[2],data.out_ip_addr_l[0])

    if data.nat_pkt_cap_enable:
        st.log("Validation through Packet Capture")
        s_ip_addr_h = util_ip_addr_to_hexa_conv(data.out_ip_addr_l[2])
        s_port_h = util_int_to_hexa_conv(data.udp_src_global_port)
        if not util_pkt_cap(tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data["tg1"]["tg1_st_napt_udp_dnat_data_str_id_1"], offset_list=[23, 26, 34], value_list=['11', s_ip_addr_h, s_port_h]):
            util_nat_debug_fun()
            st.report_fail("snat_translation_failed_in_packet", data.out_ip_addr_l[2], data.in1_ip_addr_h[2])
        d_ip_addr_h = util_ip_addr_to_hexa_conv(data.in1_ip_addr_h[2])
        d_port_h = util_int_to_hexa_conv(data.udp_src_local_port)
        if not util_pkt_cap(tg2, tg1, tg_ph_2, tg_ph_1, tg_str_data["tg2"]["tg2_st_napt_udp_dnat_data_str_id_1"], offset_list=[23, 30, 36], value_list=['11', d_ip_addr_h, d_port_h]):
            util_nat_debug_fun()
            st.report_fail("dnat_translation_fail_in_packet", data.in1_ip_addr_h[2],data.out_ip_addr_l[0])

    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_static_napt_entry_remove_reapply():
    # ################################################
    # Objective - Verify static NAPT functionality after NAT entries are removed and re applied
    # #################################################
    natapi.config_nat_static(vars.D1, protocol=data.proto_tcp, global_ip=data.out_ip_addr_l[1],
                              local_ip=data.in1_ip_addr_h[1],
                              local_port_id=data.tcp_src_local_port, global_port_id=data.tcp_src_global_port,
                              config=data.config_del, nat_type=data.nat_type_dnat)
    natapi.config_nat_static(vars.D1, protocol=data.proto_tcp, global_ip=data.out_ip_addr_l[1],
                              local_ip=data.in1_ip_addr_h[1],
                              local_port_id=data.tcp_src_local_port, global_port_id=data.tcp_src_global_port,
                              config=data.config_add, nat_type=data.nat_type_dnat)
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_st_napt_tcp_dnat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_st_napt_tcp_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_st_napt_tcp_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='stop',  handle=tg_str_data["tg2"]["tg2_st_napt_tcp_dnat_data_str_id_1"])
    st.wait(data.wait_nat_stats)
    result = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_tcp, src_ip=data.in1_ip_addr_h[1], src_ip_port=data.tcp_src_local_port)
    if not result:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet", data.in1_ip_addr_h[1], data.out_ip_addr_l[1])
    if not (int(result[0]['packets']) == (int(data.pkt_count))):
        util_nat_debug_fun()
        st.report_fail("snat_translation_failed_in_packet",data.in1_ip_addr_h[1],data.out_ip_addr_l[1])
    nat_stats = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_tcp, dst_ip=data.out_ip_addr_l[1], dst_ip_port=data.tcp_src_global_port)
    if not nat_stats:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[1], data.in1_ip_addr_h[1])
    if not (int(nat_stats[0]['packets']) == (int(data.pkt_count))):
        util_nat_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr_l[1], data.in1_ip_addr_h[1])
    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_static_napt_same_zone():
    # ################################################
    # Objective - Verify that if zones are same traffic should get forwarded as per L3 table.
    # #################################################
    natapi.config_nat_interface(vars.D1, interface_name=vars.D1T1P2, zone_value=data.zone_1, config=data.config_add)
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_st_nat_dnat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_st_nat_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_st_nat_dnat_data_str_id_1"])
    tg2.tg_traffic_control(action='stop',  handle=tg_str_data["tg2"]["tg2_st_nat_dnat_data_str_id_1"])
    natapi.config_nat_interface(vars.D1, interface_name=vars.D1T1P2, zone_value=data.zone_2, config=data.config_add)
    st.wait(data.wait_nat_stats)
    nat_stats = natapi.get_nat_statistics(vars.D1, protocol=data.proto_all, dst_ip=data.out_ip_addr_l[0])
    if not nat_stats:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_debug_fun()
        st.report_fail("nat_translation_happening_in_no_nat_case")
    if int(nat_stats[0]['packets']) == (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("nat_translation_happening_in_no_nat_case")
    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_static_twicenat():
    # ################################################
    # Objective - Verify static twicenat functionality
    # #################################################
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_st_nat_twicenat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_st_nat_twicenat_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_st_nat_twicenat_data_str_id_1"])
    tg2.tg_traffic_control(action='stop',  handle=tg_str_data["tg2"]["tg2_st_nat_twicenat_data_str_id_1"])
    natapi.show_nat_translations(vars.D1)
    nat_stats = natapi.poll_for_twice_nat_statistics(vars.D1, protocol=data.proto_all, src_ip=data.tw_global_ip_addr, dst_ip=data.out_ip_addr_l[3])
    if not nat_stats:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("twicenat_translation_failed_in_packet")
    if not int(nat_stats[0]['packets']) == (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("twicenat_translation_failed_in_packet")
    result = natapi.poll_for_twice_nat_statistics(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[3], dst_ip=data.tw_test_ip_addr)
    if not result:
        st.error("Received empty list, nat statistics not updated")
        util_nat_debug_fun()
        st.report_fail("twicenat_translation_failed_in_packet")
    if not int(result[0]['packets']) == (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("twicenat_translation_failed_in_packet")

    if data.nat_pkt_cap_enable:
        st.log("Validation through Packet Capture")
        s_ip_addr_h = util_ip_addr_to_hexa_conv(data.out_ip_addr_l[3])
        d_ip_addr_h = util_ip_addr_to_hexa_conv(data.tw_global_ip_addr)
        if not util_pkt_cap(tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data["tg1"]["tg1_st_nat_twicenat_data_str_id_1"], offset_list=[26, 30], value_list=[s_ip_addr_h, d_ip_addr_h]):
            util_nat_debug_fun()
            st.report_fail("snat_translation_failed_in_packet", data.out_ip_addr_l[2], data.in1_ip_addr_h[2])
        s_ip_addr_h = util_ip_addr_to_hexa_conv(data.tw_test_ip_addr)
        d_ip_addr_h = util_ip_addr_to_hexa_conv(data.in1_ip_addr_h[3])
        if not util_pkt_cap(tg2, tg1, tg_ph_2, tg_ph_1, tg_str_data["tg2"]["tg2_st_nat_twicenat_data_str_id_1"], offset_list=[26, 30], value_list=[s_ip_addr_h, d_ip_addr_h]):
            util_nat_debug_fun()
            st.report_fail("dnat_translation_fail_in_packet", data.in1_ip_addr_h[2],data.out_ip_addr_l[0])

    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_dynamic_napt_without_acl_bind_udp():
    # ################################################
    # Objective - Verify dynamic NAT establishes a mapping between an inside local address and an inside global address
    # dynamically selected from a pool of global addresses. Also verifies udp entry time out.
    # #################################################
    natapi.config_nat_timeout(vars.D1, udp_timeout=120, config='set')
    natapi.clear_nat(vars.D1, translations=True)
    st.log("Traffic for snat learning via dynamic pool")
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    st.log("Traffic for data forwarding to check nat stats")
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    trn_val = natapi.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in1_ip_addr_h[-1],src_ip_port=data.local_src_port[0])
    if not trn_val:
        st.error("Received empty list,nat translation table not updated")
        util_nat_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    ip_addr_h = util_ip_addr_to_hexa_conv(trn_src_ip)
    port_h = util_int_to_hexa_conv(trn_src_port)
    st.log("Sending traffic for dnat verification")
    tg2_str_obj = tg2_str_selector(trn_src_ip, trn_src_port)
    tg2.tg_traffic_control(action='run', handle=tg2_str_obj)
    tg2.tg_traffic_control(action='stop', handle=tg2_str_obj)
    # Show command for debugging purpose in case of failures.
    intfapi.show_interface_counters_all(vars.D1)
    st.wait(data.wait_nat_stats)
    nat_stats_s = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                src_ip=data.in1_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        st.error("Received empty list,nat statistics are not updated")
        util_nat_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    if not int(nat_stats_s[0]['packets']) >= (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])

    nat_stats_d = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=trn_src_ip,dst_ip_port=trn_src_port)
    if not nat_stats_d:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail",data.out_ip_pool[0],data.out_ip_pool[0])
    if not int(nat_stats_d[0]['packets']) >= (int(data.pkt_count)):
        util_nat_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail",data.out_ip_pool[0],data.out_ip_pool[0])
    st.log("Try deleting the pool")
    if not natapi.config_nat_pool(vars.D1, pool_name=data.pool_name[0], global_ip_range=data.out_ip_range,
                               global_port_range= data.global_port_range, config=data.config_del, skip_error=True):
         util_nat_debug_fun()
         st.report_fail("pool_del_fail",data.pool_name[0])

    if data.nat_pkt_cap_enable:
        st.log("Validation through Packet Capture")
        if not util_pkt_cap(tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"],
                        offset_list=[23, 26, 34], value_list=['11', ip_addr_h, port_h]):
            util_nat_debug_fun()
            st.report_fail("snat_translation_failed_in_packet", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
        ip_addr_h = util_ip_addr_to_hexa_conv(data.in1_ip_addr_h[-1])
        port_h = util_int_to_hexa_conv(data.local_src_port[0])
        if not util_pkt_cap(tg2, tg1, tg_ph_2, tg_ph_1, tg2_str_obj,
                        offset_list=[23, 30, 36], value_list=['11', ip_addr_h, port_h]):
            util_nat_debug_fun()
            st.report_fail("dnat_translation_fail_in_packet", data.out_ip_pool[0],data.in1_ip_addr_h[-1])

    st.log("NAT UDP entry timeout verification")
    st.log("Waiting for UDP timeout")
    st.wait(180)
    trn_val = natapi.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in1_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])

    if trn_val:
        st.error("Received non-empty list,nat translation entry exists")
        util_nat_debug_fun()
        st.report_fail("nat_translation_table_not_cleared")
    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_nat_docker_restart():
    # ################################################
    # Objective - Verify nat translation table after nat docket restart
    # #################################################

    st.log("Sending traffic for dynamic NAT snat case")
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    basicapi.docker_operation(vars.D1,"nat","stop")
    st.log("Wait for NAT docker to STOP")
    st.wait(data.wait_time_after_docker_restart)
    basicapi.docker_operation(vars.D1, "nat", "start")
    st.log("Wait for NAT docker to START")
    st.wait(data.wait_time_after_docker_restart)
    trn_val = natapi.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in1_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])
    if trn_val:
        util_nat_debug_fun()
        st.report_fail("dynamic_napt_entry_exists_after_docker_restart")
    trn_val_1 = natapi.get_nat_translations(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[0])
    if not trn_val_1:
        util_nat_debug_fun()
        st.report_fail("static_nat_entry_not_restored_after_docker_restart")
    st.report_pass("test_case_passed")


@pytest.mark.nat_regression
def test_ft_dynamic_nat():
    # ################################################
    # Objective - Verify basic dynamic nat translation
    # #################################################
    natapi.clear_nat(vars.D1, translations=True)
    st.log("Deleting NAT Pool binding")
    natapi.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    config=data.config_del)
    st.log("Creating NAT Pool-1 without port")
    natapi.config_nat_pool(vars.D1, pool_name=data.pool_name[1], global_ip_range=data.out_ip_pool[0],
                             config=data.config_add)
    st.log("Creating NAT Pool binding")
    natapi.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    config=data.config_add)
    st.log("Traffic for learning")
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_dyn_nat_udp_1_data_str_id_1"])
    tg2.tg_traffic_control(action='stop', handle=tg_str_data["tg2"]["tg2_dyn_nat_udp_1_data_str_id_1"])
    st.log("Traffic for data forwarding to check nat stats")
    tg1.tg_traffic_control(action='run', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data["tg2"]["tg2_dyn_nat_udp_1_data_str_id_1"])
    tg2.tg_traffic_control(action='stop', handle=tg_str_data["tg2"]["tg2_dyn_nat_udp_1_data_str_id_1"])
    st.wait(data.wait_nat_stats)
    tc_fail_flag = 0
    result = natapi.get_nat_translations(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[-1])
    if not result:
        st.error("Dynamic NAT failed for SRC IP")
        tc_fail_flag = 1
    nat_stats_s = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_all,src_ip=data.in1_ip_addr_h[-1])
    if not nat_stats_s:
        tc_fail_flag = 1
    nat_stats_d = natapi.poll_for_nat_statistics(vars.D1, protocol=data.proto_all, dst_ip=data.out_ip_pool[0])
    if not nat_stats_d:
        tc_fail_flag = 1

    if data.nat_pkt_cap_enable:
        st.log("Validation through Packet Capture")
        s_ip_addr_h = util_ip_addr_to_hexa_conv(data.out_ip_pool[0])
        if not util_pkt_cap(tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data["tg1"]["tg1_dyn_nat_udp_data_str_id_1"],
                        offset_list=[26], value_list=[s_ip_addr_h]):
            tc_fail_flag = 1
        d_ip_addr_h = util_ip_addr_to_hexa_conv(data.in1_ip_addr_h[-1])
        if not util_pkt_cap(tg2, tg1, tg_ph_2, tg_ph_1, tg_str_data["tg2"]["tg2_dyn_nat_udp_1_data_str_id_1"],
                        offset_list=[30], value_list=[d_ip_addr_h]):
            tc_fail_flag = 1

    natapi.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    config=data.config_del)
    natapi.config_nat_pool(vars.D1, pool_name=data.pool_name[0], global_ip_range=data.out_ip_range,
                            global_port_range= data.global_port_range, config=data.config_add)
    natapi.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    config=data.config_add)
    if tc_fail_flag:
        util_nat_debug_fun()
        st.report_fail("dynamic_nat_fail")
    st.report_pass("dynamic_nat_successful")


def nat_tg_config():
    global tg_handler, tg1, tg2, tg_ph_1, tg_ph_2, tg_str_data, tg_rt_int_handle
    tg_handler = util_tg_init(vars, [vars.T1D1P1, vars.T1D1P2])
    tg1 = tg_handler["tg"]
    tg2 = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_rt_int_handle = util_tg_routing_int_config(vars, tg1, tg2, tg_ph_1, tg_ph_2)
    tg_str_data = util_tg_stream_config(tg1, tg2, tg_ph_1, tg_ph_2)


def nat_dut_config():
    global dut1_rt_int_mac
    ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.in1_ip_addr, data.in1_ip_addr_mask, family=data.af_ipv4)
    for i in range(0, len(data.out_ip_addr_l)):
        ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.out_ip_addr_l[i], data.out_ip_addr_mask,
                                       family=data.af_ipv4)
    for i in range(0, len(data.out_ip_pool)):
        ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.out_ip_pool[i], data.out_ip_addr_mask,
                                       family=data.af_ipv4)
    dut1_rt_int_mac = basicapi.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    ipapi.create_static_route(vars.D1, data.out_ip_addr_h,
                              "{}/{}".format(data.global_ip_addr_rt, data.global_ip_addr_mask),
                              shell=data.shell_vtysh, family=data.af_ipv4)
    ipapi.create_static_route(vars.D1, data.in1_ip_addr_h[0],
                              "{}/{}".format(data.s_global_ip_rt, data.s_global_ip_mask))
    ipapi.create_static_route(vars.D1, data.out_ip_addr_h,
                              "{}/{}".format(data.tw_global_ip_addr_rt, data.tw_global_ip_addr_mask))

    st.log("NAT Configuration")
    natapi.config_nat_feature(vars.D1, 'enable')
    util_nat_zone_config(vars, [vars.D1T1P1, vars.D1T1P2], [data.zone_1, data.zone_2], config=data.config_add)
    natapi.config_nat_static(vars.D1, protocol=data.proto_all, global_ip=data.out_ip_addr_l[0],
                             local_ip=data.in1_ip_addr_h[0], config=data.config_add, nat_type=data.nat_type_dnat)
    natapi.config_nat_static(vars.D1, protocol=data.proto_tcp, global_ip=data.out_ip_addr_l[1],
                             local_ip=data.in1_ip_addr_h[1],
                             local_port_id=data.tcp_src_local_port, global_port_id=data.tcp_src_global_port,
                             config=data.config_add, nat_type=data.nat_type_dnat)
    natapi.config_nat_static(vars.D1, protocol=data.proto_udp, global_ip=data.in1_ip_addr_h[2],
                             local_ip=data.out_ip_addr_l[2],
                             local_port_id=data.udp_src_global_port, global_port_id=data.udp_src_local_port,
                             config=data.config_add, nat_type=data.nat_type_snat)
    natapi.config_nat_static(vars.D1, protocol=data.proto_all, global_ip=data.s_global_ip, local_ip=data.s_local_ip,
                             config=data.config_add, nat_type=data.nat_type_snat)
    natapi.config_nat_static(vars.D1, protocol=data.proto_all, global_ip=data.out_ip_addr_l[3],
                             local_ip=data.in1_ip_addr_h[3],
                             config=data.config_add, nat_type=data.nat_type_dnat, twice_nat_id=data.twice_nat_id_1)
    natapi.config_nat_static(vars.D1, protocol=data.proto_all, global_ip=data.tw_global_ip_addr,
                             local_ip=data.tw_test_ip_addr,
                             config=data.config_add, nat_type=data.nat_type_snat, twice_nat_id=data.twice_nat_id_1)
    natapi.show_nat_translations(vars.D1)
    # dynamic NAT config
    st.log("Creating NAT Pool-1")
    natapi.config_nat_pool(vars.D1, pool_name=data.pool_name[0], global_ip_range=data.out_ip_range,
                           global_port_range=data.global_port_range, config=data.config_add)
    st.log("Creating NAT Pool binding")
    natapi.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                   config=data.config_add)


def nat_prolog():
    global vars
    vars = st.ensure_min_topology("D1T1:2")
    platform = basicapi.get_hwsku(vars.D1)
    common_constants = st.get_datastore(vars.D1, "constants", "default")
    if platform.lower() in common_constants['TH3_PLATFORMS']:
        st.error("NAT is not supported for this platform {}".format(platform))
        st.report_unsupported('NAT_unsupported_platform',platform)
    [_, exceptions] = exec_all(True, [[nat_tg_config], [nat_dut_config]], first_on_main=True)
    ensure_no_exception(exceptions)


def nat_epilog():
    vars = st.get_testbed_vars()
    util_nat_zone_config(vars, [vars.D1T1P1, vars.D1T1P2], [data.zone_1, data.zone_2], config=data.config_del)
    natapi.clear_nat_config(vars.D1)
    natapi.config_nat_feature(vars.D1, 'disable')
    ipapi.delete_static_route(vars.D1, data.out_ip_addr_h,
                               "{}/{}".format(data.global_ip_addr_rt, data.global_ip_addr_mask))
    ipapi.clear_ip_configuration(st.get_dut_names())
    vlanapi.clear_vlan_configuration(st.get_dut_names())
    if vars.config.module_epilog_tgen_cleanup:
        st.log("Clearing Routing interface config on TG ports")
        tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_rt_int_handle[0]['handle'], mode='destroy')
        tg1.tg_interface_config(port_handle=tg_ph_2, handle=tg_rt_int_handle[1]['handle'], mode='destroy')
        tgapi.traffic_action_control(tg_handler, actions=['reset'])


def util_nat_zone_config(vars, intf, zone, config):
    if config == data.config_add:
        st.log("zone value configuration")
        for i in range(len(intf)):
            natapi.config_nat_interface(vars.D1, interface_name=intf[i], zone_value=zone[i], config=data.config_add)
    else:
        st.log("zone value un configuration")
        for i in range(len(intf)):
            natapi.config_nat_interface(vars.D1, interface_name=intf[i], zone_value=zone[i], config=data.config_del)

    return True


def util_tg_init(vars, tg_port_list):
    tg_port_list = list(tg_port_list) if isinstance(tg_port_list, list) else [tg_port_list]
    tg_handler = tgapi.get_handles(vars, tg_port_list)
    return tg_handler


def util_tg_routing_int_config(vars, tg1, tg2, tg_ph_1, tg_ph_2):
    st.log("TG1 {} IPv4 address {} config".format(vars.T1D1P1,data.in1_ip_addr_h[0]))
    tg1_rt_int_handle = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.in1_ip_addr_h[0],
                                     gateway=data.in1_ip_addr, netmask='255.255.0.0', arp_send_req='1',count='10', gateway_step='0.0.0.0')
    st.log("TG2 {} IPv4 address {} config".format(vars.T1D1P2,data.out_ip_addr_h))
    tg2_rt_int_handle = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.out_ip_addr_h,
                                     gateway=data.out_ip_addr_l[0], netmask='255.255.255.0', arp_send_req='1',count='10', gateway_step='0.0.0.0')
    return tg1_rt_int_handle,tg2_rt_int_handle


def util_tg_stream_config(tg1, tg2, tg_ph_1, tg_ph_2):
    result = {"tg1":{},"tg2":{}}
    st.log("TG1 Stream config")
    tg1_st_nat_dnat_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                                                     pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                     l3_protocol='ipv4',mac_src=data.tg1_src_mac_addr, mac_dst=dut1_rt_int_mac,
                                                     ip_src_addr=data.in1_ip_addr_h[0],ip_dst_addr=data.global_ip_addr)
    result["tg1"]["tg1_st_nat_dnat_data_str_id_1"] = tg1_st_nat_dnat_data_str['stream_id']
    tg1_st_napt_tcp_dnat_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                             pkts_per_burst=data.pkt_count,rate_pps=data.rate_traffic, l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,
                          ip_src_addr=data.in1_ip_addr_h[1], ip_dst_addr=data.global_ip_addr, l4_protocol='tcp',
                          tcp_src_port=data.tcp_src_local_port, tcp_dst_port=data.tcp_dst_local_port)
    result["tg1"]["tg1_st_napt_tcp_dnat_data_str_id_1"] = tg1_st_napt_tcp_dnat_data_str['stream_id']
    tg1_st_nat_snat_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                             pkts_per_burst=data.pkt_count,rate_pps=data.rate_traffic, l3_protocol='ipv4',
                          mac_src=data.tg1_src_mac_addr, mac_dst=dut1_rt_int_mac,
                          ip_src_addr=data.s_global_ip, ip_dst_addr=data.global_ip_addr)
    result["tg1"]["tg1_st_nat_snat_data_str_id_1"] = tg1_st_nat_snat_data_str['stream_id']
    tg1_st_napt_udp_dnat_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create',transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,
                                                          ip_src_addr=data.in1_ip_addr_h[2],
                                                          ip_dst_addr=data.global_ip_addr, l4_protocol='udp',
                                                          udp_src_port=data.udp_src_local_port,
                                                          udp_dst_port=data.udp_dst_local_port)
    result["tg1"]["tg1_st_napt_udp_dnat_data_str_id_1"] = tg1_st_napt_udp_dnat_data_str['stream_id']
    tg1_st_nat_twicenat_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst', pkts_per_burst=data.pkt_count,
                                         rate_pps=data.rate_traffic, l3_protocol='ipv4',
                                         mac_src=data.tg1_src_mac_addr, mac_dst=dut1_rt_int_mac,
                                         ip_src_addr=data.in1_ip_addr_h[3],ip_dst_addr=data.tw_test_ip_addr)
    result["tg1"]["tg1_st_nat_twicenat_data_str_id_1"] = tg1_st_nat_twicenat_data_str['stream_id']
    tg1_dyn_nat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,
                                                          ip_src_addr=data.in1_ip_addr_h[-1],
                                                          ip_dst_addr=data.global_ip_addr, l4_protocol='udp',
                                                           udp_src_port=data.local_src_port[0],
                                                           udp_dst_port=data.local_dst_port[0])
    result["tg1"]["tg1_dyn_nat_udp_data_str_id_1"] = tg1_dyn_nat_udp_data_str['stream_id']

    st.log("TG2 Stream config")
    tg2_st_nat_dnat_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst',
                            pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic, l3_protocol='ipv4',
                            mac_src=data.tg2_src_mac_addr,mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                            ip_dst_addr=data.out_ip_addr_l[0])
    result["tg2"]["tg2_st_nat_dnat_data_str_id_1"] = tg2_st_nat_dnat_data_str['stream_id']
    tg2_st_napt_tcp_dnat_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst',
                             pkts_per_burst=data.pkt_count,rate_pps=data.rate_traffic, l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr, ip_dst_addr=data.out_ip_addr_l[1],
                          l4_protocol='tcp',tcp_src_port=data.tcp_dst_global_port, tcp_dst_port=data.tcp_src_global_port)
    result["tg2"]["tg2_st_napt_tcp_dnat_data_str_id_1"] = tg2_st_napt_tcp_dnat_data_str['stream_id']
    tg2_st_nat_snat_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst',
                             pkts_per_burst=data.pkt_count,rate_pps=data.rate_traffic, l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,ip_dst_addr=data.s_local_ip)
    result["tg2"]["tg2_st_nat_snat_data_str_id_1"] = tg2_st_nat_snat_data_str['stream_id']
    tg2_st_napt_udp_dnat_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst',
                             pkts_per_burst=data.pkt_count,rate_pps=data.rate_traffic, l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr, ip_dst_addr=data.out_ip_addr_l[2],
                          l4_protocol='udp',udp_src_port=data.udp_dst_global_port, udp_dst_port=data.udp_src_global_port)
    result["tg2"]["tg2_st_napt_udp_dnat_data_str_id_1"] = tg2_st_napt_udp_dnat_data_str['stream_id']
    tg2_st_nat_twicenat_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='single_burst', pkts_per_burst=data.pkt_count,
                                         rate_pps=data.rate_traffic, l3_protocol='ipv4',
                                         mac_src=data.tg2_src_mac_addr, mac_dst=dut1_rt_int_mac,
                                         ip_src_addr=data.tw_global_ip_addr,ip_dst_addr=data.out_ip_addr_l[3])
    result["tg2"]["tg2_st_nat_twicenat_data_str_id_1"] = tg2_st_nat_twicenat_data_str['stream_id']
    tg2_dyn_nat_udp_1_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0],l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result["tg2"]["tg2_dyn_nat_udp_1_data_str_id_1"] = tg2_dyn_nat_udp_1_data_str['stream_id']
    tg2_dyn_nat_udp_2_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0], l4_protocol='udp',udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result["tg2"]["tg2_dyn_nat_udp_2_data_str_id_1"] = tg2_dyn_nat_udp_2_data_str['stream_id']
    tg2_dyn_nat_udp_3_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result["tg2"]["tg2_dyn_nat_udp_3_data_str_id_1"] = tg2_dyn_nat_udp_3_data_str['stream_id']
    tg2_dyn_nat_udp_4_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result["tg2"]["tg2_dyn_nat_udp_4_data_str_id_1"] = tg2_dyn_nat_udp_4_data_str['stream_id']
    return result


def tg2_str_selector(trn_ip, trn_port):
    ip1 = data.out_ip_pool[0]
    ip2 = data.out_ip_pool[1]
    p1 = data.global_dst_port[0]
    p2 = data.global_dst_port[1]
    s1 = tg_str_data["tg2"]["tg2_dyn_nat_udp_1_data_str_id_1"]
    s2 = tg_str_data["tg2"]["tg2_dyn_nat_udp_2_data_str_id_1"]
    s3 = tg_str_data["tg2"]["tg2_dyn_nat_udp_3_data_str_id_1"]
    s4 = tg_str_data["tg2"]["tg2_dyn_nat_udp_4_data_str_id_1"]
    tg2_stream_map = {s1: [ip1, p1], s2: [ip1, p2], s3: [ip2, p1], s4:[ip2, p2]}
    for k, v in tg2_stream_map.items():
        if v ==[trn_ip, trn_port]:
            return k


def util_pkt_cap(tg_tx, tg_rx, tx_p_h, rx_p_h, str_h, offset_list=[], value_list=[]):
    tg_rx.tg_packet_control(port_handle=rx_p_h, action='start')
    tg_tx.tg_traffic_control(action='run', handle=str_h)
    tg_rx.tg_packet_control(port_handle=rx_p_h, action='stop')
    tg_tx.tg_traffic_control(action='stop', handle=str_h)
    pkt_cap = tg_rx.tg_packet_stats(port_handle=rx_p_h, format='var', output_type='hex')
    st.log(pkt_cap)
    pkt_cap_res = tgapi.validate_packet_capture(tg_type=tg_rx.tg_type, pkt_dict=pkt_cap,
                                                    offset_list=offset_list, value_list=value_list)
    return pkt_cap_res


def util_ip_addr_to_hexa_conv(ipaddr):
    ipaddr_h = hexlify(inet_aton(ipaddr)).upper()
    return ipaddr_h


def util_int_to_hexa_conv(trn_src_port):
    return (hex(int(trn_src_port)))[2:].zfill(4).upper()


def util_nat_debug_fun():
    st.banner("Collecting the needed debug info for failure analysis", width=100)
    intfapi.show_interface_counters_all(vars.D1)
    natapi.show_nat_translations(vars.D1)
    ipapi.get_interface_ip_address(vars.D1)
    arpapi.show_arp(vars.D1)
