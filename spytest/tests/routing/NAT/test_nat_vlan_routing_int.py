
import pytest
import datetime

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj
import apis.routing.nat as nat_obj
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as pc_obj
import apis.system.interface as intf_obj
import apis.qos.acl as acl_obj
import apis.system.basic as basic_obj

import utilities.common as utils
from utilities.parallel import exec_all, ensure_no_exception

data = SpyTestDict()
data.in1_ip_addr = "12.12.0.1"
data.in1_ip_addr_h = ["12.12.0.2", "12.12.0.3", "12.12.0.4","12.12.0.5", "12.12.0.6", "12.12.0.7","12.12.0.8",
                      "12.12.0.9", "12.12.0.10", "12.12.0.11"]
data.in1_ip_addr_rt = "12.12.0.0"
data.in1_ip_addr_mask = "16"
data.in2_ip_addr = "13.13.13.1"
data.in2_ip_addr_h = ["13.13.13.2", "13.13.13.3", "13.13.13.4","13.13.13.5", "13.13.13.6", "13.13.13.7"]
data.in2_ip_addr_rt = "13.13.13.0"
data.in2_ip_addr_mask = "24"
data.in3_ip_addr = "23.1.0.1"
data.in3_ip_addr_h = ["23.1.0.2", "23.1.0.3", "23.1.0.4"]
data.in3_ip_addr_rt = "23.1.0.0"
data.in3_ip_addr_mask = "16"
data.out_ip_addr = "125.56.90.12"
data.out_ip_addr_l = ["125.56.90.13", "125.56.90.14", "125.56.90.15", "125.56.90.16"]
data.out_ip_addr_h = "125.56.90.1"
data.out_ip_range = "125.56.90.23-125.56.90.24"
data.out_ip_pool = ["125.56.90.23", "125.56.90.24"]
data.out_ip_addr_rt = "125.56.90.0"
data.out_ip_addr_mask = "24"
data.out2_ip_addr = "85.16.0.49"
data.out2_ip_addr_l = ["85.16.0.50", "85.16.0.51","85.16.0.52", "85.16.0.53", "85.16.0.54"]
data.out2_ip_addr_h = "85.16.0.1"
data.out2_ip_range = "85.16.0.55-85.16.0.56"
data.out2_ip_pool =["85.16.0.55", "85.16.0.56"]
data.out2_ip_addr_rt = "85.16.0.0"
data.out2_ip_addr_mask = "24"
data.global_ip_addr_h = "129.2.30.1"
data.global_ip_addr = "129.2.30.12"
data.global_ip_addr_rt = "129.2.30.0"
data.global_ip_addr_mask = "24"
data.global2_ip_addr_h = "149.2.30.13"
data.global2_ip_addr = "149.2.30.12"
data.global2_ip_addr_rt = "149.2.30.0"
data.global2_ip_addr_mask = "24"
data.tw_global_ip_addr = "99.99.99.1"
data.tw_global_ip_addr_rt = "99.99.99.0"
data.tw_global_ip_addr_mask = "24"
data.tw_test_ip_addr = "15.15.0.1"
data.tw_test_ip_addr_mask = "16"
data.tw_test_ip_addr_rt = "15.15.0.0"
data.test_ip_addr = "22.22.22.1"
data.test_ip_addr_mask = "16"
data.test_ip_addr_rt = "22.22.0.0"
data.s_local_ip = "11.11.11.2"
data.s_local_ip_route = "11.11.0.0"
data.s_local_ip_mask = "16"
data.s_global_ip = "88.98.128.2"
data.proto_all = "all"
data.proto_tcp = "tcp"
data.proto_udp = "udp"
data.zone_1 = "0"
data.zone_2 = "1"
data.zone_3 = "2"
data.zone_4 = "3"
data.pool_name = ["pool_nat_1", "88912_pool", "123Pool"]
data.bind_name = ["bind_1", "7812_bind", "bind_11"]
data.global_port_range = "333-334"
data.local_src_port = ["251", "252"]
data.local_dst_port = ["444", "8991"]
data.global_src_port = ["12001", "7781"]
data.global_dst_port = ["333", "334"]
data.tw_global_port_range = "101-102"
data.tw_global_dst_port = ["101", "102"]
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
data.vlan_list = utils.random_vlan_list(4)
data.vlan_int_1 = "Vlan{}".format(str(data.vlan_list[0]))
data.vlan_int_2 = "Vlan{}".format(str(data.vlan_list[1]))
data.vlan_int_3 = "Vlan{}".format(str(data.vlan_list[2]))
data.vlan_int_4 = "Vlan{}".format(str(data.vlan_list[3]))
data.port_channel = "PortChannel100"
data.l2_source_mac = "00:00:00:EA:23:0F"
data.l2_destination_mac = "00:00:11:0A:45:33"
data.rate_pkt_cap = '5'
data.rate_traffic = '1500'
data.pkt_count = '1500'
data.host_mask = '32'
data.mask_2 = '24'
data.high_priority = '9999'
data.low_priority = '5'
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
data.tg1_src_mac_addr = '00:00:23:11:14:08'
data.tg2_src_mac_addr = '00:00:23:1B:14:07'
data.tg3_src_mac_addr = '00:00:43:32:1A:01'
data.wait_nat_stats = 7
data.wait_time_traffic_run = 3
data.wait_time_to_no_shut = 30
data.wait_nat_tcp_timeout = 60
data.wait_nat_udp_timeout = 60
data.wait_aclrule_stats = 10
data.config_add='add'
data.config_del='del'
data.twice_nat_id_1 = '7100'
data.mask = '32'
data.max_nat_entries = "1024"
dut1_rt_int_mac = None
dut2_rt_int_mac = None

@pytest.fixture(scope="module", autouse=True)
def nat_vlan_module_config(request):
    nat_vlan_pre_config()
    yield
    nat_vlan_post_config()


@pytest.fixture(scope="function", autouse=True)
def nat_vlan_func_hooks(request):
    utils.exec_all(True,
                   [[intf_obj.clear_interface_counters, vars.D1], [intf_obj.clear_interface_counters, vars.D2]])
    yield
    if st.get_func_name(request) == "test_ft_dynamic_napt_acl_modifiy":
        acl_obj.delete_acl_rule(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_out_nat_eg, acl_rule_name="rule-no-nat-150")
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_out_nat_eg)


@pytest.mark.nat_vlan_regression
def test_ft_static_napt_vlan():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective - Verify the static NAPT functionality over vlan routing interfaces
    # #################################################
    nat_obj.clear_nat(vars.D1, statistics=True)
    acl_obj.clear_acl_counter(vars.D1, acl_type=data.type)
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_st_napt_tcp_dnat_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_st_napt_tcp_dnat_data_str_id_1"])
    tg3.tg_traffic_control(action='run', handle=tg_str_data[3]["tg3_st_napt_tcp_dnat_data_str_id_1"])
    tg3.tg_traffic_control(action='stop', handle=tg_str_data[3]["tg3_st_napt_tcp_dnat_data_str_id_1"])
    count = data.pkt_count
    result = acl_obj.poll_for_acl_counters(vars.D1, acl_table= data.acl_table_out_nat_eg, acl_rule='rule-2', acl_type=data.type)
    if not result:
        st.error("Received empty list, acl counters not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("snat_translation_failed_in_packet", data.in1_ip_addr_h[1], data.out_ip_addr)
    if not (int(result[0]['packetscnt']) > (0.90 * (int(count)))):
        util_nat_vlan_debug_fun()
        st.report_fail("snat_translation_failed_in_packet",data.in1_ip_addr_h[1],data.out_ip_addr)
    nat_stats = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_tcp, dst_ip=data.out_ip_addr, dst_ip_port=data.tcp_src_global_port)
    if not nat_stats:
        st.error("Received empty list, acl counters not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr, data.in1_ip_addr_h[1])
    if not (int(nat_stats[0]['packets']) > (0.90 * (int(count)))):
        util_nat_vlan_debug_fun()
        st.report_fail("dnat_translation_fail_in_packet", data.out_ip_addr, data.in1_ip_addr_h[1])
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_napt_vlan_udp():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective - Verify dynamic NAPT functionality over vlan routing interfaces with acl bind to pool.
    # Also verify dynamic entry convertion to static entry.
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    st.log("Traffic for snat case")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    count = data.pkt_count
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in1_ip_addr_h[-1],src_ip_port=data.local_src_port[0])
    if not trn_val:
        st.error("Received empty list,nat translation table not updated")
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    tg3_str_obj = tg3_vlan_str_selector(trn_src_ip, trn_src_port)
    st.log("Traffic for dnat case")
    tg3.tg_traffic_control(action='run', handle=tg3_str_obj)
    tg3.tg_traffic_control(action='stop', handle=tg3_str_obj)
    st.wait(12)
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                src_ip=data.in1_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        st.error("Received empty list,nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    if not int(nat_stats_s[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=trn_src_ip,dst_ip_port=trn_src_port)
    if not nat_stats_d:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail",data.out_ip_pool[0],data.out_ip_pool[0])
    if not int(nat_stats_d[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail",data.out_ip_pool[0],data.out_ip_pool[0])
    st.log("dynamic to static nat conversion")
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_udp, global_ip=trn_src_ip, global_port_id=trn_src_port,
                              local_ip=data.in1_ip_addr_h[-1], local_port_id=data.local_src_port[0],
                              config=data.config_add, nat_type=data.nat_type_dnat)
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.in1_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_udp, global_ip=trn_src_ip,global_port_id=trn_src_port,
                              local_ip=data.in1_ip_addr_h[-1],local_port_id=data.tcp_src_local_port,
                              config=data.config_del, nat_type=data.nat_type_dnat)
    if not nat_stats_s:
        st.error("Received empty list,nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    if not int(nat_stats_s[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_nat_napt_multi_pool():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective -Verify dynamic NAPT functionality with ACL binding to NAT Pool with two different NAT Pools.
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    st.log("Traffic for snat case")
    tg2.tg_traffic_control(action='run', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    tg2.tg_traffic_control(action='stop', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    count = data.pkt_count
    st.wait(data.wait_nat_stats)
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in2_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])
    if not trn_val:
        st.error("Received empty list,nat translation table not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    tg3_str_obj = tg3_vlan_str_selector(trn_src_ip, trn_src_port)
    st.log("Traffic for dnat case")
    tg3.tg_traffic_control(action='run', handle=tg3_str_obj)
    tg3.tg_traffic_control(action='stop', handle=tg3_str_obj)
    st.wait(data.wait_nat_stats)
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.in2_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        st.error("Received empty list,nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    if not int(nat_stats_s[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=trn_src_ip,
                                                  dst_ip_port=trn_src_port)
    if not nat_stats_d:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out2_ip_pool[0], data.in2_ip_addr_h[-1])
    if not int(nat_stats_d[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out2_ip_pool[0], data.in2_ip_addr_h[-1])
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_napt_nh_resolve():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective - Verify the NAT functionality when nexthop entries are cleared and resolved again.
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    st.log("clearing ARP table and Resolving NH entries again")
    arp_obj.clear_arp_table(vars.D1)
    if not ip_obj.ping(vars.D1, data.in2_ip_addr_h[-1], family='ipv4',count=3):
        util_nat_vlan_debug_fun()
        st.report_fail("ping_fail",data.in2_ip_addr,data.in2_ip_addr_h[-1])
    if not ip_obj.ping(vars.D1, data.in1_ip_addr_h[-1], family='ipv4', count=3):
        util_nat_vlan_debug_fun()
        st.report_fail("ping_fail", data.in1_ip_addr, data.in1_ip_addr_h[-1])
    st.log("Traffic for snat case")
    tg2.tg_traffic_control(action='run', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    tg2.tg_traffic_control(action='stop', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    count = data.pkt_count
    st.wait(data.wait_nat_stats)
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in2_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])
    if not trn_val:
        st.error("Received empty list,nat translation table not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    tg3_str_obj = tg3_vlan_str_selector(trn_src_ip, trn_src_port)
    st.log("Traffic for dnat case")
    tg3.tg_traffic_control(action='run', handle=tg3_str_obj)
    tg3.tg_traffic_control(action='stop', handle=tg3_str_obj)
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.in2_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        st.error("Received empty list,nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    if not int(nat_stats_s[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=trn_src_ip,
                                                  dst_ip_port=trn_src_port)
    if not nat_stats_d:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out2_ip_pool[0], data.in2_ip_addr_h[-1])
    if not int(nat_stats_d[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out2_ip_pool[0], data.in2_ip_addr_h[-1])
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_nat_ip_addr_change():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective -Verify the dynamic NAPT functionality after removing and re adding the global ipv4 address.
    # #################################################
    cli_type=st.get_ui_type(vars.D1)
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'

    #Enable zebra debug
    debug_zebra(vars.D1, config='yes')

    ip_obj.config_unconfig_interface_ip_addresses(vars.D1, nat_if_data_list_1, config='remove', cli_type=cli_type, ip_type="secondary")
    ip_obj.config_ip_addr_interface(vars.D1, data.vlan_int_3, data.out2_ip_addr, data.out2_ip_addr_mask,
                                    family=data.af_ipv4, config='remove', cli_type=cli_type)
    ip_obj.config_ip_addr_interface(vars.D1, data.vlan_int_3, data.out2_ip_addr, data.out2_ip_addr_mask,
                                    family=data.af_ipv4, config='add', cli_type=cli_type)
    ip_obj.config_unconfig_interface_ip_addresses(vars.D1, nat_if_data_list_1, config='add', cli_type=cli_type, ip_type="secondary")
    nat_obj.config_nat_interface(vars.D1, interface_name=data.vlan_int_3, zone_value=data.zone_3, config=data.config_add)
    st.log("After remove and re add check nat translation table updating or not")
    st.log("Traffic for snat case")
    tg2.tg_traffic_control(action='run', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    tg2.tg_traffic_control(action='stop', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    count = data.pkt_count
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in2_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])
    if not trn_val:
        st.error("Received empty list,nat translation table not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.in2_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        st.error("Received empty list,nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out_ip_pool[0])
    if not int(nat_stats_s[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out_ip_pool[0])
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_napt_acl_modifiy():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective -Validate the ACL modifications are gracefully handled
    # #################################################
    acl_ingress_config('VLAN')
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    st.log("Traffic for snat case")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    count = data.pkt_count
    # Waiting for acl counters to get updated, acl counters get update once in every 10 seconds
    st.wait(data.wait_aclrule_stats)
    result = acl_obj.poll_for_acl_counters(vars.D1, acl_rule='rule-no-nat-150', acl_type=data.type)
    if not result:
        st.error("Received empty list, acl counters not updated")
        util_nat_vlan_debug_fun()
        acl_ingress_config('BOTH')
        st.report_fail("nat_translation_happening_in_no_nat_case")
    if not (int(result[0]['packetscnt']) > (0.90 * (int(count)))):
        util_nat_vlan_debug_fun()
        acl_ingress_config('BOTH')
        st.report_fail("nat_translation_happening_in_no_nat_case")
    st.log("Deleting acl rule with packet action as do_no_nat")
    acl_obj.delete_acl_rule(vars.D1, acl_table_name=data.acl_table_in_nat_eg, acl_rule_name="rule-33", acl_type=data.type)
    st.log("Adding acl rule with packet action as forward")
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                            packet_action=data.packet_forward_action,
                            SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', acl_type=data.type, ip_protocol="4")
    st.log("checking nat translation for above rule")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip='14.1.0.1',
                                           src_ip_port=data.local_src_port[0])
    if not trn_val:
        acl_obj.delete_acl_rule(vars.D1, acl_table_name=data.acl_table_in_nat_eg, acl_rule_name="rule-33", acl_type=data.type)
        acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                                packet_action=data.packet_do_not_nat_action,
                                SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', acl_type=data.type, ip_protocol="4")
        st.error("Received empty list,nat translation table not updated")
        util_nat_vlan_debug_fun()
        acl_ingress_config('BOTH')
        st.report_fail("dynamic_snat_translation_entry_create_fail", "14.1.0.1", data.out2_ip_pool[0])
    st.log("Deleting acl rule with packet action as forward")
    acl_obj.delete_acl_rule(vars.D1, acl_table_name=data.acl_table_in_nat_eg, acl_rule_name="rule-33", acl_type=data.type)
    nat_obj.clear_nat(vars.D1, translations=True)
    st.log("Adding acl rule with packet action as do_not_nat")
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                            packet_action=data.packet_do_not_nat_action,
                            SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', acl_type=data.type, ip_protocol="4")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    # Waiting for acl counters to get updated, acl counters get update once in every 10 seconds
    st.wait(data.wait_aclrule_stats)
    result = acl_obj.poll_for_acl_counters(vars.D1, acl_rule='rule-no-nat-150', acl_type=data.type)
    if not result:
        st.error("Received empty list, acl counters not updated")
        util_nat_vlan_debug_fun()
        acl_ingress_config('BOTH')
        st.report_fail("nat_translation_happening_in_no_nat_case")
    if not (int(result[0]['packetscnt']) > (0.90 * (int(count)))):
        util_nat_vlan_debug_fun()
        acl_ingress_config('BOTH')
        st.report_fail("nat_translation_happening_in_no_nat_case")

    acl_ingress_config('BOTH')
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_napt_acl_bind_remove_reapply():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective -Verify the dynamic NAPT functionality after remove and reapply the acl binding to pool.
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    st.log("Removing acl bind")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_del)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_del)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0], config=data.config_add)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],  config=data.config_add)
    st.log("Deleting acl rule with packet action as do_no_nat")
    acl_obj.delete_acl_rule(vars.D1, acl_table_name=data.acl_table_in_nat_eg, acl_type=data.type, acl_rule_name="rule-33")
    st.log("Adding acl rule with packet action as forward")
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                            packet_action=data.packet_forward_action,
                            SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', acl_type=data.type, ip_protocol="4")
    st.log("Traffic for snat case")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip='14.1.0.1', src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        st.error("Received empty list,nat statistics are not updated")
        util_nat_vlan_debug_fun()
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                        acl_name=data.acl_table_in_nat_eg, config=data.config_add)
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                        acl_name=data.acl_table_in_nat_eg, config=data.config_add)
        st.report_fail("dynamic_snat_translation_entry_create_fail", '14.1.0.1', data.out_ip_pool[0])
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    st.log("Deleting acl rule with packet action as forward")
    acl_obj.delete_acl_rule(vars.D1, acl_table_name=data.acl_table_in_nat_eg, acl_rule_name="rule-33", acl_type=data.type)
    nat_obj.clear_nat(vars.D1, translations=True)
    st.log("Adding acl rule with packet action as do_not_nat")
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                            packet_action=data.packet_do_not_nat_action,
                            SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', acl_type=data.type, ip_protocol="4")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_no_nat_udp_data_str_id_1"])
    nat_stats_s = nat_obj.get_nat_statistics(vars.D1, protocol=data.proto_udp.upper(),
                                                  src_ip='14.1.0.1', src_ip_port=data.local_src_port[0])
    if nat_stats_s:
        util_nat_vlan_debug_fun()
        st.report_fail("nat_translation_happening_in_no_nat_case")
    st.log("Traffic for snat case for {}".format(data.pool_name[1]))
    tg2.tg_traffic_control(action='run', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    tg2.tg_traffic_control(action='stop', handle=tg_str_data[2]["tg2_dyn_nat_udp_data_str_id_1"])
    count = data.pkt_count
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in2_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])
    if not trn_val:
        st.error("Received empty list,nat translation table not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in2_ip_addr_h[-1], data.out2_ip_pool[0])
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    tg3_str_obj = tg3_vlan_str_selector(trn_src_ip, trn_src_port)
    st.log("Traffic for dnat case")
    tg3.tg_traffic_control(action='run', handle=tg3_str_obj)
    tg2.tg_traffic_control(action='stop', handle=tg3_str_obj)
    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=trn_src_ip,
                                                  dst_ip_port=trn_src_port)
    if not nat_stats_d:
        st.error("Received empty list, nat statistics are not updated")
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out2_ip_pool[0], data.in2_ip_addr_h[-1])
    if not int(nat_stats_d[0]['packets']) >= (0.80 * (int(count))):
        util_nat_vlan_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out2_ip_pool[0], data.in2_ip_addr_h[-1])
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_twicenat_napt():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective - Verify dynamic twicenat napt functionality
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    result_flag = 0
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_del)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name="twicenat_pool",
                                    acl_name=data.acl_table_in_nat_eg,twice_nat_id=data.twice_nat_id_1,
                                    config=data.config_add)
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_dyn_twicenat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_dyn_twicenat_udp_data_str_id_1"])
    count = data.pkt_count
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in1_ip_addr_h[-2],
                                           src_ip_port=data.local_src_port[1])
    if not trn_val:
        util_nat_vlan_debug_fun()
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name="twicenat_pool",
                                        acl_name=data.acl_table_in_nat_eg, twice_nat_id=data.twice_nat_id_1,
                                        config=data.config_del)
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                        acl_name=data.acl_table_in_nat_eg, config=data.config_add)
        st.error("Received empty list,nat translation table not updated")
        st.report_fail("twicenat_translation_failed_in_packet")
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    tg3_str_obj = tg3_vlan_str_selector(trn_src_ip, trn_src_port)
    st.log("Traffic for dnat case")
    tg3.tg_traffic_control(action='run', handle=tg3_str_obj)
    tg3.tg_traffic_control(action='stop', handle=tg3_str_obj)
    st.wait(data.wait_nat_stats)
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.in1_ip_addr_h[-2],
                                                  src_ip_port=data.local_src_port[1], dst_ip=data.tw_test_ip_addr,
                                                  dst_ip_port="40000")
    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.tw_global_ip_addr,
                                                  src_ip_port="50000", dst_ip=trn_src_ip, dst_ip_port=trn_src_port)
    if not nat_stats_s:
        util_nat_vlan_debug_fun()
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name="twicenat_pool",
                                        acl_name=data.acl_table_in_nat_eg, twice_nat_id=data.twice_nat_id_1,
                                        config=data.config_del)
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                        acl_name=data.acl_table_in_nat_eg, config=data.config_add)
        st.error("Received empty list,nat statistics are not updated")
        st.report_fail("twicenat_translation_failed_in_packet")
    if not nat_stats_d:
        util_nat_vlan_debug_fun()
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name="twicenat_pool",
                                        acl_name=data.acl_table_in_nat_eg, twice_nat_id=data.twice_nat_id_1,
                                        config=data.config_del)
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                        acl_name=data.acl_table_in_nat_eg, config=data.config_add)
        st.error("Received empty list,nat statistics are not updated")
        st.report_fail("twicenat_translation_failed_in_packet")
    if not int(nat_stats_s[0]['packets']) >= (0.80 * (int(count))):
        result_flag = 1
    if not int(nat_stats_d[0]['packets']) >= (0.80 * (int(count))):
        result_flag = 1
    if result_flag:
        util_nat_vlan_debug_fun()
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name="twicenat_pool",
                                        acl_name=data.acl_table_in_nat_eg, twice_nat_id=data.twice_nat_id_1,
                                        config=data.config_del)
        nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                        acl_name=data.acl_table_in_nat_eg, config=data.config_add)
        st.report_fail("twicenat_translation_failed_in_packet")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name="twicenat_pool",
                                    acl_name=data.acl_table_in_nat_eg, twice_nat_id=data.twice_nat_id_1,
                                    config=data.config_del)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_nat_ping():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective -Validate ping operation is successful across nat zones.
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    st.log("check ping - from DUT to global ip address")
    if not ip_obj.ping(vars.D1, data.global_ip_addr_h, family='ipv4',count=3):
        util_nat_vlan_debug_fun()
        st.report_fail("ping_fail_across_nat_zone")
    st.log("check ping - from inside host to global ip address")
    res = tgapi.verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=tg_rt_int_handle[0]['handle'][0], dst_ip=data.global_ip_addr, \
                      ping_count='3', exp_count='3')
    if not res:
        util_nat_vlan_debug_fun()
        st.report_fail("ping_fail_across_nat_zone")
    st.report_pass("test_case_passed")


@pytest.mark.nat_vlan_regression
def test_ft_dynamic_nat_scale():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective - (i) test_ft_dynamic_nat_scale - Verify dynamic napt scaling.
    # (ii) FtOpSoRoNatPe001 - Verify nat entry learning rate and throughput.
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    result_flag=0
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_del)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name="scale_bind", pool_name="scale_pool",
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    st.log("Sending continuous traffic at 600 pps for the max dynamic nat entries to get learned")
    # Taking the Start time timestamp
    start_time = datetime.datetime.now()
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    st.log("Waiting for traffic to run, such that max nat entries get learned")
    if not util_check_nat_translations_count(vars.D1,20,data.max_nat_entries):
        st.log("Failed to learn max nat entries")
        result_flag = 1
    # Taking the End time timestamp
    end_time = datetime.datetime.now()
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    # Time taken for max SNAT entries learning
    st.log("Start Time: {}".format(start_time))
    st.log("End Time: {}".format(end_time))
    time_in_secs = end_time - start_time
    st.log("Time taken for max SNAT entries learning = " + str(time_in_secs.seconds))
    st.log("Checking the throughput with max NAT entries")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    st.wait(data.wait_time_traffic_run)
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg3],
             }
                      }

    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        st.log("Traffic loss observed for the SNAT traffic")
        util_nat_vlan_debug_fun()
        result_flag = 1
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name="scale_bind", pool_name="scale_pool",
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_del)
    if result_flag:
        st.report_fail("dynamic_nat_scaling_failed")
    st.report_pass("test_case_passed")


def util_tg_init(vars, tg_port_list):
    tg_port_list = list(tg_port_list) if isinstance(tg_port_list, list) else [tg_port_list]
    tg_handler = tgapi.get_handles(vars, tg_port_list)
    return tg_handler


def nat_vlan_tg_config():
    global tg_handler, tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3, tg_str_data, tg_rt_int_handle
    tg_handler = util_tg_init(vars, [vars.T1D1P1, vars.T1D1P2, vars.T1D2P1])
    tg1 = tg_handler["tg"]
    tg2 = tg_handler["tg"]
    tg3 = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_3 = tg_handler["tg_ph_3"]
    # TG routing interface config
    tg_rt_int_handle = util_tg_vlan_routing_int_config(vars, tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3)
    tg_str_data = util_tg_vlan_stream_config(tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3)


def nat_vlan_dut_config():
    global dut1_rt_int_mac, dut2_rt_int_mac, nat_if_data_list_1, nat_if_data_list
    pc_obj.config_portchannel(vars.D1, vars.D2, "PortChannel009", [vars.D1D2P1, vars.D1D2P2],
                              [vars.D2D1P1, vars.D2D1P2], config='add', thread=True)
    # vlan config
    utils.exec_all(True, [[vlan_obj.create_vlan, vars.D1, [data.vlan_list[0], data.vlan_list[1],
                                                           data.vlan_list[2]]],
                          [vlan_obj.create_vlan, vars.D2, [data.vlan_list[1], data.vlan_list[2]]]])
    utils.exec_all(True, [
        [vlan_mem_cfg, vars.D1, [[data.vlan_list[0], vars.D1T1P1, True], [data.vlan_list[1], vars.D1D2P3, True],
                                 [data.vlan_list[2], "PortChannel009", True]]],
        [vlan_mem_cfg, vars.D2, [[data.vlan_list[1], vars.D2D1P3, True], [data.vlan_list[2], "PortChannel009", True]]]])

    # Routing interface config
    thread1_list = []
    thread2_list = []
    thread1_list.append(utils.ExecAllFunc(ip_obj.config_ip_addr_interface, vars.D1, vars.D1T1P2, data.in2_ip_addr,
                                          data.in2_ip_addr_mask, family=data.af_ipv4))
    thread1_list.append(utils.ExecAllFunc(ip_obj.config_ip_addr_interface, vars.D2, data.vlan_int_2, data.out_ip_addr_h,
                                          data.out_ip_addr_mask,
                                          family=data.af_ipv4))
    thread2_list.append(utils.ExecAllFunc(ip_obj.config_ip_addr_interface, vars.D1, data.vlan_int_1, data.in1_ip_addr,
                                          data.in1_ip_addr_mask, family=data.af_ipv4))
    thread2_list.append(
        utils.ExecAllFunc(ip_obj.config_ip_addr_interface, vars.D2, vars.D2T1P1, data.global_ip_addr_h,
                          data.global_ip_addr_mask))
    [out, exceptions] = utils.exec_all(True, thread1_list)
    st.log([out, exceptions])
    [out, exceptions] = utils.exec_all(True, thread2_list)
    st.log([out, exceptions])

    cli_type=st.get_ui_type(vars.D1)
    if cli_type in ['rest-patch', 'rest-put']:
        cli_type = 'klish'

    ip_obj.config_ip_addr_interface(vars.D1, data.vlan_int_2, data.out_ip_addr, data.out_ip_addr_mask,
                                    family=data.af_ipv4, config='add', cli_type=cli_type)
    nat_if_data_list = []
    for i in range(0, len(data.out_ip_addr_l)):
        nat_if_data_list.append({'name': data.vlan_int_2, 'ip': data.out_ip_addr_l[i], 'subnet': data.out_ip_addr_mask,
                                 'family': data.af_ipv4})
    for i in range(0, len(data.out_ip_pool)):
        nat_if_data_list.append({'name': data.vlan_int_2, 'ip': data.out_ip_pool[i], 'subnet': data.out_ip_addr_mask,
                                 'family': data.af_ipv4})
    ip_obj.config_unconfig_interface_ip_addresses(vars.D1, nat_if_data_list, config='add', cli_type=cli_type, ip_type="secondary")

    ip_obj.config_ip_addr_interface(vars.D1, data.vlan_int_3, data.out2_ip_addr, data.out2_ip_addr_mask,
                                    family=data.af_ipv4, config='add', cli_type=cli_type)
    nat_if_data_list_1 = []
    for i in range(0, len(data.out2_ip_addr_l)):
        nat_if_data_list_1.append(
            {'name': data.vlan_int_3, 'ip': data.out2_ip_addr_l[i], 'subnet': data.out2_ip_addr_mask,
             'family': data.af_ipv4})
    for i in range(0, len(data.out2_ip_pool)):
        nat_if_data_list_1.append(
            {'name': data.vlan_int_3, 'ip': data.out2_ip_pool[i], 'subnet': data.out2_ip_addr_mask,
             'family': data.af_ipv4})
    ip_obj.config_unconfig_interface_ip_addresses(vars.D1, nat_if_data_list_1, config='add', cli_type=cli_type, ip_type="secondary")
    ip_obj.config_ip_addr_interface(vars.D2, data.vlan_int_3, data.out2_ip_addr_h, data.out2_ip_addr_mask,
                                    family=data.af_ipv4, cli_type=cli_type)
    # Get DUT mac address
    [rt_int_mac, exceptions] = utils.exec_all(True, [[basic_obj.get_ifconfig_ether, vars.D1, vars.D1T1P1],
                                                     [basic_obj.get_ifconfig_ether, vars.D2, vars.D2T1P1]])
    for value in exceptions:
        if value is not None:
            st.log("Exceptions observed {}".format(value))
            st.error("Exceptions observed while getting mac address of routing interface")
    dut1_rt_int_mac = rt_int_mac[0]
    dut2_rt_int_mac = rt_int_mac[1]
    # Static Route config
    ip_obj.create_static_route(vars.D1, data.out_ip_addr_h,
                               "{}/{}".format(data.global_ip_addr_rt, data.global_ip_addr_mask))
    utils.exec_all(True, [[ip_obj.create_static_route, vars.D1, data.out2_ip_addr_h,
                           "{}/{}".format(data.global2_ip_addr_rt, data.global2_ip_addr_mask)],
                          [ip_obj.create_static_route, vars.D2, data.global_ip_addr_h,
                           "{}/{}".format(data.global2_ip_addr_rt, data.global2_ip_addr_mask)]])
    utils.exec_all(True, [[ip_obj.create_static_route, vars.D1, data.out_ip_addr_h,
                           "{}/{}".format(data.tw_global_ip_addr_rt, data.tw_global_ip_addr_mask)],
                          [ip_obj.create_static_route, vars.D2, data.global_ip_addr_h,
                           "{}/{}".format(data.tw_global_ip_addr_rt, data.tw_global_ip_addr_mask)]])
    utils.exec_all(True, [[ip_obj.create_static_route, vars.D1, data.out_ip_addr_h,
                           "{}/{}".format(data.tw_test_ip_addr_rt, data.tw_test_ip_addr_mask)],
                          [ip_obj.create_static_route, vars.D2, data.global_ip_addr_h,
                           "{}/{}".format(data.tw_test_ip_addr_rt, data.tw_test_ip_addr_mask)]])

    st.log("NAT Configuration")
    nat_obj.config_nat_feature(vars.D1)
    util_nat_zone_config(vars, [data.vlan_int_1, data.vlan_int_2, data.vlan_int_3],
                         [data.zone_1, data.zone_2, data.zone_3], config=data.config_add)
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_tcp, global_ip=data.out_ip_addr,
                              local_ip=data.in1_ip_addr_h[1],
                              local_port_id=data.tcp_src_local_port, global_port_id=data.tcp_src_global_port,
                              config=data.config_add, nat_type=data.nat_type_dnat)
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_udp, global_ip=data.tw_global_ip_addr,
                              local_ip=data.tw_test_ip_addr, local_port_id="40000", global_port_id="50000",
                              config=data.config_add, nat_type=data.nat_type_snat, twice_nat_id=data.twice_nat_id_1)
    # dynamic NAT config
    st.log("Creating NAT Pools")
    nat_obj.config_nat_pool(vars.D1, pool_name=data.pool_name[0], global_ip_range=data.out2_ip_range,
                            global_port_range=data.global_port_range, config=data.config_add)
    nat_obj.config_nat_pool(vars.D1, pool_name=data.pool_name[1], global_ip_range=data.out_ip_range,
                            global_port_range=data.global_port_range, config=data.config_add)
    nat_obj.config_nat_pool(vars.D1, pool_name="scale_pool", global_ip_range="125.56.90.23-125.56.90.30",
                            global_port_range="1001-8001", config=data.config_add)
    nat_obj.config_nat_pool(vars.D1, pool_name="twicenat_pool", global_ip_range="125.56.90.23",
                            global_port_range=data.tw_global_port_range, config=data.config_add)
    # nat acl for ingress traffic
    acl_obj.create_acl_table(vars.D1, name=data.acl_table_in_nat_eg, stage="INGRESS", type=data.type,
                             description="ingress-acl", ports=[data.vlan_int_1, vars.D1T1P2])
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-31",
                            packet_action=data.packet_forward_action,
                            SRC_IP="{}/{}".format(data.in2_ip_addr_rt, data.in2_ip_addr_mask), priority='99', type=data.type, ip_protocol="4")
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-32",
                            packet_action=data.packet_forward_action,
                            SRC_IP="{}/{}".format(data.in1_ip_addr_rt, data.in1_ip_addr_mask), priority='98', type=data.type, ip_protocol="4")

    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                            packet_action=data.packet_do_not_nat_action,
                            SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', type=data.type, ip_protocol="4")
    # acl to filter the nat translated packets that egress at inside/outside interface.
    acl_obj.create_acl_table(vars.D1, name=data.acl_table_out_nat_eg, stage="EGRESS", type=data.type,
                             description="egress-acl", ports=[data.vlan_int_2])
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_out_nat_eg, rule_name="rule-2",
                            packet_action=data.packet_forward_action,
                            SRC_IP="{}/{}".format(data.out_ip_addr, data.mask), ip_protocol='6',
                            l4_src_port=data.tcp_src_global_port, priority='101', type=data.type)
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_out_nat_eg, rule_name="rule-no-nat-150",
                            packet_action=data.packet_forward_action,
                            SRC_IP="{}/{}".format("14.1.0.1", data.mask), priority='150', type=data.type, ip_protocol="4")
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_out_nat_eg, rule_name="rule-3",
                            packet_action=data.packet_forward_action,
                            priority='100', type=data.type, ip_protocol="4")
    st.log("Creating NAT Pool binding")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)


def nat_vlan_pre_config():
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:2", "D2T1:1")
    platform = basic_obj.get_hwsku(vars.D1)
    common_constants = st.get_datastore(vars.D1, "constants", "default")
    if platform.lower() in common_constants['TH3_PLATFORMS']:
        st.error("NAT is not supported for this platform {}".format(platform))
        st.report_unsupported('NAT_unsupported_platform',platform)
    [_, exceptions] = exec_all(True, [[nat_vlan_tg_config], [nat_vlan_dut_config]], first_on_main=True)
    ensure_no_exception(exceptions)


def nat_vlan_post_config():
    vars = st.get_testbed_vars()
    #Disable debug for zebra
    debug_zebra(vars.D1, config='no')
    nat_obj.clear_nat_config(vars.D1)
    # Deleted the ACL after NAT binding is removed
    acl_tables = [data.acl_table_nat, data.acl_table_in_nat_eg, data.acl_table_out_nat_eg]
    for acl_table in acl_tables:
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=acl_table)
    nat_obj.config_nat_feature(vars.D1, 'disable')
    ip_obj.delete_static_route(vars.D1, data.out_ip_addr_h,
                               "{}/{}".format(data.global_ip_addr_rt, data.global_ip_addr_mask))
    utils.exec_all(True, [[ip_obj.delete_static_route, vars.D1, data.out2_ip_addr_h,
                               "{}/{}".format(data.global2_ip_addr_rt, data.global2_ip_addr_mask)], [ip_obj.delete_static_route, vars.D2, data.global_ip_addr_h,
                               "{}/{}".format(data.global2_ip_addr_rt, data.global2_ip_addr_mask)]])
    utils.exec_all(True, [[ip_obj.delete_static_route, vars.D1, data.out_ip_addr_h,
                           "{}/{}".format(data.tw_global_ip_addr_rt, data.tw_global_ip_addr_mask)],
                          [ip_obj.delete_static_route, vars.D2, data.global_ip_addr_h,
                           "{}/{}".format(data.tw_global_ip_addr_rt, data.tw_global_ip_addr_mask)]])
    utils.exec_all(True, [[ip_obj.delete_static_route, vars.D1, data.out_ip_addr_h,
                           "{}/{}".format(data.tw_test_ip_addr_rt, data.tw_test_ip_addr_mask)],
                          [ip_obj.delete_static_route, vars.D2, data.global_ip_addr_h,
                           "{}/{}".format(data.tw_test_ip_addr_rt, data.tw_test_ip_addr_mask)]])
    ip_obj.clear_ip_configuration(st.get_dut_names(), skip_error_check=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    pc_obj.clear_portchannel_configuration(st.get_dut_names())
    if vars.config.module_epilog_tgen_cleanup:
        st.log("Cleaning up routing interfaces configured on TG")
        tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_rt_int_handle[0]['handle'], mode='destroy')
        tg1.tg_interface_config(port_handle=tg_ph_2, handle=tg_rt_int_handle[1]['handle'], mode='destroy')
        tg3.tg_interface_config(port_handle=tg_ph_3, handle=tg_rt_int_handle[2]['handle'], mode='destroy')
        tgapi.traffic_action_control(tg_handler, actions=['reset'])


def acl_ingress_config(config):
    #Delete the Binding first before deleting the ACLs
    cli_type = st.get_ui_type(vars.D1)
    if cli_type in ["klish", "rest-patch", "rest-put"]:
        in_nat_eg_bindings = nat_obj.show_nat_config(vars.D1, "bindings", acl_name=data.acl_table_in_nat_eg)
        if in_nat_eg_bindings:
            for bind_data in in_nat_eg_bindings:
                nat_obj.config_nat_pool_binding(vars.D1, config="del", binding_name=bind_data["binding_name"])
        out_nat_eg_bindings = nat_obj.show_nat_config(vars.D1, "bindings", acl_name=data.acl_table_out_nat_eg)
        if out_nat_eg_bindings:
            for bind_data in out_nat_eg_bindings:
                nat_obj.config_nat_pool_binding(vars.D1, config="del", binding_name=bind_data["binding_name"])

    if config == 'VLAN':
        # nat acl for ingress traffic
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_in_nat_eg)
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_out_nat_eg)
        acl_obj.create_acl_table(vars.D1, acl_type=data.type, name=data.acl_table_in_nat_eg, stage="INGRESS",
                                 description="ingress-acl", ports=[data.vlan_int_1])
        acl_obj.create_acl_table(vars.D1, type=data.type, name=data.acl_table_out_nat_eg, stage="EGRESS",
                                 description="egress-acl", ports=[data.vlan_int_2])
        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_in_nat_eg, rule_name="rule-31", packet_action=data.packet_forward_action,
                                SRC_IP="{}/{}".format(data.in2_ip_addr_rt, data.in2_ip_addr_mask), priority='99', ip_protocol="4")
        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_in_nat_eg, rule_name="rule-32", packet_action=data.packet_forward_action,
                                SRC_IP="{}/{}".format(data.in1_ip_addr_rt, data.in1_ip_addr_mask), priority='98', ip_protocol="4")

        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                                packet_action=data.packet_do_not_nat_action,
                                SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', ip_protocol="4")
        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_out_nat_eg, rule_name="rule-no-nat-150",
                                packet_action=data.packet_forward_action,
                                SRC_IP="{}/{}".format("14.1.0.1", data.mask), priority='150', ip_protocol="4")

        if cli_type in ["klish", "rest-patch", "rest-put"]:        
            nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                            acl_name=data.acl_table_in_nat_eg, config=data.config_add)
            nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                            acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    elif config == 'BOTH':
        # nat acl for ingress traffic
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_in_nat_eg)
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_out_nat_eg)
        acl_obj.create_acl_table(vars.D1, type=data.type, name=data.acl_table_in_nat_eg, stage="INGRESS",
                                 description="ingress-acl", ports=[data.vlan_int_1, vars.D1T1P2])
        acl_obj.create_acl_table(vars.D1, type=data.type, name=data.acl_table_out_nat_eg, stage="EGRESS",
                                 description="egress-acl", ports=[data.vlan_int_2, vars.D1D2P3])
        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_in_nat_eg, rule_name="rule-31",
                                packet_action=data.packet_forward_action,
                                SRC_IP="{}/{}".format(data.in2_ip_addr_rt, data.in2_ip_addr_mask), priority='99', ip_protocol="4")
        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_in_nat_eg, rule_name="rule-32",
                                packet_action=data.packet_forward_action,
                                SRC_IP="{}/{}".format(data.in1_ip_addr_rt, data.in1_ip_addr_mask), priority='98', ip_protocol="4")

        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                                packet_action=data.packet_do_not_nat_action,
                                SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', ip_protocol="4")
        acl_obj.create_acl_rule(vars.D1, acl_type=data.type, table_name=data.acl_table_out_nat_eg, rule_name="rule-no-nat-150",
                                packet_action=data.packet_forward_action,
                                SRC_IP="{}/{}".format("14.1.0.1", data.mask), priority='150', ip_protocol="4")
        if cli_type in ["klish", "rest-patch", "rest-put"]:
            nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                            acl_name=data.acl_table_in_nat_eg, config=data.config_add)
            nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                            acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    elif config == 'DEL':
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_in_nat_eg)
        acl_obj.delete_acl_table(vars.D1, acl_type=data.type, acl_table_name=data.acl_table_out_nat_eg)


def vlan_mem_cfg(dut, data):
    if type(data)== list and len(data)>0:
        for vlan, port, mode in data:
            vlan_obj.add_vlan_member(dut, vlan, port, tagging_mode=mode)
        return True
    return False


def util_tg_vlan_stream_config(tg1,tg2, tg3, tg_ph_1,tg_ph_2, tg_ph_3):
    result = {1:{},2:{},3:{}}
    #### TG1 config
    tg1_st_napt_tcp_dnat_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='single_burst',
                             pkts_per_burst=data.pkt_count,rate_pps=data.rate_traffic, l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,vlan_id=data.vlan_list[0], vlan="enable",
                          ip_src_addr=data.in1_ip_addr_h[1], ip_dst_addr=data.global_ip_addr, l4_protocol='tcp',
                          tcp_src_port=data.tcp_src_local_port, tcp_dst_port=data.tcp_dst_local_port)
    result[1]["tg1_st_napt_tcp_dnat_data_str_id_1"] = tg1_st_napt_tcp_dnat_data_str['stream_id']
    tg1_dyn_nat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,vlan_id=data.vlan_list[0], vlan="enable",
                                                          ip_src_addr=data.in1_ip_addr_h[-1],
                                                          ip_dst_addr=data.global_ip_addr, l4_protocol='udp',
                                                           udp_src_port=data.local_src_port[0],
                                                           udp_dst_port=data.local_dst_port[0])
    result[1]["tg1_dyn_nat_udp_data_str_id_1"] = tg1_dyn_nat_udp_data_str['stream_id']
    tg1_no_nat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,vlan_id=data.vlan_list[0], vlan="enable",
                                                          ip_src_addr="14.1.0.1",
                                                          ip_dst_addr=data.global_ip_addr, l4_protocol='udp',
                                                           udp_src_port=data.local_src_port[0],
                                                           udp_dst_port=data.local_dst_port[0])
    result[1]["tg1_no_nat_udp_data_str_id_1"] = tg1_no_nat_udp_data_str['stream_id']
    tg1_scale_nat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',
                                                       rate_pps="600", l3_protocol='ipv4',
                                                       mac_src=data.tg1_src_mac_addr, mac_src_step='00:00:00:00:00:01',
                                                       mac_src_mode='increment', mac_src_count=1023,
                                                       mac_dst=dut1_rt_int_mac, vlan_id=data.vlan_list[0],
                                                       vlan="enable", ip_src_addr=data.in1_ip_addr_h[2],
                                                       ip_src_mode='increment', ip_src_count='1023',
                                                       ip_src_step='0.0.0.1', ip_dst_addr=data.global_ip_addr,
                                                       l4_protocol='udp', udp_src_port=data.local_src_port[0],
                                                       udp_dst_port=data.local_dst_port[0],udp_dst_port_mode="incr", udp_dst_port_step='1', udp_dst_port_count ='1023')
    result[1]["tg1_scale_nat_udp_data_str_id_1"] = tg1_scale_nat_udp_data_str['stream_id']
    tg1_dyn_twicenat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,vlan_id=data.vlan_list[0], vlan="enable",
                                                          ip_src_addr=data.in1_ip_addr_h[-2],
                                                          ip_dst_addr=data.tw_test_ip_addr, l4_protocol='udp',
                                                           udp_src_port=data.local_src_port[1],
                                                           udp_dst_port="40000")
    result[1]["tg1_dyn_twicenat_udp_data_str_id_1"] = tg1_dyn_twicenat_udp_data_str['stream_id']
    #### TG2 config
    tg2_dyn_nat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,
                                                          ip_src_addr=data.in2_ip_addr_h[-1],
                                                          ip_dst_addr=data.global2_ip_addr, l4_protocol='udp',
                                                           udp_src_port=data.local_src_port[0],
                                                           udp_dst_port=data.local_dst_port[0])
    result[2]["tg2_dyn_nat_udp_data_str_id_1"] = tg2_dyn_nat_udp_data_str['stream_id']
    ### TG3 config pool-1 config
    tg3_st_napt_tcp_dnat_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create', transmit_mode='single_burst',
                             pkts_per_burst=data.pkt_count,rate_pps=data.rate_traffic, l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global_ip_addr, ip_dst_addr=data.out_ip_addr,
                          l4_protocol='tcp',tcp_src_port=data.tcp_dst_global_port, tcp_dst_port=data.tcp_src_global_port)
    result[3]["tg3_st_napt_tcp_dnat_data_str_id_1"] = tg3_st_napt_tcp_dnat_data_str['stream_id']
    tg3_dyn_nat_udp_1_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0],l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result[3]["tg3_dyn_nat_udp_1_data_str_id_1"] = tg3_dyn_nat_udp_1_data_str['stream_id']
    tg3_dyn_nat_udp_2_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0], l4_protocol='udp',udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result[3]["tg3_dyn_nat_udp_2_data_str_id_1"] = tg3_dyn_nat_udp_2_data_str['stream_id']
    tg3_dyn_nat_udp_3_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result[3]["tg3_dyn_nat_udp_3_data_str_id_1"] = tg3_dyn_nat_udp_3_data_str['stream_id']
    tg3_dyn_nat_udp_4_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result[3]["tg3_dyn_nat_udp_4_data_str_id_1"] = tg3_dyn_nat_udp_4_data_str['stream_id']
    # #### TG3 pool-2 config
    tg3_dyn_nat_udp_5_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global2_ip_addr,
                                                          ip_dst_addr=data.out2_ip_pool[0],l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result[3]["tg3_dyn_nat_udp_5_data_str_id_1"] = tg3_dyn_nat_udp_5_data_str['stream_id']
    tg3_dyn_nat_udp_6_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global2_ip_addr,
                                                          ip_dst_addr=data.out2_ip_pool[0], l4_protocol='udp',udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result[3]["tg3_dyn_nat_udp_6_data_str_id_1"] = tg3_dyn_nat_udp_6_data_str['stream_id']
    tg3_dyn_nat_udp_7_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global2_ip_addr,
                                                          ip_dst_addr=data.out2_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result[3]["tg3_dyn_nat_udp_7_data_str_id_1"] = tg3_dyn_nat_udp_7_data_str['stream_id']
    tg3_dyn_nat_udp_8_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.global2_ip_addr,
                                                          ip_dst_addr=data.out2_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result[3]["tg3_dyn_nat_udp_8_data_str_id_1"] = tg3_dyn_nat_udp_8_data_str['stream_id']
    #### TG3 twicenat pool config
    tg3_dyn_twicenat_udp_9_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.tw_global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0], l4_protocol='udp', udp_src_port="50000",
                                                           udp_dst_port=data.tw_global_dst_port[0])
    result[3]["tg3_dyn_twicenat_udp_9_data_str"] = tg3_dyn_twicenat_udp_9_data_str['stream_id']
    tg3_dyn_twicenat_udp_10_data_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg3_src_mac_addr,
                                                          mac_dst=dut2_rt_int_mac, ip_src_addr=data.tw_global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0], l4_protocol='udp', udp_src_port="50000",
                                                           udp_dst_port=data.tw_global_dst_port[1])
    result[3]["tg3_dyn_twicenat_udp_10_data_str"] = tg3_dyn_twicenat_udp_10_data_str['stream_id']
    return result


def tg3_vlan_str_selector(trn_ip, trn_port):
    ip1 = data.out_ip_pool[0]
    ip2 = data.out_ip_pool[1]
    ip3 = data.out2_ip_pool[0]
    ip4 = data.out2_ip_pool[1]
    p1 = data.global_dst_port[0]
    p2 = data.global_dst_port[1]
    p3 = data.tw_global_dst_port[0]
    p4 = data.tw_global_dst_port[1]
    s1 = tg_str_data[3]["tg3_dyn_nat_udp_1_data_str_id_1"]
    s2 = tg_str_data[3]["tg3_dyn_nat_udp_2_data_str_id_1"]
    s3 = tg_str_data[3]["tg3_dyn_nat_udp_3_data_str_id_1"]
    s4 = tg_str_data[3]["tg3_dyn_nat_udp_4_data_str_id_1"]
    s5 = tg_str_data[3]["tg3_dyn_nat_udp_5_data_str_id_1"]
    s6 = tg_str_data[3]["tg3_dyn_nat_udp_6_data_str_id_1"]
    s7 = tg_str_data[3]["tg3_dyn_nat_udp_7_data_str_id_1"]
    s8 = tg_str_data[3]["tg3_dyn_nat_udp_8_data_str_id_1"]
    s9 = tg_str_data[3]["tg3_dyn_twicenat_udp_9_data_str"]
    s10 = tg_str_data[3]["tg3_dyn_twicenat_udp_10_data_str"]

    tg3_stream_map = {s1: [ip1, p1], s2: [ip1, p2], s3: [ip2, p1], s4:[ip2, p2], s5:[ip3, p1], s6:[ip3, p2], s7:[ip4, p1], s8:[ip4,p2], s9:[ip1, p3], s10:[ip1, p4]}
    for k, v in tg3_stream_map.items():
        if v ==[trn_ip, trn_port]:
            return k


def util_tg_vlan_routing_int_config(vars,tg1,tg2, tg3,tg_ph_1,tg_ph_2, tg_ph_3):

    st.log("TG1 {} IPv4 address {} config".format(vars.T1D1P1, data.in1_ip_addr_h[0]))
    tg1_rt_int_handle = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.in1_ip_addr_h[0],
                                         gateway=data.in1_ip_addr, netmask='255.255.0.0', vlan='1',
                                         vlan_id=data.vlan_list[0], vlan_id_step=0, arp_send_req='1',
                                         gateway_step='0.0.0.0', intf_ip_addr_step='0.0.0.1', count='10')
    st.log("TG2 {} IPv4 address {} config".format(vars.T1D1P2, data.in2_ip_addr_h[0]))
    tg2_rt_int_handle = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.in2_ip_addr_h[0],
                                         gateway=data.in2_ip_addr, netmask='255.255.0.0', arp_send_req='1',count='10', gateway_step='0.0.0.0')
    st.log("TG3 {} IPv4 address {} config".format(vars.T1D2P1, data.global_ip_addr_h))
    tg3_rt_int_handle = tg3.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr=data.global_ip_addr,
                                         gateway=data.global_ip_addr_h, netmask='255.255.255.0', arp_send_req='1')
    return tg1_rt_int_handle,tg2_rt_int_handle,tg3_rt_int_handle


def util_nat_zone_config(vars,intf,zone,config):
    if config == data.config_add:
        st.log("zone value configuration")
        for i in range(len(intf)):
            nat_obj.config_nat_interface(vars.D1, interface_name=intf[i], zone_value=zone[i], config=data.config_add)
    else:
        st.log("zone value un configuration")
        for i in range(len(intf)):
            nat_obj.config_nat_interface(vars.D1, interface_name=intf[i], zone_value=zone[i], config=data.config_del)

    return True


def util_check_nat_translations_count(dut, loopCnt, expcount):
    flag = 0
    iter = 1
    while iter <= loopCnt:
        ret_val = nat_obj.get_nat_translations_count(dut, counter_name="total_entries")
        st.log("Number of NAT entries learned after iteration {} : {}".format(iter,ret_val))
        if int(ret_val) >= int(expcount):
            flag = 1
            break
        iter = iter+1
    if flag:
        return True
    else:
        return False


def util_nat_vlan_debug_fun():
    st.banner("Start of Collecting the needed debug info for failure analysis", width=100)
    utils.exec_all(True, [[intf_obj.show_interface_counters_all, vars.D1], [intf_obj.show_interface_counters_all, vars.D2]])
    utils.exec_all(True, [[nat_obj.show_nat_translations, vars.D1], [nat_obj.show_nat_translations, vars.D2]])
    utils.exec_all(True, [[ip_obj.get_interface_ip_address, vars.D1], [ip_obj.get_interface_ip_address, vars.D2]])
    utils.exec_all(True, [[arp_obj.show_arp, vars.D1], [arp_obj.show_arp, vars.D2]])
    st.banner("End of Collecting the needed debug info for failure analysis", width=100)

def debug_zebra(dut,**kwargs):
    """
    Enable or Disable debugs for zebra
    """
    if 'config' in kwargs:
        config= kwargs['config']
    else:
        config = 'yes'

    if config == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    cmd = "{} debug zebra kernel \n".format(config_cmd)

    if config == 'yes':
        cmd += "debug zebra dplane detailed \n"
    else:
        cmd += "no debug zebra dplane \n"

    cmd += "{} log syslog debugging \n".format(config_cmd)

    st.config(dut, cmd, type='vtysh')

