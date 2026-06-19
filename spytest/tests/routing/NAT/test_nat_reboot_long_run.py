import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.routing.ip as ip_obj
import apis.routing.nat as nat_obj
import apis.switching.vlan as vlan_obj
import apis.system.interface as intf_obj
import apis.qos.acl as acl_obj
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj
import apis.routing.arp as arp_obj

dut = dict()

def nat_reboot_initialize_variables():
    global data
    data = SpyTestDict()
    data.in1_ip_addr = "12.12.0.1"
    data.in1_ip_addr_h = ["12.12.0.2", "12.12.0.3", "12.12.0.4","12.12.0.5", "12.12.0.6", "12.12.0.7","12.12.0.8",
                      "12.12.0.9", "12.12.0.10", "12.12.0.11"]
    data.in1_ip_addr_rt = "12.12.0.0"
    data.in1_ip_addr_mask = "16"
    data.in2_ip_addr = "13.13.13.1"
    data.in2_ip_addr_h = ["13.13.13.2", "13.13.13.3", "13.13.13.4"]
    data.in2_ip_addr_rt = "13.13.13.0"
    data.in2_ip_addr_mask = "24"
    data.in3_ip_addr = "23.1.0.1"
    data.in3_ip_addr_h = ["23.1.0.2", "23.1.0.3", "23.1.0.4"]
    data.in3_ip_addr_rt = "23.1.0.0"
    data.in3_ip_addr_mask = "16"
    data.out_ip_addr = "125.56.90.11"
    data.out_ip_addr_l = ["125.56.90.12", "125.56.90.13", "125.56.90.14", "125.56.90.15", "125.56.90.16"]
    data.out_ip_addr_h = "125.56.90.1"
    data.out_ip_range = "125.56.90.23-125.56.90.24"
    data.out_ip_pool = ["125.56.90.23", "125.56.90.24"]
    data.out_ip_addr_rt = "125.56.90.0"
    data.out_ip_addr_mask = "24"
    data.out2_ip_addr = "85.16.0.48"
    data.out2_ip_addr_l = ["85.16.0.49", "85.16.0.50", "85.16.0.51"]
    data.out2_ip_addr_h = "85.16.0.49"
    data.out2_ip_range = "85.16.0.30-85.16.0.50"
    data.out2_ip_addr_rt = "85.16.0.0"
    data.out2_ip_addr_mask = "16"
    data.global_ip_addr_h = "129.2.30.13"
    data.global_ip_addr = "129.2.30.12"
    data.global_ip_addr_rt = "129.2.30.0"
    data.global_ip_addr_mask = "24"
    data.test_ip_addr = "22.22.22.1"
    data.test_ip_addr_mask = "16"
    data.test_ip_addr_rt = "22.22.0.0"
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
    data.bind_name = ["bind_1", "7812_bind", "bind_11"]
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
    data.vlan_list = random_vlan_list(4)
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
    data.tg2_src_mac_addr = '00:00:23:1B:14:07'
    data.tg2_src_mac_addr = '00:00:43:32:1A:01'
    data.wait_time_traffic_run_to_pkt_cap = 1
    data.wait_time_traffic_run = 1
    data.wait_time_after_reload = 30
    data.wait_time_after_reboot = 60
    data.wait_time_to_no_shut = 30
    data.wait_time_after_docker_restart = 30
    data.wait_nat_tcp_timeout = 60
    data.wait_nat_udp_timeout = 60
    data.wait_nat_stats = 7
    data.config_add='add'
    data.config_del='del'
    data.twice_nat_id_1 = '100'
    data.twice_nat_id_2 = '1100'
    data.wait_time_after_docker_restart = 10
    data.mask = '32'
    data.max_nat_entries = "1024"



@pytest.fixture(scope="module", autouse=True)
def nat_module_config(request):
    nat_reboot_initialize_variables()
    nat_pre_config()
    yield
    nat_post_config()


@pytest.fixture(scope="function")
def cmds_func_hooks(request):
    yield


@pytest.mark.nat_longrun
def test_ft_nat_save_reboot():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Eamil: kiran-kumar.vedula@broadcom.com
    # ################################################
    # Objective - Verify dynamic NAPT translations after DUT reboot
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    nat_obj.show_nat_translations(vars.D1)
    st.log("Reboot the DUT")
    reboot_obj.config_save(vars.D1, "sonic")
    reboot_obj.config_save(vars.D1, "vtysh")
    st.reboot(vars.D1)
    st.log("Traffic for snat case")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    if not ip_obj.ping(vars.D1, data.in1_ip_addr_h[-1], family='ipv4',count=3):
        nat_reboot_debug_fun()
        st.report_fail("ping_fail",data.in1_ip_addr,data.in1_ip_addr_h[-1])
    st.wait(data.wait_nat_stats)
    st.log("Checking for STATIC entries after reboot")
    trn_val_1 = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[0])
    if not trn_val_1:
        nat_reboot_debug_fun()
        st.report_fail("static_nat_translation_entry_create_fail", data.in1_ip_addr_h[0], data.out_ip_pool[0])
    count = data.pkt_count
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in1_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])
    if not trn_val:
        nat_reboot_debug_fun()
        st.error("Received empty list,nat translation table not updated")
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    st.log("Traffic for dnat case")
    tg2_str_obj = tg2_str_selector(trn_src_ip, trn_src_port)
    tg2.tg_traffic_control(action='run', handle=tg2_str_obj)
    tg2.tg_traffic_control(action='stop', handle=tg2_str_obj)
    st.wait(data.wait_nat_stats)
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.in1_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        nat_reboot_debug_fun()
        st.error("Received empty list,nat statistics are not updated")
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    if not (int(nat_stats_s[0]['packets']) >= (0.80 * (int(count)))):
        nat_reboot_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])

    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=trn_src_ip,
                                                  dst_ip_port=trn_src_port)
    if not nat_stats_d:
        nat_reboot_debug_fun()
        st.error("Received empty list, nat statistics are not updated")
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out_ip_pool[0], data.out_ip_pool[0])
    if not (int(nat_stats_d[0]['packets']) >= (0.80 * (int(count)))):
        nat_reboot_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out_ip_pool[0], data.out_ip_pool[0])
    st.report_pass("nat_translation_successful_after_reboot")


@pytest.mark.nat_longrun
def test_ft_nat_config_reload():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Eamil: kiran-kumar.vedula@broadcom.com
    # ################################################
    # Objective - Verify dynamic NAPT translations after config save and reload
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    st.log("Config reload the DUT")
    reboot_obj.config_save_reload(vars.D1)
    st.log("Get some debug info after config reload is complete")
    ip_obj.show_ip_route(vars.D1)
    arp_obj.show_arp(vars.D1)
    nat_obj.show_nat_translations(vars.D1)
    st.wait(2)
    st.log("Traffic for snat case")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    st.wait(data.wait_nat_stats)
    trn_val_1 = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[0])
    if not trn_val_1:
        nat_reboot_debug_fun()
        st.report_fail("nat_translation_table_entry_deleted_incorrectly")
    count = data.pkt_count
    trn_val = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_udp, src_ip=data.in1_ip_addr_h[-1],
                                           src_ip_port=data.local_src_port[0])
    if not trn_val:
        nat_reboot_debug_fun()
        st.error("Received empty list,nat translation table not updated")
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    trn_src_ip = trn_val[0]["trn_src_ip"]
    trn_src_port = trn_val[0]["trn_src_ip_port"]
    st.log("Traffic for dnat case")
    tg2_str_obj = tg2_str_selector(trn_src_ip, trn_src_port)
    tg2.tg_traffic_control(action='run', handle=tg2_str_obj)
    tg2.tg_traffic_control(action='stop', handle=tg2_str_obj)
    st.wait(data.wait_nat_stats)
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp,
                                                  src_ip=data.in1_ip_addr_h[-1], src_ip_port=data.local_src_port[0])
    if not nat_stats_s:
        nat_reboot_debug_fun()
        st.error("Received empty list,nat statistics are not updated")
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])
    if not int(nat_stats_s[0]['packets']) >= (0.80 * (int(count))):
        nat_reboot_debug_fun()
        st.report_fail("dynamic_snat_translation_entry_create_fail", data.in1_ip_addr_h[-1], data.out_ip_pool[0])

    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_udp, dst_ip=trn_src_ip,
                                                  dst_ip_port=trn_src_port)
    if not nat_stats_d:
        nat_reboot_debug_fun()
        st.error("Received empty list, nat statistics are not updated")
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out_ip_pool[0], data.out_ip_pool[0])
    if not int(nat_stats_d[0]['packets']) >= (0.80 * (int(count))):
        nat_reboot_debug_fun()
        st.report_fail("dynamic_dnat_translation_entry_create_fail", data.out_ip_pool[0], data.out_ip_pool[0])
    st.report_pass("nat_translation_successful_after_config_reload")


@pytest.mark.nat_longrun
def test_ft_dynamic_nat_timeout():
    # ################ Author Details ################
    # Name: Kiran Vedula
    # Eamil: kiran-kumar.vedula@broadcom.com
    # ################################################
    # Objective - Verify that NAT translations after a reboot of DUT
    # #################################################
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.clear_nat(vars.D1, statistics=True)
    nat_obj.config_nat_timeout(vars.D1, timeout=300, config='set')
    st.log("Deleting NAT Pool binding")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    config=data.config_del)
    st.log("Creating NAT Pool-1 without port")
    nat_obj.config_nat_pool(vars.D1, pool_name=data.pool_name[1], global_ip_range=data.out_ip_pool[0],
                            config=data.config_add)
    st.log("Creating NAT Pool binding")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    config=data.config_add)
    st.log("Traffic for Dynamic NAT case")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_dyn_nat_udp_data_str_id_1"])
    tg2.tg_traffic_control(action='run', handle=tg_str_data[2]["tg2_dyn_nat_udp_1_data_str_id_1"])
    tg2.tg_traffic_control(action='stop', handle=tg_str_data[2]["tg2_dyn_nat_udp_1_data_str_id_1"])
    tc_fail_flag = 0
    st.wait(data.wait_nat_stats)
    result = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[-1])
    if not result:
        nat_reboot_debug_fun()
        st.error("Dynamic NAT failed for SRC IP")
        tc_fail_flag = 1
    nat_stats_s = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[-1])
    if not nat_stats_s:
        nat_reboot_debug_fun()
        tc_fail_flag = 1
    nat_stats_d = nat_obj.poll_for_nat_statistics(vars.D1, protocol=data.proto_all, dst_ip=data.out_ip_pool[0])
    if not nat_stats_d:
        nat_reboot_debug_fun()
        tc_fail_flag = 1
    st.log("Waiting for NAT global timeout")
    st.wait(350)
    result = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_all, src_ip=data.in1_ip_addr_h[-1])
    if result:
        nat_reboot_debug_fun()
        st.error("Dynamic NAT SRC translations present after timeout")
        tc_fail_flag = 1
    result = nat_obj.get_nat_translations(vars.D1, protocol=data.proto_all, dst_ip=data.out_ip_pool[0])
    if result:
        nat_reboot_debug_fun()
        st.error("Dynamic NAT DST translations present after timeout")
        tc_fail_flag = 1
    st.log("Reversing the Module config")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    config=data.config_del)
    nat_obj.config_nat_pool(vars.D1, pool_name=data.pool_name[0], global_ip_range=data.out_ip_range,
                            global_port_range=data.global_port_range, config=data.config_add)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    config=data.config_add)
    nat_obj.config_nat_timeout(vars.D1, timeout=600, config='set')
    if tc_fail_flag:
        nat_reboot_debug_fun()
        st.report_fail("nat_translation_table_not_cleared")
    st.report_pass("nat_translation_global_timeout_verified")


@pytest.mark.nat_longrun
def test_ft_dynamic_nat_warmboot():
    # ################ Author Details ################
    # Name: Kesava Swamy Karedla
    # Eamil: kesava-swamy.karedla@broadcom.com
    # ################################################
    # Objective - FtOpSoRoNatWb001 - Verify warm boot with dynamic nat scaling entries.
    # #################################################
    result_flag=0
    platform = basic_obj.get_hwsku(vars.D1)
    common_constants = st.get_datastore(vars.D1, "constants", "default")
    if not platform.lower() in common_constants['WARM_REBOOT_SUPPORTED_PLATFORMS']:
        st.error("Warm-Reboot is not supported for this platform {}".format(platform))
        st.report_unsupported('test_case_unsupported')
    nat_obj.clear_nat(vars.D1, translations=True)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    config=data.config_del)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name="scale_bind", pool_name="scale_pool",
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_add)
    st.log("Sending continuous traffic at 600 pps for the max dynamic nat entries to get learned")
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    st.log("Waiting for traffic to run, such that max nat entries get learned")
    if not util_check_nat_translations_count(vars.D1,20,data.max_nat_entries):
        nat_reboot_debug_fun()
        st.log("Failed to learn max nat entries")
        result_flag = 1
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    # Show command for debugging purpose in case of failures.
    intf_obj.show_interface_counters_all(vars.D1)
    st.log("Warm boot verification")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg1.tg_traffic_control(action='run', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    st.log("Performing warm-reboot, while traffic is forwarding for nat entries")
    st.reboot(vars.D1, 'warm')
    tg1.tg_traffic_control(action='stop', handle=tg_str_data[1]["tg1_scale_nat_udp_data_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
             }
                      }

    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        nat_reboot_debug_fun()
        st.log("Traffic loss observed for the SNAT traffic during warm-boot")
        result_flag = 1
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    config=data.config_add)
    nat_obj.config_nat_pool_binding(vars.D1, binding_name="scale_bind", pool_name="scale_pool",
                                    acl_name=data.acl_table_in_nat_eg, config=data.config_del)
    if result_flag:
        st.report_fail("nat_warm_reboot_failed")
    st.report_pass("test_case_passed")


def nat_pre_config():
    global vars
    vars = st.ensure_min_topology("D1T1:2")
    platform = basic_obj.get_hwsku(vars.D1)
    common_constants = st.get_datastore(vars.D1, "constants", "default")
    if platform.lower() in common_constants['TH3_PLATFORMS']:
        st.error("NAT is not supported for this platform {}".format(platform))
        st.report_unsupported('NAT_unsupported_platform',platform)
    global tg_handler, tg1, tg2, tg_ph_1, tg_ph_2, dut1_rt_int_mac, tg_str_data, tg_rt_int_handle
    tg_handler = util_tg_init(vars, [vars.T1D1P1, vars.T1D1P2])
    tg1 = tg_handler["tg"]
    tg2 = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.in1_ip_addr, data.in1_ip_addr_mask, family=data.af_ipv4)
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P2, data.out_ip_addr_l[0], data.out_ip_addr_mask, family=data.af_ipv4)
    dut1_rt_int_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    ip_obj.create_static_route(vars.D1, data.out_ip_addr_h,
                               "{}/{}".format(data.global_ip_addr_rt, data.global_ip_addr_mask),
                               shell=data.shell_vtysh, family=data.af_ipv4)
    ip_obj.create_static_route(vars.D1, data.in1_ip_addr_h[0], "{}/{}".format(data.s_global_ip_rt, data.s_global_ip_mask))
    tg_rt_int_handle = util_tg_routing_int_config(vars, tg1, tg2, tg_ph_1, tg_ph_2)
    st.log("NAT Configuration")
    nat_obj.config_nat_feature(vars.D1, 'enable')
    util_nat_zone_config(vars, [vars.D1T1P1, vars.D1T1P2], [data.zone_1, data.zone_2], config=data.config_add)
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_all, global_ip=data.out_ip_addr_l[0],
                              local_ip=data.in1_ip_addr_h[0], config=data.config_add, nat_type=data.nat_type_dnat)
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_tcp, global_ip=data.out_ip_addr_l[1],
                               local_ip=data.in1_ip_addr_h[1],
                               local_port_id=data.tcp_src_local_port, global_port_id=data.tcp_src_global_port,
                               config=data.config_add, nat_type=data.nat_type_dnat)
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_udp, global_ip=data.in1_ip_addr_h[2],
                               local_ip=data.out_ip_addr_l[2],
                               local_port_id=data.udp_src_global_port, global_port_id=data.udp_src_local_port,
                               config=data.config_add, nat_type=data.nat_type_snat)
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_all, global_ip=data.s_global_ip, local_ip=data.s_local_ip,
                              config=data.config_add, nat_type=data.nat_type_snat)
    nat_obj.config_nat_static(vars.D1,protocol=data.proto_all,global_ip=data.out_ip_addr_l[3],local_ip=data.in1_ip_addr_h[3],
                              config=data.config_add,nat_type=data.nat_type_dnat,twice_nat_id=data.twice_nat_id_1)
    nat_obj.config_nat_static(vars.D1, protocol=data.proto_all, global_ip=data.global_ip_addr,
                              local_ip=data.test_ip_addr,
                              config=data.config_add, nat_type=data.nat_type_snat, twice_nat_id=data.twice_nat_id_1)
    # dynamic NAT config
    st.log("Creating NAT Pool-1")
    nat_obj.config_nat_pool(vars.D1, pool_name=data.pool_name[0], global_ip_range=data.out_ip_range,
                            global_port_range= data.global_port_range, config=data.config_add)
    nat_obj.config_nat_pool(vars.D1, pool_name="scale_pool", global_ip_range="125.56.90.23-125.56.90.30",
                            global_port_range="1001-8001", config=data.config_add)
    st.log("Creating NAT Pool binding")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[0], pool_name=data.pool_name[0],
                                    config=data.config_add)
    st.log("Creating NAT Pool-2")
    nat_obj.config_nat_pool(vars.D1, pool_name=data.pool_name[1], global_ip_range=data.out2_ip_range,
                             config=data.config_add)
    st.log("Creating NAT Pool-2 binding")
    nat_obj.config_nat_pool_binding(vars.D1, binding_name=data.bind_name[1], pool_name=data.pool_name[1],
                                    config=data.config_add)
    # nat acl for ingress traffic
    acl_obj.create_acl_table(vars.D1, name=data.acl_table_in_nat_eg, stage="INGRESS", type=data.type,
                             description="ingress-acl", ports=[vars.D1T1P1])
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-32", packet_action=data.packet_forward_action,
                            SRC_IP="{}/{}".format(data.in1_ip_addr_rt, data.in1_ip_addr_mask), priority='98', type=data.type, ip_protocol="4")
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_table_in_nat_eg, rule_name="rule-33",
                            packet_action=data.packet_do_not_nat_action,
                            SRC_IP="{}/{}".format('14.1.0.1', data.mask), priority='97', type=data.type, ip_protocol="4")
    # Checking arp table for debugging
    arp_obj.show_arp(vars.D1)
    ip_obj.show_ip_route(vars.D1)
    # Clearing all interface counters for debugging purpose
    intf_obj.clear_interface_counters(vars.D1)
    tg_str_data = util_tg_stream_config(tg1, tg2, tg_ph_1, tg_ph_2)


def nat_post_config():
    vars = st.get_testbed_vars()

    util_nat_zone_config(vars, [vars.D1T1P1, vars.D1T1P2], [data.zone_1, data.zone_2], config=data.config_del)
    nat_obj.clear_nat_config(vars.D1)
    nat_obj.config_nat_feature(vars.D1, 'disable')
    ip_obj.delete_static_route(vars.D1, data.out_ip_addr_h,
                               "{}/{}".format(data.global_ip_addr_rt, data.global_ip_addr_mask))
    ip_obj.clear_ip_configuration(st.get_dut_names())
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    st.log("Cleaning up routing interfaces configured on TG")
    tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_rt_int_handle[0]['handle'], mode='destroy')
    tg1.tg_interface_config(port_handle=tg_ph_2, handle=tg_rt_int_handle[1]['handle'], mode='destroy')
    tgapi.traffic_action_control(tg_handler, actions=['reset'])


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


def util_tg_init(vars, tg_port_list):
    tg_port_list = list(tg_port_list) if isinstance(tg_port_list, list) else [tg_port_list]
    tg_handler = tgapi.get_handles(vars, tg_port_list)
    tgapi.traffic_action_control(tg_handler, actions=['reset', 'clear_stats'])
    return tg_handler


def util_tg_routing_int_config(vars,tg1,tg2,tg_ph_1,tg_ph_2):

    st.log("TG1 {} IPv4 address {} config".format(vars.T1D1P1,data.in1_ip_addr_h[0]))
    tg1_rt_int_handle = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.in1_ip_addr_h[0],enable_ping_response=1,
                                     gateway=data.in1_ip_addr, netmask='255.255.0.0', arp_send_req='1',count='10', gateway_step='0.0.0.0')
    st.log("TG2 {} IPv4 address {} config".format(vars.T1D1P2,data.out_ip_addr_h))
    tg2_rt_int_handle = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.out_ip_addr_h,
                                     gateway=data.out_ip_addr_l[0], netmask='255.255.255.0', arp_send_req='1',count='10', gateway_step='0.0.0.0')
    return tg1_rt_int_handle,tg2_rt_int_handle


def util_tg_stream_config(tg1,tg2,tg_ph_1,tg_ph_2):
    result = {1:{},2:{}}

    tg1_dyn_nat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg1_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac,
                                                          ip_src_addr=data.in1_ip_addr_h[-1],
                                                          ip_dst_addr=data.global_ip_addr, l4_protocol='udp',
                                                           udp_src_port=data.local_src_port[0],
                                                           udp_dst_port=data.local_dst_port[0])
    result[1]["tg1_dyn_nat_udp_data_str_id_1"] = tg1_dyn_nat_udp_data_str['stream_id']
    tg1_scale_nat_udp_data_str = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',
                                                       rate_pps="600", l3_protocol='ipv4',enable_stream_only_gen=0,enable_stream=0,
                                                       mac_src=data.tg1_src_mac_addr, mac_src_step='00:00:00:00:00:01',
                                                       mac_src_mode='increment', mac_src_count=1018,
                                                       mac_dst=dut1_rt_int_mac, ip_src_addr=data.in1_ip_addr_h[2],
                                                       ip_src_mode='increment', ip_src_count='1018',
                                                       ip_src_step='0.0.0.1', ip_dst_addr=data.global_ip_addr,
                                                       l4_protocol='udp', udp_src_port=data.local_src_port[0],
                                                       udp_dst_port=data.local_dst_port[0],udp_dst_port_mode="incr", udp_dst_port_step='1', udp_dst_port_count ='1023')
    result[1]["tg1_scale_nat_udp_data_str_id_1"] = tg1_scale_nat_udp_data_str['stream_id']
    #### TG2 config
    tg2_dyn_nat_udp_1_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0],l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result[2]["tg2_dyn_nat_udp_1_data_str_id_1"] = tg2_dyn_nat_udp_1_data_str['stream_id']
    tg2_dyn_nat_udp_2_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[0], l4_protocol='udp',udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result[2]["tg2_dyn_nat_udp_2_data_str_id_1"] = tg2_dyn_nat_udp_2_data_str['stream_id']
    tg2_dyn_nat_udp_3_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[0])
    result[2]["tg2_dyn_nat_udp_3_data_str_id_1"] = tg2_dyn_nat_udp_3_data_str['stream_id']
    tg2_dyn_nat_udp_4_data_str = tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create',
                                                          transmit_mode='single_burst',
                                                          pkts_per_burst=data.pkt_count, rate_pps=data.rate_traffic,
                                                          l3_protocol='ipv4', mac_src=data.tg2_src_mac_addr,
                                                          mac_dst=dut1_rt_int_mac, ip_src_addr=data.global_ip_addr,
                                                          ip_dst_addr=data.out_ip_pool[1], l4_protocol='udp', udp_src_port=data.global_src_port[0],
                                                           udp_dst_port=data.global_dst_port[1])
    result[2]["tg2_dyn_nat_udp_4_data_str_id_1"] = tg2_dyn_nat_udp_4_data_str['stream_id']
    return result


def tg2_str_selector(trn_ip, trn_port):
    ip1 = data.out_ip_pool[0]
    ip2 = data.out_ip_pool[1]
    p1 = data.global_dst_port[0]
    p2 = data.global_dst_port[1]
    s1 = tg_str_data[2]["tg2_dyn_nat_udp_1_data_str_id_1"]
    s2 = tg_str_data[2]["tg2_dyn_nat_udp_2_data_str_id_1"]
    s3 = tg_str_data[2]["tg2_dyn_nat_udp_3_data_str_id_1"]
    s4 = tg_str_data[2]["tg2_dyn_nat_udp_4_data_str_id_1"]
    tg2_stream_map = {s1: [ip1, p1], s2: [ip1, p2], s3: [ip2, p1], s4:[ip2, p2]}
    for k, v in tg2_stream_map.items():
        if v ==[trn_ip, trn_port]:
            return k


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

def nat_reboot_debug_fun():
    st.banner("Start of Collecting the needed debug info for failure analysis", width=100)
    ip_obj.show_ip_route(vars.D1)
    intf_obj.show_interface_counters_all(vars.D1)
    arp_obj.show_arp(vars.D1)
    nat_obj.show_nat_translations(vars.D1)
    st.banner("End of Collecting the needed debug info for failure analysis", width=100)

