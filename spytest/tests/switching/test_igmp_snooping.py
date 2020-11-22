import pytest
import random

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list
from utilities.common import poll_wait, make_list
from utilities.parallel import exec_foreach, exec_all, exec_parallel, ensure_no_exception
from utilities.utils import util_ip_addr_to_hexa_conv, util_int_to_hexa_conv, retry_api

from apis.switching.vlan import create_vlan_and_add_members, clear_vlan_configuration, config_vlan_members, delete_vlan_member, add_vlan_member, config_vlan_range, config_vlan_range_members
from apis.switching.portchannel import config_portchannel, clear_portchannel_configuration, add_del_portchannel_member, poll_for_portchannel_status
from apis.system.interface import clear_interface_counters, show_interface_counters_all, interface_operation, poll_for_interface_status, show_interface_counters_detailed
import apis.switching.igmp_snooping as igmp
from apis.routing.ip import config_ip_addr_interface
from apis.routing.pim import config_intf_pim
import apis.system.reboot as rebootapi
import apis.system.gnmi as gnmiapi

igmp_data = SpyTestDict()


def igmp_snooping_initialize_variables():
    igmp_data.vlan_li = random_vlan_list(4)
    igmp_data.tg4_src_mac_addr = "00:00:11:32:0B:C0"
    igmp_data.tg5_src_mac_addr = "00:00:99:32:3B:12"
    igmp_data.igmp_grp_ip = ["224.2.1.2",  "224.1.1.2", "224.3.1.1", "225.5.2.2", "225.4.1.1"]
    igmp_data.igmp_grp_mac = ["01:00:5e:02:01:02",  "01:00:5e:01:01:02", "01:00:5e:03:01:01","01:00:5e:05:02:02","01:00:5e:04:01:01"]
    igmp_data.igmp_st_grp_ip = ["225.2.1.1", "225.2.1.2", "225.2.1.4"]
    igmp_data.igmp_st_grp_mac = ["01:00:5e:02:01:01", "01:00:5e:02:01:02", "01:00:5e:02:01:04"]
    igmp_data.igmpv3_src_addr = "41.1.1.100"
    igmp_data.mem_qry_hex_val = "11"
    igmp_data.max_groups = 512
    igmp_data.max_groups_static = 2
    igmp_data.max_groups_v2 = (igmp_data.max_groups / 2)-(igmp_data.max_groups_static / 2)
    igmp_data.max_groups_v3 = (igmp_data.max_groups / 2)-(igmp_data.max_groups_static / 2)
    igmp_data.lmqt_val = "10000"
    igmp_data.lmqt_default_val = "1000"
    igmp_data.vlan3_intf = "Vlan" + str(igmp_data.vlan_li[3])
    igmp_data.int_ip4_addr = "192.168.1.1"
    igmp_data.qry_int = '4'
    igmp_data.max_qry_res = '2'
    igmp_data.qry_int_for_join = '10'
    igmp_data.max_qry_res_for_join = '8'
    igmp_data.qry_check_wait_time = 10
    igmp_data.max_res_qry_check_wait_time = 5


@pytest.fixture(scope="module", autouse=True)
def igmp_snooping_module_config(request):
    igmp_snooping_initialize_variables()
    igmp_snooping_prologue()
    yield
    igmp_snooping_epilogue()


@pytest.fixture(scope="function", autouse=True)
def igmp_snooping_func_hooks(request):
    exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])
    yield
    if st.get_func_name(request) == 'test_ft_igmp_snooping_static_group':
        exec_all(True, [
            [util_igmp_snooping_st_group_config, vars.D1, igmp_data.vlan_li[1], igmp_data.igmp_grp_ip[1], vars.D1T1P1,
             True],
            [util_igmp_snooping_st_group_config, vars.D2, igmp_data.vlan_li[1], igmp_data.igmp_grp_ip[1],
             igmp_data.prt_chnl, True]])
    if st.get_func_name(request) == 'test_ft_igmp_snooping_pim_mrouter':
        config_intf_pim(dut=vars.D2, intf=vars.D2D1P4, pim_enable='no', config='no')
        config_ip_addr_interface(vars.D2, interface_name=igmp_data.vlan3_intf, ip_address=igmp_data.int_ip4_addr,
                                 subnet="24", family="ipv4", config="remove")
        util_igmp_snooping_enable(vars.D2, igmp_data.vlan_li[3], '3')
    if st.get_func_name(request) == 'test_ft_igmp_snooping_warm_boot':
        config_static_group('no')
        exec_all(True, [
            [delete_vlan_member, vars.D1, igmp_data.vlan_li[1], vars.D1D2P3,True],
            [delete_vlan_member, vars.D2, igmp_data.vlan_li[1], vars.D2D1P3,True]])
        exec_all(True, [
            [add_vlan_member, vars.D1, igmp_data.vlan_li[1], igmp_data.prt_chnl, True],
            [add_vlan_member, vars.D2, igmp_data.vlan_li[1], igmp_data.prt_chnl, True]])
        tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        tg5.tg_traffic_control(action='stop', handle=tg_str_data["tg5"]["tg5_mcast_data_1_str_id_1"])


def igmp_snooping_prologue():
    global vars
    vars = st.ensure_min_topology("D1D2:4", "D1T1:3", "D2T1:2")
    global tg_handler, tg1, tg2, tg3, tg4, tg5, tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4, tg_ph_5, tg_str_data, tg_comn_handle, tg_handler
    tg_handler = util_tg_init(vars, [vars.T1D1P1, vars.T1D1P2, vars.T1D1P3, vars.T1D2P1, vars.T1D2P2])
    tg1 = tg_handler["tg"]
    tg2 = tg_handler["tg"]
    tg3 = tg_handler["tg"]
    tg4 = tg_handler["tg"]
    tg5 = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_3 = tg_handler["tg_ph_3"]
    tg_ph_4 = tg_handler["tg_ph_4"]
    tg_ph_5 = tg_handler["tg_ph_5"]
    st.banner("TG Stream & IGMP host config")
    tg_str_data = util_tg_stream_config(tg3, tg4, tg_ph_3, tg_ph_4, tg5, tg_ph_5)
    tg_comn_handle = util_tg_routing_int_config(tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3)
    common_constants = st.get_datastore(vars.D1, "constants", "default")
    max_po_num = int(common_constants['MAX_SUPPORTED_PORTCHANNELS'])
    igmp_data.prt_chnl_rad_num = random.randint(1, 2)
    igmp_data.prt_chnl = "PortChannel{}".format(igmp_data.prt_chnl_rad_num)
    config_portchannel(vars.D1, vars.D2, igmp_data.prt_chnl, [vars.D1D2P1, vars.D1D2P2],
                       [vars.D2D1P1, vars.D2D1P2], config='add', thread=True)
    st.banner("Vlan creation and VLan membership config in both DUTs")
    dut1_data = [{"dut": [vars.D1], "vlan_id": igmp_data.vlan_li[0],
                  "tagged": [igmp_data.prt_chnl, vars.D1T1P1, vars.D1T1P2, vars.D1T1P3]},
                 {"dut": [vars.D1], "vlan_id": igmp_data.vlan_li[1],
                  "tagged": [igmp_data.prt_chnl, vars.D1T1P1, vars.D1T1P2, vars.D1T1P3]},
                 {"dut": [vars.D1], "vlan_id": igmp_data.vlan_li[2],
                  "tagged": [vars.D1D2P3, vars.D1T1P1, vars.D1T1P2, vars.D1T1P3]},
                 {"dut": [vars.D1], "vlan_id": igmp_data.vlan_li[3],
                  "tagged": [vars.D1D2P4, vars.D1T1P1, vars.D1T1P2, vars.D1T1P3]}]
    dut2_data = [
        {"dut": [vars.D2], "vlan_id": igmp_data.vlan_li[0], "tagged": [igmp_data.prt_chnl, vars.D2T1P1, vars.D2T1P2]},
        {"dut": [vars.D2], "vlan_id": igmp_data.vlan_li[1], "tagged": [igmp_data.prt_chnl, vars.D2T1P1, vars.D2T1P2]},
        {"dut": [vars.D2], "vlan_id": igmp_data.vlan_li[2], "tagged": [vars.D2D1P3, vars.D2T1P1, vars.D2T1P2]},
        {"dut": [vars.D2], "vlan_id": igmp_data.vlan_li[3], "tagged": [vars.D2D1P4, vars.D2T1P1, vars.D2T1P2]}]
    exec_foreach(True, [dut1_data, dut2_data], create_vlan_and_add_members)
    st.banner("igmp snooping config on vlans in both DUTs")
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_enable, igmp_data.vlan_li[0], '1')
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_enable, [igmp_data.vlan_li[1], igmp_data.vlan_li[2]], '2')
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_enable, igmp_data.vlan_li[3], '3')


def igmp_snooping_epilogue():
    st.banner("disabling igmp snooping")
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_disable, igmp_data.vlan_li)
    st.banner("Vlan and Port Channel clean up")
    clear_vlan_configuration(st.get_dut_names(),cli_type='click')
    clear_portchannel_configuration(st.get_dut_names())
    if vars.config.module_epilog_tgen_cleanup:
        st.banner("Removing IGMP hosts and Routing interfaces on TG")
        tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_comn_handle["rt_host"]["tg1_rt_int_handle_1"]['handle'],
                                mode='destroy')
        tg1.tg_interface_config(port_handle=tg_ph_1, handle=tg_comn_handle["rt_host"]["tg1_rt_int_handle_2"]['handle'],
                                mode='destroy')
        tg2.tg_interface_config(port_handle=tg_ph_2, handle=tg_comn_handle["rt_host"]["tg2_rt_int_handle_1"]['handle'],
                                mode='destroy')
        tg2.tg_interface_config(port_handle=tg_ph_2, handle=tg_comn_handle["rt_host"]["tg2_rt_int_handle_2"]['handle'],
                                mode='destroy')
        tg2.tg_interface_config(port_handle=tg_ph_2, handle=tg_comn_handle["rt_host"]["tg2_rt_int_handle_3"]['handle'],
                                mode='destroy')
        tg2.tg_interface_config(port_handle=tg_ph_2, handle=tg_comn_handle["rt_host"]["tg2_rt_int_handle_max_v2"]['handle'],
                                mode='destroy')
        tg2.tg_interface_config(port_handle=tg_ph_2, handle=tg_comn_handle["rt_host"]["tg2_rt_int_handle_max_v3"]['handle'],
                                mode='destroy')
        tg3.tg_interface_config(port_handle=tg_ph_3, handle=tg_comn_handle["rt_host"]["tg3_rt_int_handle_1"]['handle'],
                                mode='destroy')
        tg3.tg_interface_config(port_handle=tg_ph_3, handle=tg_comn_handle["rt_host"]["tg3_rt_int_handle_2"]['handle'],
                                mode='destroy')


def util_tg_init(vars, tg_port_list):
    tg_port_list = list(tg_port_list) if isinstance(tg_port_list, list) else [tg_port_list]
    tg_handler = tgapi.get_handles(vars, tg_port_list)
    return tg_handler


def send_leave_stc(tg_obj, handle):
    if tg_obj.tg_type == 'stc':
        tg_obj.tg_emulation_igmp_control(handle=handle, mode='leave')


def util_tg_routing_int_config(tg1, tg2, tg3, tg_ph_1, tg_ph_2, tg_ph_3):
    result = {"igmp_host": {}, "rt_host": {}, "querier": {}}

    st.banner("TG1 - IGMPv1 Host")
    tg1_rt_int_handle_1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='21.1.1.100', gateway='21.1.1.1',
                                 arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[0], ipv4_resolve_gateway=0)
    result["rt_host"]["tg1_rt_int_handle_1"] = tg1_rt_int_handle_1
    session_conf1 = {'mode': 'create', 'igmp_version': 'v1'}
    group_conf1 = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': igmp_data.igmp_grp_ip[0], }
    igmp_group_conf1 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg1_igmp_host_1 = tgapi.tg_igmp_config(tg=tg1, handle=tg1_rt_int_handle_1['handle'], session_var=session_conf1, group_var=group_conf1,
                                igmp_group_var=igmp_group_conf1)
    result["igmp_host"]["tg1_igmp_host_1"] = tg1_igmp_host_1

    st.banner("TG1 - IGMPv2 Host")
    tg1_rt_int_handle_2 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='21.1.1.101',
                                                 gateway='21.1.1.1',
                                                 arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[1],
                                                 ipv4_resolve_gateway=0)
    result["rt_host"]["tg1_rt_int_handle_2"] = tg1_rt_int_handle_2
    session_conf2 = {'mode': 'create', 'igmp_version': 'v2'}
    group_conf2 = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': igmp_data.igmp_grp_ip[1], }
    igmp_group_conf2 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg1_igmp_host_2 = tgapi.tg_igmp_config(tg=tg1, handle=tg1_rt_int_handle_2['handle'], session_var=session_conf2,
                                     group_var=group_conf2,
                                     igmp_group_var=igmp_group_conf2)
    result["igmp_host"]["tg1_igmp_host_2"] = tg1_igmp_host_2

    st.banner("TG2 - IGMPv3 Host")
    tg2_rt_int_handle_1 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='41.1.1.100',
                                                 gateway='41.1.1.1',
                                                 arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[3],
                                                 ipv4_resolve_gateway=0)
    result["rt_host"]["tg2_rt_int_handle_1"] = tg2_rt_int_handle_1
    session_conf3 = {'mode': 'create', 'igmp_version': 'v3'}
    group_conf3 = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': igmp_data.igmp_grp_ip[-1], }
    source_conf3 = {'mode': 'create', 'num_sources': '1', 'ip_addr_start': igmp_data.igmpv3_src_addr, }
    igmp_group_conf3 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg2_igmp_host_1 = tgapi.tg_igmp_config(tg=tg1, handle=tg2_rt_int_handle_1['handle'], session_var=session_conf3,
                                     group_var=group_conf3,source_var=source_conf3,
                                     igmp_group_var=igmp_group_conf3)
    result["igmp_host"]["tg2_igmp_host_1"] = tg2_igmp_host_1

    st.banner("TG2 - IGMPv2 Host")

    tg2_rt_int_handle_2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='41.1.1.101',
                                                  gateway='41.1.1.1',
                                                  arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[2],
                                                  ipv4_resolve_gateway=0)
    result["rt_host"]["tg2_rt_int_handle_2"] = tg2_rt_int_handle_2
    session_conf4 = {'mode': 'create', 'igmp_version': 'v2'}
    group_conf4 = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': igmp_data.igmp_grp_ip[2], }
    igmp_group_conf4 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg2_igmp_host_2 = tgapi.tg_igmp_config(tg=tg2, handle=tg2_rt_int_handle_2['handle'], session_var=session_conf4,
                                     group_var=group_conf4,
                                     igmp_group_var=igmp_group_conf4)
    result["igmp_host"]["tg2_igmp_host_2"] = tg2_igmp_host_2

    st.banner("TG2 - IGMPv2 Host with same as IGMPv3 group")
    tg2_rt_int_handle_3 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='41.1.1.99',
                                                 gateway='41.1.1.1',
                                                 arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[3],
                                                 ipv4_resolve_gateway=0)
    result["rt_host"]["tg2_rt_int_handle_3"] = tg2_rt_int_handle_3
    session_conf5 = {'mode': 'create', 'igmp_version': 'v2'}
    group_conf5 = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': igmp_data.igmp_grp_ip[-1], }
    igmp_group_conf5 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg2_igmp_host_3 = tgapi.tg_igmp_config(tg=tg1, handle=tg2_rt_int_handle_3['handle'], session_var=session_conf5,
                                     group_var=group_conf5,igmp_group_var=igmp_group_conf5)
    result["igmp_host"]["tg2_igmp_host_3"] = tg2_igmp_host_3

    st.banner("TG3 - IGMPv3 Host with 0.0.0.0 as source address")
    tg3_rt_int_handle_1 = tg3.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr='61.61.61.99',
                                                 gateway='61.1.1.1',
                                                 arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[3],
                                                 ipv4_resolve_gateway=0)
    result["rt_host"]["tg3_rt_int_handle_1"] = tg3_rt_int_handle_1
    session_conf6 = {'mode': 'create', 'igmp_version': 'v3'}
    group_conf6 = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': igmp_data.igmp_grp_ip[-2], }
    source_conf6 = {'mode': 'create', 'num_sources': '1', 'ip_addr_start': "0.0.0.0", }
    igmp_group_conf6 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg3_igmp_host_1 = tgapi.tg_igmp_config(tg=tg3, handle=tg3_rt_int_handle_1['handle'], session_var=session_conf6,
                                     group_var=group_conf6,source_var=source_conf6,
                                     igmp_group_var=igmp_group_conf6)
    result["igmp_host"]["tg3_igmp_host_1"] = tg3_igmp_host_1

    tg3_rt_int_handle_2 = tg3.tg_interface_config(port_handle=tg_ph_3, mode='config', intf_ip_addr='61.61.61.89',
                                                 gateway='61.1.1.1',
                                                 arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[1],
                                                 ipv4_resolve_gateway=0)
    result["rt_host"]["tg3_rt_int_handle_2"] = tg3_rt_int_handle_2
    session_conf7 = {'mode': 'create', 'igmp_version': 'v2'}
    group_conf7 = {'mode': 'create', 'num_groups': '1', 'ip_addr_start': igmp_data.igmp_grp_ip[1], }
    igmp_group_conf7 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg3_igmp_host_2 = tgapi.tg_igmp_config(tg=tg3, handle=tg3_rt_int_handle_2['handle'], session_var=session_conf7,
                                     group_var=group_conf7,
                                     igmp_group_var=igmp_group_conf7)
    result["igmp_host"]["tg3_igmp_host_2"] = tg3_igmp_host_2

    # MAX IGMP Host config - Start
    st.banner("TG2 - IGMPv2 Host MAX")
    tg2_rt_int_handle_max_v2 = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='21.1.1.102',
                                                       gateway='21.1.1.1',
                                                       arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[1],
                                                       ipv4_resolve_gateway=0)
    result["rt_host"]["tg2_rt_int_handle_max_v2"] = tg2_rt_int_handle_max_v2
    session_conf2 = {'mode': 'create', 'igmp_version': 'v2'}
    group_conf2 = {'mode': 'create', 'num_groups': igmp_data.max_groups_v2, 'ip_addr_start': "225.3.1.1"}
    igmp_group_conf2 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg2_igmp_host_max_v2 = tgapi.tg_igmp_config(tg=tg1, handle=tg2_rt_int_handle_max_v2['handle'], session_var=session_conf2,
                                          group_var=group_conf2,
                                          igmp_group_var=igmp_group_conf2)
    result["igmp_host"]["tg2_igmp_host_max_v2"] = tg2_igmp_host_max_v2

    st.banner("TG2 - IGMPv3 Host MAX")
    tg2_rt_int_handle_max_v3 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='41.1.1.102',
                                                       gateway='41.1.1.1',
                                                       arp_send_req='1', vlan='1', vlan_id=igmp_data.vlan_li[3],
                                                       ipv4_resolve_gateway=0)
    result["rt_host"]["tg2_rt_int_handle_max_v3"] = tg2_rt_int_handle_max_v3
    session_conf3 = {'mode': 'create', 'igmp_version': 'v3'}
    group_conf3 = {'mode': 'create', 'num_groups': igmp_data.max_groups_v3, 'ip_addr_start': "225.4.1.1"}
    source_conf3 = {'mode': 'create', 'num_sources': '1', 'ip_addr_start': igmp_data.igmpv3_src_addr}
    igmp_group_conf3 = {'mode': 'create', 'g_filter_mode': 'include'}
    tg2_igmp_host_max_v3 = tgapi.tg_igmp_config(tg=tg1, handle=tg2_rt_int_handle_max_v3['handle'], session_var=session_conf3,
                                          group_var=group_conf3, source_var=source_conf3,
                                          igmp_group_var=igmp_group_conf3)
    result["igmp_host"]["tg2_igmp_host_max_v3"] = tg2_igmp_host_max_v3
    # MAX IGMP Host config - End


    tg3.tg_emulation_igmp_control(handle=tg3_igmp_host_1['session']['host_handle'], mode='start')
    tg3.tg_emulation_igmp_control(handle=tg3_igmp_host_2['session']['host_handle'], mode='start')
    tg1.tg_emulation_igmp_control(handle=tg1_igmp_host_1['session']['host_handle'], mode='start')
    tg1.tg_emulation_igmp_control(handle=tg1_igmp_host_2['session']['host_handle'], mode='start')
    tg2.tg_emulation_igmp_control(handle=tg2_igmp_host_1['session']['host_handle'], mode='start')
    tg2.tg_emulation_igmp_control(handle=tg2_igmp_host_2['session']['host_handle'], mode='start')
    tg2.tg_emulation_igmp_control(handle=tg2_igmp_host_3['session']['host_handle'], mode='start')

    return result


def util_tg_stream_config(tg3, tg4, tg_ph_3, tg_ph_4, tg5, tg_ph_5):
    result = {"tg3":{}, "tg4":{}, "tg5":{}}
    st.log("Mcast data for vlan : {}, group : {}".format(igmp_data.vlan_li[1], igmp_data.igmp_grp_ip[1]))
    tg4_mcast_data_1_str = tg4.tg_traffic_config(port_handle=tg_ph_4, mode='create', transmit_mode='single_burst',
                                                     length_mode='fixed', rate_pps='1000',pkts_per_burst='1000',
                                                     l3_protocol='ipv4', mac_src=igmp_data.tg4_src_mac_addr, mac_dst=igmp_data.igmp_grp_mac[1],
                                                vlan_id=igmp_data.vlan_li[1], vlan="enable",
                                                ip_src_addr="32.1.1.1",
                                                ip_dst_addr=igmp_data.igmp_grp_ip[1], l4_protocol='udp',
                                                udp_src_port="991",
                                                udp_dst_port="112")
    result["tg4"]["tg4_mcast_data_1_str_id_1"] = tg4_mcast_data_1_str['stream_id']

    st.log("Mcast data for vlan : {}, group : {}".format(igmp_data.vlan_li[0], igmp_data.igmp_grp_ip[0]))
    tg4_mcast_data_2_str = tg4.tg_traffic_config(port_handle=tg_ph_4, mode='create', transmit_mode='single_burst',
                                                 length_mode='fixed', rate_pps='1000',pkts_per_burst='1000',
                                                 l3_protocol='ipv4', mac_src=igmp_data.tg4_src_mac_addr,
                                                 mac_dst=igmp_data.igmp_grp_mac[0],
                                                 vlan_id=igmp_data.vlan_li[0], vlan="enable",
                                                 ip_src_addr="32.1.1.1",
                                                 ip_dst_addr=igmp_data.igmp_grp_ip[0], l4_protocol='udp',
                                                 udp_src_port="9091",
                                                 udp_dst_port="1212")
    result["tg4"]["tg4_mcast_data_2_str_id_1"] = tg4_mcast_data_2_str['stream_id']

    st.log("Mcast data for vlan : {}, group : {}".format(igmp_data.vlan_li[1], igmp_data.igmp_grp_ip[1]))
    tg5_mcast_data_1_str = tg5.tg_traffic_config(port_handle=tg_ph_5, mode='create', transmit_mode='continuous',
                                                 length_mode='fixed', rate_pps='1000',
                                                 l3_protocol='ipv4', mac_src=igmp_data.tg5_src_mac_addr,
                                                 mac_dst=igmp_data.igmp_grp_mac[1],
                                                 vlan_id=igmp_data.vlan_li[1], vlan="enable",
                                                 ip_src_addr="33.141.1.1",
                                                 ip_dst_addr=igmp_data.igmp_grp_ip[1], l4_protocol='udp',
                                                 udp_src_port="891",
                                                 udp_dst_port="212")
    result["tg5"]["tg5_mcast_data_1_str_id_1"] = tg5_mcast_data_1_str['stream_id']

    st.log("Mcast data for vlan : {}, group : {}".format(igmp_data.vlan_li[2], igmp_data.igmp_st_grp_ip[2]))
    tg3_mcast_data_1_str = tg3.tg_traffic_config(port_handle=tg_ph_3, mode='create', transmit_mode='continuous',
                                                 length_mode='fixed', rate_pps='1000',
                                                 l3_protocol='ipv4', mac_src=igmp_data.tg4_src_mac_addr,
                                                 mac_dst=igmp_data.igmp_st_grp_mac[2],
                                                 vlan_id=igmp_data.vlan_li[2], vlan="enable",
                                                 ip_src_addr="32.1.1.1",
                                                 ip_dst_addr=igmp_data.igmp_st_grp_ip[2], l4_protocol='udp',
                                                 udp_src_port="991",
                                                 udp_dst_port="112")
    result["tg3"]["tg3_mcast_data_1_str_id_1"] = tg3_mcast_data_1_str['stream_id']

    return result


def util_igmp_snooping_disable(dut, vlan):
    vlan_list = make_list(vlan)
    for i in vlan_list:
        igmp.config(dut, "no_form", "mode", vlan = i )


def util_igmp_snooping_enable(dut,vlan,version):
    vlan_list = make_list(vlan)
    for i in vlan_list:
        igmp.config(dut, "mode", vlan = i, version = version )


def util_igmp_snooping_mrouter_config(dut, vlan, mrouter_interface, no_form):
    mroute_int_li = make_list(mrouter_interface)
    for i in mroute_int_li:
        if no_form:
            igmp.config(dut, "no_form", vlan = vlan, mrouter_interface = i  )
        else:
            igmp.config(dut, vlan=vlan, mrouter_interface=i  )

def util_igmp_snooping_st_group_config(dut, vlan, group, intf,  no_form):
    if no_form:
        igmp.config(dut, "no_form", vlan = vlan, static_group_address=group, static_group_interface = intf,   )
    else:
        igmp.config(dut, vlan = vlan,  static_group_address=group, static_group_interface = intf )


def util_igmp_snooping_version(dut, vlan, version):
        igmp.config(dut, vlan = vlan,  version = version)


def config_static_group(config='yes'):
    st.log("{}Configuring Static IGMP entries.".format('' if config == 'yes' else 'Un'))
    no_form = '' if config == 'yes' else 'no_form'
    igmp.config(vars.D1, no_form, vlan=igmp_data.vlan_li[1], static_group_interface=vars.D1T1P2,
                static_group_address=igmp_data.igmp_st_grp_ip[0] )
    igmp.config(vars.D1, no_form, vlan=igmp_data.vlan_li[3], static_group_interface=vars.D1T1P2,
                static_group_address=igmp_data.igmp_st_grp_ip[1] )


def max_entries_adv(mode='start'):
    if tg2.tg_type == 'stc':
        mode = 'join' if mode == 'start' else 'leave'
    st.log("{} simulating MAX V2 and V3 IGMP entries.".format(mode.capitalize()))
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_max_v2"]['session']['host_handle'],
                                  mode=mode)
    st.log("Waiting for 5 sec for the stability in IGMP group lear/unlearn in case of scaling")
    st.wait(5)
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_max_v3"]['session']['host_handle'],
                                  mode=mode)
    st.log("Waiting for 5 sec for the stability in IGMP group learn/unlearn in case of scaling")
    st.wait(5)


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_v2():
    """
    FtOpSoSwIgFn006 - Verify that switch adds entries to the IGMP Snooping table as it receives the appropriate IGMPv2 join messages and
    forwards multicast data to only the registered hosts.
    FtOpSoSwIgFn012 - Verify that traffic is forwarded fine after shut and no shut of interface on which igmp v2 snooping entries are learnt.
    FtOpSoSwIgFi001 -  Verify the IGMPv2 snooping functionality over port channel
    """
    st.banner("FtOpSoSwIgFn006 - Verify that switch adds entries to the IGMP Snooping table as it receives the appropriate IGMPv2 join messages", width=150)
    tc1_report_flag = 0
    st.log("Send join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    st.wait(3)
    st.log("Check the igmp snooping table entry")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list =[{"vlan":igmp_data.vlan_li[1],"source_address":"*",
                              "group_address":igmp_data.igmp_grp_ip[1],"outgoing_ports":[vars.D1T1P1]}] ):
        tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                      mode='leave')
        exec_all(True,[[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        tc1_report_flag = 1
    if tc1_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn006", "igmp_snooping_verification_fail_for_igmpv2")
    else:
        st.report_tc_pass("FtOpSoSwIgFn006", "igmp_snooping_verification_successful_for_igmpv2")

    st.banner("FtOpSoSwIgFn012 - Verify that traffic is forwarded fine after shut and no shut of interface on which igmp v2 snooping entries are learnt.", width=150)
    tc2_report_flag = 0
    interface_operation(vars.D1, [vars.D1T1P1], operation="shutdown", skip_verify=True )
    st.log("Waiting for 2 sec after shutdown the interface")
    st.wait(2)
    interface_operation(vars.D1, [vars.D1T1P1], operation="startup", skip_verify=True)
    if not poll_for_interface_status(vars.D1, vars.D1T1P1, "oper", "up", iteration=10, delay=1):
        st.error("Failed to startup interface {} on the DUT {}".format(vars.D1T1P1, vars.D1))
        st.report_fail("interface_is_down_on_dut", vars.D1T1P1)
    st.log("Waiting for 5 sec after interface is UP for stability in IGMP join learing")
    st.wait(5)
    send_leave_stc(tg1, tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'])
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    st.wait(1)
    st.log("Check the igmp snooping table entry after shut no shut on port")
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}],
                               ):
        st.log("Initiate mcast data from TG4 and check traffic forwards to IGMP hosts joined ports")
        tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
        tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        traffic_details = {
            '1': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [1],
                'rx_ports': [vars.T1D1P1],
                'rx_obj': [tg1],
            },
            '2': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [0],
                'rx_ports': [vars.T1D1P2],
                'rx_obj': [tg2],
            }
        }
        if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
            st.error("Multicast traffic is either not forwarded to IGMP join learned port or flood to all ports ")
            exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
            tc2_report_flag = 1
    else:
        st.error("IGMPv2 join not learned successfully after shut no shut on the interface")
        tc2_report_flag = 1
    if tc2_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn012", "igmp_snooping_verification_shut_no_shut", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn012", "igmp_snooping_verification_shut_no_shut", "successful")

    st.log("Send Leave msg from IGMP host on TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')

    tc3_report_flag = 0
    st.banner("FtOpSoSwIgFi001 -  Verify the IGMPv2 snooping functionality over port channel", width=100)
    util_igmp_snooping_disable(vars.D1, igmp_data.vlan_li[1])

    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    st.wait(3)
    if not igmp.verify_groups(vars.D2, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [igmp_data.prt_chnl]}]):
        tc3_report_flag = 1
    add_del_portchannel_member(vars.D2, igmp_data.prt_chnl, [vars.D2D1P1, vars.D2D1P2], flag="del", skip_verify=True)
    add_del_portchannel_member(vars.D2, igmp_data.prt_chnl, [vars.D2D1P1, vars.D2D1P2], flag="add", skip_verify=True)
    if not poll_for_portchannel_status(vars.D2, igmp_data.prt_chnl, state="up", iteration=20, delay=1):
        tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                      mode='leave')
        util_igmp_snooping_enable(vars.D1, igmp_data.vlan_li[1], '2')
        st.report_fail("portchannel_verification_failed", igmp_data.prt_chnl, vars.D2)
    st.log("Waiting for 5 sec after Port Channel is UP for stability in IGMP join learing")
    st.wait(5)
    send_leave_stc(tg1, tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'])
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    st.wait(3)
    if not igmp.verify_groups(vars.D2, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [igmp_data.prt_chnl]}]):
        tc3_report_flag = 1
    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMP hosts joined ports")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D2P2],
            'rx_obj': [tg5],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error("Multicast traffic is either not forwarded to IGMP join learned port or flood to all ports ")
        exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        tc3_report_flag = 1
    if tc3_report_flag:
        st.report_tc_fail("FtOpSoSwIgFi001", "igmp_snooping_verification_fail_for_igmp_pc")
    else:
        st.report_tc_pass("FtOpSoSwIgFi001", "igmp_snooping_verification_successful_for_igmp_pc")


    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    util_igmp_snooping_enable(vars.D1, igmp_data.vlan_li[1], '2')
    if (tc1_report_flag | tc2_report_flag | tc3_report_flag):
        st.report_fail("igmp_snooping_verification_fail_for_igmpv2")
    else:
        st.report_pass("igmp_snooping_verification_successful_for_igmpv2")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_v1():
    """
    Verify that switch adds entries to the IGMP Snooping table as it receives the appropriate IGMPv1 join messages and
    forwards multicast data to only the registered hosts.
    """
    st.log("Send join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.log("Check the igmp snooping table entry")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[0], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[0],
                                                                    "outgoing_ports": [vars.D1T1P1]}],
                               ):
        tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                      mode='leave')
        exec_all(True,[[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        st.report_fail("igmp_snooping_verification_fail_for_igmpv1")
    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMP hosts joined ports")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_2_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_2_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        }
    }
    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if not filter_result:
        tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                      mode='leave')
        exec_all(True, [[show_interface_counters_all, vars.D1],[show_interface_counters_all, vars.D2]])
        st.report_fail("igmp_snooping_verification_fail_for_igmpv1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    st.report_pass("igmp_snooping_verification_successful_for_igmpv1")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_static_mrotuter():
    """
    FtOpSoSwIgFn016 - Verify that multicast traffic forwards to static mrouter ports along with IGMP registered hosts.
    FtOpSoSwIgFn003 - Verify that the data is correctly forwarded when statically configured mrouter and dynamically
    mrouter entries are present.
    """
    st.banner("FtOpSoSwIgFn016 - Verify that multicast traffic forwards to static mrouter ports along with IGMP registered hosts.")
    tc1_report_flag = 0
    st.log("Send join from TG2")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    if not igmp.verify_groups(vars.D1, "groups_vlan",
                              verify_list=[{"vlan": igmp_data.vlan_li[2], "source_address": "*",
                                            "group_address": igmp_data.igmp_grp_ip[2],
                                            "outgoing_ports": [vars.D1T1P2]}],
                               ):
        tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_2"]['config']['group_handle'],
                                      mode='leave')
        exec_all(True,[[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        st.report_fail("igmp_snooping_verification_fail_for_igmpv2")
    st.log("Adding static mrouter for IGMPv2 in vlan {}".format(igmp_data.vlan_li[2]))
    util_igmp_snooping_mrouter_config(vars.D1,igmp_data.vlan_li[2],[vars.D1T1P1], False)

    if not igmp.verify(vars.D1, mrouter_interface=[vars.D1T1P1], vlan=igmp_data.vlan_li[2] ):
        st.error("Static Mrouter Port list not updated")
        tc1_report_flag=1
    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMP hosts joined ports and Static Mrouter Port")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                          ip_dst_addr=igmp_data.igmp_grp_ip[2], vlan_id=igmp_data.vlan_li[2], mac_dst=igmp_data.igmp_grp_mac[2])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        },
        '3': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P3],
            'rx_obj': [tg3],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        exec_all(True, [[show_interface_counters_all, vars.D1],[show_interface_counters_all, vars.D2]])
        tc1_report_flag=1
    if tc1_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn016", "igmp_snooping_static_mroute_verification_fail")
    else:
        st.report_tc_pass("FtOpSoSwIgFn016", "igmp_snooping_static_mroute_verification_success")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')

    st.banner("FtOpSoSwIgFn003 - Verify that the data is correctly forwarded when statically configured mrouter and dynamically mrouter entries are present.", width =150)
    tc2_report_flag = 0
    st.log("Enable IGMP Querier in DUT2 to get it learned as dynamic mrouter in DUT1")
    igmp.config(vars.D2, "querier", vlan=igmp_data.vlan_li[2] )

    exec_all(True, [
        [util_igmp_snooping_st_group_config, vars.D1, igmp_data.vlan_li[2], igmp_data.igmp_st_grp_ip[2], vars.D1T1P2,
         False],
        [util_igmp_snooping_st_group_config, vars.D2, igmp_data.vlan_li[2], igmp_data.igmp_st_grp_ip[2],
         vars.D2T1P2, False]])

    if not igmp.verify(vars.D1, mrouter_interface=[vars.D1T1P1, vars.D1D2P3], vlan=igmp_data.vlan_li[2] ):
        st.error("Dynamic Mrouter Port list not updated")
        tc2_report_flag=1
    st.log("Initiate mcast data from TG3 and check traffic forwards to static group configured port and Mrouter Ports")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg3.tg_traffic_control(action='run', handle=tg_str_data["tg3"]["tg3_mcast_data_1_str_id_1"])
    tg3.tg_traffic_control(action='stop', handle=tg_str_data["tg3"]["tg3_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P3],
            'tx_obj': [tg3],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D1P3],
            'tx_obj': [tg3],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        },
        '3': {
            'tx_ports': [vars.T1D1P3],
            'tx_obj': [tg3],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D2P2],
            'rx_obj': [tg5],
        },
        '4': {
            'tx_ports': [vars.T1D1P3],
            'tx_obj': [tg3],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [tg4],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        tc2_report_flag = 1
    if tc2_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn003", "igmp_snooping_static_mroute_verification_fail")
    else:
        st.report_tc_pass("FtOpSoSwIgFn003", "igmp_snooping_static_mroute_verification_success")

    util_igmp_snooping_mrouter_config(vars.D1, igmp_data.vlan_li[2], [vars.D1T1P1], True)
    igmp.config(vars.D2, "no_form", "querier", vlan=igmp_data.vlan_li[2] )
    exec_all(True, [
        [util_igmp_snooping_st_group_config, vars.D1, igmp_data.vlan_li[2], igmp_data.igmp_st_grp_ip[2], vars.D1T1P2,
         True],
        [util_igmp_snooping_st_group_config, vars.D2, igmp_data.vlan_li[2], igmp_data.igmp_st_grp_ip[2],
         vars.D2T1P2, True]])
    if (tc1_report_flag | tc2_report_flag):
        st.report_fail("igmp_snooping_static_mroute_verification_fail")
    else:
        st.report_pass("igmp_snooping_static_mroute_verification_success")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_static_group():
    """
    FtOpSoSwIgFn017 - Verify that multicast traffic forwards as per static groups configured on Physical and Port Channel
    interfaces. Also verify that static entries are intact after shut no shut on the interfaces.
    FtOpSoSwIgFn009 - Verify that IGMP leaves do not have any effect on the IGMP snooping table for static entries.
    """
    tc1_report_flag = 0
    st.banner("FtOpSoSwIgFn017 - Verify that multicast traffic forwards as per static groups configured on Physical and Port Channel Interfaces", width=150)
    st.log("Static group addition on Physical interface and Port Channel interface")
    exec_all(True,[[util_igmp_snooping_st_group_config, vars.D1, igmp_data.vlan_li[1], igmp_data.igmp_grp_ip[1], vars.D1T1P1, False],
              [util_igmp_snooping_st_group_config, vars.D2, igmp_data.vlan_li[1], igmp_data.igmp_grp_ip[1], igmp_data.prt_chnl, False]])
    data1 = {"verify_list":[{"vlan":igmp_data.vlan_li[1],
                      "source_address":"*", "group_address":igmp_data.igmp_grp_ip[1],
                      "outgoing_ports":[vars.D1T1P1]}]}
    data2 =  {"verify_list":[{"vlan": igmp_data.vlan_li[1],
                      "source_address": "*", "group_address": igmp_data.igmp_grp_ip[1],
                      "outgoing_ports": [igmp_data.prt_chnl]}],  }
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], igmp.verify_groups, [data1, data2], "groups_vlan")
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.error("Static group addition not successful on Physical interface or on Port Channel")
            st.report_fail("igmp_snooping_static_group_verification_fail")
    interface_operation(vars.D1, [vars.D1T1P1, igmp_data.prt_chnl], operation="shutdown", skip_verify=True )
    st.wait(1)
    interface_operation(vars.D1, [vars.D1T1P1, igmp_data.prt_chnl], operation="startup", skip_verify=True,
                              )
    if not poll_for_interface_status(vars.D1, vars.D1T1P1, "oper", "up", iteration=10, delay=1):
        st.error("Failed to startup interface {} on the DUT {}".format(vars.D1T1P1, vars.D1))
        st.report_fail("interface_is_down_on_dut", vars.D1T1P1)
    if not poll_for_portchannel_status(vars.D1, igmp_data.prt_chnl, state="up", iteration=10, delay=1):
        st.report_fail("portchannel_verification_failed", igmp_data.prt_chnl, vars.D1)
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], igmp.verify_groups, [data1, data2], "groups_vlan")
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.error("Static group addition not successful on Physical interface or on Port Channel")
            st.report_fail("igmp_snooping_static_group_verification_fail")
    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMP hosts joined ports and Static Mrouter Port")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                          ip_dst_addr=igmp_data.igmp_grp_ip[1], vlan_id=igmp_data.vlan_li[1], mac_dst=igmp_data.igmp_grp_mac[1])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error("Traffic forwarding is not successful for static group")
        exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        tc1_report_flag =1
    if tc1_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn017", "igmp_snooping_static_group_verification_fail")
    else:
        st.report_tc_pass("FtOpSoSwIgFn017", "igmp_snooping_static_group_verification_success")

    #############################################
    st.banner("FtOpSoSwIgFn009 - Verify that IGMP leaves do not have any effect on the mcast forwarding table for static entries", width=150)
    tc2_report_flag = 0
    st.log("Send IGMP Leave for the static group created")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    st.wait(1)
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], igmp.verify_groups, [data1, data2], "groups_vlan")
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.error("Static group removed when IGMP Leave message received")
            tc2_report_flag = 1
    if tc2_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn009", "igmp_snooping_static_group_verification_fail")
    else:
        st.report_tc_pass("FtOpSoSwIgFn009", "igmp_snooping_static_group_verification_success")
    #############################################
    if (tc1_report_flag | tc2_report_flag):
        st.report_fail("igmp_snooping_static_group_verification_fail")
    else:
        st.report_pass("igmp_snooping_static_group_verification_success")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_v3():
    """
    FtOpSoSwIgFn002 - Verify that switch adds entries to the IGMPv3 Snooping table as it receives the appropriate IGMPv3 join messages and
    forwards multicast data to only the registered hosts with the specific source and floods traffic with different source
    address.
    FtOpSoSwIgFi002 - Verify the IGMPv3 snooping functionality over port channel
    """
    st.banner(
        " FtOpSoSwIgFn002 - Verify that switch adds entries to the IGMPv3 Snooping table as it receives the appropriate IGMPv3 join messages", width=150)
    st.log("Send join from TG2")
    tc1_report_flag =0
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.wait(3)
    st.log("Check the igmp snooping table entry")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list = [{"vlan":igmp_data.vlan_li[3],
                              "source_address":igmp_data.igmpv3_src_addr,"group_address":igmp_data.igmp_grp_ip[-1],
                              "outgoing_ports":[vars.D1T1P2]}] ):
        tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                      mode='leave')
        exec_all(True,[[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        st.report_fail("igmp_snooping_verification_fail_for_igmpv3")
    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMPv3 hosts joined ports")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                          ip_dst_addr=igmp_data.igmp_grp_ip[-1],  ip_src_addr=igmp_data.igmpv3_src_addr,
                          vlan_id=igmp_data.vlan_li[3], mac_dst=igmp_data.igmp_grp_mac[-1])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error("Mcast data traffic for IGMPv3 host is either not forwarded to host learned port or flooded to other ports too")
        tc1_report_flag = 1
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                          ip_dst_addr=igmp_data.igmp_grp_ip[-1], ip_src_addr="32.1.1.1",
                          vlan_id=igmp_data.vlan_li[3], mac_dst=igmp_data.igmp_grp_mac[-1])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error(
            "Mcast data traffic with different source for IGMPv3 host is either forwarded to host learned port only or not flooded all ports")
        tc1_report_flag = 1

    if tc1_report_flag:
        exec_all(True, [[show_interface_counters_all, vars.D1],[show_interface_counters_all, vars.D2]])
        st.report_tc_fail("FtOpSoSwIgFn002", "igmp_snooping_verification_fail_for_igmpv3")
    else:
        st.report_tc_pass("FtOpSoSwIgFn002", "igmp_snooping_verification_successful_for_igmpv3")

    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    #############################################
    tc2_report_flag = 0
    st.banner(" FtOpSoSwIgFi002 - Verify that IGMP snooping functionality works over portchannel interfaces with IGMPv3 messages", width=150)
    util_igmp_snooping_disable(vars.D1, igmp_data.vlan_li[3])
    interface_operation(vars.D1, [vars.D1D2P4], operation="shutdown", skip_verify=True )
    exec_foreach(True, [vars.D1, vars.D2], config_vlan_members, igmp_data.vlan_li[3], igmp_data.prt_chnl, "add")
    st.wait(1)
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.wait(2)
    if not igmp.verify_groups(vars.D2, "groups_vlan", verify_list = [{"vlan":igmp_data.vlan_li[3],
                              "source_address":igmp_data.igmpv3_src_addr,"group_address":igmp_data.igmp_grp_ip[-1],
                              "outgoing_ports":[igmp_data.prt_chnl]}] ):
        tc2_report_flag = 1
        exec_all(True,[[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])

    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMPv3 hosts joined ports")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                          ip_dst_addr=igmp_data.igmp_grp_ip[-1],  ip_src_addr=igmp_data.igmpv3_src_addr,
                          vlan_id=igmp_data.vlan_li[3], mac_dst=igmp_data.igmp_grp_mac[-1])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D2P2],
            'rx_obj': [tg5],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error("Mcast data traffic for IGMPv3 host is either not forwarded to host learned port or flooded to other ports too")
        tc2_report_flag =1

    if tc2_report_flag:
        st.error("IGMPv3 joins learning failed on Port Channel")
        st.report_tc_fail("FtOpSoSwIgFi002", "igmp_snooping_verification_fail_for_igmp_pc")
    else:
        st.report_tc_pass("FtOpSoSwIgFi002", "igmp_snooping_verification_successful_for_igmp_pc")
    exec_foreach(True, [vars.D1, vars.D2], config_vlan_members, igmp_data.vlan_li[3], igmp_data.prt_chnl, "del")
    interface_operation(vars.D1, [vars.D1D2P4], operation="startup", skip_verify=True )
    util_igmp_snooping_enable(vars.D1, igmp_data.vlan_li[3], '3')
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    #############################################

    if (tc1_report_flag | tc2_report_flag):
        st.report_fail("igmp_snooping_verification_fail_for_igmpv3")
    else:
        st.report_pass("igmp_snooping_verification_successful_for_igmpv3")

@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_change():
    """
    FtOpSoSwIgFn005 - Verify that the snooping entries are removed and added again on removing an interface from vlan and adding it back.
    FtOpSoSwIgFn004- Verify that the snooping entries are removed and added again on disabling and enabling igmp snooping.
    """
    st.banner("FtOpSoSwIgFn005 - Verify that the snooping entries are removed and added again on removing an interface from vlan and adding it back", width =150)
    tc1_report_flag = 0
    st.log("Send IGMPv1 join")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.log("Send IGMPv2 join")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    st.log("Send IGMPv3 join")
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.log("Check the igmp snooping table entry")
    res = igmp.verify_groups(vars.D1, "groups", verify_list=[
        {"vlan": igmp_data.vlan_li[1], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[1]},
        {"vlan": igmp_data.vlan_li[0], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[0]},
        {"vlan": igmp_data.vlan_li[3], "source_address": igmp_data.igmpv3_src_addr,
         "group_address": igmp_data.igmp_grp_ip[-1]}],
                              )
    if not res:
        tc1_report_flag = 1
    st.log("Check the igmp snooping table entries are not present after the vlan association is removed")
    config_vlan_members(vars.D1, igmp_data.vlan_li, [vars.D1T1P1, vars.D1T1P2], "del")
    res = igmp.verify_groups(vars.D1, "groups", verify_list=[
        {"vlan": igmp_data.vlan_li[1], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[1]},
        {"vlan": igmp_data.vlan_li[0], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[0]},
        {"vlan": igmp_data.vlan_li[3], "source_address": igmp_data.igmpv3_src_addr,
         "group_address": igmp_data.igmp_grp_ip[-1]}],
                              )
    if res:
        tc1_report_flag = 1
    st.log("Check the igmp snooping table entries are present after the vlan association is added")
    config_vlan_members(vars.D1, igmp_data.vlan_li, [vars.D1T1P1, vars.D1T1P2], "add")
    send_leave_stc(tg1, [tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                         tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                         tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle']])
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    res = igmp.verify_groups(vars.D1, "groups", verify_list=[
        {"vlan": igmp_data.vlan_li[1], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[1]},
        {"vlan": igmp_data.vlan_li[0], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[0]},
        {"vlan": igmp_data.vlan_li[3], "source_address": igmp_data.igmpv3_src_addr,
         "group_address": igmp_data.igmp_grp_ip[-1]}],
                              )
    if not res:
        tc1_report_flag = 1
    if tc1_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn005","igmp_snooping_verification_fail_for_vlan_change")
    else:
        st.report_tc_pass("FtOpSoSwIgFn005","igmp_snooping_verification_successful_for_vlan_change")

    #############################################
    tc2_report_flag = 0
    st.banner(
        "FtOpSoSwIgFn004- Verify that the snooping entries are removed and added again on disabling and enabling igmp snooping",
        width=150)
    send_leave_stc(tg1, [tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                         tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                         tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle']])
    util_igmp_snooping_disable(vars.D1, igmp_data.vlan_li)
    util_igmp_snooping_enable(vars.D1, igmp_data.vlan_li[0], '1')
    util_igmp_snooping_enable(vars.D1, [igmp_data.vlan_li[1], igmp_data.vlan_li[2]], '2' )
    util_igmp_snooping_enable(vars.D1, igmp_data.vlan_li[3], '3')

    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.wait(5)
    st.log("Check the igmp snooping table entries are present after disable and enable igmp snooping")
    res = igmp.verify_groups(vars.D1, "groups", verify_list=[
        {"vlan": igmp_data.vlan_li[1], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[1]},
        {"vlan": igmp_data.vlan_li[0], "source_address": "*", "group_address": igmp_data.igmp_grp_ip[0]},
        {"vlan": igmp_data.vlan_li[3], "source_address": igmp_data.igmpv3_src_addr,
         "group_address": igmp_data.igmp_grp_ip[-1]}],
                              )
    if not res:
        tc2_report_flag = 1
    if tc2_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn004","igmp_snooping_verification_fail_disable_enable")
    else:
        st.report_tc_pass("FtOpSoSwIgFn004","igmp_snooping_verification_successful_disable_enable")
    #############################################
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    if (tc1_report_flag | tc2_report_flag):
        st.report_fail("igmp_snooping_verification_fail_disable_enable")
    else:
        st.report_pass("igmp_snooping_verification_successful_disable_enable")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_leave():
    """
     FtOpSoSwIgFn008 - Verify that the Snooping Switch sends Group Specific Query when the switch receives an IGMPv2 Leave message.
     FtOpSoSwIgFn019 - Verify last member query interval functionality.
     FtOpSoSwIgFn007 - Verify IGMP Snooping Fast-leave functionality
    """
    st.banner("FtOpSoSwIgFn008 - Verify that the Snooping Switch sends Group Specific Query when the switch receives an IGMPv2 Leave message.", width=150)
    tc1_report_flag = 0
    st.log("Send join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    if not retry_api(igmp.verify_groups,vars.D1, "groups_vlan", verify_list =[{"vlan":igmp_data.vlan_li[1],"source_address":"*",
                              "group_address":igmp_data.igmp_grp_ip[1],"outgoing_ports":[vars.D1T1P1]}],retry_count=5,delay=1):
        tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                      mode='leave')
        exec_all(True,[[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
        st.report_fail("igmp_snooping_verification_fail_for_igmpv2")
    igmp_data.pkt_cap_grp_val = util_ip_addr_to_hexa_conv(igmp_data.igmp_grp_ip[1])
    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')
    st.log("Send Leave msg from IGMP host on TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    st.wait(2)
    tg1.tg_packet_control(port_handle=tg_ph_1, action='stop')
    igmp_pkt_cap = tg1.tg_packet_stats(port_handle=tg_ph_1, format='var', output_type='hex')
    st.log(igmp_pkt_cap)
    igmp_pkt_res = tgapi.validate_packet_capture(tg_type=tg1.tg_type, pkt_dict=igmp_pkt_cap,
                                             offset_list=[38, 42],
                                             value_list=[igmp_data.mem_qry_hex_val, igmp_data.pkt_cap_grp_val])
    if not igmp_pkt_res:
        tc1_report_flag =1
    if tc1_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn008", "igmp_snooping_verification_fail_group_query")
    else:
        st.report_tc_pass("FtOpSoSwIgFn008", "igmp_snooping_verification_successful_group_query")

    st.banner("FtOpSoSwIgFn007 - Verify IGMP Snooping Fast-leave functionality")
    tc2_report_flag = 0
    igmp_data.lmqt_val_actual = int(2*(int(igmp_data.lmqt_val)/1000))+5
    st.log("For IGMPv2, set Last Member query interval to {} msec and enable fast-leave mode".format(igmp_data.lmqt_val))
    igmp.config(vars.D1, vlan=igmp_data.vlan_li[1], last_member_query_interval=igmp_data.lmqt_val  )
    igmp.config(vars.D1,"fast_leave", vlan=igmp_data.vlan_li[1]  )
    st.log("Send IGMPv2 join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.error("IGMPv2 join not learned with fast-leave enabled")
        tc2_report_flag = 1
    st.log("Send Leave msg from IGMP host on TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.error("With fast-leave enabled and LMQT set to {} sec, IGMPv2 snooping entry not removed immediately "
               "after receiving the Leave message".format(igmp_data.lmqt_val_actual))
        tc2_report_flag = 1

    st.log(
        "For IGMPv3, set Last Member query interval to {} msec and enable fast-leave mode".format(igmp_data.lmqt_val))
    igmp.config(vars.D1, vlan=igmp_data.vlan_li[3], last_member_query_interval=igmp_data.lmqt_val,
                  )
    igmp.config(vars.D1, "fast_leave", vlan=igmp_data.vlan_li[3]  )
    st.log("Send IGMPv3 join from TG2")
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.log("Check the igmp snooping table entry")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3],
                                                                    "source_address": igmp_data.igmpv3_src_addr,
                                                                    "group_address": igmp_data.igmp_grp_ip[-1],
                                                                    "outgoing_ports": [vars.D1T1P2]}]):
        st.error("IGMPv3 join not learned with fast-leave enabled")
        tc2_report_flag= 1
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3],
                                                                    "source_address": igmp_data.igmpv3_src_addr,
                                                                    "group_address": igmp_data.igmp_grp_ip[-1],
                                                                    "outgoing_ports": [vars.D1T1P2]}]):
        st.error("With fast-leave enabled and LMQT set to {} sec, IGMPv3 snooping entry not removed immediately "
                 "after receiving the Leave message".format(igmp_data.lmqt_val_actual))
        tc2_report_flag = 1
    igmp.config(vars.D1, "no_form", "fast_leave", vlan=igmp_data.vlan_li[1]  )
    igmp.config(vars.D1, "no_form", "fast_leave", vlan=igmp_data.vlan_li[3]  )
    if tc2_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn007", "igmp_snooping_verification_fast_leave", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn007", "igmp_snooping_verification_fast_leave", "successful")


    st.banner("FtOpSoSwIgFn019 - Verify last member query interval functionality.")
    tc3_report_flag = 0
    st.log("Send join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        tc3_report_flag =1
    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')
    st.log("Send Leave msg from IGMP host on TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    st.wait(2)

    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.log("IGMP membership entry removed even before the last member query interval timeout")
        tc3_report_flag =1
    st.log("Waiting for {} sec for Last Member query timer to expire to remove the snooping entry".format(igmp_data.lmqt_val_actual))
    st.wait(igmp_data.lmqt_val_actual)
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.log("IGMP membership entry not removed even after the last member query interval timeout")
        tc3_report_flag =1
    tg1.tg_packet_control(port_handle=tg_ph_1, action='stop')
    igmp_pkt_cap = tg1.tg_packet_stats(port_handle=tg_ph_1, format='var', output_type='hex')
    st.log(igmp_pkt_cap)
    igmp_pkt_res = tgapi.validate_packet_capture(tg_type=tg1.tg_type, pkt_dict=igmp_pkt_cap,
                                           offset_list=[38, 42],
                                           value_list=[igmp_data.mem_qry_hex_val, igmp_data.pkt_cap_grp_val])
    if not igmp_pkt_res:
        st.log("IGMP query packets are not sent onto the host ports OR the IGMP query packet fields are incorrectly set")
        tc3_report_flag = 1
    if tc3_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn019", "igmp_snooping_verification_fail_lmqt")
    else:
        st.report_tc_pass("FtOpSoSwIgFn019", "igmp_snooping_verification_successful_lmqt")

    igmp.config(vars.D1, vlan=igmp_data.vlan_li[1], last_member_query_interval=igmp_data.lmqt_default_val)
    igmp.config(vars.D1, "no_form", vlan=igmp_data.vlan_li[3], last_member_query_interval=igmp_data.lmqt_val)
    if (tc1_report_flag | tc2_report_flag | tc3_report_flag):
        st.report_fail("igmp_snooping_verification_fail_group_query")
    else:
        st.report_pass("igmp_snooping_verification_successful_group_query")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_querier():
    """
     FtOpSoSwIgFn010 - Verify that the operational Snooping Querier sends out periodic General Queries on all member ports of the VLAN for which it is enabled.
     FtOpSoSwIgFn020 - Verify max response interval functionality.
     FtOpSoSwIgFn013 - Verify Querier delete join entry when Multicast membership timer exceeds.
    """

    qry_report_flag = 0
    max_res_report_flag = 0
    final_report_flag = 0
    min_qry_cnt = int((int(igmp_data.qry_check_wait_time)/int(igmp_data.qry_int)))
    max_qry_cnt = min_qry_cnt+10
    delete_vlan_member(vars.D1, igmp_data.vlan_li[1], [vars.D1T1P2, vars.D1T1P3] ,True )
    delete_vlan_member(vars.D1, igmp_data.vlan_li[2], [vars.D1T1P1, vars.D1T1P3]  ,True)
    delete_vlan_member(vars.D1, igmp_data.vlan_li[3], [vars.D1T1P1, vars.D1T1P2] ,True )
    for ea in range(1,4):
        igmp.config(vars.D1, vlan=igmp_data.vlan_li[ea], query_max_response_time=igmp_data.max_qry_res  )
        igmp.config(vars.D1, vlan =igmp_data.vlan_li[ea], query_interval=igmp_data.qry_int  )
    for ea in range(1,4):
        igmp.config(vars.D1, "querier", vlan=igmp_data.vlan_li[ea]  )
    clear_interface_counters(vars.D1,cli_type='click')
    st.log("waiting for IGMP generic queries to be sent as per the configured interval")
    st.wait(igmp_data.qry_check_wait_time)
    tg1_res = show_interface_counters_detailed(vars.D1, vars.D1T1P1, filter_key='pkt_tx_65_127_octets')
    tg2_res = show_interface_counters_detailed(vars.D1, vars.D1T1P2, filter_key='pkt_tx_65_127_octets')
    tg3_res = show_interface_counters_detailed(vars.D1, vars.D1T1P3, filter_key='pkt_tx_65_127_octets')
    if not (min_qry_cnt <= int(tg1_res) <= max_qry_cnt):
        st.error("for IGMPv1, queries are not sent as per the configured interval.")
        qry_report_flag = 1
    if not (min_qry_cnt <= int(tg2_res) <= max_qry_cnt):
        st.error("for IGMPv2, queries are not sent as per the configured interval.")
        qry_report_flag = 1
    if not (min_qry_cnt <= int(tg3_res) <= max_qry_cnt):
        st.error("for IGMPv3, queries are not sent as per the configured interval.")
        qry_report_flag = 1
    if qry_report_flag:
        final_report_flag = 1
        st.report_tc_fail("FtOpSoSwIgFn010", "igmp_snooping_verification_query_interval", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn010", "igmp_snooping_verification_query_interval", "successful")
    igmp_data.max_qry_res_apnd = (int(igmp_data.max_qry_res)*10)
    igmp_data.max_qry_res_hex = util_int_to_hexa_conv(igmp_data.max_qry_res_apnd,z_fill=2)
    tg1.tg_packet_control(port_handle=tg_ph_1, action='start')
    st.log("Waiting for IGMP generic query packets to get captured")
    st.wait(igmp_data.max_res_qry_check_wait_time)
    tg1.tg_packet_control(port_handle=tg_ph_1, action='stop')
    tg1_igmp_pkt_cap = tg1.tg_packet_stats(port_handle=tg_ph_1, format='var', output_type='hex')
    if not tgapi.validate_packet_capture(tg_type=tg1.tg_type, pkt_dict=tg1_igmp_pkt_cap,
                                           offset_list=[42, 43],
                                           value_list=[igmp_data.mem_qry_hex_val, igmp_data.max_qry_res_hex]):
        st.log("Captured Packet : {}".format(tg1_igmp_pkt_cap))
        st.error("for IGMPv1, max response time value in querier packet is not set as per the configured value.")
        max_res_report_flag = 1
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')
    st.log("Waiting for IGMP generic query packets to get captured")
    st.wait(igmp_data.max_res_qry_check_wait_time)
    tg2.tg_packet_control(port_handle=tg_ph_2, action='stop')
    tg2_igmp_pkt_cap = tg2.tg_packet_stats(port_handle=tg_ph_2, format='var', output_type='hex')
    if not tgapi.validate_packet_capture(tg_type=tg1.tg_type, pkt_dict=tg2_igmp_pkt_cap,
                                   offset_list=[42, 43],
                                   value_list=[igmp_data.mem_qry_hex_val, igmp_data.max_qry_res_hex]):
        st.log("Captured Packet : {}".format(tg2_igmp_pkt_cap))
        st.error("for IGMPv2, max response time value in querier packet is not set as per the configured value.")
        max_res_report_flag = 1
    tg3.tg_packet_control(port_handle=tg_ph_3, action='start')
    st.log("Waiting for IGMP generic query packets to get captured")
    st.wait(igmp_data.max_res_qry_check_wait_time)
    tg3.tg_packet_control(port_handle=tg_ph_3, action='stop')
    tg3_igmp_pkt_cap = tg1.tg_packet_stats(port_handle=tg_ph_3, format='var', output_type='hex')
    if not tgapi.validate_packet_capture(tg_type=tg1.tg_type, pkt_dict=tg3_igmp_pkt_cap,
                                   offset_list=[42, 43],
                                   value_list=[igmp_data.mem_qry_hex_val, igmp_data.max_qry_res_hex]):
        st.log("Captured Packet : {}".format(tg3_igmp_pkt_cap))
        st.error("for IGMPv3, max response time value in querier packet is not set as per the configured value.")
        max_res_report_flag = 1
    if max_res_report_flag:
        final_report_flag = 1
        st.report_tc_fail("FtOpSoSwIgFn020", "igmp_snooping_verification_query_max_response_time", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn020", "igmp_snooping_verification_query_max_response_time", "successful")
    for ea in range(1, 4):
        igmp.config(vars.D1, "no_form", "querier", vlan=igmp_data.vlan_li[ea], query_interval=igmp_data.qry_int,
                        query_max_response_time=igmp_data.max_qry_res  )

    st.banner("FtOpSoSwIgFn013 - Verify Querier delete join entry when Multicast membership timer exceeds.", width = 150)
    qry_del_join_f = 0
    tolerance = 5
    qry_del_joi_timer = ((2*int(igmp_data.qry_int_for_join))+(int(igmp_data.max_qry_res_for_join))+int(tolerance))
    igmp.config(vars.D1, vlan=igmp_data.vlan_li[1], query_max_response_time=igmp_data.max_qry_res_for_join  )
    igmp.config(vars.D1, vlan =igmp_data.vlan_li[1], query_interval=igmp_data.qry_int_for_join  )
    igmp.config(vars.D1, "querier", vlan=igmp_data.vlan_li[1]  )
    st.log("Send IGMPv2 join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    igmp.config(vars.D1, "no_form", "querier", vlan=igmp_data.vlan_li[1]  )
    st.log("Check the igmp snooping table entry")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.error("Failed to Learn IGMPv2 join with non-default querier interval")
        qry_del_join_f = 1
    st.log("Waiting for IGMP group membership timer to expire")
    st.wait(qry_del_joi_timer)
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.error("IGMPv2 join entry not expired as per the group membership interval")
        qry_del_join_f = 1
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    igmp.config(vars.D1, "no_form", vlan=igmp_data.vlan_li[1], query_interval=igmp_data.qry_int,
                query_max_response_time=igmp_data.max_qry_res  )
    if qry_del_join_f:
        final_report_flag = 1
        st.report_tc_fail("FtOpSoSwIgFn013", "igmp_snooping_verification_query_del_join", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn013", "igmp_snooping_verification_query_del_join", "successful")

    add_vlan_member(vars.D1, igmp_data.vlan_li[1], [vars.D1T1P2, vars.D1T1P3], tagging_mode= True  )
    add_vlan_member(vars.D1, igmp_data.vlan_li[2], [vars.D1T1P1, vars.D1T1P3], tagging_mode= True  )
    add_vlan_member(vars.D1, igmp_data.vlan_li[3], [vars.D1T1P1, vars.D1T1P2], tagging_mode= True  )

    if final_report_flag:
        st.report_fail("igmp_snooping_verification_query_interval", "failed")
    else:
        st.report_pass("igmp_snooping_verification_query_interval", "passed")


@pytest.mark.igmp_snooping_scale
def test_ft_igmp_snooping_max_groups():
    """
    Verify the Max supported IGMP snooping entries gets installed successfully (with IGMPv1/v2).
    Verify the Max supported IGMP snooping entries gets installed successfully (with IGMPv3)
    """
    max_entries_adv('start')
    config_static_group('yes')
    result = igmp.poll_igmp_groups_count(vars.D1, igmp_data.max_groups, iteration_count=5, delay=2)
    max_entries_adv('stop')
    config_static_group('no')
    if not result:
        st.report_fail('igmp_snoop_max_entry_status', "Test Fail")
    else:
        st.report_pass('igmp_snoop_max_entry_status', "Test Pass")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_pim_mrouter():
    """
    FtOpSoSwIgFn018 - Verify that on receiving the PIM helo message, port should be updated as mrouter port.
    """
    st.log("Disable IGMP snooping and enable pim on DUT2 for vlan {}".format(igmp_data.vlan_li[3]))
    util_igmp_snooping_disable(vars.D2, igmp_data.vlan_li[3])
    config_ip_addr_interface(vars.D2, interface_name=igmp_data.vlan3_intf, ip_address=igmp_data.int_ip4_addr,
                                       subnet="24", family="ipv4", config="add")
    config_intf_pim(dut=vars.D2, intf=igmp_data.vlan3_intf, pim_enable='yes', config='yes', hello_intv=1)
    st.log("waiting for pim hello packet to exchange from D2 to D1")
    if not poll_wait(igmp.verify,5,vars.D1,mrouter_interface=[vars.D1D2P4], vlan=igmp_data.vlan_li[3] ):
        st.report_fail("igmp_snooping_verification_pim_mrouter_status","failed")
    else:
        st.report_pass("igmp_snooping_verification_pim_mrouter_status","passed")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_v2_v3():
    """
    FtOpSoSwIgFn014 - When a switch receives an older version (IGMPv2 or IGMPv1) report on an interface on a given VLAN, all the previously
    gathered IGMPv3 source filtering information for that group on the given VLAN is ignored.
    FtOpSoSwIgFn022 - Verify IGMPv3 joins with zero source ip address must be learned in the IGMP snooping table.
    FtOpSoSwIgFn023 - Verify the IGMP snooping after version change and check the multiple members join and leave working.
    """
    tc1_report_flag = 0
    st.banner(
        "FtOpSoSwIgFn023 - Verify the IGMP snooping after version change and check the multiple members join and leave working")
    st.log("Change the version in {} to v3 and revert to v2".format(igmp_data.vlan_li[1]))
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_version, igmp_data.vlan_li[1], "3" )
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_version, igmp_data.vlan_li[1], "2" )
    st.log("Send IGMPv2 join from TG1, TG3")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1],
                                                             "source_address": "*",
                                                             "group_address": igmp_data.igmp_grp_ip[1],
                                                             "outgoing_ports": [vars.D1T1P1]}])
    tg3.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg3_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1],
                                                                "source_address": "*",
                                                                "group_address": igmp_data.igmp_grp_ip[1],
                                                                "outgoing_ports": [vars.D1T1P1, vars.D1T1P3]}]):
        tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                              ip_dst_addr=igmp_data.igmp_grp_ip[1], ip_src_addr="32.1.1.1",
                              vlan_id=igmp_data.vlan_li[1], mac_dst=igmp_data.igmp_grp_mac[1])
        tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
        tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        traffic_details = {
            '1': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [1],
                'rx_ports': [vars.T1D1P1],
                'rx_obj': [tg1],
            },
            '2': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [0],
                'rx_ports': [vars.T1D1P2],
                'rx_obj': [tg2],
            },
            '3': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [1],
                'rx_ports': [vars.T1D1P3],
                'rx_obj': [tg3],
            }
        }
        if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
            st.error(
                "Mcast data traffic forwarding for multiple IGMPv2 hosts is failed")
            tc1_report_flag = 1
    else:
        st.error("IGMPv2 multiple host learning failed.")
        tc1_report_flag = 1
    st.log("Send Leave from TG3, for the group from one of the host and check the outgoing ports list updated.")
    tg3.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg3_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1],
                                                                "source_address": "*",
                                                                "group_address": igmp_data.igmp_grp_ip[1],
                                                                "outgoing_ports": [vars.D1T1P1]}]):
        tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
        tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        traffic_details = {
            '1': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [1],
                'rx_ports': [vars.T1D1P1],
                'rx_obj': [tg1],
            },
            '2': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [0],
                'rx_ports': [vars.T1D1P2],
                'rx_obj': [tg2],
            },
            '3': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [0],
                'rx_ports': [vars.T1D1P3],
                'rx_obj': [tg3],
            }
        }
        if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
            st.error(
                "Mcast data traffic forwarding for multiple IGMPv2 hosts is failed")
            tc1_report_flag = 1
    else:
        st.error("IGMPv2 outgoing port list not updated when one of the two hosts sends leave message.")
        tc1_report_flag = 1
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    if tc1_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn023", "igmp_snooping_verification_multi_host", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn023", "igmp_snooping_verification_multi_host", "successful")

    tc2_report_flag = 0
    st.banner(
        "FtOpSoSwIgFn022 - Verify IGMPv3 joins with zero source ip address must be learned in the IGMP snooping table.")
    tg3.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg3_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3],
                                                                "source_address": "*",
                                                                "group_address": igmp_data.igmp_grp_ip[-2],
                                                                "outgoing_ports": [vars.D1T1P3]}]):
        tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                              ip_dst_addr=igmp_data.igmp_grp_ip[-2], ip_src_addr="32.1.1.1",
                              vlan_id=igmp_data.vlan_li[3], mac_dst=igmp_data.igmp_grp_mac[-2])
        tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
        tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        traffic_details = {
            '1': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [0],
                'rx_ports': [vars.T1D1P1],
                'rx_obj': [tg1],
            },
            '2': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [1],
                'rx_ports': [vars.T1D1P3],
                'rx_obj': [tg3],
            }
        }
        if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
            st.error(
                "Mcast data traffic for IGMPv3 host(learned with 0.0.0.0 source address) is either not forwarded to host learned port or flooded to all ports")
            tc2_report_flag = 1
    else:
        st.error("IGMPv3 join with source address as 0.0.0.0 is not learned")
        tc2_report_flag = 1
    if tc2_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn022", "igmp_snooping_verification_v3_report_w_zero_src_addr", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn022", "igmp_snooping_verification_v3_report_w_zero_src_addr", "successful")
    tg3.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg3_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_disable, igmp_data.vlan_li[3])
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_enable, igmp_data.vlan_li[3], '3')

    tc3_report_flag = 0
    st.banner(
        " FtOpSoSwIgFn014 - When a switch receives an older version report on an interface on a given VLAN, all the "
        "previously gathered IGMPv3 source filtering information for that group on the given VLAN is ignored.",
        width=150)
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3],
                                                                    "source_address": igmp_data.igmpv3_src_addr,
                                                                    "group_address": igmp_data.igmp_grp_ip[-1],
                                                                    "outgoing_ports": [vars.D1T1P2]}]):
        tc3_report_flag = 1
    st.log("Send IGMPv2 join for the same group leanred as IGMPv3 host")
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_3"]['config']['group_handle'],
                                  mode='join')
    if igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3],
                                                                    "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[-1],
                                                                    "outgoing_ports": [vars.D1T1P2]}]):
        tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
        tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                              ip_dst_addr=igmp_data.igmp_grp_ip[-1], ip_src_addr="32.1.1.1",
                              vlan_id=igmp_data.vlan_li[3], mac_dst=igmp_data.igmp_grp_mac[-1])
        tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
        traffic_details = {
            '1': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [0],
                'rx_ports': [vars.T1D1P1],
                'rx_obj': [tg1],
            },
            '2': {
                'tx_ports': [vars.T1D2P1],
                'tx_obj': [tg4],
                'exp_ratio': [1],
                'rx_ports': [vars.T1D1P2],
                'rx_obj': [tg2],
            }
        }
        if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
            st.error(
                "Mcast data traffic for IGMPv2 host (in IGMPv3 enabled vlan) is either not forwarded to host learned port or flooded to all ports")
            tc3_report_flag = 1
    else:
        st.error("IGMPv2 join for the same group as of IGMPv3 host is not learned")
        tc3_report_flag =1
    if tc3_report_flag:
        st.report_tc_fail("FtOpSoSwIgFn014", "igmp_snooping_verification_v2_report_in_v3", "failed")
    else:
        st.report_tc_pass("FtOpSoSwIgFn014", "igmp_snooping_verification_v2_report_in_v3", "successful")
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')

    if (tc1_report_flag | tc2_report_flag | tc3_report_flag):
        st.report_fail("igmp_snooping_verification_v2_report_in_v3", "failed")
    else:
        st.report_pass("igmp_snooping_verification_v2_report_in_v3", "successful")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_rest():
    """
    FtOpSoSwIgUiRest001 - Verify REST operation for IGMP Snooping.
    """
    report_flag = 0
    util_igmp_snooping_disable(vars.D1, igmp_data.vlan_li[1])
    igmp_vlan_name = 'Vlan'+str(igmp_data.vlan_li[1])

    data = {
            "sonic-igmp-snooping:CFG_L2MC_TABLE_LIST": [
                {
                "enabled": True,
                "fast-leave": False,
                "last-member-query-interval": 1000,
                "querier": False,
                "query-interval": 125,
                "query-max-response-time": 10,
                "version": 2,
                "vlan-name": igmp_vlan_name
                }
            ]
        }

    rest_url = "/restconf/data/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_TABLE/CFG_L2MC_TABLE_LIST"
    st.log("Enbale IGMP Snooping for vlan {} using REST".format(igmp_data.vlan_li[1]))
    response1 = st.rest_update(vars.D1, path=rest_url, data=data)
    if not response1["status"] in [200, 204]:
        report_flag = 1
        st.error("Failed to update/enable IGMP snooping for {} through REST".format(igmp_vlan_name))
    rest_url_vlan = "/restconf/data/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_TABLE/CFG_L2MC_TABLE_LIST={}/enabled".format(
        igmp_vlan_name)
    response2 = st.rest_read(vars.D1, rest_url_vlan)
    if response2["status"] in [200, 204]:
        st.log("Send join from TG1")
        tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                      mode='join')
        st.log("Check the igmp snooping table entry")
        port = st.get_other_names(vars.D1, [vars.D1T1P1])[0] if "/" in vars.D1T1P1 else vars.D1T1P1
        rest_url_grp = "/restconf/data/sonic-igmp-snooping:sonic-igmp-snooping/APP_L2MC_MEMBER_TABLE/APP_L2MC_MEMBER_TABLE_LIST={},{},{},{}".format(igmp_vlan_name, '0.0.0.0', igmp_data.igmp_grp_ip[1], port)
        response_grp = st.rest_read(vars.D1, rest_url_grp)
        if not response_grp["status"] == 200:
            st.error("IGMPv2 join not learned successfully when enabled through REST")
            report_flag = 1
            igmp.verify_groups(vars.D1, "groups_vlan",
                               verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                             "group_address": igmp_data.igmp_grp_ip[1],
                                             "outgoing_ports": [vars.D1T1P1]}] )
    else:
        report_flag = 1
        st.error("Failed to check IGMP snooping status as enabled for {} through REST".format(igmp_vlan_name))
    st.log("Disable IGMP Snooping for vlan {} using REST".format(igmp_data.vlan_li[1]))
    rest_url_del = "/restconf/data/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_TABLE/CFG_L2MC_TABLE_LIST={}".format(
        igmp_vlan_name)
    response3 = st.rest_delete(vars.D1, rest_url_del)
    if not response3["status"] in [200, 204]:
        report_flag = 1
        st.error("Failed to Disable IGMP snooping for {} through REST".format(igmp_vlan_name))
    tg1.tg_emulation_igmp_control(
        handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
        mode='leave')
    util_igmp_snooping_enable(vars.D1, igmp_data.vlan_li[1], '2')
    if report_flag:
        st.report_fail('igmp_snooping_verification_rest', "failed")
    else:
        st.report_pass('igmp_snooping_verification_rest', "successful")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_gnmi():
    """
    FtOpSoSwIggNMI001 - Verify gNMI operation for IGMP Snooping.
    """
    report_flag = 0
    igmp_vlan_name = 'Vlan' + str(igmp_data.vlan_li[1])
    gnmi_url = "/sonic-igmp-snooping:sonic-igmp-snooping/CFG_L2MC_TABLE/CFG_L2MC_TABLE_LIST[vlan-name={}]/querier".format(
        igmp_vlan_name)
    json_data_enable = {
        "sonic-igmp-snooping:querier": True
    }
    json_data_disable = {
        "sonic-igmp-snooping:querier": False
    }
    result = gnmiapi.gnmi_set(vars.D1, gnmi_url, json_data_enable)
    res_en = "" if result is False else result
    if not "op: UPDATE" in res_en:
        report_flag = 1
    res_get = gnmiapi.gnmi_get(vars.D1, gnmi_url)
    if "sonic-igmp-snooping:querier" not in res_get:
        report_flag = 1
    result = gnmiapi.gnmi_set(vars.D1, gnmi_url, json_data_disable)
    res_dis = "" if result is False else result
    if not "op: UPDATE" in res_dis:
        report_flag = 1
    if report_flag:
        st.report_fail('igmp_snooping_verification_gnmi', "failed")
    else:
        st.report_pass('igmp_snooping_verification_gnmi', "successful")


@pytest.mark.igmp_snooping_regression
def test_ft_igmp_snooping_save_reboot():
    """
    Verify IGMPv1/v2/v3 snooping after save and reboot.
    """
    report_flag = 0
    tc1_report_flag = 0
    tc2_report_flag = 0
    tc3_report_flag = 0
    exec_all(True, [
        [util_igmp_snooping_st_group_config, vars.D1, igmp_data.vlan_li[1], igmp_data.igmp_st_grp_ip[1], vars.D1T1P1,
         False],
        [util_igmp_snooping_st_group_config, vars.D2, igmp_data.vlan_li[1], igmp_data.igmp_st_grp_ip[1],
         igmp_data.prt_chnl, False]])
    data1 = {"verify_list": [{"vlan": igmp_data.vlan_li[1],
                              "source_address": "*", "group_address": igmp_data.igmp_st_grp_ip[1],
                              "outgoing_ports": [vars.D1T1P1]}],  }
    data2 = {"verify_list": [{"vlan": igmp_data.vlan_li[1],
                              "source_address": "*", "group_address": igmp_data.igmp_st_grp_ip[1],
                              "outgoing_ports": [igmp_data.prt_chnl]}],  }
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], igmp.verify_groups, [data1, data2], "groups_vlan")
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.error("Static group addition not successful on Physical interface or on Port Channel")
            tc1_report_flag = 1
            report_flag = 1
    st.log("Send IGMPv2 join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')

    st.wait(3)
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.error("Failed to learn IGMPv2 join")
        tc2_report_flag = 1
        report_flag = 1
    st.log("Perform Save and Reboot")
    rebootapi.config_save(vars.D1)
    st.reboot(vars.D1)
    st.log("Checking Port channel status after Reboot")
    if not poll_for_portchannel_status(vars.D2, igmp_data.prt_chnl, state="up", iteration=20, delay=1):
        st.error("In DUT2, Port Channel is not UP after Reboot in DUT1")
        report_flag = 1
    st.log("Checking static groups are retained across Save Reboot")
    [out, exceptions] = exec_parallel(True, [vars.D1, vars.D2], igmp.verify_groups, [data1, data2], "groups_vlan")
    ensure_no_exception(exceptions)
    for each in out:
        if not each:
            st.error("Static group config not retained across save Reboot")
            tc1_report_flag = 1
            report_flag = 1
    st.log("Checking dynamic group learning after Save Reboot")
    st.log("Send IGMPv2 join from TG1")
    send_leave_stc(tg1, [tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                         tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                         tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle']])
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    st.wait(3)
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.error("Failed to learn IGMPv2 join after Reboot")
        tc2_report_flag = 1
        report_flag = 1
    st.log("Send IGMPv1 join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.wait(3)
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[0], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[0],
                                                                    "outgoing_ports": [vars.D1T1P1]}]):
        st.error("Failed to learn IGMPv1 join after Reboot")
        tc2_report_flag = 1
        report_flag = 1
    st.log("Send IGMPv3 join from TG2")
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.wait(3)
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3],
                                                                    "source_address": igmp_data.igmpv3_src_addr,
                                                                    "group_address": igmp_data.igmp_grp_ip[-1],
                                                                    "outgoing_ports": [vars.D1T1P2]}]):
        st.error("Failed to learn IGMPv3 join after Reboot")
        tc3_report_flag = 1
        report_flag = 1
    st.log("Initiate mcast data from TG4 and check traffic forwards to static IGMP Group after save and reboot")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                          ip_dst_addr=igmp_data.igmp_st_grp_ip[1], vlan_id=igmp_data.vlan_li[1],
                          mac_dst=igmp_data.igmp_st_grp_mac[1])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error("After save and Reboot, mcast data traffic forwarding is not successful for static group")
        tc1_report_flag = 1
        report_flag = 1
        exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])

    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMPv3 hosts joined ports")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                          ip_dst_addr=igmp_data.igmp_grp_ip[-1], ip_src_addr=igmp_data.igmpv3_src_addr,
                          vlan_id=igmp_data.vlan_li[3], mac_dst=igmp_data.igmp_grp_mac[-1])
    tg4.tg_traffic_control(action='run', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    tg4.tg_traffic_control(action='stop', handle=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg2],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error(
            "Mcast data traffic for IGMPv3 host is either not forwarded to host learned port or flooded to other ports too")
        tc3_report_flag = 1
        report_flag = 1
        exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
    st.log("Check the dynamic entries are removed upon receiving the leave message after save reboot")
    st.log("Send IGMPv1 leave from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    st.wait(1)
    st.log("Send IGMPv2 leave from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='leave')
    st.wait(1)
    st.log("Send IGMPv3 leave from TG2")
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='leave')
    st.log("Waiting for the IGMP snooping table to be updated after receiving the leave messages.")
    st.wait(5)
    if not igmp.poll_igmp_groups_count(vars.D1, 2, iteration_count=5, delay=2,
                                          ):
        st.error("After save Reboot, dynamic groups learned are not removed upon receiving the Leave message")
        tc2_report_flag = 1
        tc3_report_flag = 1
        report_flag = 1

    if tc1_report_flag:
        st.report_tc_fail("FtOpSoSwIgCb001","igmp_snooping_verification_save_reboot", "for static group failed")
    else:
        st.report_tc_pass("FtOpSoSwIgCb001", "igmp_snooping_verification_save_reboot", "for static group successful")
    if tc2_report_flag:
        st.report_tc_fail("FtOpSoSwIgCb002","igmp_snooping_verification_save_reboot", "for IGMPv1/2 failed")
    else:
        st.report_tc_pass("FtOpSoSwIgCb002", "igmp_snooping_verification_save_reboot", "for IGMPv1/2 successful")
    if tc3_report_flag:
        st.report_tc_fail("FtOpSoSwIgCb003","igmp_snooping_verification_save_reboot", "for IGMPv3 failed")
    else:
        st.report_tc_pass("FtOpSoSwIgCb003", "igmp_snooping_verification_save_reboot", "for IGMPv3 successful")

    exec_all(True, [
        [util_igmp_snooping_st_group_config, vars.D1, igmp_data.vlan_li[1], igmp_data.igmp_st_grp_ip[1], vars.D1T1P1,
         True],
        [util_igmp_snooping_st_group_config, vars.D2, igmp_data.vlan_li[1], igmp_data.igmp_st_grp_ip[1],
         igmp_data.prt_chnl, True]])
    if report_flag:
        st.report_fail("igmp_snooping_verification_save_reboot", "failed")
    else:
        st.report_pass("igmp_snooping_verification_save_reboot", "successful")


@pytest.mark.igmp_snooping_regression_wb
def test_ft_igmp_snooping_warm_boot():
    """
    FtOpSoSwIgWb001 - Verify IGMP snooping during warm boot.
    """
    report_flag = 0
    exec_all(True, [
        [delete_vlan_member, vars.D1, igmp_data.vlan_li[1], igmp_data.prt_chnl,True],
        [delete_vlan_member, vars.D2, igmp_data.vlan_li[1], igmp_data.prt_chnl,True]])
    exec_all(True, [
        [add_vlan_member, vars.D1, igmp_data.vlan_li[1], vars.D1D2P3, True],
        [add_vlan_member, vars.D2, igmp_data.vlan_li[1], vars.D2D1P3, True]])
    st.log("Static Group configuration")
    config_static_group('yes')
    st.log("Send IGMPv2 join from TG1")
    tg1.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg1_igmp_host_2"]['config']['group_handle'],
                                  mode='join')
    st.log("Check the igmp snooping table entry")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P1]}],
                               ):
        report_flag = 1
        st.error("IGMPv2 join not learned successfully")
    st.log("Send IGMPv3 join from TG2")
    tg2.tg_emulation_igmp_control(handle=tg_comn_handle["igmp_host"]["tg2_igmp_host_1"]['config']['group_handle'],
                                  mode='join')
    st.log("Check the igmp snooping table entry")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3],
                                                                    "source_address": igmp_data.igmpv3_src_addr,
                                                                    "group_address": igmp_data.igmp_grp_ip[-1],
                                                                    "outgoing_ports": [vars.D1T1P2]}],
                               ):
        report_flag = 1
        st.error("IGMPv3 join not learned successfully")

    st.log("Initiate mcast data from TG4 and check traffic forwards to IGMPv3 host joined ports")
    tgapi.traffic_action_control(tg_handler, actions=['clear_stats'])
    tg4.tg_traffic_config(mode='modify', stream_id=tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"], port_handle=tg_ph_4,
                          ip_dst_addr=igmp_data.igmp_grp_ip[-1], ip_src_addr=igmp_data.igmpv3_src_addr,
                          vlan_id=igmp_data.vlan_li[3], mac_dst=igmp_data.igmp_grp_mac[-1], transmit_mode='continuous')
    tg4.tg_traffic_control(action='run', handle=[tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                                                 tg_str_data["tg5"]["tg5_mcast_data_1_str_id_1"]])

    rebootapi.config_save(vars.D1)
    st.reboot(vars.D1, "warm")

    st.log("Traffic validation after Warm boot")
    tg4.tg_traffic_control(action='stop', handle=[tg_str_data["tg4"]["tg4_mcast_data_1_str_id_1"],
                                                 tg_str_data["tg5"]["tg5_mcast_data_1_str_id_1"]])
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P1],
            'tx_obj': [tg4],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P3],
            'rx_obj': [tg3],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count'):
        st.error(
            "During or after Warm Boot, Mcast data traffic for IGMPv3 host is either not forwarded to host learned port "
            "or flooded to other ports too")
        report_flag = 1
        igmp.show(vars.D1, 'groups' )
        exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])

    traffic_details_2 = {
        '1': {
            'tx_ports': [vars.T1D2P2],
            'tx_obj': [tg5],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
        },
        '2': {
            'tx_ports': [vars.T1D2P2],
            'tx_obj': [tg5],
            'exp_ratio': [0],
            'rx_ports': [vars.T1D1P3],
            'rx_obj': [tg3],
        }
    }
    if not tgapi.validate_tgen_traffic(traffic_details=traffic_details_2, mode='aggregate', comp_type='packet_count'):
        st.error(
            "During or after Warm Boot, Mcast data traffic for IGMPv2 host is either not forwarded to host learned port "
            "or flooded to other ports too")
        report_flag = 1
        igmp.show(vars.D1, 'groups' )
        exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])

    st.log("Verify static group entries are retained across warm boot")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[1], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_st_grp_ip[0],
                                                                    "outgoing_ports": [vars.D1T1P2]}],
                               ):
        report_flag = 1
        st.error("Static Group Entry not retained across Warm Boot")
    if not igmp.verify_groups(vars.D1, "groups_vlan", verify_list=[{"vlan": igmp_data.vlan_li[3], "source_address": "*",
                                                                    "group_address": igmp_data.igmp_st_grp_ip[1],
                                                                    "outgoing_ports": [vars.D1T1P2]}],
                               ):
        report_flag = 1
        st.error("Static Group Entry not retained across Warm Boot")

    if report_flag:
        st.report_fail("igmp_snooping_verification_warm_boot", "failed")
    else:
        st.report_pass("igmp_snooping_verification_warm_boot", "successful")


@pytest.mark.igmp_snooping_scale
def test_ft_igmp_snooping_max_vlan():
    """
    FtOpSoSwIgSc001 - Verify that IGMP snooping enabled successfully on max supported vlans.
    """
    common_constants = st.get_datastore(vars.D1, "constants", "default")
    max_vlan_cnt = int(common_constants['MAX_SUPPORTED_VLANS'])
    report_flag = 0
    st.banner("disabling igmp snooping")
    exec_foreach(True, [vars.D1, vars.D2], util_igmp_snooping_disable, igmp_data.vlan_li)
    st.banner("Vlan clean up")
    clear_vlan_configuration(st.get_dut_names())
    config_vlan_range(vars.D1, "1 {}".format(max_vlan_cnt), config="add", skip_verify=False)
    config_vlan_range_members(vars.D1, "1 {}".format(max_vlan_cnt), [vars.D1T1P1], config="add", skip_verify=False)
    igmp.config_igmp_on_vlan_list_db(vars.D1, range(1,max_vlan_cnt), version='2', mode='true')
    res = igmp.get(vars.D1, value='vlan_count')
    st.log("MAX VLAN COUNT : {}".format(max_vlan_cnt-1))
    st.log("VLAN COUNT FROM DUT: {}".format(res))
    if not res == (max_vlan_cnt-1):
        st.error("Failed to enable IGMP snooping in max vlans")
        report_flag=1
    if report_flag:
        st.report_fail("igmp_snooping_verification_max_vlan", "failed")
    else:
        st.report_pass("igmp_snooping_verification_max_vlan", "successful")

