# Snapshot Feature FT test cases.
# Author : Phani kumar ravula (phanikumar.ravula@broadcom.com) and prudviraj k (prudviraj.kristipati@broadcom.com)

import pytest
from datetime import datetime

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.system.snapshot as sfapi
from apis.switching.vlan import create_vlan,clear_vlan_configuration,add_vlan_member,delete_vlan_member,delete_vlan
from apis.system.basic import get_hwsku,get_ifconfig_ether,get_platform_summary
from apis.system.port import get_interface_counters_all,clear_interface_counters
import apis.system.reboot as reboot_api
import apis.qos.cos as cos_api
import apis.system.sflow as sflow

sf_data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def snapshot_feature_module_hooks(request):
    global vars
    vars = st.ensure_min_topology('D1T1:4')
    global_vars_and_constants_init()
    sf_module_prolog()
    yield
    sf_module_epilog()

@pytest.fixture(scope="function", autouse=True)
def snapshot_feature_func_hooks(request):
    if (st.get_func_name(request) not in  'test_ft_watermark_telemetry_interval') and (st.get_func_name(request) not in 'test_ft_snapshot_interval'):
        clear_interface_counters(vars.D1)
    yield
    if st.get_func_name(request) == 'test_ft_sf_all_buffer_stats_using_unicast_traffic' or st.get_func_name(request) == 'test_ft_sf_verify_buffer_pool_counters':
        sf_tg_traffic_start_stop(sf_data.unicast, False)
        sfapi.config_snapshot_interval(vars.D1, snap="clear_snaphot_interval")
    if st.get_func_name(request) == 'test_ft_sf_all_buffer_stats_using_multicast_traffic':
        sf_tg_traffic_start_stop(sf_data.multicast, False)
        sfapi.config_snapshot_interval(vars.D1, snap="clear_snaphot_interval")
    if st.get_func_name(request) == 'test_ft_sf_verify_cpu_counters':
        sflow.config_attributes(vars.D1, sample_rate=sf_data.sflow_sample_rate, interface_name=vars.D1T1P1, no_form=True)
        sflow.enable_disable_config(vars.D1, interface=False, interface_name=None, action="disable")
        sf_tg_traffic_start_stop(sf_data.unicast, False)
        sfapi.config_snapshot_interval(vars.D1, snap="clear_snaphot_interval")


def global_vars_and_constants_init():
    sf_data.clear()
    sf_data.tg_port_list = [vars.T1D1P1, vars.T1D1P2, vars.T1D1P3, vars.T1D1P4]
    sf_data.port_list = [vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4]
    sf_data.default_snapshot_interval = 10
    sf_data.snapshot_interval = 5
    sf_data.telemetry_interval = 30
    sf_data.default_telemetry_interval = 120
    sf_data.unicast = 'unicast'
    sf_data.multicast = 'multicast'
    sf_data.cpu = 'cpu'
    sf_data.periodic = 'periodic'
    sf_data.dut_mac = get_ifconfig_ether(vars.D1, 'eth0')
    sf_data.tg_current_mode = sf_data.unicast
    sf_data.traffic_duration = 5
    sf_data.initial_counter_value = 0
    sf_data.PG=['shared','headroom','unicast','multicast']
    sf_data.group = ['priority-group', 'queue']
    sf_data.table = ['watermark', 'persistent-watermark']
    sf_data.platform = get_hwsku(vars.D1).lower()
    sf_data.config_file = "buffers.json"
    sf_data.device_j2_file = "buffers.json.j2"
    sf_data.vlan1 = 1
    sf_data.reload_interval = 70
    sf_data.FMT = '%H:%M:%S'
    sf_data.buffer_pool_tolerance=2080
    sf_data.percentage = ['--percentage', '-p']
    sf_data.dot1p_to_tc_map_dict = {'0': '0', '1': '1', '2': '2', '3': '3', '4': '4', '5': '5', '6': '6', '7': '7'}
    sf_data.tc_to_pg_map_dict = {'0-7': '7'}
    sf_data.obj_name = ['dot1p_tc_map', 'tc_pg_map']
    sf_data.map_name = ['dot1p_to_tc_map', 'tc_to_pg_map']
    sf_data.dot1p_tc_bind_map = {'port': vars.D1T1P1, 'map': sf_data.map_name[0], 'obj_name': sf_data.obj_name[0]}
    sf_data.tc_pg_bind_map = {'port': vars.D1T1P1, 'map': sf_data.map_name[1], 'obj_name': sf_data.obj_name[1]}
    sf_data.sflow_sample_rate = 256
    return sf_data

def sf_module_prolog():
    clear_vlan_configuration(vars.D1)
    sf_data.vlan = str(random_vlan_list()[0])
    create_vlan(vars.D1, sf_data.vlan)
    add_vlan_member(vars.D1, sf_data.vlan, port_list=sf_data.port_list, tagging_mode=True)
    sf_data.tg, sf_data.tg_ph_list, sf_data.stream_sf_data = sf_tg_stream_config()

def sf_module_epilog():
    delete_vlan_member(vars.D1, sf_data.vlan, port_list=sf_data.port_list, tagging_mode=True)
    delete_vlan(vars.D1, sf_data.vlan)

def sf_tg_stream_config():
    global tg_handler
    st.log('TG configuration for snapshot tests')
    tg_handler = tgapi.get_handles(vars, sf_data.tg_port_list)
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_3 = tg_handler["tg_ph_3"]
    tg_ph_4 = tg_handler["tg_ph_4"]
    tg_ph_list = [tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4]

    stream_sf_data = {}

    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])

    stream_sf_data['1'] = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:01",
                                               mac_dst="00:00:00:00:00:05", vlan_id=sf_data.vlan,high_speed_result_analysis= 1,
                                               l2_encap='ethernet_ii_vlan')['stream_id']
    stream_sf_data['2'] = tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:02",
                                               mac_dst="00:00:00:00:00:05", vlan_id=sf_data.vlan,high_speed_result_analysis= 1,
                                               l2_encap='ethernet_ii_vlan')['stream_id']
    stream_sf_data['3'] = tg.tg_traffic_config(port_handle=tg_ph_3, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:03",
                                               mac_dst="00:00:00:00:00:05", vlan_id=sf_data.vlan,high_speed_result_analysis= 1,
                                               l2_encap='ethernet_ii_vlan')['stream_id']
    stream_sf_data['4'] = tg.tg_traffic_config(port_handle=tg_ph_4, mode='create', rate_percent=100,
                                               transmit_mode="continuous", mac_src="00:00:00:00:00:05",
                                               mac_dst="00:00:00:00:00:01", vlan_id=sf_data.vlan,high_speed_result_analysis= 1,
                                               l2_encap='ethernet_ii_vlan')['stream_id']

    return tg, tg_ph_list, stream_sf_data

def sf_tg_traffic_start_stop(traffic_mode, traffic_action):
    st.log(">>> Configuring '{}' traffic streams".format(traffic_mode))
    st.debug("TG Streams : Current Mode = {}, Requested Mode = {}".format(sf_data.tg_current_mode, traffic_mode))
    if not sf_data.tg_current_mode == traffic_mode:
        sf_data.tg_current_mode = traffic_mode
        if traffic_mode == sf_data.multicast:
            for each in sf_data.stream_sf_data:
                sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data[each],
                                             mac_dst="01:82:33:33:33:33")

        elif traffic_mode == sf_data.cpu:
            for each in sf_data.stream_sf_data:
                sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data[each],
                                             mac_dst=sf_data.dut_mac,vlan_id=sf_data.vlan1)
        elif traffic_mode == sf_data.periodic:
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['1'],mac_dst="00:00:00:00:00:05",rate_percent=40)
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['2'],mac_dst="00:00:00:00:00:05",rate_percent=40)
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['3'],
                                             mac_dst="00:00:00:00:00:05",rate_percent=40)
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['4'],
                                             mac_dst="00:00:00:00:00:01",rate_percent=40)
        else:
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['1'],
                                         mac_dst="00:00:00:00:00:05",rate_percent=100)
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['2'],
                                         mac_dst="00:00:00:00:00:05",rate_percent=100)
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['3'],
                                         mac_dst="00:00:00:00:00:05",rate_percent=100)
            sf_data.tg.tg_traffic_config(mode='modify', stream_id=sf_data.stream_sf_data['4'],
                                         mac_dst="00:00:00:00:00:01",rate_percent=100)

    if traffic_action is True:
        sf_data.tg.tg_traffic_control(action='run', stream_handle=sf_data.stream_sf_data.values())
    else:
        sf_data.tg.tg_traffic_control(action='stop', stream_handle=sf_data.stream_sf_data.values())
        st.wait(1)

def sf_collecting_debug_logs_when_test_fails():
    get_interface_counters_all(vars.D1)

def clear_qos_map_config():
    cos_api.clear_port_qos_map_all(vars.D1, sf_data.dot1p_tc_bind_map)
    cos_api.clear_qos_map_table(vars.D1, sf_data.dot1p_tc_bind_map)
    cos_api.clear_port_qos_map_all(vars.D1, sf_data.tc_pg_bind_map)
    cos_api.clear_qos_map_table(vars.D1, sf_data.tc_pg_bind_map)


@pytest.mark.snapshot_regression
def test_ft_watermark_telemetry_interval():
    """
    Author : Phani kumar R (phanikumar.ravula@broadcom.com)
    """
    result = 0
    st.banner('ft_sf_wm_telemetry_interval')
    if not sfapi.config_snapshot_interval(vars.D1, snap="telemetry", interval_val=sf_data.telemetry_interval):
        st.error("Failed to configure watermark telemetry interval")
        result += 1
    match = [{'telemetryinterval': sf_data.telemetry_interval}]
    if not sfapi.verify(vars.D1,'telemetry_interval', verify_list=match):
        st.error("Failed to verify the configured watermark telemetry interval value")
        result += 1
    if not sfapi.config_snapshot_interval(vars.D1, snap="telemetry", interval_val=sf_data.default_telemetry_interval):
        st.error("Failed to configure default watermark telemetry interval")
        result += 1
    match = [{'telemetryinterval': sf_data.default_telemetry_interval}]
    if not sfapi.verify(vars.D1,'telemetry_interval', verify_list=match):
        st.error("Failed to verify the default watermark telemetry interval value")
        result += 1

    if not result:
        st.report_pass("snapshot_telemetry_interval_config_and_reset", "successful")
    else:
        st.report_fail("snapshot_telemetry_interval_config_and_reset", "failed")

@pytest.mark.snapshot_regression
def test_ft_snapshot_interval():
    """
    Author : Phani kumar R (phanikumar.ravula@broadcom.com)
    """
    st.banner('ft_sf_snapshot_interval, ft_sf_verify_default_snapshot_interval')

    result1=result2=0
    if not sfapi.config_snapshot_interval(vars.D1, snap="interval", interval_val=sf_data.snapshot_interval):
        st.error("Failed to configure snapshot interval")
        result1 += 1
    match = [{'snapshotinterval': sf_data.snapshot_interval}]
    if not sfapi.verify(vars.D1,'snapshot_interval', verify_list=match):
        st.error("Failed to verify the configured snapshot interval")
        result1 += 1
        st.report_tc_fail("ft_sf_snapshot_interval", "snapshot_interval_config", "failed")
    else:
        st.report_tc_pass("ft_sf_snapshot_interval", "snapshot_interval_config", "successful")

    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_snaphot_interval"):
        st.error("Failed to clear the snapshot interval")
        result2 += 1
    match = [{'snapshotinterval': sf_data.default_snapshot_interval}]
    if not sfapi.verify(vars.D1, 'snapshot_interval', verify_list=match):
        st.error("Failed to reset the snapshot interval to default value after clear")
        result2 += 1
        st.report_tc_fail("ft_sf_verify_default_snapshot_interval", "snapshot_verify_default_interval", "failed")
    else:
        st.report_tc_pass("ft_sf_verify_default_snapshot_interval", "snapshot_verify_default_interval", "successful")
    if not (result1 or result2):
        st.report_pass("snapshot_interval_config_and_reset", "successful")
    else:
        st.report_fail("snapshot_interval_config_and_reset", "failed")

@pytest.mark.snapshot_regression
def test_ft_sf_all_buffer_stats_using_unicast_traffic():
    """
    Author : prudviraj k (prudviraj.kristipati@broadcom.com) and phani kumar ravula(phanikumar.ravula@broadcom.com)
    """
    result = 0
    per_result = 0
    clr_result = 0
    if not sfapi.config_snapshot_interval(vars.D1, snap="interval", interval_val=sf_data.snapshot_interval):
        st.error("Failed to configure snapshot interval")
        result += 1
    match = [{'snapshotinterval': sf_data.snapshot_interval}]
    if not sfapi.verify(vars.D1,'snapshot_interval', verify_list=match):
        st.error("Failed to verify the configured snapshot interval")
        result += 1
    st.log("configuring the QOS maps")
    if not cos_api.config_dot1p_to_tc_map(vars.D1, sf_data.obj_name[0], sf_data.dot1p_to_tc_map_dict):
        st.error("Failed to configure qos map of type dot1p to tc")
    if not cos_api.config_tc_to_pg_map(vars.D1, sf_data.obj_name[1], sf_data.tc_to_pg_map_dict):
        st.error("Failed to configure qos map of type tc to pg")
    if not cos_api.verify_qos_map_table(vars.D1, 'dot1p_to_tc_map', sf_data.obj_name[0],
                                 {'0': '0', '1': '1', '2': '2', '3': '3', '4': '4', '5': '5', '6': '6', '7': '7'}):
        st.error("Failed to verify configured dot1p to tc map values")
        result += 1

    if not cos_api.verify_qos_map_table(vars.D1, 'tc_to_pg_map', sf_data.obj_name[1],
                                 {'0': '7', '1': '7', '2': '7', '3': '7', '4': '7', '5': '7', '6': '7', '7': '7'}):
        st.error("Failed to verify configured tc to pg map values")
        result += 1

    if not cos_api.config_port_qos_map_all(vars.D1, sf_data.dot1p_tc_bind_map):
        st.error("Failed to bind the configured qos map of type dot1p to tc on interface")
    if not cos_api.config_port_qos_map_all(vars.D1, sf_data.tc_pg_bind_map):
        st.error("Failed to bind the configured qos map of type tc to pg on interface")

    sf_tg_traffic_start_stop(sf_data.unicast, True)
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('#### PG_shared_for_user_watermark####')
    st.banner('TC name :::: ft_sf_pg_shared_using_uwm ::::')
    match = [{'pg7': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, 'user_watermark_PG_shared', verify_list=match, port_alias=vars.D1T1P1):
        st.error("Failed to verify the user_watermark_PG_shared counter value")
        result += 1
        st.report_tc_fail("ft_sf_pg_shared_using_uwm", "snapshot_tc_verify", "PG_shared_for_user_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_pg_shared_using_uwm", "snapshot_tc_verify", "PG_shared_for_user_watermark", "successful")

    st.banner('####verification_of_PG_shared_using_counter_DB####')
    st.banner('TC name :::: ft_sf_pg_shared_using_Counter_DB ::::')
    match = [{'SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, column_name="COUNTERS_PG_NAME_MAP",interface_name= vars.D1T1P1,queue_value=7,table_name="COUNTERS",verify_list=match):
        st.error("Failed to verify the user_watermark_PG_shared counter DB value")
        result += 1
        st.report_tc_fail("ft_sf_pg_shared_using_Counter_DB", "snapshot_tc_counter_DB_verify", "PG_shared", "failed")
    else:
        st.report_tc_pass("ft_sf_pg_shared_using_Counter_DB", "snapshot_tc_counter_DB_verify", "PG_shared", "successful")

    st.banner('TC name:::: ft_sf_queue_unicast_using_uwm ::::')
    match = [{'uc0': sf_data.initial_counter_value}]


    st.banner('#### queue_unicast_for_user_watermark using percentage values####')
    if sfapi.verify(vars.D1, 'queue_user_watermark_unicast', verify_list=match, port_alias=vars.D1T1P4, percentage=sf_data.percentage[0]):
        st.error("Failed to verify the queue_user_watermark_unicast counter value using percentage")
        result += 1
        per_result += 1

    st.banner('#### queue_unicast_for_user_watermark using CLI####')
    if sfapi.verify(vars.D1, 'queue_user_watermark_unicast', verify_list=match, port_alias=vars.D1T1P4):
        st.error("Failed to verify the queue_user_watermark_unicast counter value")
        result += 1
        per_result += 1

    if per_result:
        st.report_tc_fail("ft_sf_queue_unicast_using_uwm", "snapshot_tc_verify", "queue_unicast_for_user_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_unicast_using_uwm", "snapshot_tc_verify", "queue_unicast_for_user_watermark", "successful")


    st.banner('####verification_of_queue_unicast_for_user_watermark_using_counter_DB####')
    st.banner('TC name:::: ft_sf_queue_unicast_using_Counter_DB ::::')
    match = [{'SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, column_name="COUNTERS_QUEUE_NAME_MAP",interface_name= vars.D1T1P4,queue_value=0,table_name="COUNTERS",verify_list=match):
        st.error("Failed to verify the queue_user_watermark_unicast counter DB value")
        result += 1
        st.report_tc_fail("ft_sf_queue_unicast_using_Counter_DB", "snapshot_tc_counter_DB_verify", "queue_unicast", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_unicast_using_Counter_DB", "snapshot_tc_counter_DB_verify", "queue_unicast", "successful")

    st.banner('#### PG_shared_for_persistent_watermark####')
    st.banner('TC name :::: ft_sf_pg_shared_using_persistent_wm ::::')
    match = [{'pg7': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, 'persistent_PG_shared', verify_list=match, port_alias=vars.D1T1P2):
        st.error("Failed to verify the persistent_watermark_PG_shared counter value")
        result += 1
        st.report_tc_fail("ft_sf_pg_shared_using_persistent_wm", "snapshot_tc_verify",
                          "PG_shared_for_persistent_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_pg_shared_using_persistent_wm", "snapshot_tc_verify",
                          "PG_shared_for_persistent_watermark", "successful")

    st.banner('#### queue_unicast_for_persistent_watermark ####')
    st.banner('TC name :::: ft_sf_queue_unicast_using_persistent_wm ::::')
    match = [{'uc0': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, 'queue_persistent_watermark_unicast', verify_list=match,
                    port_alias=vars.D1T1P4):
        st.error("Failed to verify the queue_persistent_watermark_unicast counter value")
        result += 1
        st.report_tc_fail("ft_sf_queue_unicast_using_persistent_wm", "snapshot_tc_verify",
                          "queue_unicast_for_persistent_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_unicast_using_persistent_wm", "snapshot_tc_verify",
                          "queue_unicast_for_persistent_watermark", "successful")

    sf_tg_traffic_start_stop(sf_data.unicast, False)
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('#### clear_PG_shared_for_user_watermark####')
    st.banner('TC name :::: ft_sf_pg_shared_clear_using_uwm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_snapshot_counters", group=sf_data.group[0],table=sf_data.table[0],counter_type=sf_data.PG[0]):
        st.error("Failed to execute the command clear {} snapshot counters".format(sf_data.group[0]))
        result += 1
    match = [{'pg0': sf_data.initial_counter_value}]
    if not sfapi.verify(vars.D1, 'user_watermark_PG_shared', verify_list=match, port_alias=vars.D1T1P1):
        st.error("Failed to clear the snapshot counters")
        result += 1
        st.report_tc_fail("ft_sf_pg_shared_clear_using_uwm", "snapshot_clear_verify", "clearing the PG shared counters for user_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_pg_shared_clear_using_uwm", "snapshot_clear_verify", "clearing the PG shared counters for user watermark", "successful")



    st.banner('TC name :::: ft_sf_queue_unicast_clear_using_uwm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_snapshot_counters", group=sf_data.group[1],
                                          table=sf_data.table[0], counter_type=sf_data.PG[2]):
        st.error("Failed to execute the command clear  {} snapshot counters".format(sf_data.group[0]))
        result += 1
    match = [{'uc0': sf_data.initial_counter_value}]


    st.banner('#### clear_queue_unicast_percentage_Values_for_user_watermark ####')
    if not sfapi.verify(vars.D1, 'queue_user_watermark_unicast', verify_list=match, port_alias=vars.D1T1P4, percentage=sf_data.percentage[1]):
        st.error("Failed to clear percentage snapshot counters")
        result += 1
        clr_result += 1
    st.banner('#### clear_queue_unicast_for_user_watermark using CLI####')
    if not sfapi.verify(vars.D1, 'queue_user_watermark_unicast', verify_list=match, port_alias=vars.D1T1P4):
        st.error("Failed to clear the snapshot counters")
        result += 1
        clr_result += 1

    if clr_result:
        st.report_tc_fail("ft_sf_queue_unicast_clear_using_uwm", "snapshot_clear_verify", "clearing the unicast queue counters for user watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_unicast_clear_using_uwm", "snapshot_clear_verify", "clearing the unicast queue counters for user watermark", "successful")



    st.banner('#### clear_PG_shared_for_persistent_watermark ####')
    st.banner('TC name :::: ft_sf_pg_shared_clear_using_persistent_wm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_snapshot_counters", group=sf_data.group[0],table=sf_data.table[1],counter_type=sf_data.PG[0]):
        st.error("Failed to execute the command clear {} snapshot counters".format(sf_data.group[0]))
        result += 1
    match = [{'pg0': sf_data.initial_counter_value}]
    if not sfapi.verify(vars.D1, 'persistent_PG_shared', verify_list=match, port_alias=vars.D1T1P2):
        st.error("Failed to clear the snapshot counters")
        result += 1
        st.report_tc_fail("ft_sf_pg_shared_clear_using_persistent_wm", "snapshot_clear_verify", "clearing the PG shared counters for persistent watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_pg_shared_clear_using_persistent_wm", "snapshot_clear_verify", "clearing the PG shared counters for persistent watermark", "successful")

    st.banner('#### clear_queue_unicast_for_persistent_watermark ####')
    st.banner('TC name :::: ft_sf_queue_unicast_clear_using_persistent_wm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_snapshot_counters", group=sf_data.group[1],
                                          table=sf_data.table[1], counter_type=sf_data.PG[2]):
        st.error("Failed to execute the command clear {} snapshot counters".format(sf_data.group[0]))
        result += 1
    match = [{'uc0': sf_data.initial_counter_value}]
    if not sfapi.verify(vars.D1, 'queue_persistent_watermark_unicast', verify_list=match,
                        port_alias=vars.D1T1P4):
        st.error("Failed to clear the snapshot counters")
        result += 1
        st.report_tc_fail("ft_sf_queue_unicast_clear_using_persistent_wm", "snapshot_clear_verify",
                          "clearing the unicast queue counters for persistent watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_unicast_clear_using_persistent_wm", "snapshot_clear_verify",
                          "clearing the unicast queue counters for persistent watermark", "successful")
    clear_qos_map_config()
    if not result:
        st.report_pass("snapshot_all_buffer_counters", "unicast", "successful")
    else:
        sf_collecting_debug_logs_when_test_fails()
        st.report_fail("snapshot_all_buffer_counters", "unicast", "failed")


@pytest.mark.snapshot_regression
def test_ft_sf_all_buffer_stats_using_multicast_traffic():
    """
    Author : prudviraj k (prudviraj.kristipati@broadcom.com) and phani kumar ravula(phanikumar.ravula@broadcom.com)
    """
    result = 0
    if not sfapi.config_snapshot_interval(vars.D1, snap="interval", interval_val=sf_data.snapshot_interval):
        st.error("Failed to configure snapshot interval")
        result += 1
    match = [{'snapshotinterval': sf_data.snapshot_interval}]
    if not sfapi.verify(vars.D1,'snapshot_interval', verify_list=match):
        st.error("Failed to verify the configured snapshot interval")
        result += 1

    if sfapi.multicast_queue_start_value(vars.D1, 'queue_user_watermark_multicast', port_alias=vars.D1T1P4):
        match = [{'mc8': sf_data.initial_counter_value}]
    else:
        match = [{'mc10': sf_data.initial_counter_value}]

    sf_tg_traffic_start_stop(sf_data.multicast, True)
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('#### queue_multicast_for_user_watermark ####')
    st.banner('TC name:::: ft_sf_queue_multicast_using_uwm ::::')

    if sfapi.verify(vars.D1, 'queue_user_watermark_multicast', verify_list=match, port_alias=vars.D1T1P4):
        st.error("Failed to verify the queue_user_watermark_multicast counter value")
        result += 1
        st.report_tc_fail("ft_sf_queue_multicast_using_uwm", "snapshot_tc_verify", "queue_multicast_for_user_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_multicast_using_uwm", "snapshot_tc_verify", "queue_multicast_for_user_watermark", "successful")


    st.banner('#### queue_multicast_for_persistent_watermark ####')
    st.banner('TC name :::: ft_sf_queue_multicast_using_persistent_wm ::::')

    if sfapi.verify(vars.D1, 'queue_persistent_watermark_multicast', verify_list=match,
                    port_alias=vars.D1T1P4):
        st.error("Failed to verify the queue_persistent_watermark_unicast counter value")
        result += 1
        st.report_tc_fail("ft_sf_queue_multicast_using_persistent_wm", "snapshot_tc_verify", "queue_multicast_for_persistent_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_multicast_using_persistent_wm", "snapshot_tc_verify", "queue_multicast_for_persistent_watermark", "successful")

    sf_tg_traffic_start_stop(sf_data.multicast, False)
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('#### clear_queue_multicast_for_user_watermark ####')
    st.banner('TC name :::: ft_sf_queue_multicast_clear_using_uwm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_snapshot_counters", group=sf_data.group[1],
                                          table=sf_data.table[0], counter_type=sf_data.PG[3]):
        st.error("Failed to execute the command clear {} snapshot counters".format(sf_data.PG[3]))
        result += 1

    if not sfapi.verify(vars.D1, 'queue_user_watermark_multicast', verify_list=match, port_alias=vars.D1T1P4):
        st.error("Failed to clear the snapshot counters")
        result += 1
        st.report_tc_fail("ft_sf_queue_multicast_clear_using_uwm", "snapshot_clear_verify", "clearing the multicast queue counters for user watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_multicast_clear_using_uwm", "snapshot_clear_verify", "clearing the multicast queue counters for user watermark", "successful")


    st.banner('#### clear_queue_multicast_for_persistent_watermark ####')
    st.banner('TC name :::: ft_sf_queue_multicast_clear_using_persistent_wm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_snapshot_counters", group=sf_data.group[1],
                                          table=sf_data.table[1], counter_type=sf_data.PG[3]):
        st.error("Failed to execute the command clear {} snapshot counters".format(sf_data.PG[3]))
        result += 1

    if not sfapi.verify(vars.D1, 'queue_persistent_watermark_multicast', verify_list=match,
                        port_alias=vars.D1T1P4):
        st.error("Failed to clear the snapshot counters")
        result += 1
        st.report_tc_fail("ft_sf_queue_multicast_clear_using_persistent_wm", "snapshot_clear_verify",
                          "clearing the multicast queue counters for persistent watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_queue_multicast_clear_using_persistent_wm", "snapshot_clear_verify",
                          "clearing the multicast queue counters for persistent watermark", "successful")

    if not result:
        st.report_pass("snapshot_all_buffer_counters", "multicast", "successful")
    else:
        sf_collecting_debug_logs_when_test_fails()
        st.report_fail("snapshot_all_buffer_counters", "multicast", "failed")


@pytest.mark.snapshot_regression
def test_ft_sf_periodic_verify_using_counter_DB():
    """
    Author : prudviraj k (prudviraj.kristipati@broadcom.com) and phani kumar ravula(phanikumar.ravula@broadcom.com)
    """
    result = 0
    if not sfapi.config_snapshot_interval(vars.D1, snap="interval", interval_val=sf_data.snapshot_interval):
        st.error("Failed to configure snapshot interval")
        result += 1
    match = [{'snapshotinterval': sf_data.snapshot_interval}]
    if not sfapi.verify(vars.D1,'snapshot_interval', verify_list=match):
        st.error("Failed to verify the configured snapshot interval")
        result += 1
    #sf_tg_traffic_start_stop(sf_data.periodic, True)
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('####verification_of_queue_unicast_periodic_update_using_counter_DB####')
    st.banner('TC name:::: ft_sf_verify_time_stamp_using_counter_DB::::')


    counters=sfapi.show(vars.D1,column_name="COUNTERS_QUEUE_NAME_MAP", interface_name=vars.D1T1P4, queue_value=0, table_name="COUNTERS")

    Timestamp_40 = counters[0]['SAI_QUEUE_STAT_TIMESTAMP']
    Time_40 = Timestamp_40.split('.')

    st.log("Collecting Time stamp  when traffic rate is 40..... :{}".format(Time_40[1]))
    st.wait(sf_data.snapshot_interval)

    counters = sfapi.show(vars.D1, column_name="COUNTERS_QUEUE_NAME_MAP", interface_name=vars.D1T1P4, queue_value=0,table_name="COUNTERS")

    Timestamp_100 = counters[0]['SAI_QUEUE_STAT_TIMESTAMP']
    Time_100 = Timestamp_100.split('.')
    st.log("Collecting Time stamp when traffic rate is 100 ..... :{}".format(Time_100[1]))

    Timestamp_diff= datetime.strptime(Time_100[1], sf_data.FMT) - datetime.strptime(Time_40[1], sf_data.FMT)
    st.log("Time stamp difference in Seconds is :{}".format(Timestamp_diff.seconds))
    if (Timestamp_diff.seconds) < (sf_data.snapshot_interval):
        st.error("Time stamp interval is not increementing correctly")
        result += 1

    if not result:
        st.report_pass("snapshot_tc_verify", "Time stamp interval", "successful")
    else:
        sf_collecting_debug_logs_when_test_fails()
        st.report_fail("snapshot_tc_verify", "Time stamp interval", "failed")


    """
    ############################## Below TCs are permanent readme so not testing now###################################
    st.banner('TC name:::: ft_sf_verify_periodic_update_using_counter_DB,ft_sf_verify_percentage_value_using_counter_DB  ::::')
    counters_40=counters[0]['SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES']
    st.log("unicast queue counter with  traffic rate 40 is :{}".format(counters_40))
    percentage_40=counters[0]['SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK']



    sf_tg_traffic_start_stop(sf_data.periodic, False)

    st.wait(sf_data.snapshot_interval)
    st.log("Sending traffic with rate 100")

    sf_tg_traffic_start_stop(sf_data.unicast, True)
    st.wait(2 * sf_data.snapshot_interval)



    counters_100=counters[0]['SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES']
    st.log("unicast queue counter with traffic rate 100 is :{}".format(counters_100))

    percentage_100=counters[0]['SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK']
    st.log("unicast queue percentage value with traffic rate 100 is :{}".format(percentage_100))


    sf_tg_traffic_start_stop(sf_data.unicast, False)
    st.wait(2 * sf_data.snapshot_interval)


    if counters_40 >= counters_100 or counters_40 == 0 or counters_100 == 0:
        st.error("counters values are not increemented after increasing the transmit rate")
        result += 1

        st.report_tc_fail("ft_sf_verify_periodic_update_using_counter_DB", "snapshot_tc_verify", "periodic update","failed")
    else:
        st.report_tc_pass("ft_sf_verify_periodic_update_using_counter_DB", "snapshot_tc_verify", "periodic update","successful")

    if percentage_100 <= percentage_40:
        st.error("percentage value is not increemented after increasing the transmit rate")
        result += 1

        st.report_tc_fail("ft_sf_verify_periodic_update_using_counter_DB", "snapshot_tc_verify", "periodic percentage update",
                          "failed")
    else:
        st.report_tc_pass("ft_sf_verify_periodic_update_using_counter_DB", "snapshot_tc_verify", "periodic percentage update",
                          "successful")


    st.banner('#### clearing_Counter_DB_counters ########')
    st.banner('TC name :::: ft_sf_verify_periodic_clear_using_counter_DB ::::')

    counters=sfapi.show(vars.D1,column_name="COUNTERS_QUEUE_NAME_MAP", interface_name=vars.D1T1P4, queue_value=0, table_name="COUNTERS")

    counters = counters[0]['SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES']
    st.log("unicast queue counter after stopping the traffic is :{}".format(counters))

    match = [{'SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES': sf_data.initial_counter_value}]
    if not sfapi.verify(vars.D1, column_name="COUNTERS_QUEUE_NAME_MAP", interface_name=vars.D1T1P4, queue_value=0, table_name="COUNTERS", verify_list=match):
        st.error("counters values are not increemented after increasing the transmit rate")
        result += 1

        st.report_tc_fail("ft_sf_verify_periodic_clear_using_counter_DB", "snapshot_tc_verify", "periodic update and clear", "failed")
    else:
        st.report_tc_pass("ft_sf_verify_periodic_clear_using_counter_DB", "snapshot_tc_verify", "periodic update and clear","successful")
    """

@pytest.mark.snapshot_regression
def test_ft_sf_verify_buffer_pool_counters():
    """
    Author : prudviraj k (prudviraj.kristipati@broadcom.com) and phani kumar ravula(phanikumar.ravula@broadcom.com)
    """
    result = 0
    per_result = 0
    sf_data.platform_name_summary = get_platform_summary(vars.D1)
    sf_data.platform_name = sf_data.platform_name_summary["platform"]
    sf_data.platform_hwsku = sf_data.platform_name_summary["hwsku"]

    path= "/usr/share/sonic/device/{}/{}/{}".format(sf_data.platform_name,sf_data.platform_hwsku,sf_data.device_j2_file)
    convert_json = "sonic-cfggen -d -t " "{} > {}".format(path,sf_data.config_file)
    sfapi.load_json_config(vars.D1, convert_json, sf_data.config_file)
    reboot_api.config_save_reload(vars.D1)
    st.log("To make sure after reload DUT is fully operational")
    st.wait(sf_data.reload_interval)

    if not sfapi.config_snapshot_interval(vars.D1, snap="interval", interval_val=sf_data.snapshot_interval):
        st.error("Failed to configure snapshot interval")
        result += 1
    match = [{'snapshotinterval': sf_data.snapshot_interval}]
    if not sfapi.verify(vars.D1,'snapshot_interval', verify_list=match):
        st.error("Failed to verify the configured snapshot interval")
        result += 1

    sf_tg_traffic_start_stop(sf_data.unicast, True)
    st.log("waiting for two snapshot interval times to get the counter values reflect correctly")
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('#### buffer_Pool_for_user_watermark####')
    st.banner('TC name :::: ft_sf_buffer_pool_using_uwm ::::')
    match = {'pool': 'ingress_lossless_pool'}
    value = {'bytes': sf_data.initial_counter_value }
    if sfapi.verify_buffer_pool(vars.D1, 'buffer_pool_watermark', verify_list=match, key=value):
        st.error("Failed to verify the buffer pool counters for user watermark")
        result += 1
        st.report_tc_fail("ft_sf_buffer_pool_using_uwm", "snapshot_tc_verify", "buffer_pool_for_user_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_buffer_pool_using_uwm", "snapshot_tc_verify", "buffer_pool_for_user_watermark", "successful")


    st.banner('TC name :::: ft_sf_buffer_pool_using_persistent_wm ::::')
    st.banner('#### buffer_pool_for_persistent_watermark using percentage####')
    match = {'pool': 'egress_lossless_pool'}
    value = {'percent': sf_data.initial_counter_value }
    if sfapi.verify_buffer_pool(vars.D1, 'buffer_pool_persistent-watermark', verify_list=match, key=value, percent=sf_data.percentage[0]):
        st.error("Failed to verify the buffer pool counters for persistent watermark")
        result += 1
        per_result += 1
    st.banner('#### buffer_pool_for_persistent_watermark using CLI####')
    match = {'pool': 'egress_lossless_pool'}
    value = {'bytes': sf_data.initial_counter_value }
    if sfapi.verify_buffer_pool(vars.D1, 'buffer_pool_persistent-watermark', verify_list=match, key=value):
        st.error("Failed to verify the buffer pool counters for persistent watermark")
        result += 1
        per_result += 1
    if per_result:
        st.report_tc_fail("ft_sf_buffer_pool_using_persistent_wm", "snapshot_tc_verify",
                              "buffer_pool_for_persistent_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_buffer_pool_using_persistent_wm", "snapshot_tc_verify",
                              "buffer_pool_for_persistent_watermark", "successful")

    st.banner('#### buffer_pool_using_counter_DB ####')
    st.banner('TC name :::: ft_sf_buffer_pool_using_counter_DB ::::')

    match = [{'SAI_BUFFER_POOL_STAT_WATERMARK_BYTES': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, 'buffer_pool_counters_DB', oid_type='ingress_lossless_pool', verify_list=match):
        st.error("Failed to verify the ingress lossless buffer pool counter using counter DB value")
        result += 1
        st.report_tc_fail("ft_sf_buffer_pool_using_counter_DB", "snapshot_tc_verify", "ingress lossless buffer pool",
                          "failed")
    else:
        st.report_tc_pass("ft_sf_buffer_pool_using_counter_DB", "snapshot_tc_verify", "ingress lossless buffer pool",
                          "successful")

    sf_tg_traffic_start_stop(sf_data.unicast, False)
    st.log("waiting for two snapshot interval times to get the counter values reflect correctly")
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('#### clear_buffer_Pool_for_user_watermark####')
    st.banner('TC name :::: ft_sf_buffer_pool_clear_using_uwm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_buffer-pool watermark"):
        st.error("Failed to clear buffer-pool watermark")

    st.log("After clear buffer_pool checking the stats with 10 cells tolerance")
    counters= sfapi.get(vars.D1, 'buffer_pool_watermark', get_value='bytes', match={'pool':'ingress_lossless_pool'})
    if counters > sf_data.buffer_pool_tolerance:
        st.error("Failed to clear the buffer pool counters for user watermark")
        result += 1
        st.report_tc_fail("ft_sf_buffer_pool_clear_using_uwm", "snapshot_tc_verify", "buffer_pool_clear_for_user_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_buffer_pool_clear_using_uwm", "snapshot_tc_verify", "buffer_pool_clear_for_user_watermark", "successful")

    st.banner('#### clear_buffer_pool_for_persistent_watermark ####')
    st.banner('TC name :::: ft_sf_buffer_pool_clear_using_persistent_wm ::::')
    if not sfapi.config_snapshot_interval(vars.D1, snap="clear_buffer-pool persistent-watermark"):
        st.error("Failed to clear_buffer-pool persistent-watermark")

    st.log("After clear buffer_pool checking the stats with 10 cells tolerance")
    counters = sfapi.get(vars.D1, 'buffer_pool_watermark',get_value='bytes', match={'pool':'egress_lossless_pool'})
    if counters > sf_data.buffer_pool_tolerance:
        st.error("Failed to clear the buffer pool counters for persistent watermark")
        result += 1
        st.report_tc_fail("ft_sf_buffer_pool_clear_using_persistent_wm", "snapshot_tc_verify",
                              "buffer_pool_clear_for_persistent_watermark", "failed")
    else:
        st.report_tc_pass("ft_sf_buffer_pool_clear_using_persistent_wm", "snapshot_tc_verify",
                              "buffer_pool_clear_for_persistent_watermark", "successful")
    if not result:
        st.report_pass("snapshot_tc_verify", "buffer pool", "successful")
    else:
        sf_collecting_debug_logs_when_test_fails()
        st.report_fail("snapshot_tc_verify", "buffer pool", "failed")

@pytest.mark.snapshot_regression
def test_ft_sf_verify_cpu_counters():
    """
    Author : prudviraj k (prudviraj.kristipati@broadcom.com) and phani kumar ravula(phanikumar.ravula@broadcom.com)
    """
    result = 0
    if not sfapi.config_snapshot_interval(vars.D1, snap="interval", interval_val=sf_data.snapshot_interval):
        st.error("Failed to configure snapshot interval")
        result += 1
    match = [{'snapshotinterval': sf_data.snapshot_interval}]
    if not sfapi.verify(vars.D1,'snapshot_interval', verify_list=match):
        st.error("Failed to verify the configured snapshot interval")
        result += 1

    st.log("sflow configuration")
    sflow.enable_disable_config(vars.D1, interface=False, interface_name=None, action="enable")
    sflow.config_attributes(vars.D1, sample_rate=sf_data.sflow_sample_rate, interface_name=vars.D1T1P1)

    sf_tg_traffic_start_stop(sf_data.unicast, True)
    st.log("waiting for two snapshot interval times to get the counter values reflect correctly")
    st.wait(2 * sf_data.snapshot_interval)

    st.banner('TC name:::: ft_sf_verify_cpu_counter_value_using_counter_DB ::::')

    st.banner('#### cpu_counters using CLI ####')
    match = [{'CPU:3': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, 'queue_user_watermark_cpu', verify_list=match, port_alias="CPU"):
        st.error("Failed to verify the cpu counter value using CLI")
        result += 1

    st.banner('#### cpu_counters using counter DB ####')
    match = [{'SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES': sf_data.initial_counter_value}]
    if sfapi.verify(vars.D1, column_name="COUNTERS_QUEUE_NAME_MAP",interface_name= 'CPU',queue_value=3,table_name="COUNTERS",verify_list=match):
        st.error("Failed to verify the cpu counter value using counter DB")
        result += 1
        sf_collecting_debug_logs_when_test_fails()
    if result:
        st.report_fail("snapshot_tc_verify", "cpu", "failed")
    else:
        st.report_pass("snapshot_tc_verify", "cpu", "successful")
