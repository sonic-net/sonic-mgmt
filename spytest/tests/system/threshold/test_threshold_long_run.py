# Threshold Feature FT long run test cases.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.system.threshold as tfapi
import apis.switching.vlan as vapi
import apis.routing.ip as ipapi
import apis.system.reboot as rbapi
import apis.system.basic as bcapi
import apis.system.box_services as bsapi
import apis.system.interface as intapi
import apis.system.switch_configuration as scapi

@pytest.fixture(scope="module", autouse=True)
def threshold_feature_module_hooks(request):
    global_vars_and_constants_init()
    tf_module_config(config='yes')
    yield
    tf_module_config(config='no')


@pytest.fixture(scope="function", autouse=True)
def threshold_feature_func_hooks(request):
    verify_system_map_status(tf_data.max_time_to_check_sys_maps[0], tf_data.max_time_to_check_sys_maps[1])
    yield


def global_vars_and_constants_init():
    global vars
    global tf_data
    vars = st.ensure_min_topology('D1T1:4')
    tf_data = SpyTestDict()
    hw_constants = st.get_datastore(vars.D1, "constants")
    scapi.get_running_config(vars.D1)
    # Global Vars
    tf_data.tg_port_list = [vars.T1D1P1, vars.T1D1P2, vars.T1D1P3, vars.T1D1P4]
    tf_data.port_list = [vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4]
    tf_data.platform = bcapi.get_hwsku(vars.D1)
    tf_data.unicast = 'unicast'
    tf_data.multicast = 'multicast'
    tf_data.queues_to_check = ['COUNTERS_PG_NAME_MAP', 'COUNTERS_QUEUE_NAME_MAP']
    tf_data.max_time_to_check_sys_maps = [150, 2]  # Seconds
    tf_data.traffic_duration = 3  # Seconds
    # Common Constants
    tf_data.warm_reboot_supported_platforms = hw_constants['WARM_REBOOT_SUPPORTED_PLATFORMS']


def tf_module_config(config='yes'):
    if config == 'yes':
        vapi.clear_vlan_configuration(vars.D1)
        ipapi.clear_ip_configuration(vars.D1, 'all')
        tf_data.vlan = str(random_vlan_list()[0])
        vapi.create_vlan(vars.D1, tf_data.vlan)
        vapi.add_vlan_member(vars.D1, tf_data.vlan, port_list=tf_data.port_list, tagging_mode=True)
        tf_data.tg, tf_data.tg_ph_list, tf_data.stream_tf_data = tf_tg_stream_config()
    else:
        vapi.delete_vlan_member(vars.D1, tf_data.vlan, port_list=tf_data.port_list)
        vapi.delete_vlan(vars.D1, tf_data.vlan)


def tf_tg_stream_config():
    st.log('TG configuration for tf tests')
    tg_handler = tgapi.get_handles(vars, tf_data.tg_port_list)
    tg = tg_handler["tg"]
    tg_ph_1 = tg_handler["tg_ph_1"]
    tg_ph_2 = tg_handler["tg_ph_2"]
    tg_ph_3 = tg_handler["tg_ph_3"]
    tg_ph_4 = tg_handler["tg_ph_4"]
    tg_ph_list = [tg_ph_1, tg_ph_2, tg_ph_3, tg_ph_4]

    stream_tf_data = {tf_data.unicast: [], tf_data.multicast: []}

    tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])
    stream_tf_data[tf_data.unicast].append(tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_percent=100,
                                                                transmit_mode="continuous",
                                                                mac_src="00:00:00:00:00:02", mac_src_mode="fixed",
                                                                mac_dst="00:00:00:00:00:01", mac_dst_mode="fixed",
                                                                vlan_id=tf_data.vlan,
                                                                l2_encap='ethernet_ii')['stream_id'])
    stream_tf_data[tf_data.unicast].append(tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_percent=100,
                                                                transmit_mode="continuous",
                                                                mac_src="00:00:00:00:00:03", mac_src_mode="fixed",
                                                                mac_dst="00:00:00:00:00:01", mac_dst_mode="fixed",
                                                                vlan_id=tf_data.vlan,
                                                                l2_encap='ethernet_ii')['stream_id'])
    stream_tf_data[tf_data.unicast].append(tg.tg_traffic_config(port_handle=tg_ph_3, mode='create', rate_percent=100,
                                                                transmit_mode="continuous",
                                                                mac_src="00:00:00:00:00:04", mac_src_mode="fixed",
                                                                mac_dst="00:00:00:00:00:01", mac_dst_mode="fixed",
                                                                vlan_id=tf_data.vlan,
                                                                l2_encap='ethernet_ii')['stream_id'])
    stream_tf_data[tf_data.unicast].append(tg.tg_traffic_config(port_handle=tg_ph_4, mode='create', rate_percent=100,
                                                                transmit_mode="continuous",
                                                                mac_src="00:00:00:00:00:01", mac_src_mode="fixed",
                                                                mac_dst="00:00:00:00:00:02", mac_dst_mode="fixed",
                                                                vlan_id=tf_data.vlan,
                                                                l2_encap='ethernet_ii')['stream_id'])

    stream_tf_data[tf_data.multicast].append(tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', rate_percent=100,
                                                                  transmit_mode="continuous",
                                                                  mac_src="00:00:0b:00:04:00", mac_src_mode="fixed",
                                                                  mac_dst="01:82:33:33:33:33", mac_dst_mode="fixed",
                                                                  vlan_id=tf_data.vlan,
                                                                  l2_encap='ethernet_ii')['stream_id'])

    stream_tf_data[tf_data.multicast].append(tg.tg_traffic_config(port_handle=tg_ph_2, mode='create', rate_percent=100,
                                                                  transmit_mode="continuous",
                                                                  mac_src="00:00:00:00:00:03", mac_src_mode="fixed",
                                                                  mac_dst="01:82:33:33:33:33", mac_dst_mode="fixed",
                                                                  vlan_id=tf_data.vlan,
                                                                  l2_encap='ethernet_ii')['stream_id'])

    stream_tf_data[tf_data.multicast].append(tg.tg_traffic_config(port_handle=tg_ph_3, mode='create', rate_percent=100,
                                                                  transmit_mode="continuous",
                                                                  mac_src="00:00:00:00:00:01", mac_src_mode="fixed",
                                                                  mac_dst="01:82:33:33:33:33", mac_dst_mode="fixed",
                                                                  vlan_id=tf_data.vlan,
                                                                  l2_encap='ethernet_ii')['stream_id'])

    stream_tf_data[tf_data.multicast].append(tg.tg_traffic_config(port_handle=tg_ph_4, mode='create', rate_percent=100,
                                                                  transmit_mode="continuous",
                                                                  mac_src="00:00:0b:00:05:00", mac_src_mode="fixed",
                                                                  mac_dst="01:82:33:33:33:33", mac_dst_mode="fixed",
                                                                  vlan_id=tf_data.vlan,
                                                                  l2_encap='ethernet_ii')['stream_id'])

    return tg, tg_ph_list, stream_tf_data


def verify_system_map_status(itter_count, delay):
    bsapi.get_system_uptime_in_seconds(vars.D1)
    if not tfapi.verify_hardware_map_status(vars.D1, tf_data.queues_to_check, itter_count=itter_count, delay=delay):
        st.error('Required Threshold Feature Queues are not initialized in the DUT')
        report_result(0)


def tf_tg_traffic_start_stop(traffic_mode, duration=3):
    streams = tf_data.stream_tf_data.keys()
    if traffic_mode not in streams:
        st.error('Invalid Traffic mode - {}.'.format(traffic_mode))
        return
    st.log(">>> Enabling '{}' traffic streams".format(traffic_mode))
    streams.remove(traffic_mode)
    for each_stream in tf_data.stream_tf_data[traffic_mode]:
        tf_data.tg.tg_traffic_config(mode='enable', stream_id=each_stream)
    for each_type in streams:
        for each_stream in tf_data.stream_tf_data[each_type]:
            tf_data.tg.tg_traffic_config(mode='disable', stream_id=each_stream)

    tf_data.stream_list = tf_data.stream_tf_data['unicast']

    tf_data.tg.tg_traffic_control(action='run',stream_handle=tf_data.stream_list)
    st.wait(duration)
    tf_data.tg.tg_traffic_control(action='stop', stream_handle=tf_data.stream_list)
    # Allow the breach event to be handled and written to DB.
    st.wait(1)


def tf_unconfig():
    tfapi.clear_threshold(vars.D1, breach='all')
    tfapi.clear_threshold(vars.D1, threshold_type='priority-group', buffer_type='all', port_alias=vars.D1T1P1)
    tfapi.clear_threshold(vars.D1, threshold_type='queue', buffer_type='all', port_alias=vars.D1T1P1)


def report_result(status):
    if status:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_cli
@pytest.mark.threshold_ft_long_run
def test_ft_tf_warm_boot():
    """
    Verify that threshold configuration is saved across warm reboot .
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    tf_data.index = 7
    tf_data.threshold = 4
    result = 1

    if tf_data.platform and tf_data.platform.lower() not in tf_data.warm_reboot_supported_platforms:
        st.error("Warm-Reboot is not supported for this platform ({})".format(tf_data.platform))
        st.report_unsupported('test_case_unsupported')

    st.log("Configure priority group threshold and verify")
    tfapi.config_threshold(vars.D1, threshold_type='priority-group', port_alias=vars.D1T1P1, index=tf_data.index,
                           buffer_type='shared', value=tf_data.threshold)
    st.log("verify threshold")
    if not tfapi.verify_threshold(vars.D1, threshold_type='priority-group', port_alias=vars.D1T1P1,
                                  buffer_type='shared', pg7=tf_data.threshold):
        st.error("Unable to configure threshold on pg shared buffer.")
        result = 0

    st.log("Warm boot the node.")
    rbapi.config_save(vars.D1)
    if not st.reboot(vars.D1, "warm"):
        st.error(">>> WARM-REBOOT FAILED")
        result = 0
    if not intapi.poll_for_interfaces(vars.D1, iteration_count=180, delay=1):
        st.error("Ports are not Up, Post Warm reboot.")
        result = 0

    st.log("verify threshold")
    if not tfapi.verify_threshold(vars.D1, threshold_type='priority-group', port_alias=vars.D1T1P1,
                                  buffer_type='shared', pg7=tf_data.threshold):
        st.error("threshold on pg shared buffer lost port warm boot.")
        result = 0

    st.log("Traffic start and stop")
    tf_tg_traffic_start_stop(tf_data.unicast, tf_data.traffic_duration)

    st.log("Verify if a breach event has been generated for PG shared buffer.")
    if not tfapi.verify_threshold_breaches(vars.D1, buffer='priority-group', port=vars.D1T1P1, index=tf_data.index,
                                           threshold_type='shared'):
        st.error("Invalid output of show threshold breaches.")
        result = 0

    tf_unconfig()
    report_result(result)
