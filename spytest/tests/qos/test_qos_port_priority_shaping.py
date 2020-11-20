import pytest
import json
import string
import random
from decimal import Decimal

from spytest import st, tgapi, SpyTestDict, poll_wait

import apis.system.reboot as reboot_obj
from apis.system.switch_configuration import get_running_config
from apis.system.logging import show_logging
from apis.system.interface import show_queue_counters, interface_status_show, clear_interface_counters, show_interface_counters_all, interface_operation, poll_for_interface_status
from apis.switching.mac import config_mac_agetime, config_mac, get_mac_agetime
from apis.switching.vlan import create_vlan_and_add_members, clear_vlan_configuration
import tests.qos.qos_shaper_json_config as data
import apis.qos.qos_shaper as shaper
from apis.qos.qos import clear_qos_config
import apis.common.asic_bcm as asicapi

from utilities.common import random_vlan_list, filter_and_select

port_shaping_data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def scheduler_shaper_module_hooks(request):
    global vars
    global shaping_data
    vars = st.ensure_min_topology("D1T1:4")
    initialize_variables()
    port_speed = filter_and_select(interface_status_show(vars.D1, interfaces=vars.D1T1P3), ['speed'], {'interface': vars.D1T1P3})[0]['speed']
    shaping_data = data.init_vars(vars, port_speed.replace('G', '000'))
    port_shaping_module_prolog()
    port_shaping_data.pmap_details = asicapi.get_interface_pmap_details(vars.D1, interface_name=[vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4])
    if not port_shaping_data.pmap_details:
        st.debug("PMAP details are: {}".format(port_shaping_data.pmap_details))
        st.report_fail('no_data_found')
    st.log("Getting TG handlers")
    tg1, port_shaping_data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, port_shaping_data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    tg3, port_shaping_data.tg_ph_3 = tgapi.get_handle_byname("T1D1P3")
    port_shaping_data.tg = tg1
    st.unused(tg2, tg3)

    st.log("Creating TG streams")
    port_shaping_data.streams = {}
    stream = port_shaping_data.tg.tg_traffic_config(port_handle=port_shaping_data.tg_ph_3, mode='create',
             transmit_mode='continuous', frame_size=64, length_mode='fixed', rate_pps=10, vlan="enable", 
             l2_encap='ethernet_ii_vlan', vlan_id=port_shaping_data.vlan, mac_src=port_shaping_data.mac_egress,
             mac_dst='00:0a:12:00:00:01')
    port_shaping_data.streams['egress_port'] = stream['stream_id']

    stream = port_shaping_data.tg.tg_traffic_config(port_handle=port_shaping_data.tg_ph_1, mode='create',
             transmit_mode='continuous', frame_size=1024, length_mode='fixed', rate_percent=100, vlan="enable",
             l2_encap='ethernet_ii_vlan', vlan_id=port_shaping_data.vlan, vlan_user_priority="1",
             mac_src="00:00:00:00:00:11", mac_dst=port_shaping_data.mac_egress)
    port_shaping_data.streams['ingress_port_1'] = stream['stream_id']

    stream = port_shaping_data.tg.tg_traffic_config(port_handle=port_shaping_data.tg_ph_2, mode='create',
             transmit_mode='continuous', frame_size=1024, length_mode='fixed', rate_percent=100, vlan="enable",
             l2_encap='ethernet_ii_vlan', vlan_id=port_shaping_data.vlan, vlan_user_priority="2",
             mac_src="00:00:00:00:00:22", mac_dst=port_shaping_data.mac_egress)
    port_shaping_data.streams['ingress_port_2'] = stream['stream_id']
    yield
    port_shaping_module_epilog()


@pytest.fixture(scope="function", autouse=True)
def scheduler_shaper_function_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    clear_interface_counters(vars.D1)
    yield
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=port_shaping_data.streams.values())
    if st.get_func_name(request) in ['test_ft_qos_port_shaping_functionality', 'test_ft_qos_port_shaper_cold_reboot', 'test_ft_qos_port_shaper_fast_reboot', 'test_ft_qos_port_shaper_config_reload', 'test_ft_qos_port_shaper_warm_reboot']:
        shaper.clear_port_shaper(vars.D1, port=shaping_data['port_shaper_json_config']['port'], shaper_data=shaping_data['port_shaper_json_config']['policy_name'], qos_clear=True)
    elif st.get_func_name(request) in ['test_ft_qos_queue_shaping_functionality', 'test_ft_qos_queue_shaping_testcase_2', 'test_ft_qos_queue_shaper_cold_reboot', 'test_ft_qos_queue_shaper_fast_reboot', 'test_ft_qos_queue_shaper_config_reload', 'test_ft_qos_queue_shaper_warm_reboot']:
        shaper.clear_port_shaper(vars.D1, port=shaping_data['queue_shaper_json_config_q0102']['port'], shaper_data=shaping_data['queue_shaper_json_config_q0102']['policy_name'], qos_clear=True)
    elif st.get_func_name(request) in ['test_ft_qos_queue_scheduling_min_not_met_functionality', 'test_ft_qos_shaper_scheduler_interaction']:
        shaper.clear_port_shaper(vars.D1, port=shaping_data['port_shaper_json_config_10G']['port'], shaper_data=shaping_data['port_shaper_json_config_10G']['policy_name'], qos_clear=True)
    elif st.get_func_name(request) == 'test_ft_qos_queue_and_port_level_shaping':
        shaper.clear_port_shaper(vars.D1, port=shaping_data['port_queue_shaper_json_config1']['port'], shaper_data=shaping_data['port_queue_shaper_json_config1']['policy_name'], qos_clear=True)
    elif st.get_func_name(request) == 'test_ft_qos_queue_shaping_testcase_1':
        shaper.clear_port_shaper(vars.D1, port=shaping_data['queue_shaper_json_config_q0']['port'], shaper_data=shaping_data['queue_shaper_json_config_q0']['policy_name'], qos_clear=True)
    elif st.get_func_name(request) == 'test_ft_qos_port_shaping_testcase_1':
        port_shaping_data.tg.tg_traffic_config(mode='remove', stream_id=port_shaping_data.streams['ingress_port_stream_2'], port_handle=port_shaping_data.tg_ph_1)
        port_shaping_data.streams.pop('ingress_port_stream_2', None)
        port_shaping_data.tg.tg_traffic_config(mode='modify', stream_id=port_shaping_data.streams['ingress_port_1'], rate_percent=100)
        port_shaping_data.tg.tg_traffic_config(mode='modify', stream_id=port_shaping_data.streams['ingress_port_2'], rate_percent=100)
        shaper.clear_port_shaper(vars.D1, port=shaping_data['port_shaper_json_config_1G']['port'], shaper_data=shaping_data['port_shaper_json_config_1G']['policy_name'], qos_clear=True)
    elif st.get_func_name(request) == 'test_ft_change_port_shaper_rate_on_fly':
        shaper.clear_port_shaper(vars.D1, port=vars.D1T1P3, shaper_data=port_shaping_data.profile_name, qos_clear=True)
    elif st.get_func_name(request) == 'test_ft_change_queue_shaper_rate_on_fly':
        shaper.clear_port_shaper(vars.D1, port=vars.D1T1P3, shaper_data=port_shaping_data.profile_name, qos_clear=True)
    else:
        clear_qos_config(vars.D1)

def initialize_variables():
    port_shaping_data.clear()
    port_shaping_data.ageout_time = 10000
    port_shaping_data.vlan = str(random_vlan_list()[0])
    port_shaping_data.mac_egress = "00:00:01:02:12:22"
    port_shaping_data.profile_name = 'port_qos_shaper'
    port_shaping_data.rate_tolerance = 5.0
    port_shaping_data.queue_num = [0, 1, 2]
    constants = st.get_datastore(vars.D1, 'constants')
    port_shaping_data.max_profile = int(constants['MAX_SCHEDULER_PROFILES'])
    port_shaping_data.max_scheduler_data = dict()
    port_shaping_data.max_scheduler_data["SCHEDULER"] = dict()
    for i in range(1, port_shaping_data.max_profile+2):
        port_shaping_data.max_scheduler_data["SCHEDULER"]["scheduler.q{}".format(i)] = dict()
        port_shaping_data.max_scheduler_data["SCHEDULER"]["scheduler.q{}".format(i)].update({"meter_type": "bytes"})
        port_shaping_data.max_scheduler_data["SCHEDULER"]["scheduler.q{}".format(i)].update({"pir": "1236545"})

def apply_port_shaping_config2(dut, config):
    json_config = json.dumps(config)
    json.loads(json_config)
    st.apply_json(dut, json_config)

def port_shaping_module_prolog():
    st.log("Create a vlan and add ports as tagged members of it")
    if not create_vlan_and_add_members([{"dut": [vars.D1], "vlan_id": port_shaping_data.vlan,
                                         "tagged": [vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4]}]):
        st.report_fail('vlan_tagged_member_fail', [vars.D1T1P1, vars.D1T1P2, vars.D1T1P3, vars.D1T1P4], port_shaping_data.vlan)
    if not config_mac_agetime(vars.D1, port_shaping_data.ageout_time):
        st.report_fail("msg", "Failed to configure MAC aging time as: {}".format(port_shaping_data.ageout_time))
    get_mac_agetime(vars.D1)


def port_shaping_module_epilog():
    port_shaping_data.tg.tg_traffic_control(action='reset',
                                            port_handle=[port_shaping_data.tg_ph_1, port_shaping_data.tg_ph_2,
                                                         port_shaping_data.tg_ph_3])
    port_shaping_data.tg.tg_traffic_control(action='clear_stats',
                                            port_handle=[port_shaping_data.tg_ph_1, port_shaping_data.tg_ph_2,
                                                         port_shaping_data.tg_ph_3])
    clear_vlan_configuration([vars.D1])
    config_mac_agetime(vars.D1, agetime = 600, config= 'delete')

def mac_learning():
    st.log("Sending traffic from egress port to learn the MAC in FDB table")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=port_shaping_data.streams['egress_port'])
    st.wait(3)
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=port_shaping_data.streams['egress_port'])
    asicapi.dump_l2(vars.D1)

def shaper_debug_info():
    st.debug("Collecting debug information on the DUT")
    asicapi.bcmcmd_show_c(vars.D1)
    st.debug("Dump running-config")
    get_running_config(vars.D1)
    st.debug("Dump l2 entries")
    asicapi.dump_l2(vars.D1)
    st.debug("Collecting interface counters")
    show_interface_counters_all(vars.D1)

def get_port_queue_tx_counter(dut, port, tx_queue_list, counter):
    queue_dict_list = show_queue_counters(dut, port)
    st.log('Queue counter output is:{}'.format(queue_dict_list))
    output = []
    for tx_queue in tx_queue_list:
        for queue_dict in queue_dict_list:
            if (queue_dict['port'] == port and queue_dict['txq'] == tx_queue):
                output.append(int(queue_dict[counter].replace(',', '')))
    return output

def qos_shaping_verify_clmib_rate_pps(intf, port_pir, num_of_iter=5):
    for i in range(0, num_of_iter):
        st.banner("Iteration: {}".format(i))
        st.wait(20, "Wait till rate interval")
        q_rate = shaper.get_port_tx_rate_in_bps(vars.D1, intf)
        st.debug("TX_BPS for port: {} is: {}".format(intf, q_rate))
        if not q_rate:
            continue
        diff_rate = (Decimal((abs(port_pir - q_rate) * 100)) / Decimal(port_pir))
        if diff_rate <= port_shaping_data.rate_tolerance:
            return True
        st.debug("Interface: {}" . format(intf))
        st.debug("Expected port shaper rate: {}" . format(port_pir))
        st.debug("Actual port shaper rate: {}" . format(q_rate))
        st.debug("diff_rate:{}".format(diff_rate))
    return False

def qos_shaping_verify_clmib_rate_pps_more_than_min_expected(intf, port_pir, num_of_iter=5):
    for i in range(0, num_of_iter):
        st.banner("Iteration: {}".format(i))
        st.wait(20, "Wait till rate interval")
        q_rate = shaper.get_port_tx_rate_in_bps(vars.D1, intf)
        if not q_rate:
            continue
        if q_rate >= int(port_pir):
            return True
        st.debug("Interface: {}" . format(intf))
        st.debug("Expected port shaper rate: {}" . format(port_pir))
        st.debug("Actual port shaper rate: {}" . format(q_rate))
    return False

def qos_shaping_verify_uc_per_q_rate_pps(queue_pir, perq_priority, egress_port=''):
    egress_port = egress_port if egress_port else vars.D1T1P3
    num_of_iterations = 5
    bcm_ce = port_shaping_data.pmap_details[egress_port]
    try:
        for i in range(0, num_of_iterations):
            st.banner("Iteration: {}".format(i))
            asicapi.clear_counters(vars.D1)
            asicapi.bcmcmd_show_c(vars.D1, bcm_ce)
            st.wait(5)
            output = asicapi.bcmcmd_show_c(vars.D1, bcm_ce)
            port_shaping_data.cntr_uc_perq_byte = "UC_PERQ_BYTE({}).{}".format(perq_priority, bcm_ce)
            st.log("port_shaping_data.cntr_uc_perq_byte = {}" . format(port_shaping_data.cntr_uc_perq_byte))
            q_rate = filter_and_select(output, ['time'], {'key': port_shaping_data.cntr_uc_perq_byte})
            if not (q_rate and q_rate[0]['time']):
                st.debug("Expected Queue rate for Queue-{}: {}" . format(perq_priority, queue_pir))
                st.debug('Actual Queue rate for Queue-{}: {}'.format(perq_priority, q_rate))
                st.debug('Output is: {}'.format(output))
                st.debug("bcm_ce: {}" . format(bcm_ce))
                continue
            q_rate = int(q_rate[0]['time'].replace(',', '').replace('/s', ''))
            diff_rate = (Decimal((abs(queue_pir - q_rate) * 100)) / Decimal(queue_pir))
            if diff_rate<= port_shaping_data.rate_tolerance:
                return True
            st.debug("Expected Queue rate for Queue-{}: {}" . format(perq_priority, queue_pir))
            st.debug('Actual Queue rate for Queue-{}: {}'.format(perq_priority, q_rate))
            st.debug("diff_rate:{}".format(diff_rate))
            st.debug('Output is: {}'.format(output))
            st.debug("bcm_ce: {}" . format(bcm_ce))
        return False
    except Exception as e:
        st.error('Exception occurred is: {}'.format(e))
        return False

def qos_shaping_verify_uc_per_q_rate_pps_with_expected_mul_factor(queue_pir, perq_priority, expected_min_mul_factor):
    num_of_iterations = 5
    bcm_ce = port_shaping_data.pmap_details[vars.D1T1P3]
    st.log("expected_min_mul_factor = {}".format(expected_min_mul_factor))
    try:
        for i in range(0, num_of_iterations):
            st.banner("Iteration: {}".format(i))
            asicapi.clear_counters(vars.D1)
            asicapi.bcmcmd_show_c(vars.D1, bcm_ce)
            st.wait(5)
            output = asicapi.bcmcmd_show_c(vars.D1, bcm_ce)
            port_shaping_data.cntr_uc_perq_byte = "UC_PERQ_BYTE({}).{}".format(perq_priority, bcm_ce)
            st.log("port_shaping_data.cntr_uc_perq_byte = {}" . format(port_shaping_data.cntr_uc_perq_byte))
            q_rate = filter_and_select(output, ['time'], {'key': port_shaping_data.cntr_uc_perq_byte})
            if not (q_rate and q_rate[0]['time']):
                st.debug("Expected Queue rate for Queue-{}: {}" . format(perq_priority, queue_pir))
                st.debug('Actual Queue rate for Queue-{}: {}'.format(perq_priority, q_rate))
                st.debug('Output is: {}'.format(output))
                st.debug("bcm_ce: {}" . format(bcm_ce))
                continue
            q_rate = int(q_rate[0]['time'].replace(',', '').replace('/s', ''))
            diff_rate = (Decimal((abs(queue_pir - q_rate) * 100)) / Decimal(queue_pir))
            calculated_mul_factor = int(abs(q_rate/queue_pir))
            if calculated_mul_factor >= int(expected_min_mul_factor):
                return True
            st.debug("Expected Queue rate for Queue-{}: {}" . format(perq_priority, queue_pir))
            st.debug('Actual Queue rate for Queue-{}: {}'.format(perq_priority, q_rate))
            st.debug("diff_rate:{}".format(diff_rate))
            st.debug('Output is: {}'.format(output))
            st.debug("bcm_ce: {}" . format(bcm_ce))
            st.debug("calculated multiplication factor .. actual q_rate/queue_pir = {}".format(calculated_mul_factor))
        return False
    except Exception as e:
        st.error('Exception occurred is: {}'.format(e))
        return False



@pytest.mark.port_level_shaping
@pytest.mark.qos_shaper
def test_ft_qos_port_shaping_functionality():
    '''
    FtOpQosPrPsFn001: Verify the functionality of Port-Level shaper configuration
    '''
    st.log("Applying port shaping configuration on {}".format(vars.D1T1P3))
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Checking QOS scehduling on interface level with pir_8G")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("port_shaping_verify", "failed")
    st.report_pass("port_shaping_verify", "passed")


@pytest.mark.queue_level_shaping
@pytest.mark.qos_shaper
def test_ft_qos_queue_shaping_functionality():
    '''
    FtOpQosPrPsFn002: Verify the functionality of Queue-Level shaper configuration.
    '''
    st.log("Set the max bandwidth setting on queue-1 and queue-2 to 8G and 2G respectively on the port {}".format(vars.D1T1P3))
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0102']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0102']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scheduling on queue level with pir_8G on queue1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    st.log("Checking QOS scheduling on queue level with pir_2G on queue2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "2G")
    st.report_pass("queue_shaping_verify", "passed")


@pytest.mark.min_not_met_scheduling
@pytest.mark.qos_shaper
def test_ft_qos_queue_scheduling_min_not_met_functionality():
    '''
    FtOpQosPrPsFn003: Verify the scheduling of the queue in MinNotMet case.
    '''
    st.log("Applying min bandwidth profile on the port {}".format(vars.D1T1P3))
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config_10G']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config_10G']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_min_not_met_json_config']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_min_not_met_json_config']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scehduling on queue level with pir_10G on queue1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_10G'], port_shaping_data.queue_num[1]):
            shaper_debug_info()
            st.report_fail("min_not_met_scheduling", "failed")
    st.report_pass("min_not_met_scheduling","passed")


@pytest.mark.qos_port_shaping_remove_config
@pytest.mark.qos_shaper
def test_ft_qos_port_shaping_remove_config():
    '''
    FtOpQosPrPsFn006:Verify that after removing the QoS scheduler profile configuration on interface, the traffic rate is no longer rate limited.
    '''
    st.log("Applying shaping configuration on port {} to limit bandwidth to 8G".format(vars.D1T1P3))
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Checking QOS scehduling on interface level with pir_8G")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_port", "not", vars.D1T1P3, "8G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Removing the QoS scheduler config on the egress port {}".format(vars.D1T1P3))
    shaper.clear_port_shaper(vars.D1, port=shaping_data['port_shaper_json_config']['port'], shaper_data=shaping_data['port_shaper_json_config']['policy_name'])
    st.log("Clear the DUT counters")
    clear_interface_counters(vars.D1)
    st.log("Sending traffic from ingress port {} to check for no loss".format(vars.D1T1P1))
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.wait(5)
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Fetching interfaces statistics")
    counter_output = show_interface_counters_all(vars.D1)
    ingress_rx_cnt = filter_and_select(counter_output, ['rx_ok'], {'iface': vars.D1T1P1})[0]['rx_ok']
    egress_tx_cnt = filter_and_select(counter_output, ['tx_ok'], {'iface': vars.D1T1P3})[0]['tx_ok']
    st.log("Verifying traffic sent from {} is egressing at {} without any loss".format(vars.D1T1P1, vars.D1T1P3))
    st.log("Traffic sent: {} and Traffic received: {}".format(ingress_rx_cnt.replace(',', ''),
                                                              egress_tx_cnt.replace(',', '')))
    if not ((0.99*int(ingress_rx_cnt.replace(',', ''))) <= int(egress_tx_cnt.replace(',', ''))):
        shaper_debug_info()
        st.report_fail("port_shaping_after_profile_removed", "")
    st.report_pass("port_shaping_after_profile_removed", "not")


@pytest.mark.qos_queue_shaping_testcase_2
@pytest.mark.qos_shaper
def test_ft_qos_queue_shaping_testcase_2():
    '''
    FtOpQosPrPsFn007:Verify that traffic is rate-limited as per the updated value when user updates the existing QoS shaper configuration.
    '''
    st.log("Configuring max bandwidth on queue-1 to 8G and queue-2 to 2G on the port {}".format(vars.D1T1P3))
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0102']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0102']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scehduling with queue leve with pir_8G with queue1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    st.log("Checking QOS scehduling with queue leve with pir_2G with queue2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                          port_shaping_data.streams['ingress_port_2']])
    st.log("Remove the queue shaping profile")
    clear_qos_config(vars.D1)
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scehduling with queue leve with pir_5G with queue1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scehduling with queue leve with pir_5G with queue2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Configure max bandwidth on queue-1 to 2G and queue-2 to 8G")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0102_1']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0102_1']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scheduling with queue level with pir_2G with queue1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "2G")
    st.log("Checking QOS scheduling with queue level with pir_8G with queue2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "8G")
    st.report_pass("queue_shaping_profile_update", "")


@pytest.mark.qos_queue_and_port_level_shaping
@pytest.mark.qos_shaper
def test_ft_qos_queue_and_port_level_shaping():
    '''
    FtOpQosPrPsFn008:Verify the functionality of QOS scheduling with both Queue-Level and interface level shaper configurations
    '''
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_queue_shaper_json_config1']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_queue_shaper_json_config1']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['port_queue_shaper_json_config2']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['port_queue_shaper_json_config2']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scheduling on queue leve with pir_5G on queue1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        st.log("Traffic not transmitted on egress port {} at a rate of 5G on queue-1".format(vars.D1T1P3))
        shaper_debug_info()
        st.report_fail("queue_and_port_level_shaping", "failed")
    st.log("Checking QOS scheduling on queue level with pir_2G on queue2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        st.log("Traffic not transmitted on egress port {} at a rate of 2G on queue-2".format(vars.D1T1P3))
        shaper_debug_info()
        st.report_fail("queue_and_port_level_shaping", "failed")
    st.log("Checking QOS scheduling on interface level with pir_7G")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_7G']):
        st.log("Traffic not transmitted on egress port {} at a rate of 7G".format(vars.D1T1P3))
        shaper_debug_info()
        st.report_fail("queue_and_port_level_shaping", "failed")
    st.report_pass("queue_and_port_level_shaping", "passed")


@pytest.mark.qos_shaper_scheduler_interaction
@pytest.mark.qos_scheduler
@pytest.mark.qos_shaper
def test_ft_qos_shaper_scheduler_interaction():
    '''
    FtOpQosPrPsFn010:Verify the QOS shaper interaction with scheduler.
    '''
    st.log("Set the queue-1 and queue-2 bandwidth to 9G and scheduler weights for queue-1 and queue-2 to 20 and 80 respectively on the port")
    #apply_port_shaping_config(vars.D1, shaping_data['queue_sched_shaper_json_config'])
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config_10G']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config_10G']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    if not shaper.apply_queue_shcheduling_config(vars.D1, shaping_data['queue_scheduler_json_config_q0102']):
        st.error("Failed to configure scheduler with the data: {}".format(shaping_data['queue_scheduler_json_config_q0102']))
        st.report_fail("msg", "Failed to configure scheduler")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scehduling on queue level with pir_2G on queue1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[1]):
        st.log("Traffic not transmitted on egress port {} at a rate of 2G on queue-1".format(vars.D1T1P3))
        shaper_debug_info()
        st.report_fail("shaper_scheduler_interaction", "failed")
    st.log("Checking QOS scehduling on queue level with pir_8G on queue2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[2]):
        st.log("Traffic not transmitted on egress port {} at a rate of 8G on queue-2".format(vars.D1T1P3))
        shaper_debug_info()
        st.report_fail("shaper_scheduler_interaction", "failed")
    st.report_pass("shaper_scheduler_interaction", "passed")


@pytest.mark.qos_port_shaper_cold_reboot
@pytest.mark.qos_shaper
def test_ft_qos_port_shaper_cold_reboot():
    '''
    FtOpQosPrPsLr001:Verify QOS port shaper functionality with valid startup configuration and after normal/cold reboot
    '''
    st.log("Applying port shaping configuration")
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_port", "not", vars.D1T1P3, "8G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Saving the configuration on the device")
    reboot_obj.config_save(vars.D1)
    st.log("Perform reboot and check the port shaping functionality")
    st.reboot(vars.D1)
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("port_shaping_after_cold_reboot", "failed")
    st.report_pass("port_shaping_after_cold_reboot", "passed")


@pytest.mark.qos_port_shaper_fast_reboot
@pytest.mark.qos_shaper
def test_ft_qos_port_shaper_fast_reboot():
    '''
    FtOpQosPrPsLr002:Verify QOS port shaper functionality with valid startup configuration and after fast-reboot
    '''
    st.log("Applying port shaping configuration")
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_port", "not", vars.D1T1P3, "8G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Saving the configuration on the device")
    reboot_obj.config_save(vars.D1)
    st.log("Perform fast reboot and check the port shaping functionality")
    st.reboot(vars.D1, 'fast')
    mac_learning()
    st.log("Sending the traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("port_shaping_after_fast_reboot", "failed")
    st.report_pass("port_shaping_after_fast_reboot", "passed")


@pytest.mark.qos_port_shaper_config_reload
@pytest.mark.qos_shaper
def test_ft_qos_port_shaper_config_reload():
    '''
    FtOpQosPrPsLr003:Verify QOS port shaper functionality with valid startup configuration and after config reload
    '''
    st.log("Applying port shaping configuration")
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_port", "not", vars.D1T1P3, "8G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Perform config reload and check the port shaping functionality")
    reboot_obj.config_reload(vars.D1)
    st.log("Testing port shaping functionality after config-reload")
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("port_shaping_after_config_reload", "failed")
    st.report_pass("port_shaping_after_config_reload", "passed")


@pytest.mark.qos_port_shaper_warm_reboot
@pytest.mark.qos_shaper
def test_ft_qos_port_shaper_warm_reboot():
    '''
    FtOpQosPrPsLr004:Verify QOS port shaper functionality after warm reboot
    '''
    st.log("Applying port shaping configuration")
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_port", "not", vars.D1T1P3, "8G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1']])
    st.log("Saving the configuration on the device")
    reboot_obj.config_save(vars.D1)
    st.log("Perform warm reboot and check the port shaping functionality")
    st.reboot(vars.D1, 'warm')
    mac_learning()
    st.log("Sending traffic from ingress port")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("port_shaping_after_warm_reboot", "failed")
    st.report_pass("port_shaping_after_warm_reboot", "passed")


@pytest.mark.qos_queue_shaper_cold_reboot
@pytest.mark.qos_shaper
def test_ft_qos_queue_shaper_cold_reboot():
    '''
    FtOpQosPrPsLr005:Verify QOS queue shaper functionality with valid startup configuration and after normal/cold reboot.
    '''
    st.log("Set the max bandwidth setting on queue-1 and queue-2 to 8G and 2G respectively")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0102']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0102']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Saving the configuration on the device")
    reboot_obj.config_save(vars.D1)
    st.log("Perform cold reboot and check the queue shaping functionality")
    st.reboot(vars.D1)
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1 after reboot", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2 after reboot", "2G")
    st.report_pass("queue_shaping_after_cold_reboot", "passed")


@pytest.mark.qos_queue_shaper_fast_reboot
@pytest.mark.qos_shaper
def test_ft_qos_queue_shaper_fast_reboot():
    '''
    FtOpQosPrPsLr006:Verify QOS queue shaper functionality with valid startup configuration and after fast-reboot
    '''
    st.log("Set the max bandwidth setting on queue-1 and queue-2 to 8G and 2G respectively")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0102']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0102']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Saving the configuration on the device")
    reboot_obj.config_save(vars.D1)
    st.log("Perform fast reboot and check the queue shaping functionality")
    st.reboot(vars.D1, 'fast')
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1 after fast-boot", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2 after fast-boot", "2G")
    st.report_pass("queue_shaping_after_fast_reboot", "passed")



@pytest.mark.qos_queue_shaper_config_reload
@pytest.mark.qos_shaper
def test_ft_qos_queue_shaper_config_reload():
    '''
    FtOpQosPrPsLr007:Verify QOS queue shaper functionality with valid startup configuration and after config reload
    '''
    st.log("Set the max bandwidth setting on queue-1 and queue-2 to 8G and 2G respectively")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0102']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0102']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Perform config reload and check the queue shaping functionality")
    reboot_obj.config_reload(vars.D1)
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1 after config-reload", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2 after config-reload", "2G")
    st.report_pass("queue_shaping_after_config_reload", "passed")


@pytest.mark.qos_queue_shaper_warm_reboot
@pytest.mark.qos_shaper
def test_ft_qos_queue_shaper_warm_reboot():
    '''
    FtOpQosPrPsLr008:Verify QOS queue shaper functionality with valid startup configuration and after warm reboot
    '''
    st.log("Set the max bandwidth setting on queue-1 and queue-2 to 8G and 2G respectively")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0102']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0102']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    port_shaping_data.tg.tg_traffic_control(action='stop', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Perform warm reboot and check the port shaping functionality")
    st.reboot(vars.D1, 'warm')
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1 after warm-boot", "8G")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2 after warm-boot", "2G")
    st.report_pass("queue_shaping_after_warm_reboot", "passed")


@pytest.mark.qos_queue_shaping_testcase_1
@pytest.mark.qos_shaper
def test_ft_qos_queue_shaping_testcase_1():
    '''
    FtOpQosPrPsFn004:Verify that other traffic streams are unaffected by the QoS shaping configuration at queue level
    '''
    st.log("Applying shaper profile on queue-0 and scheduler profile on queues 0 and 1")
    if not shaper.apply_queue_shaping_config(vars.D1, shaping_data['queue_shaper_json_config_q0']):
        st.error("Failed to configure queue-shaper with the data: {}".format(shaping_data['queue_shaper_json_config_q0']))
        st.report_fail("msg", "Failed to configure queue-level shaper")
    if not shaper.apply_queue_shcheduling_config(vars.D1, shaping_data['queue_scheduler_json_config_q001']):
        st.error("Failed to configure scheduler with the data: {}".format(shaping_data['queue_scheduler_json_config_q001']))
        st.report_fail("msg", "Failed to configure scheduler")
    port_shaping_data.tg.tg_traffic_config(mode='modify', stream_id=port_shaping_data.streams['ingress_port_2'],
                                           vlan_user_priority="0")
    port_shaping_data.tg.tg_traffic_config(mode='modify', stream_id=port_shaping_data.streams['ingress_port_1'],
                                           rate_percent=90)
    mac_learning()
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_2']])
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_1G'], port_shaping_data.queue_num[0]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-0", "1G")
    st.log("About verify the traffic rate corresponding to queue - = {}" . format(port_shaping_data.queue_num[1]))

    # Here pir_8G is being passed because most of the platforms have links speeds of 10G and above.
    # For queue#0, 1G is allocated for spaing. Left over bandwidth will be minimum of 9G.
    # To have some allowance, queue#1 rate should be min of 2G. So, pir_2G is used for verification.

    expected_min_mul_factor_int_value = 1
    if not qos_shaping_verify_uc_per_q_rate_pps_with_expected_mul_factor(shaping_data['pir_2G'], port_shaping_data.queue_num[1], expected_min_mul_factor_int_value):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "9G")
    st.report_pass("queue_shaping_effect_on_other", "passed")


@pytest.mark.qos_port_shaping_testcase_1
@pytest.mark.qos_shaper
def test_ft_qos_port_shaping_testcase_1():
    '''
    FtOpQosPrPsFn005:Verify that QOS shaper configuration at port level on one port is not effecting the other
    '''
    st.log("Applying shaper profile on port {} to limit the traffic to 1G".format(vars.D1T1P2))
    if not shaper.apply_port_shaping_config(vars.D1, shaping_data['port_shaper_json_config_1G']):
        st.error("Failed to configure port-shaper with the data: {}".format(shaping_data['port_shaper_json_config_1G']))
        st.report_fail("msg", "Failed to configure port-level shaper")
    port_shaping_data.tg.tg_traffic_config(mode='modify', stream_id=port_shaping_data.streams['ingress_port_1'],
                                           rate_percent=50)
    port_shaping_data.tg.tg_traffic_config(mode='modify', stream_id=port_shaping_data.streams['ingress_port_2'],
                                           vlan_user_priority="2", rate_pps=10)
    stream = port_shaping_data.tg.tg_traffic_config(port_handle=port_shaping_data.tg_ph_1, mode='create',
                                                    transmit_mode='continuous',
                                                    frame_size=1024, length_mode='fixed', rate_percent=50,
                                                    l2_encap='ethernet_ii_vlan',
                                                    vlan_id=port_shaping_data.vlan, vlan="enable",
                                                    vlan_user_priority="1",
                                                    mac_src="00:00:00:00:00:13", mac_dst="00:00:00:00:00:22")
    port_shaping_data.streams['ingress_port_stream_2'] = stream['stream_id']
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_2']])
    st.log("Sending traffic from ingress ports")
    port_shaping_data.tg.tg_traffic_control(action='run',
                                            stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                           port_shaping_data.streams['ingress_port_stream_2']])
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P2, shaping_data['pir_1G']):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_port", "not", vars.D1T1P2, "1G")
    st.log("About verify the traffic rate corresponding to egress port-2")
    if not qos_shaping_verify_clmib_rate_pps_more_than_min_expected(vars.D1T1P3, shaping_data['pir_4G']):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_port", "not", vars.D1T1P3, "5G")
    st.report_pass("port_shaping_effect_on_other", "passed")


@pytest.mark.qos_shaper
def test_ft_scheduler_max_profiles():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    FtOpQosPrPsSc001:	Verify that failure occurs with configuration of max+1 QoS scheduler profiles
    '''
    apply_port_shaping_config2(vars.D1, port_shaping_data.max_scheduler_data)
    if not poll_wait(show_logging, 15, vars.D1, filter_list="Max user scheduler profiles of {} reached".format(port_shaping_data.max_profile), lines=None):
        st.report_fail("max_supported_scheduler_success")
    st.report_pass("max_supported_scheduler_failed")


@pytest.mark.qos_shaper
def test_ft_change_port_shaper_rate_on_fly():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsFn013:  Verify the port level shaper by modifying the shaper rate on fly.
    '''
    st.banner("Configuring Port PIR as 8GB")
    shaper_data = {'port': vars.D1T1P3, 'pir': shaping_data['pir_8G'], 'meter_type': 'bytes', 'policy_name': port_shaping_data.profile_name}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data):
        st.error("Failed to configure port-shaper with data: {}".format(shaper_data))
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 8G")
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1']], enable_arp=0)
    st.log("Checking QOS shaper on interface level with pir_8G")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_8G']):
        shaper_debug_info()
        st.report_fail("port_shaping_verify", "failed")
    st.banner("Modifying the Port PIR to 6GB on fly")
    shaper_data = {'pir': shaping_data['pir_6G'], 'policy_name': port_shaping_data.profile_name}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data):
        st.error("Failed to configure port-shaper with the data: {}".format(shaper_data))
        st.report_fail("msg", "Failed to change the port-level shaper PIR rate to 6G")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_6G']):
        shaper_debug_info()
        st.report_fail("port_shaping_verify", "failed")
    st.banner("Reset the Port PIR on fly")
    if not shaper.reset_port_shaper_params(vars.D1, port_shaping_data.profile_name, 'pir'):
        shaper_debug_info()
        st.report_fail("msg", "Failed to reset the port PIR rate")
    st.wait(2, "To stabilize the counters")
    show_interface_counters_all(vars.D1)
    clear_interface_counters(vars.D1)
    st.wait(2, "Waiting to update counters")
    counters = show_interface_counters_all(vars.D1)
    egress_tx_drp_cnt = filter_and_select(counters, ['tx_drp'], {'iface': vars.D1T1P3})[0]['tx_drp']
    if int(egress_tx_drp_cnt.replace(",", "")) > 0:
        st.report_fail("msg", "Traffic drop observed even the port shaper PIR is RESET")
    st.banner("Modifying the Port PIR to 5GB on fly")
    shaper_data = {'pir': shaping_data['pir_5G'], 'policy_name': port_shaping_data.profile_name}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data):
        st.error("Failed to configure port-shaper with the data: {}".format(shaper_data))
        st.report_fail("msg", "Failed to change the port-level shaper PIR rate to 5G")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_5G']):
        shaper_debug_info()
        st.report_fail("port_shaping_verify", "failed")
    st.banner("Detaching the shaper profile from egress port on fly")
    if not shaper.clear_port_shaper(vars.D1, vars.D1T1P3, port_shaping_data.profile_name, remove_shaper = False):
        shaper_debug_info()
        st.report_fail("msg", "Failed to detach shaper from port: {}".format(vars.D1T1P3))
    st.wait(2, "To stabilize the counters")
    clear_interface_counters(vars.D1)
    st.wait(2, "Waiting to update counters")
    counters = show_interface_counters_all(vars.D1)
    egress_tx_drp_cnt = filter_and_select(counters, ['tx_drp'], {'iface': vars.D1T1P3})[0]['tx_drp']
    if int(egress_tx_drp_cnt.replace(",", "")) > 0:
        shaper_debug_info()
        st.report_fail("msg", "Traffic drop observed even the port shaper detached from the Egress port: {}".format(vars.D1T1P3))
    st.banner("Attaching the shaper profile to egress port on fly")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'port': vars.D1T1P3}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to attach the shaper profile: {} to Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_5G']):
        shaper_debug_info()
        st.report_fail("port_shaping_verify", "failed")
    st.report_pass("msg", "Successfully verified port level shaper by modifying the shaper rate on fly")


@pytest.mark.qos_shaper
def test_ft_change_queue_shaper_rate_on_fly():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsFn014:  Verify the queue level shaper by modifying the shaper rate on fly.
    '''
    st.banner("Configuring Queue-1 PIR as 8GB and Queue-2 PIR as 2GB")
    shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': port_shaping_data.queue_num[1], 'pir': shaping_data['pir_8G'], 'meter_type': 'bytes'}, {'queue': port_shaping_data.queue_num[2], 'pir': shaping_data['pir_2G'], 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(shaper_data))
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                          port_shaping_data.streams['ingress_port_2']], enable_arp=0)
    st.log("Checking QOS scheduling on queue level with pir_8G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    st.log("Checking QOS scheduling on queue level with pir_2G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    st.banner("Configuring Queue-1 PIR as 2GB and Queue-2 PIR as 8GB on fly")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': port_shaping_data.queue_num[1], 'pir': shaping_data['pir_2G']}, {'queue': port_shaping_data.queue_num[2], 'pir': shaping_data['pir_8G']}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(shaper_data))
    st.log("Checking QOS scheduling on queue level with pir_2G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "2G")
    st.log("Checking QOS scheduling on queue level with pir_8G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "8G")
    st.banner("Reset the Queue-1, Queue-2 PIR values on fly")
    params_dict = {port_shaping_data.queue_num[1]: 'pir', port_shaping_data.queue_num[2]: 'pir'}
    if not shaper.reset_queue_shaper_params(vars.D1, port_shaping_data.profile_name, params_dict):
        shaper_debug_info()
        st.report_fail("msg", "Failed to reset the Queue-Level PIR values of shaper profile: {}".format(port_shaping_data.profile_name))
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    st.banner("Configuring Queue-1 PIR as 8GB and Queue-2 PIR as 2GB on fly")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': port_shaping_data.queue_num[1], 'pir': shaping_data['pir_8G']}, {'queue': port_shaping_data.queue_num[2], 'pir': shaping_data['pir_2G']}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(shaper_data))
    st.log("Checking QOS scheduling on queue level with pir_8G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    st.log("Checking QOS scheduling on queue level with pir_2G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    st.banner("Detaching the shaper profile from egress port on fly")
    if not shaper.clear_port_shaper(vars.D1, vars.D1T1P3, port_shaping_data.profile_name, remove_shaper=False):
        shaper_debug_info()
        st.report_fail("msg", "Failed to detach queue-shaper: {} from Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    st.banner("Attaching the shaper profile to egress port on fly")
    shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': port_shaping_data.queue_num[1]}, {'queue': port_shaping_data.queue_num[2]}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to attach Queue-Shaper profile: {} to Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    st.log("Checking QOS scheduling on queue level with pir_8G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    st.log("Checking QOS scheduling on queue level with pir_2G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    st.report_pass("msg", "Successfully verified queue level shaper by modifying the shaper rate on fly")


@pytest.mark.qos_shaper
def test_ft_change_port_queue_shaper_rate_on_fly():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsFn015:  Verify the shaper functionality by modifying the port and queue shapers repeatedly on fly.
    '''
    st.banner("Configuring shaper with Port PIR as 8GB, Queue-1 PIR as 6GB and Queue-2 PIR as 4GB")
    port_shaper_data = {'port': vars.D1T1P3, 'meter_type': 'bytes', 'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_8G']}
    queue_shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'pir': shaping_data['pir_6G'], 'meter_type': 'bytes'}, {'queue': 2, 'pir': shaping_data['pir_4G'], 'meter_type': 'bytes'}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 8G")
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(queue_shaper_data))
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "4G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4G")
    st.banner("Modifying Port PIR to 10GB, Queue-1 PIR to 4GB and Queue-2 PIR to 6GB on fly")
    port_shaper_data = {'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_10G']}
    queue_shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'pir': shaping_data['pir_4G']}, {'queue': 2, 'pir': shaping_data['pir_6G']}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to modify port-level shaper PIR rate to 10G")
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to modify queue-level shaper with data: {}".format(queue_shaper_data))
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "4G")
    st.log("Checking QOS scheduling on queue level with pir_6G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_6G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "6G")
    st.banner("Modifying Port PIR to 9GB on fly")
    port_shaper_data = {'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_9G']}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to modify port-level shaper PIR rate to 10G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "4G")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    st.banner("Reset the Queue-1, Queue-2 PIR values on fly")
    params_dict = {port_shaping_data.queue_num[1]: 'pir', port_shaping_data.queue_num[2]: 'pir'}
    if not shaper.reset_queue_shaper_params(vars.D1, port_shaping_data.profile_name, params_dict):
        shaper_debug_info()
        st.report_fail("msg", "Failed to reset the Queue-Level PIR values of shaper profile: {}".format(port_shaping_data.profile_name))
    st.log("Checking QOS scheduling on queue level with pir_4.5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_9G']//2, port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "4.5G")
    st.log("Checking QOS scheduling on queue level with pir_4.5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_9G']//2, port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4.5G")
    st.banner("Reset the Port PIR value on fly")
    if not shaper.reset_port_shaper_params(vars.D1, port_shaping_data.profile_name, 'pir'):
        shaper_debug_info()
        st.report_fail("msg", "Failed to reset the port PIR rate")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    st.banner("Configuring Port PIR as 8GB, Queue-1 PIR as 6GB and Queue-2 PIR as 4GB on fly")
    port_shaper_data = {'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_8G']}
    queue_shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'pir': shaping_data['pir_6G']}, {'queue': 2, 'pir': shaping_data['pir_4G']}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 8G")
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(queue_shaper_data))
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "4G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4G")
    st.banner("Detaching the shaper profile from egress port on fly")
    if not shaper.clear_port_shaper(vars.D1, vars.D1T1P3, port_shaping_data.profile_name, remove_shaper=False):
        shaper_debug_info()
        st.report_fail("msg", "Failed to detach queue-shaper: {} from Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    st.banner("Attaching the shaper profile to the egress port on fly")
    port_shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name}
    queue_shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': port_shaping_data.queue_num[1]}, {'queue': port_shaping_data.queue_num[2]}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to attach Shaper profile: {} to Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to attach Shaper profile: {} to Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "4G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4G")
    st.report_pass("msg", "Successfully verified shaper functionality by modifying the port and queue shapers repeatedly on fly")
    

@pytest.mark.qos_shaper
def test_ft_change_port_queue_shaper_rate_all_params_on_fly():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsFn016:  Verify the shaper functionality by modifying the port pir and queue cir, pir repeatedly on fly.
    '''
    st.banner("Configuring shaper with Port PIR as 9GB, Queue-1 CIR, PIR as 6GB, 7GB and Queue-2 CIR, PIR as 3GB, 9GB")
    port_shaper_data = {'port': vars.D1T1P3, 'meter_type': 'bytes', 'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_9G']}
    queue_shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'cir': shaping_data['pir_6G'], 'pir': shaping_data['pir_7G'], 'meter_type': 'bytes'}, {'queue': 2, 'cir': shaping_data['pir_3G'], 'pir': shaping_data['pir_9G'], 'meter_type': 'bytes'}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 9G")
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(queue_shaper_data))
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scheduling on queue level with pir_6G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_6G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "6G")
    st.log("Checking QOS scheduling on queue level with pir_3G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_3G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "3G")
    st.banner("Reset the Queue-1, Queue-2 CIR values on fly")
    params_dict = {port_shaping_data.queue_num[1]: 'cir', port_shaping_data.queue_num[2]: 'cir'}
    if not shaper.reset_queue_shaper_params(vars.D1, port_shaping_data.profile_name, params_dict):
        shaper_debug_info()
        st.report_fail("msg", "Failed to reset the Queue-Level CIR values of shaper profile: {}".format(port_shaping_data.profile_name))
    st.log("Checking QOS scheduling on queue level with pir_4.5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_9G']//2, port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "4.5G")
    st.log("Checking QOS scheduling on queue level with pir_4.5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_9G']//2, port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4.5G")
    st.banner("Modifying the CIR of Queue-1 to 6GB, Queue-2 to 4GB")
    queue_shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'cir': shaping_data['pir_6G']}, {'queue': 2, 'cir': shaping_data['pir_4G']}]}
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(queue_shaper_data))
    st.banner("Reset the Queue-1, Queue-2 PIR values on fly")
    params_dict = {port_shaping_data.queue_num[1]: 'pir', port_shaping_data.queue_num[2]: 'pir'}
    if not shaper.reset_queue_shaper_params(vars.D1, port_shaping_data.profile_name, params_dict):
        shaper_debug_info()
        st.report_fail("msg", "Failed to reset the Queue-Level PIR values of shaper profile: {}".format(port_shaping_data.profile_name))
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4G")
    st.banner("Reset the Port PIR value on fly")
    if not shaper.reset_port_shaper_params(vars.D1, port_shaping_data.profile_name, 'pir'):
        shaper_debug_info()
        st.report_fail("msg", "Failed to reset the port PIR rate")
    st.log("Checking QOS scheduling on queue level with pir_6G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_6G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4G")
    st.banner("Modifying the Port-level PIR to 7GB")
    port_shaper_data = {'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_7G']}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 7G")
    st.log("Checking QOS scheduling on queue level with pir_3.5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_7G']//2, port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "3.5G")
    st.log("Checking QOS scheduling on queue level with pir_3.5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_7G']//2, port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "3.5G")
    st.banner("Detaching the shaper profile from egress port on fly")
    if not shaper.clear_port_shaper(vars.D1, vars.D1T1P3, port_shaping_data.profile_name, remove_shaper=False):
        shaper_debug_info()
        st.report_fail("msg", "Failed to detach queue-shaper: {} from Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    st.banner("Attaching the shaper profile to the egress port on fly")
    port_shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name}
    queue_shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': port_shaping_data.queue_num[1]}, {'queue': port_shaping_data.queue_num[2]}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to attach Shaper profile: {} to Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to attach Shaper profile: {} to Port: {}".format(port_shaping_data.profile_name, vars.D1T1P3))
    st.log("Checking QOS scheduling on queue level with pir_3.5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_7G']//2, port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "3.5G")
    st.log("Checking QOS scheduling on queue level with pir_3.5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_7G']//2, port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "3.5G")
    st.report_pass("msg", "Successfully Verified the shaper functionality by modifying the port pir and queue cir, pir repeatedly on fly")


@pytest.mark.qos_shaper
def test_nt_port_shaper_shut_noshut():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt002: Verify the port level shaper functionality after shutdown-noshutdown operation repeatedly on shaper applied port continuously on fly.
    '''
    st.banner("Configuring Port PIR as 6GB")
    shaper_data = {'port': vars.D1T1P3, 'pir': shaping_data['pir_6G'], 'meter_type': 'bytes', 'policy_name': port_shaping_data.profile_name}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data):
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 6G")
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1']], enable_arp=0)
    st.log("Checking QOS shaper on interface level with pir_6G")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_6G']):
        shaper_debug_info()
        st.report_fail("port_shaping_verify", "failed")
    st.banner("Performing egress port shutdown-noshutdown in fly")
    for _ in range(3):
        if not interface_operation(vars.D1, vars.D1T1P3, "shutdown"):
            st.report_fail('interface_admin_shut_down_fail', vars.D1T1P3)
        if not interface_operation(vars.D1, vars.D1T1P3, "startup"):
            st.report_fail('interface_admin_startup_fail', vars.D1T1P3)
    poll_for_interface_status(vars.D1, vars.D1T1P3, property='oper', value='up', iteration=2)
    st.wait(5)
    st.log("Checking QOS shaper on interface level with pir_6G after egress port shutdown-noshutdown")
    if not qos_shaping_verify_clmib_rate_pps(vars.D1T1P3, shaping_data['pir_6G']):
        shaper_debug_info()
        st.report_fail("port_shaping_verify", "failed")
    st.report_pass("msg", "Successfully verified Port shaper with port shutdown-noshutdown")


@pytest.mark.qos_shaper
def test_nt_queue_shaper_shut_noshut():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt003: Verify the queue level shaper functionality after shutdown-noshutdown operation repeatedly on shaper applied port continuously on fly.
    '''
    st.banner("Configuring Queue-1 PIR as 8GB and Queue-2 PIR as 2GB")
    shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': port_shaping_data.queue_num[1], 'pir': shaping_data['pir_8G'], 'meter_type': 'bytes'}, {'queue': port_shaping_data.queue_num[2], 'pir': shaping_data['pir_2G'], 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(shaper_data))
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                          port_shaping_data.streams['ingress_port_2']], enable_arp=0)
    st.log("Checking QOS scheduling on queue level with pir_8G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    st.log("Checking QOS scheduling on queue level with pir_2G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    st.banner("Performing egress port shutdown-noshutdown in fly")
    for _ in range(3):
        if not interface_operation(vars.D1, vars.D1T1P3, "shutdown"):
            st.report_fail('interface_admin_shut_down_fail', vars.D1T1P3)
        if not interface_operation(vars.D1, vars.D1T1P3, "startup"):
            st.report_fail('interface_admin_startup_fail', vars.D1T1P3)
    poll_for_interface_status(vars.D1, vars.D1T1P3, property='oper', value='up', iteration=2)
    st.wait(5)
    mac_learning()
    st.log("Checking QOS scheduling on queue level with pir_8G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_8G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "8G")
    st.log("Checking QOS scheduling on queue level with pir_2G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_2G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "2G")
    st.report_pass("msg", "Successfully verified Queue shaper with port shutdown-noshutdown")
    

@pytest.mark.qos_shaper
def test_nt_port_queue_shaper_shut_noshut():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt004: Verify the port-queue combination shaper functionality after shutdown-noshutdown operation repeatedly on shaper applied port continuously on fly.
    '''
    st.banner("Configuring shaper with Port PIR as 9GB, Queue-1 PIR as 6GB and Queue-2 PIR as 4GB")
    port_shaper_data = {'port': vars.D1T1P3, 'meter_type': 'bytes', 'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_9G']}
    queue_shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'pir': shaping_data['pir_6G'], 'meter_type': 'bytes'}, {'queue': 2, 'pir': shaping_data['pir_4G'], 'meter_type': 'bytes'}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 9G")
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(queue_shaper_data))
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4G")
    for _ in range(3):
        if not interface_operation(vars.D1, vars.D1T1P3, "shutdown"):
            st.report_fail('interface_admin_shut_down_fail', vars.D1T1P3)
        if not interface_operation(vars.D1, vars.D1T1P3, "startup"):
            st.report_fail('interface_admin_startup_fail', vars.D1T1P3)
    poll_for_interface_status(vars.D1, vars.D1T1P3, property='oper', value='up', iteration=2)
    st.wait(5)
    mac_learning()
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1 after port shutdown-noshutdown")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_4G on Queue: 2 after port shutdown-noshutdown")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_4G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "4G")
    st.report_pass("msg", "Successfully verified Port-Queue combination shaper with port shutdown-noshutdown")


@pytest.mark.qos_shaper
def test_ft_apply_shaper_multilple_ports():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsFn017:  Verify the shaper functionality can be attached to more than one interface.
    '''
    st.banner("Configuring shaper with Port PIR as 9GB, Queue-1 CIR, PIR as 6GB, 7GB and Queue-2 CIR, PIR as 3GB, 9GB")
    port_shaper_data = {'port': [vars.D1T1P4, vars.D1T1P3], 'meter_type': 'bytes', 'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_9G']}
    queue_shaper_data = {'port': [vars.D1T1P4, vars.D1T1P3], 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'cir': shaping_data['pir_6G'], 'pir': shaping_data['pir_7G'], 'meter_type': 'bytes'}, {'queue': 2, 'cir': shaping_data['pir_3G'], 'pir': shaping_data['pir_9G'], 'meter_type': 'bytes'}]}
    if not shaper.apply_port_shaping_config(vars.D1, port_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure port-level shaper PIR rate as 9G")
    if not shaper.apply_queue_shaping_config(vars.D1, queue_shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(queue_shaper_data))
    mac_learning()
    port_shaping_data.tg.tg_traffic_control(action='run', stream_handle=[port_shaping_data.streams['ingress_port_1'],
                                                                         port_shaping_data.streams['ingress_port_2']])
    st.log("Checking QOS scheduling on queue level with pir_6G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_6G'], port_shaping_data.queue_num[1]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "6G")
    st.log("Checking QOS scheduling on queue level with pir_3G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_3G'], port_shaping_data.queue_num[2]):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "3G")
    if not config_mac(vars.D1, port_shaping_data.mac_egress, port_shaping_data.vlan, vars.D1T1P4):
        st.report_fail("msg", "Faied to configure static MAC: {} on port: {}".format(port_shaping_data.mac_egress, vars.D1T1P4))
    st.log("Checking QOS scheduling on queue level with pir_6G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_6G'], port_shaping_data.queue_num[1], egress_port=vars.D1T1P4):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "6G")
    st.log("Checking QOS scheduling on queue level with pir_3G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_3G'], port_shaping_data.queue_num[2], egress_port=vars.D1T1P4):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "3G")
    st.banner("Detaching the shaper profile from egress port on fly")
    if not shaper.clear_port_shaper(vars.D1, vars.D1T1P4, port_shaping_data.profile_name, remove_shaper=False):
        shaper_debug_info()
        st.report_fail("msg", "Failed to detach queue-shaper: {} from Port: {}".format(port_shaping_data.profile_name, vars.D1T1P4))
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 1")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[1], egress_port=vars.D1T1P4):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-1", "5G")
    st.log("Checking QOS scheduling on queue level with pir_5G on Queue: 2")
    if not qos_shaping_verify_uc_per_q_rate_pps(shaping_data['pir_5G'], port_shaping_data.queue_num[2], egress_port=vars.D1T1P4):
        shaper_debug_info()
        st.report_fail("traffic_transmitted_on_the_queue", "not", "queue-2", "5G")
    st.report_pass("msg", "Successfully verified the shaper functionality can be attached to more than one interface")


@pytest.mark.qos_shaper
def test_nt_apply_invalid_queue_shaper_to_interface():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt005: Verify that policy with queue greater than 7 should be rejected while trying to attach to physical interface.
    '''
    st.banner("Configuring PIR as 8GB for queue greater than 7")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 9, 'pir': shaping_data['pir_6G'], 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper with data: {}".format(shaper_data))
    st.banner("Applying the shaper to physical interface")
    shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 9}]}
    if shaper.apply_queue_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Successfully attached the queue shaper with queue-9 to physical interface")
    st.report_pass("msg", "Successfully verified that policy with queue greater than 7 is rejected while trying to attach to physical interface")


@pytest.mark.qos_shaper
def test_nt_port_pir_greater_than_speed():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt006: Verify that port pir rate can't be configurable greater than port speed.
    '''
    st.banner("Configuring port PIR greater than port speed")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_10G']+125, 'meter_type': 'bytes', 'port': vars.D1T1P3}
    if shaper.apply_port_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Successfully configured port-level shaper with rate greater than port speed")
    st.report_pass("msg", "Successfully verified that port PIR rate can't be configurable greater than port speed")


@pytest.mark.qos_shaper
def test_nt_queue_pir_greater_than_speed():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt007: Verify that queue pir rate can't be configurable greater than port speed.
    '''
    st.banner("Configuring Queue PIR greater than port speed")
    shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'meter_type': 'bytes', 'pir': shaping_data['pir_10G']}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure the queue PIR as {}".format(shaping_data['pir_10G']))
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'meter_type': 'bytes', 'pir': shaping_data['pir_10G']+125}]}
    if shaper.apply_queue_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Successfully configured queue-level shaper with rate greater than port speed")
    st.report_pass("msg", "Successfully verified that queue PIR rate can't be configurable greater than port speed")


@pytest.mark.qos_shaper
def test_nt_queue_cir_gt_eq_pir():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt008: Verify that queue cir rate can't be configurable greater than or equal to it's PIR rate.
    '''
    st.banner("Configuring Queue level PIR as 7G")
    shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'meter_type': 'bytes', 'pir': shaping_data['pir_7G']}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Filed to configure queue-level shaper for queue-1 with PIR as 7G")
    st.banner("Configuring Queue CIR as equal to it's PIR")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'cir': shaping_data['pir_7G']}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Failed to configure queue-level shaper CIR value equal to it's PIR")
    st.banner("Configuring Queue CIR as greater than it's PIR")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'shaper_data': [{'queue': 1, 'cir': shaping_data['pir_7G']+125}]}
    if shaper.apply_queue_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Allowed to configure queue-level shaper CIR value greater than it's PIR")
    st.report_pass("msg", "Successfully verified that queue cir rate can't be configurable greater than or equal to it's pir rate")


@pytest.mark.qos_shaper
def test_nt_attach_policy_invalid_interface():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt009: Verify that policy can't be attached to invalid interface.
    '''
    st.banner("Configuring port-level shaper")
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_7G'], 'meter_type': 'bytes'}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Filed to configure port-level shaper with PIR as 7G")
    ##Decide invalid interface
    invalid_interface = 'Loopback1'
    shaper_data = {'policy_name': port_shaping_data.profile_name, 'port': invalid_interface}
    if shaper.apply_port_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Successfully attached shaper profile to invalid interface")
    st.report_pass("msg", "Successfully verified that policy can't be attached to invalid interface")


@pytest.mark.qos_shaper
def test_nt_attach_invalid_shaper():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt011: Verify that invalid policy can't be attached to interface.
    '''
    letters = string.ascii_lowercase
    policy_name = ''.join(random.choice(letters) for i in range(32))
    shaper_data = {'port': vars.D1T1P3, 'policy_name': policy_name}
    if shaper.apply_port_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Allowed to attach invalid shaper profile to egress port")
    st.report_pass("msg", "Successfully verified that invalid policy can't be attached to interface")


@pytest.mark.qos_shaper
def test_nt_delete_active_shaper_profile():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt013: Verify that active shaper profile can't be deleted.
    '''
    st.banner("Configuring port level shaper with PIR as 7G")
    shaper_data = {'port': vars.D1T1P3, 'policy_name': port_shaping_data.profile_name, 'pir': shaping_data['pir_7G'], 'meter_type': 'bytes'}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data):
        shaper_debug_info()
        st.report_fail("msg", "Filed to configure port-level shaper profile with PIR as 7G")
    st.banner("Trying to delete active shaper profile")
    if shaper.clear_port_shaper(vars.D1, shaper_data=port_shaping_data.profile_name, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Allowed to delete active shaper")
    st.report_pass("msg", "Successfully Verified that active shaper profile can't be deleted")


@pytest.mark.qos_shaper
def test_nt_policy_name_string_max():
    '''
    Author: Jagadish Chatrasi <jagadish.chatrasi@broadcom.com>
    FtOpQosPrPsNt010: Verify that policy name can't be more than 32 characters.
    '''
    st.banner("Configuring policy with string length as 32")
    letters = string.ascii_lowercase
    valid_policy_name = ''.join(random.choice(letters) for i in range(32))
    invalid_policy_name = ''.join(random.choice(letters) for i in range(33))
    shaper_data = {'policy_name': valid_policy_name, 'pir': shaping_data['pir_7G'], 'meter_type': 'bytes'}
    if not shaper.apply_port_shaping_config(vars.D1, shaper_data, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Filed to configure shaper profile with 32 characters")
    st.banner("Configuring policy with string length as 33(more than allowed)")
    if shaper.config_invalid_shaper(vars.D1, invalid_policy_name, skip_error=True):
        shaper_debug_info()
        st.report_fail("msg", "Allowed to configure shaper profile with more than allowed characters")
    st.report_pass("msg", "Successfully verified that policy name can't be more than 32 characters")
