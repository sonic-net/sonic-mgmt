import pytest
from spytest import st, tgapi, SpyTestDict

from apis.system.interface import interface_status_show, clear_interface_counters, show_interface_counters_all
import apis.system.switch_configuration as sconf_obj
from apis.switching.vlan import create_vlan_and_add_members, clear_vlan_configuration
from apis.switching.mac import config_mac_agetime, get_mac_agetime, get_mac
from apis.qos.qos_shaper import apply_queue_shcheduling_config, clear_port_shaper
import apis.common.asic_bcm as asicapi

from utilities.common import filter_and_select, random_vlan_list
from utilities.parallel import exec_all, ensure_no_exception

@pytest.fixture(scope="module", autouse=True)
def qos_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = dict()
    vars = st.ensure_min_topology("D1D2:1", "D1T1:2", "D2T1:2")
    intf_show = interface_status_show(vars.D1, interfaces=[vars.D1T1P1, vars.D1D2P1])
    port_speed_info = dict()
    for port in [vars.D1T1P1, vars.D1D2P1]:
        filter_data = filter_and_select(intf_show, ['speed'], {'interface': port})
        if filter_data and 'speed' in filter_data[0]:
            port_speed_info[port] = int(filter_data[0]['speed'].replace('G', '000'))
    if port_speed_info[vars.D1D2P1] != port_speed_info[vars.D1T1P1]:
        st.debug("The TG connected port speed: {}".format(port_speed_info[vars.D1T1P1]))
        st.debug("The DUT interconnected port speed: {}".format(port_speed_info[vars.D1D2P1]))
        st.report_unsupported("msg", "The TG connected port and the DUT interconnected port speeds are not equal")
    scheduling_vars()
    scheduling_data.pmap_details = asicapi.get_interface_pmap_details(vars.D1, interface_name=[vars.D1D2P1])
    if not scheduling_data.pmap_details:
        st.debug("PMAP details are: {}".format(scheduling_data.pmap_details))
        st.report_fail('no_data_found')
    scheduling_module_config(config='yes')

    st.debug("Getting TG handlers")
    tg1, scheduling_data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, scheduling_data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    tg3, scheduling_data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    tg4, scheduling_data.tg_ph_4 = tgapi.get_handle_byname("T1D2P2")
    scheduling_data.tg = tg1; st.unused(tg2, tg3, tg4)

    st.debug("Reset and clear statistics of TG ports")
    scheduling_data.tg.tg_traffic_control(action='reset',port_handle=[scheduling_data.tg_ph_1, scheduling_data.tg_ph_2, scheduling_data.tg_ph_3,scheduling_data.tg_ph_4])
    scheduling_data.tg.tg_traffic_control(action='clear_stats',port_handle=[scheduling_data.tg_ph_1, scheduling_data.tg_ph_2, scheduling_data.tg_ph_3,scheduling_data.tg_ph_4])

    st.debug("Creating TG streams")
    scheduling_data.streams = {}
    stream = scheduling_data.tg.tg_traffic_config(port_handle=scheduling_data.tg_ph_3, mode='create', length_mode='fixed',
                                           frame_size=64, pkts_per_burst=10, l2_encap='ethernet_ii_vlan',
                                           transmit_mode='single_burst',
                                           vlan_id=scheduling_data.vlan, mac_src=scheduling_data.mac_egress_1,
                                           mac_dst='00:0a:12:00:00:01',
                                           vlan="enable")
    scheduling_data.streams['vlan_tagged_egress_port1'] = stream['stream_id']

    stream = scheduling_data.tg.tg_traffic_config(port_handle=scheduling_data.tg_ph_4, mode='create', length_mode='fixed',
                                           frame_size=64, pkts_per_burst=10, l2_encap='ethernet_ii_vlan',
                                           transmit_mode='single_burst',
                                           vlan_id=scheduling_data.vlan, mac_src=scheduling_data.mac_egress_2,
                                           mac_dst='00:0a:12:00:00:02',
                                           vlan="enable")
    scheduling_data.streams['vlan_tagged_egress_port2'] = stream['stream_id']

    stream = scheduling_data.tg.tg_traffic_config(port_handle=scheduling_data.tg_ph_1, mode='create', transmit_mode='continuous',
                                           length_mode='fixed', rate_percent=100, l2_encap='ethernet_ii_vlan', frame_size=1024,
                                           vlan_id=scheduling_data.vlan, vlan="enable", vlan_user_priority=scheduling_data.dwrr_queue1,
                                           mac_src="00:00:00:00:00:11", mac_dst=scheduling_data.mac_egress_1)
    scheduling_data.streams['scheduling_port_dwrr_ingress1'] = stream['stream_id']

    stream = scheduling_data.tg.tg_traffic_config(port_handle=scheduling_data.tg_ph_2, mode='create', transmit_mode='continuous',
                                           length_mode='fixed', rate_percent=100, l2_encap='ethernet_ii_vlan', frame_size=1024,
                                           vlan_id=scheduling_data.vlan, vlan="enable", vlan_user_priority=scheduling_data.dwrr_queue2,
                                           mac_src="00:00:00:00:00:22", mac_dst=scheduling_data.mac_egress_2)
    scheduling_data.streams['scheduling_port_dwrr_ingress2'] = stream['stream_id']

    yield
    st.debug('Module config Cleanup')
    scheduling_module_config(config='no')


@pytest.fixture(scope="function", autouse=True)
def qos_scheduling_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    # add things at the end of this module"


def scheduling_vars():
    global scheduling_data
    scheduling_data = SpyTestDict()
    scheduling_data.ageout_time = 1000
    scheduling_data.vlan = random_vlan_list()[0]
    scheduling_data.rate_tolerance = 3.0
    scheduling_data.mac_egress_1 = "00:00:00:00:00:33"
    scheduling_data.mac_egress_2 = "00:00:00:00:00:44"
    scheduling_data.weight_1 = 40
    scheduling_data.weight_2 = 50
    scheduling_data.dwrr_queue1 = 3
    scheduling_data.dwrr_queue2 = 4
    scheduling_data.strict_queue = 1
    scheduling_data.policy_name = 'qos_scheduler'
    scheduling_data.get_percent = lambda weight: int((int(weight)*100/(scheduling_data.weight_1+scheduling_data.weight_2)))
    scheduling_data.json_content = {'port': vars.D1D2P1, 'policy_name': scheduling_data.policy_name, 'scheduler_data': [{'queue': scheduling_data.strict_queue, 'type': 'strict'}, {'queue': scheduling_data.dwrr_queue1, 'type': 'dwrr', 'weight': scheduling_data.weight_1}, {'queue': scheduling_data.dwrr_queue2, 'type': 'dwrr', 'weight': scheduling_data.weight_2}]}

def get_debug_info():
    exec_all(True, [[sconf_obj.get_running_config, vars.D1], [sconf_obj.get_running_config, vars.D2]])
    exec_all(True, [[get_mac, vars.D1], [get_mac, vars.D2]])
    exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])

def scheduling_module_config(config='yes'):
    if config == 'yes':
        st.debug("Configuring MAC age out time")
        [output, exceptions] = exec_all(True, [[config_mac_agetime, vars.D1, scheduling_data.ageout_time], [config_mac_agetime, vars.D2, scheduling_data.ageout_time]])
        ensure_no_exception(exceptions)
        if not all(output):
            st.report_fail("mac_aging_time_failed_config")
        st.debug("Verifying MAC age out time")
        [output, exceptions] = exec_all(True, [[get_mac_agetime, vars.D1], [get_mac_agetime, vars.D2]])
        ensure_no_exception(exceptions)
        if not ((int(output[0]) == scheduling_data.ageout_time) and (int(output[1]) == scheduling_data.ageout_time)):
            st.report_fail("msg", "MAC age out time is not configured as: {}".format(scheduling_data.ageout_time))
        st.debug("Create a vlan and add ports as tagged members to it")
        if not create_vlan_and_add_members([{"dut": [vars.D1], "vlan_id": scheduling_data.vlan,
                                             "tagged": [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1]}, 
                                            {"dut": [vars.D2], "vlan_id": scheduling_data.vlan,
                                             "tagged": [vars.D2T1P1, vars.D2T1P2, vars.D2D1P1]}]):
            st.report_fail("msg", "Failed to add port as tagged members of VLAN: {}".format(scheduling_data.vlan))
    else:
        # clearing scheduling and vlan config
        clear_port_shaper(vars.D1, port=vars.D1D2P1, shaper_data=scheduling_data.policy_name, qos_clear=True)
        clear_vlan_configuration([vars.D1, vars.D2], thread=True)
        scheduling_data.tg.tg_traffic_control(action='stop', stream_handle=scheduling_data.streams.values())


def mac_learning():
    st.debug("Sending traffic from egress ports to learn the MAC in FDB table")
    scheduling_data.tg.tg_traffic_control(action='run', stream_handle=[scheduling_data.streams['vlan_tagged_egress_port1'], scheduling_data.streams['vlan_tagged_egress_port2']], enable_arp=0)
    st.wait(2, "Sending traffic for 2 seconds")
    st.debug("Verifying FDB table")
    output = get_mac(vars.D1)
    for mac_address in [scheduling_data.mac_egress_1, scheduling_data.mac_egress_2]:
        entries = filter_and_select(output, None, {"macaddress": mac_address})
        if not entries:
            st.report_fail("mac_address_verification_fail")


def sched_verify_queue_rate_ratio_dwrr(q_priority_1, percent_1, q_priority_2, percent_2):
    num_of_iterations = 5
    bcm_ce = scheduling_data.pmap_details[vars.D1D2P1]
    try:
        for i in range(0, num_of_iterations):
            st.banner("Iteration: {}".format(i))
            asicapi.clear_counters(vars.D1)
            asicapi.bcmcmd_show_c(vars.D1, bcm_ce)
            st.wait(5, "Wait till rate interval")
            output = asicapi.bcmcmd_show_c(vars.D1, bcm_ce)
            cntr_uc_perq_byte_1 = "UC_PERQ_BYTE({}).{}".format(q_priority_1, bcm_ce)
            cntr_uc_perq_byte_2 = "UC_PERQ_BYTE({}).{}".format(q_priority_2, bcm_ce)
            st.debug("cntr_uc_perq_byte_1 = {}" . format(cntr_uc_perq_byte_1))
            st.debug("cntr_uc_perq_byte_2 = {}" . format(cntr_uc_perq_byte_2))
            queue_tx_rate_1 = filter_and_select(output, ['time'], {'key': cntr_uc_perq_byte_1})
            queue_tx_rate_2 = filter_and_select(output, ['time'], {'key': cntr_uc_perq_byte_2})
            if not (queue_tx_rate_1 and queue_tx_rate_1[0]['time'] and queue_tx_rate_2 and queue_tx_rate_2[0]['time']):
                st.debug('Actual Queue rate for Queue-{}: {}'.format(q_priority_1, queue_tx_rate_1))
                st.debug('Actual Queue rate for Queue-{}: {}'.format(q_priority_2, queue_tx_rate_2))
                st.debug('Output is: {}'.format(output))
                st.debug("bcm_ce: {}" . format(bcm_ce))
                continue
            queue_tx_rate_1 = int(queue_tx_rate_1[0]['time'].replace(',', '').replace('/s', ''))
            queue_tx_rate_2 = int(queue_tx_rate_2[0]['time'].replace(',', '').replace('/s', ''))
            st.debug("Queue-{} rate:{}".format(q_priority_1, queue_tx_rate_1))
            st.debug("Queue-{} rate:{}".format(q_priority_2, queue_tx_rate_2))
            result_1 = False
            result_2 = False
            if not(queue_tx_rate_1 and queue_tx_rate_2):
                continue
            actual_ratio_1 = int((queue_tx_rate_1*100)/(queue_tx_rate_1+queue_tx_rate_2))
            actual_ratio_2 = int((queue_tx_rate_2*100)/(queue_tx_rate_1+queue_tx_rate_2))
            diff_rate_1 = abs(actual_ratio_1 - percent_1)
            diff_rate_2 = abs(actual_ratio_2 - percent_2)
            st.debug("The actual ratio of Queue: {} is {}".format(q_priority_1, actual_ratio_1))
            st.debug("The actual ratio of Queue: {} is {}".format(q_priority_2, actual_ratio_2))
            st.debug("The given ratio of Queue: {} is {}".format(q_priority_1, percent_1))
            st.debug("The given ratio of Queue: {} is {}".format(q_priority_2, percent_2))
            st.debug("diff_1:{}".format(diff_rate_1))
            st.debug("diff_2:{}".format(diff_rate_2))
            if diff_rate_1 <= scheduling_data.rate_tolerance:
                result_1 = True
            if diff_rate_2 <= scheduling_data.rate_tolerance:
                result_2 = True
            if result_1 and result_2:
                return True
        return False
    except Exception as e:
        st.error('Exception occurred is: {}'.format(e))
        return False



@pytest.mark.scheduling
def test_ft_qos_scheduling_functionality():
    '''
     Author: Sai Durga <pchvsai.durga@broadcom.com>
	 This test script covers below scenarios

     FtOpSoQsDwrrFn001: Verify that traffic is forwarded based on the ratio calculated with configured weight when scheduling is enabled on egress port when congestion is happened

    Setup:
    =======
    2 TGen(IX1 and IX2)====DUT1-----DUT2=====2 TGen(IX3 and IX4)

    Procedure:
    ============
    1) Create a VLAN 555 in both the devices and include all the TGen and back to back interfaces to the VLAN
    2) Create a DWRR profiles with weights 50 and 40 and apply them on back to back interface on 1st device with queus 5 and 2
    3) Learn the MAC entries of 2 TGen connected ports on DUT2
    4) Start sending traffic from IX1 to IX3 and IX2 to IX4 with VLAN user priority 5 and 2 respectively

    Expected Result:
    ================
    1) Verify that VLAN created and all the ports included in that VLAN
    2) VLAN that strict priority is applied
    3) Verify that FDB table updated with the MAC entries
    4) Verify that traffic is forwarded  based on the ratio calsulated with configured weight

    In this case 55.5% IX1 and 44.5% from IX2

	 FtOpSoQsStPrFn001 : Verify that traffic is forwarded from highest prority queue when strict priority and DWRR is enabled on egress port when congestion is happened

    Setup:
    =======
    2 TGen(IX1 and IX2)====DUT1-----DUT2=====2 TGen(IX3 and IX4)

    Procedure:
    ============
    1) Create a VLAN 555 in both the devices and include all the TGen and back to back interfaces to the VLAN
    2) Create a strict priority profilewith one strict and weight 40(DWRR) and apply them on back to back interface on 1st device with queus 1 and 3 respectively
    3) Learn the MAC entries of 2 TGen connected ports on DUT2
    4) Start sending traffic from IX1 to IX3 and IX2 to IX4 with VLAN user priority 1 and 2 respectively

    Expected Result:
    ================
    1) Verify that VLAN created and all the ports included in that VLAN
    2) VLAN that strict priority is applied
    3) Verify that FDB table updated with the MAC entries
    4) Verify that traffic is forwarded from highest priority queue i.e., from IX1 to IX3 and also verify that IX4 receives very mimimal traffic or 0 traffic from IX2
    '''
    st.debug("Applying and verifying DWRR and strict config reflecting in running config or not")
    if not apply_queue_shcheduling_config(vars.D1, scheduling_data.json_content):
        get_debug_info()
        st.report_fail("msg", "Failed to configure scheduler")
    if not sconf_obj.verify_running_config(vars.D1, "SCHEDULER", "{}@{}".format(scheduling_data.policy_name, scheduling_data.dwrr_queue2), "type", "DWRR"):
        get_debug_info()
        st.report_fail("content_not_found")
    if not sconf_obj.verify_running_config(vars.D1, "SCHEDULER", "{}@{}".format(scheduling_data.policy_name, scheduling_data.strict_queue), "type", "STRICT"):
        get_debug_info()
        st.report_fail("content_not_found")
    mac_learning()
    exceptions = exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.debug("Sending traffic from ingress ports")
    scheduling_data.tg.tg_traffic_control(action='run', stream_handle=[scheduling_data.streams['scheduling_port_dwrr_ingress1'],
                                                                       scheduling_data.streams['scheduling_port_dwrr_ingress2']], enable_arp=0)
    if not sched_verify_queue_rate_ratio_dwrr(scheduling_data.dwrr_queue1, scheduling_data.get_percent(scheduling_data.weight_1), scheduling_data.dwrr_queue2, scheduling_data.get_percent(scheduling_data.weight_2)):
        get_debug_info()
        st.report_fail("msg", "Traffic is not schedules as configured")
    scheduling_data.tg.tg_traffic_control(action='stop', stream_handle=scheduling_data.streams.values())

    st.debug("Checking strict priority functionality")
    scheduling_data.tg.tg_traffic_config(mode='modify', stream_id=scheduling_data.streams['scheduling_port_dwrr_ingress1'], vlan_user_priority=scheduling_data.strict_queue)
    exceptions = exec_all(True, [[clear_interface_counters, vars.D1], [clear_interface_counters, vars.D2]])[1]
    ensure_no_exception(exceptions)
    st.debug("Sending traffic from ingress ports")
    scheduling_data.tg.tg_traffic_control(action='run', stream_handle=[scheduling_data.streams['scheduling_port_dwrr_ingress1'],
                                                                       scheduling_data.streams['scheduling_port_dwrr_ingress2']], enable_arp=0)
    st.wait(5, "Sending traffic for 5 seconds")
    scheduling_data.tg.tg_traffic_control(action='stop', stream_handle=scheduling_data.streams.values())
    st.wait(2, "Waiting to stabilize the interface counters")
    [output,exceptions]= exec_all(True, [[show_interface_counters_all, vars.D1], [show_interface_counters_all, vars.D2]])
    ensure_no_exception(exceptions)
    if not all(output):
        get_debug_info()
        st.report_fail("msg", "Failed to get interface counters")
    dut1_counters, dut2_counters = output
    ingress_rx_cnt = filter_and_select(dut1_counters, ['rx_ok'], {'iface': vars.D1T1P1})
    egress_tx_cnt = filter_and_select(dut2_counters, ['tx_ok'], {'iface': vars.D2T1P1})
    if not (ingress_rx_cnt and egress_tx_cnt):
        get_debug_info()
        st.report_fail("msg", "Failed to get interface counters")
    ingress_rx_cnt = ingress_rx_cnt[0]['rx_ok']
    egress_tx_cnt = egress_tx_cnt[0]['tx_ok']
    if not ((0.99*int(ingress_rx_cnt.replace(',', ''))) <= int(egress_tx_cnt.replace(',', ''))):
        st.debug("Traffic sent: {} and Traffic received: {}".format(ingress_rx_cnt.replace(',', ''),
                                                              egress_tx_cnt.replace(',', '')))
        get_debug_info()
        st.report_fail("msg", "Traffic is not scheduled as per strict priority")
    st.report_pass('test_case_passed')
