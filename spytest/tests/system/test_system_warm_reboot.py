import pytest
import time

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.system.reboot as rb_obj
import apis.system.crm as crm_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.system.basic as basic_obj

data=SpyTestDict()

data.vlan = str(random_vlan_list()[0])
data.threshold_used_type = 'used'
data.threshold_fdb_entry = 'FDB_ENTRY'
data.threshold_exceed = "THRESHOLD_EXCEEDED"
data.threshold_clear = "THRESHOLD_CLEAR"
data.family = "fdb"
data.mode_high = 'high'
data.mode_low = 'low'
data.polling_interval = 1
data.frame_size = 68
data.wait_stream_run = 10
data.wait_for_stats = 10


@pytest.fixture(scope="module", autouse=True)
def system_warm_reboot_module_hooks(request):
    # add things at the start of this module
    # global vars
    # vars = st.get_testbed_vars()
    # st.log("Ensuring minimum topology")
    # vars = st.ensure_min_topology("D1T1:1")
    #mac_src_count=data.mac_addrs_count
    global vars
    vars = st.get_testbed_vars()
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1T1:1")

    global tg_handler
    tg_handler = tgapi.get_handles(vars, [vars.T1D1P1, vars.T1D1P2])

    global tg
    tg = tg_handler["tg"]

    st.log("creating vlan and adding ports into vlan")
    vlan_config()
    st.log("configuring crm parameters for FDB resource")
    crm_fdb_config()
    st.log("verifying configured crm parameters for FDB resource")
    crm_fdb_config_verify()
    st.log("Sending TG traffic to populate fdb entries:")
    tg_stream_config()
    tg.tg_traffic_control(action='run', stream_handle=data.streams['Ixia_1'])
    st.wait(5)
    tg.tg_traffic_control(action='stop', stream_handle=data.streams['Ixia_1'])
    st.log("verifying whether proper logs are generated when crm threshold hits")
    crm_fdb_high_low_threshold_verify()

    yield
    # add things at the end of this module"
    #Below step will clear all CRM config from the device.
    crm_obj.set_crm_clear_config(vars.D1)
    #below step will clear vlan configuration from the device
    vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=False)

@pytest.fixture(scope="function", autouse=True)
def system_warm_reboot_func_hooks(request):
	# add things at the start every test case
	# use 'st.get_func_name(request)' to compare
	# if any thing specific a particular test case

	yield
	# add things at the end every test case
	# use 'st.get_func_name(request)' to compare
	# if any thing specific a particular test case

def report_result(status, msg_id):
    if status:
        st.report_pass(msg_id)
    else:
        st.report_fail(msg_id)

def tg_stream_config():

	st.log('TG configuration')
	tgapi.traffic_action_control(tg_handler, actions=["reset", "clear_stats"])
	st.log("Creating TG streams")
	data.streams = {}
	stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', rate_pps=20000,
								  mac_src='00:00:11:11:00:01', mac_src_mode="increment",
								  mac_src_count=data.mac_addrs_count,
								  transmit_mode="continuous", mac_src_step="00:00:00:00:00:01",
								  mac_dst='00:00:00:00:00:02', l2_encap='ethernet_ii_vlan', vlan_id=data.vlan,
								  vlan="enable")
	data.streams['Ixia_1'] = stream['stream_id']

def vlan_config():
	st.log("creating random vlan")
	if not vlan_obj.create_vlan(vars.D1, data.vlan):
		st.report_fail("vlan_create_fail", data.vlan)
	else:
		st.log("vlan creation is successful")
	st.log("Adding Ixia port connected interface to the vlan with tagging mode")
	if not vlan_obj.add_vlan_member(vars.D1, data.vlan, [vars.D1T1P1,vars.D1T1P2], tagging_mode=True):
		st.report_fail("vlan_tagged_member_fail", [vars.D1T1P1,vars.D1T1P2], data.vlan)
	else:
		st.log("Adding ports in the vlan is successful")

def crm_fdb_config():
    st.log("Configuring polling interval to non-default value")
    crm_obj.set_crm_polling_interval(vars.D1, data.polling_interval)
    st.wait(data.polling_interval)
    (data.used_counter_fdb, data.free_counter_fdb) = crm_obj.crm_get_resources_count(vars.D1, data.family)
    data.total_resources_fdb = data.used_counter_fdb + data.free_counter_fdb
    tx_pkt_2_percent_fdb = data.used_counter_fdb + (2 * data.total_resources_fdb) / 100
    data.mode_high_used_fdb = data.used_counter_fdb + tx_pkt_2_percent_fdb - 5
    data.mode_low_used_fdb = data.used_counter_fdb + 5
    data.mode_high_free_fdb = data.free_counter_fdb - 1
    data.mode_low_free_fdb = data.free_counter_fdb - tx_pkt_2_percent_fdb + 2
    data.mode_high_percentage_fdb = 2
    data.mode_low_percentage_fdb = 1
    data.mac_addrs_count = int(tx_pkt_2_percent_fdb) + int(10)

    st.log("Setting fdb type used:")
    crm_obj.set_crm_polling_interval(vars.D1, data.polling_interval)
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.family, type=data.threshold_used_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.family, mode=data.mode_high,
                                     value=data.mode_high_used_fdb)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.family, mode=data.mode_low,
                                     value=data.mode_low_used_fdb)

def crm_fdb_config_verify():
	st.log("CRM FDB config verification - ft_crm_fdb_warmreboot")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.family, thresholdtype=data.threshold_used_type,
										 highthreshold=data.mode_high_used_fdb,
										 lowthreshold=data.mode_low_used_fdb):
		st.report_fail("threshold_config_fail")
	else:
		st.log("CRM FDB config verified successfully")

def crm_fdb_high_low_threshold_verify():
	st.log("verifying whether CRM threshold high hits - ft_crm_fdb_warmreboot")
	out = crm_obj.threshold_polling(vars.D1, filter_list=[data.threshold_fdb_entry, data.threshold_exceed])
	if not out:
		st.report_fail('threshold_exceeded_fail')
	else:
		st.log("crm threshold fdb high hits successfully")
	st.log(out)
	log_used = out['used']
	st.log('Used count in the log is {}'.format(log_used))
	if not log_used >= int(data.mode_high_used_fdb):
		st.report_fail('threshold_exceeded_fail')
	else:
		st.log("verified that used threshold count is greater than configured threshold value")

	st.log("verifying whether CRM threshold low hits - ft_crm_fdb_warmreboot")
	mac_obj.clear_mac(vars.D1)
	out = crm_obj.threshold_polling(vars.D1, filter_list=[data.threshold_fdb_entry, data.threshold_clear])
	if not out:
		st.report_fail('threshold_clear_fail')
	else:
		st.log("crm threshold fdb low hits successfully")
	st.log(out)
	log_used = out['used']
	st.log('Used count in the log is {}'.format(log_used))
	if not log_used <= int(data.mode_low_used_fdb):
		st.report_fail('threshold_clear_fail')
	else:
		st.log("verified that used threshold count is less than configured threshold value")


def test_ft_netinstall_warm_reboot():
    """
    Author : Pradeep Bathula(pradeep.b@broadcom.com)
    Test function to verify system status after performing netinstall followed by ZTP disable and Warm reboot
    :return:
    """
    st.log("performing warm-reboot")
    st.reboot(vars.D1, 'warm')
    start_time = int(time.time())
    while True:
        current_time = int(time.time())
        if not basic_obj.poll_for_system_status(vars.D1, iteration=1):
            st.reboot(vars.D1)
            st.report_fail("system_not_ready")
        if (current_time-start_time) > 300:
            break
    st.report_pass("test_case_passed")


@pytest.mark.savereboot
def test_ft_system_config_mgmt_verifying_config_with_save_warm_reboot():
    st.log("performing Config save")
    rb_obj.config_save(vars.D1)
    st.log("performing warm-reboot")
    st.reboot(vars.D1, 'warm')
    st.log("verifying crm parameters for FDB resource after warm-reboot")
    crm_fdb_config_verify()
    st.log("Send TG traffic to populate fdb entries after warm-reboot")
    tg.tg_traffic_control(action='run', stream_handle=data.streams['Ixia_1'])
    st.wait(5)
    tg.tg_traffic_control(action='stop', stream_handle=data.streams['Ixia_1'])
    st.log("verifying whether proper logs are generated when crm threshold hits after warm-reboot")
    crm_fdb_high_low_threshold_verify()
    st.report_pass("test_case_passed")

