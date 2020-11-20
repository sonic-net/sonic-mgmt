import pytest
import apis.switching.vlan as vlan_obj
import apis.system.reboot  as rb_obj
import apis.qos.cos as cos_obj
import apis.qos.ecn as ecn_obj
import apis.qos.qos as qos_obj
import apis.qos.acl as acl_obj
import apis.system.crm as crm_obj
import apis.system.switch_configuration as sconf_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
from spytest import st
from spytest.dicts import SpyTestDict
from spytest.utils import random_vlan_list

data=SpyTestDict()
data.vlan = str(random_vlan_list()[0])

@pytest.fixture(scope="module", autouse=True)
def config_mgmt_module_hooks(request):
	# add things at the start of this module
	yield
	# add things at the end of this module"
	#Setting the MTU value to default
	intf_obj.interface_properties_set(vars.D1, data.eth, data.property, data.mtu_default)
	#Below step will clear all CRM config from the device.
	crm_obj.set_crm_clear_config(vars.D1)
	#Below step will clear COS, WRED and ECN config from the device.
	qos_obj.clear_qos_config(vars.D1)
	#Below step will clear all ACL config from the device.
	acl_obj.clear_acl_config(vars.D1)
	st.log("Deleting the vlan-{}".format(data.vlan))
	rv = vlan_obj.clear_vlan_configuration(st.get_dut_names())
	if not rv:
		st.report_fail("vlan_delete_fail", data.vlan)

@pytest.fixture(scope="function", autouse=True)
def config_mgmt_func_hooks(request):
	# add things at the start every test case
	# use 'st.get_func_name(request)' to compare
	# if any thing specific a particular test case
	global vars
	vars = st.get_testbed_vars()
	st.log("Ensuring minimum topology")
	vars = st.ensure_min_topology("D1")
	data.gmin = "100"
	data.gmax = "1000"
	data.rmin = "100"
	data.rmax = "1000"
	data.ymin = "100"
	data.ymax = "1000"
	data.ECN_profile_name = "ECN"
	data.cos_name="COS"
	data.acl_ipv4_table_name = 'acl_table_v4'
	data.acl_ipv6_table_name = 'acl_table_v6'
	data.src_ip = '192.168.11.1'
	data.src_ipv6 = '2001::10'
	data.mask = '24'
	data.mask_ipv6 = '128'
	data.description = 'INGRESS_drop'
	data.acl_rule = 'ipv4_acl_rule'
	data.acl_rule_v6 = 'ipv6_acl_rule'
	data.priority = '55'
	data.type = 'L3'
	data.type_ipv6 = 'L3V6'
	data.packet_action = 'drop'
	data.stage = 'INGRESS'
	data.mode_high = 'high'
	data.mode_low = 'low'
	data.polling_interval = '1'
	data.threshold_percentage_type = 'percentage'
	data.threshold_used_type = 'used'
	data.threshold_free_type = 'free'
	data.ipv4_route_family = "ipv4_route"
	data.ipv6_route_family = "ipv6_route"
	data.fdb_family = "fdb"
	data.ipv4_neighbor_family = "ipv4_neighbor"
	data.ipv6_neighbor_family = "ipv6_neighbor"
	data.acl_group_entry_family = 'acl_group_entry'
	data.acl_group_counter_family = 'acl_group_counter'
	data.ipv6_nexthop_family = 'ipv6_nexthop'
	data.ipv4_nexthop_family = 'ipv4_nexthop'
	data.acl_table_family = "acl_table"
	data.mode_high_percentage = 50
	data.mode_low_percentage = 20
	data.mode_high_used = 1000
	data.mode_low_used = 10
	data.mode_high_free = 1000
	data.mode_low_free = 10
	data.mtu = "9216"
	data.eth = "Ethernet4"
	data.property = "mtu"
	data.mtu_default = "9100"
	yield
	# add things at the end every test case
	# use 'st.get_func_name(request)' to compare
	# if any thing specific a particular test case

def config_ecn():
	ecn_obj.config_ecn(vars.D1, "on", data.ECN_profile_name, gmin=data.gmin, gmax=data.gmin, rmin=data.rmin,
					   rmax=data.rmax, ymin=data.ymin, ymax=data.ymax)

def cos_run_config():
	for queue in range(0,8):
		if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, queue, queue):
			st.log("Queue {} mapping not found".format(queue))
			st.report_fail("queue_map_not_found", queue)

def cos_config():
	cos_obj.config_tc_to_queue_map(vars.D1, data.cos_name,{"0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7"})

def ipv4_acl_config():
	st.log('Creating IPv4 ACL in ACL table:')
	acl_obj.create_acl_table(vars.D1, name=data.acl_ipv4_table_name, type=data.type, description=data.description,stage=data.stage)
	st.log('Adding IPv4 ACL source_ip drop rule in ACL rule table:')
	acl_obj.create_acl_rule(vars.D1, table_name=data.acl_ipv4_table_name, rule_name=data.acl_rule,
							packet_action=data.packet_action, priority=data.priority,
							SRC_IP="{}/{}".format(data.src_ip, data.mask))

def ipv6_acl_config():
	st.log('Creating IPv6 ACL in ACL table:')
	acl_obj.create_acl_table(vars.D1, name=data.acl_ipv6_table_name, type=data.type_ipv6, description=data.description,stage=data.stage)
	st.log('Adding IPv4 ACL source_ip drop rule in ACL rule table:')
	acl_obj.create_acl_rule(vars.D1, table_name=data.acl_ipv6_table_name, rule_name=data.acl_rule_v6,
							packet_action=data.packet_action, priority=data.priority,
							SRC_IPV6="{}/{}".format(data.src_ipv6, data.mask_ipv6))

def ipv4_acl_run_config():
	st.log("Verfiying IPV4 ACL and rule present in running config or not")
	if not acl_obj.verify_acl_table(vars.D1, acl_table=data.acl_ipv4_table_name):
		st.report_fail("Failed to create ACL")
	if not acl_obj.verify_acl_table_rule(vars.D1, acl_table=data.acl_ipv4_table_name, acl_rule=data.acl_rule):
		st.report_fail("failed_to_create_acl_rule")

def ipv6_acl_run_config():
	st.log('Verifying IPv6 ACL and rule present in running config or not')
	if not acl_obj.verify_acl_table(vars.D1, acl_table=data.acl_ipv6_table_name):
		st.report_fail('failed_to_create_acl', data.acl_ipv6_table_name)
	if not acl_obj.verify_acl_table_rule(vars.D1, acl_table=data.acl_ipv6_table_name, acl_rule=data.acl_rule_v6):
		st.report_fail("failed_to_create_acl_rule")

def crm_config():
	st.log("CRM config for ACL table")
	crm_obj.set_crm_polling_interval(vars.D1, data.polling_interval)
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.acl_table_family, type=data.threshold_free_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_table_family, mode=data.mode_high,
								 value=data.mode_high_free)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_table_family, mode=data.mode_low,
								 value=data.mode_low_free)
	st.log("CRM config for IPv4 route family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv4_route_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_route_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_route_family, mode=data.mode_low,
								 value=data.mode_low_percentage)
	st.log("CRM config for IPv6 route family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv6_route_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_route_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_route_family, mode=data.mode_low,
								 value=data.mode_low_percentage)
	st.log("CRM config for fdb")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.fdb_family, type=data.threshold_used_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.fdb_family, mode=data.mode_high,
								 value=data.mode_high_used)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.fdb_family, mode=data.mode_low,
								 value=data.mode_low_used)
	st.log("CRM config for IPv4 neighbor family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv4_neighbor_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_neighbor_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_neighbor_family, mode=data.mode_low,
								 value=data.mode_low_percentage)
	st.log("CRM config for IPv6 neighbor family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv6_neighbor_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_neighbor_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_neighbor_family, mode=data.mode_low,
								 value=data.mode_low_percentage)
	st.log("CRM config for ACL group entry family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.acl_group_entry_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_entry_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_entry_family, mode=data.mode_low,
								 value=data.mode_low_percentage)
	st.log("CRM config for IPv6 nexthop family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv6_nexthop_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_nexthop_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_nexthop_family, mode=data.mode_low,
								 value=data.mode_low_percentage)
	st.log("CRM config for IPv4 nexthop family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv4_nexthop_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_nexthop_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_nexthop_family, mode=data.mode_low,
									 value=data.mode_low_percentage)
	st.log("CRM config for ACL group counter family")
	crm_obj.set_crm_thresholds_type(vars.D1, family=data.acl_group_counter_family, type=data.threshold_percentage_type)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_counter_family, mode=data.mode_high,
								 value=data.mode_high_percentage)
	crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_counter_family, mode=data.mode_low,
								 value=data.mode_low_percentage)

def crm_config_verify():
	st.log("Verifying CRM ACL table config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_table_family, thresholdtype=data.threshold_free_type,
										 highthreshold=data.mode_high_free,
										 lowthreshold=data.mode_low_free):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM IPv4 route family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_route_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM IPv6 route family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_route_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM FDB config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.fdb_family, thresholdtype=data.threshold_used_type,
										 highthreshold=data.mode_high_used,
										 lowthreshold=data.mode_low_used):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM IPv4 neighbor route family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_neighbor_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM IPv6 neighbor route family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_neighbor_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM ACL group entry family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_group_entry_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM IPv6 nexthop family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_nexthop_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM IPv4 nexthop family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_nexthop_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")
	st.log("Verifying CRM ACL group counter family config after save and reload")
	if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_group_counter_family,
										 thresholdtype=data.threshold_percentage_type,
										 highthreshold=data.mode_high_percentage,
										 lowthreshold=data.mode_low_percentage):
		st.report_fail("threshold_config_fail")

@pytest.mark.savereboot
def test_ft_config_mgmt_verifying_config_with_save_reboot():
	st.log("Configuring DUT with supported feature with CLI")
	vlan_obj.delete_all_vlan(vars.D1)
	vlan_obj.verify_vlan_config(vars.D1,data.vlan)
	vlan_obj.create_vlan(vars.D1, data.vlan)
	st.log("Configuring supported QoS features with CLI")
	st.log("Configuring IPV4 ACL with rule")
	ipv4_acl_config()
	st.log("Configuring IPV6 ACL with rule")
	ipv6_acl_config()
	st.log("Configuring COS")
	cos_config()
	st.log("Configuring WRED")
	config_ecn()
	st.log("Configuring CRM")
	crm_config()
	st.log("Configuring MTU on interface")
	intf_obj.interface_properties_set(vars.D1, data.eth, data.property, data.mtu)
	st.log("performing Config save")
	rb_obj.config_save(vars.D1)
	st.log("performing Reboot")
	st.reboot(vars.D1, 'fast')
	st.log("Checking whether config is loaded to running config from config_db after reboot")
	if not vlan_obj.verify_vlan_config(vars.D1, data.vlan):
		st.report_fail("Config_not_loaded_from_config_db_json")
	st.log("Checking for IPV4 ACL config")
	ipv4_acl_run_config()
	st.log("Checking for IPV6 ACL config")
	ipv6_acl_run_config()
	st.log("Checking for COS config")
	cos_run_config()
	st.log("Checking for WRED config")
	if not ecn_obj.show_ecn_config(vars.D1):
		st.report_fail("Config_not_loaded_from_config_db_json")
	st.log("Checking CRM config after save and reload")
	crm_config_verify()
	st.log("Checking the configured MTU value after save and reload")
	if not sconf_obj.verify_running_config(vars.D1, "PORT", data.eth, data.property, data.mtu):
		st.report_fail("fail_to_configure_mtu_on_Device", 1)
	st.log("configuration  is successfully stored to config_db file after save and reboot")
	st.report_pass("test_case_passed")


def test_ft_verifying_file_content():
	"""Author:Sirisha.Gude<sirisha.gude@broadcom.com
	Verify that any broadcom specific config present in /etc/resolv.conf
	TC_ID: FtOpSoSyCmFn007
	"""
	file_path = "/etc/resolv.conf"
	out = basic_obj.download_file_content(vars.D1, file_path, device="dut")
	if "broadcom" in out:
		st.report_fail("domain_names_present", 'resolv.conf')
	st.report_pass("domain_names_not_present", 'resolv.conf')

