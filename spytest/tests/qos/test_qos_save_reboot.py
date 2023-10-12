import pytest
import json
from spytest import st
from spytest import SpyTestDict
import apis.system.reboot as rb_obj
import apis.qos.cos as cos_obj
import tests.qos.wred_ecn_config_json as wred_config
import apis.qos.qos as qos_obj
import apis.qos.acl as acl_obj
import apis.system.switch_configuration as sconf_obj
import utilities.common as utils

try:
    import apis.yang.codegen.messages.qos as umf_qos
except ImportError:
    pass

data = SpyTestDict()
data.cos_name = "COS"
data.acl_ipv4_table_name = 'acl_table_v4'
data.acl_ipv6_table_name = 'acl_table_v6'
data.src_ip = '192.168.11.1'
data.src_ipv6 = '2001::10'
data.mask = '32'
data.mask_ipv6 = '128'
data.description = 'INGRESS_drop'
data.acl_rule = 'RULE_4'
data.acl_rule_v6 = 'RULE_6'
data.priority = '55'
data.type = 'L3'
data.type_ipv6 = 'L3V6'
data.packet_action = 'drop'
data.stage = 'INGRESS'
data.pri = '5'
data.value = '1'
data.pri_replace = '6'
data.val_replace = '2'


@pytest.fixture(scope="module", autouse=True)
def qos_save_reboot_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = dict()
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1T1:1")

    st.log("Configuring supported QoS features")
    wred_data = wred_config.init_vars(vars)
    st.log('Creating WRED and ECN table')
    utils.exec_all(True, [utils.ExecAllFunc(apply_wred_ecn_config, vars.D1, wred_data['wred_ecn_json_config'])])
    st.log("Checking for wred config before save and reboot")
    wred_verify()
    st.log("checking for ecn config before save and reboot")
    ecn_verify()
    st.log("Configuring IPV4 ACL with rule")
    ipv4_acl_config()
    st.log("Configuring IPV6 ACL with rule")
    ipv6_acl_config()
    st.log("Checking for IPV4 ACL config before save and reboot")
    ipv4_acl_verify()
    st.log("Checking for IPV6 ACL config before save and reboot")
    ipv6_acl_verify()
    st.log("Configuring COS")
    cos_config()
    st.log("Checking for COS config before save and reboot")
    cos_config_verify()

    yield
    # add things at the end of this module"
    # Below step will clear COS, WRED and ECN config from the device.
    qos_obj.clear_qos_config(vars.D1)
    # Below step will clear all ACL config from the device.
    acl_obj.clear_acl_config(vars.D1)


@pytest.fixture(scope="function", autouse=True)
def qos_save_reboot_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case

    yield
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case


def cos_config():
    st.log("configuring cos config")
    cos_obj.config_tc_to_queue_map(vars.D1, data.cos_name, {"0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7"})


def cos_config_verify():
    st.log("verifying cos config is present in running-config - FtFpSoQoSCoSCfg001")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "0", "0"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '0' is successful")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "1", "1"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '1' is successful")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "2", "2"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '2' is successful")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "3", "3"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '3' is successful")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "4", "4"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '4' is successful")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "5", "5"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '5' is successful")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "6", "6"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '6' is successful")
    if not sconf_obj.verify_running_config(vars.D1, "TC_TO_QUEUE_MAP", data.cos_name, "7", "7"):
        st.report_fail("content_not_found")
    else:
        st.log("configuring cos queue mapping '7' is successful")


def ipv4_acl_config():
    st.log('Creating IPv4 ACL in ACL table:')
    acl_obj.create_acl_table(vars.D1, name=data.acl_ipv4_table_name, type=data.type, description=data.description, stage=data.stage, ports=[vars.D1T1P1])
    st.log('Adding IPv4 ACL source_ip drop rule in ACL rule table:')
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_ipv4_table_name, acl_type="ip", rule_name=data.acl_rule,
                            packet_action=data.packet_action, priority=data.priority,
                            SRC_IP="{}/{}".format(data.src_ip, data.mask))


def ipv6_acl_config():
    st.log('Creating IPv6 ACL in ACL table:')
    acl_obj.create_acl_table(vars.D1, name=data.acl_ipv6_table_name, type=data.type_ipv6, description=data.description, stage=data.stage, ports=[vars.D1T1P1])
    st.log('Adding IPv4 ACL source_ip drop rule in ACL rule table:')
    acl_obj.create_acl_rule(vars.D1, table_name=data.acl_ipv6_table_name, acl_type="ipv6", rule_name=data.acl_rule_v6,
                            packet_action=data.packet_action, priority=data.priority,
                            SRC_IPV6="{}/{}".format(data.src_ipv6, data.mask_ipv6))


def ipv4_acl_verify():
    st.log("Verfiying IPV4 ACL and rule present in running config - FtOpSoQosAclCmFn001, ft_acl_configvalues_save_reload")
    if not acl_obj.verify_acl_table(vars.D1, acl_table=data.acl_ipv4_table_name):
        st.report_fail("Failed to create ACL")
    else:
        st.log("IPv4 ACL table {} creation successful".format(data.acl_ipv4_table_name))
    if not acl_obj.verify_acl_table_rule(vars.D1, acl_table=data.acl_ipv4_table_name, acl_rule=data.acl_rule):
        st.report_fail("failed_to_create_acl_rule")
    else:
        st.log("IPv4 ACL table rule {} configuration successful".format(data.acl_rule))


def ipv6_acl_verify():
    st.log('Verifying IPv6 ACL and rule present in running config - FtOpSoQosAclCmFn002')
    if not acl_obj.verify_acl_table(vars.D1, acl_table=data.acl_ipv6_table_name):
        st.report_fail('failed_to_create_acl', data.acl_ipv6_table_name)
    else:
        st.log("Ipv6 ACl table {} creation successful".format(data.acl_ipv6_table_name))
    if not acl_obj.verify_acl_table_rule(vars.D1, acl_table=data.acl_ipv6_table_name, acl_rule=data.acl_rule_v6):
        st.report_fail("failed_to_create_acl_rule")
    else:
        st.log("IPv6 ACL table rule {} configuration successful".format(data.acl_rule_v6))


def apply_wred_ecn_config(dut, config):
    st.log("loading wred and ecn config from wred_ecn_config_json.py")
    json_config = json.dumps(config)
    json.loads(json_config)
    st.apply_json2(dut, json_config)


def wred_verify():
    st.log("verifying wred config in running config - FtOpSoQosWredCfg001")
    if not sconf_obj.verify_running_config(vars.D1, "WRED_PROFILE", "WRED", "green_max_threshold", "900000",):
        st.report_fail("wred_config_not_updated_in_config_db")
    else:
        st.log("wred configuration successful")


def ecn_verify():
    st.log("verifying ecn config in running config - ft_ecn_config_db_to_running_config_after_save_and_reload, ft_ecn_config_to_config_db_json_after_save_and_reboot, FtOpSoQosEcnCfg001")
    if not sconf_obj.verify_running_config(vars.D1, "WRED_PROFILE", "WRED", "ecn", "ecn_all"):
        st.report_fail("ecn_config_not_updated_in_config_db")
    else:
        st.log("ecn configuration successful")


def pfc_PriorityQueue_Map(dut, obj_name, pfc_priority=None, queue=None, operation=None, mode='config'):
    qos_obj = umf_qos.Qos()
    pfcq_obj = umf_qos.PfcPriorityQueueMap(Name=obj_name, Qos=qos_obj)
    if mode == 'config':
        pfcq_obj.configure(dut)
        pfcq_dict = {}
        pfcq_dict = {"Dot1p": int(pfc_priority), "OutputQueueIndex": int(queue)}
        pfcq_entry_obj = umf_qos.PfcPriorityQueueMapEntry(**pfcq_dict)
        pfcq_obj.add_PfcPriorityQueueMapEntry(pfcq_entry_obj)
        pfcq_obj.configure(dut, operation=operation)
        result = pfcq_entry_obj.configure(dut, operation=operation)
    else:
        result = pfcq_obj.unConfigure(dut)

    if result.ok():
        st.log('Pass: {} qos PfcPriorityQueueMap passed'.format(mode))
        return True
    else:
        st.log('Fail: {} qos PfcPriorityQueueMap failed'.format(mode))
        return False


def dot1p_to_tc_map(dut, obj_name, dot1p=None, tc=None, operation=None, mode='config'):
    qos_obj = umf_qos.Qos()
    dot1p_obj = umf_qos.Dot1pMap(Name=obj_name, Qos=qos_obj)
    if mode == 'config':
        dot1p_obj.configure(dut)
        dot1p_tc_dict = {}
        dot1p_tc_dict = {"Dot1p": int(dot1p), "FwdGroup": str(tc)}
        dot1p_entry_obj = umf_qos.Dot1pMapEntry(**dot1p_tc_dict)
        dot1p_obj.add_Dot1pMapEntry(dot1p_entry_obj)
        dot1p_obj.configure(dut, operation=operation)
        result = dot1p_entry_obj.configure(dut, operation=operation)
    else:
        result = dot1p_obj.unConfigure(dut)

    if result.ok():
        st.log('Pass: {} qos dot1p_to_tc_map passed'.format(mode))
        return True
    else:
        st.log('Fail: {} qos dot1p_to_tc_map failed'.format(mode))
        return False


def tc_to_dot1p_map(dut, obj_name, dot1p=None, tc=None, operation=None, mode='config'):
    qos_obj = umf_qos.Qos()
    tcdot1p_obj = umf_qos.ForwardingGroupDot1pMap(Name=obj_name, Qos=qos_obj)
    if mode == 'config':
        tcdot1p_obj.configure(dut)
        tc_dot1q_dict = {}
        fwd_obj = umf_qos.ForwardingGroup(Name=str(tc), Qos=qos_obj)
        tc_dot1q_dict = {"FwdGroup": fwd_obj, "Dot1p": int(dot1p)}
        tcdot1p_entry_obj = umf_qos.ForwardingGroupDot1pMapEntry(**tc_dot1q_dict)
        tcdot1p_obj.add_ForwardingGroupDot1pMapEntry(tcdot1p_entry_obj)
        tcdot1p_obj.configure(dut, operation=operation)
        result = tcdot1p_entry_obj.configure(dut, operation=operation)
    else:
        result = tcdot1p_obj.unConfigure(dut)

    if result.ok():
        st.log('Pass: {} qos tc_to_dot1p_map passed'.format(mode))
        return True
    else:
        st.log('Fail: {} qos tc_to_dot1p_map failed'.format(mode))
        return False


def dscp_to_tc_map(dut, obj_name, dscp=None, tc=None, operation=None, mode='config'):
    qos_obj = umf_qos.Qos()
    dscp_obj = umf_qos.DscpMap(Name=obj_name, Qos=qos_obj)
    if mode == 'config':
        dscp_obj.configure(dut)
        dscp_tc_dict = {}
        dscp_tc_dict = {"Dscp": int(dscp), "FwdGroup": str(tc)}
        dscp_entry_obj = umf_qos.DscpMapEntry(**dscp_tc_dict)
        dscp_obj.add_DscpMapEntry(dscp_entry_obj)
        dscp_obj.configure(dut, operation=operation)
        result = dscp_entry_obj.configure(dut, operation=operation)
    else:
        result = dscp_obj.unConfigure(dut)

    if result.ok():
        st.log('Pass: {} qos dscp_to_tc_map passed'.format(mode))
        return True
    else:
        st.log('Fail: {} qos dscp_to_tc_map failed'.format(mode))
        return False


def tc_to_dscp_map(dut, obj_name, dscp=None, tc=None, operation=None, mode='config'):
    qos_obj = umf_qos.Qos()
    tcdscp_obj = umf_qos.ForwardingGroupDscpMap(Name=obj_name, Qos=qos_obj)
    if mode == 'config':
        tcdscp_obj.configure(dut)
        tc_dscp_dict = {}
        fwd_obj = umf_qos.ForwardingGroup(Name=str(tc), Qos=qos_obj)
        tc_dscp_dict = {"FwdGroup": fwd_obj, "Dscp": int(dscp)}
        tcdscp_entry_obj = umf_qos.ForwardingGroupDscpMapEntry(**tc_dscp_dict)
        tcdscp_obj.add_ForwardingGroupDscpMapEntry(tcdscp_entry_obj)
        tcdscp_obj.configure(dut, operation=operation)
        result = tcdscp_entry_obj.configure(dut, operation=operation)
    else:
        result = tcdscp_obj.unConfigure(dut)

    if result.ok():
        st.log('Pass: {} qos tc_to_dscp_map passed'.format(mode))
        return True
    else:
        st.log('Fail: {} qos tc_to_dscp_map failed'.format(mode))
        return False


def tc_to_queue_map(dut, obj_name, queue=None, tc=None, operation=None, mode='config'):
    qos_obj = umf_qos.Qos()
    tcq_obj = umf_qos.ForwardingGroupQueueMap(Name=obj_name, Qos=qos_obj)
    if mode == 'config':
        tcq_obj.configure(dut)
        tcq_dict = {}
        fwd_obj = umf_qos.ForwardingGroup(Name=str(tc), Qos=qos_obj)
        tcq_dict = {"FwdGroup": fwd_obj, "OutputQueueIndex": int(queue)}
        tcqmap_obj = umf_qos.ForwardingGroupQueueMapEntry(**tcq_dict)
        tcq_obj.add_ForwardingGroupQueueMapEntry(tcqmap_obj)
        tcq_obj.configure(dut, operation=operation)
        result = tcqmap_obj.configure(dut, operation=operation)
    else:
        result = tcq_obj.unConfigure(dut)

    if result.ok():
        st.log('Pass: {} qos tc_to_queue_map passed'.format(mode))
        return True
    else:
        st.log('Fail: {} qos tc_to_queue_map failed'.format(mode))
        return False


def tc_to_pg_map(dut, obj_name, pg=None, tc=None, operation=None, mode='config'):
    qos_obj = umf_qos.Qos()
    tcpg_obj = umf_qos.ForwardingGroupPriorityGroupMap(Name=obj_name, Qos=qos_obj)
    if mode == 'config':
        tcpg_obj.configure(dut)
        tc_pg_dict = {}
        fwd_obj = umf_qos.ForwardingGroup(Name=str(tc), Qos=qos_obj)
        tc_pg_dict = {"FwdGroup": fwd_obj, "PriorityGroupIndex": int(pg)}
        tcpg_entry_obj = umf_qos.ForwardingGroupPriorityGroupMapEntry(**tc_pg_dict)
        tcpg_obj.add_ForwardingGroupPriorityGroupMapEntry(tcpg_entry_obj)
        tcpg_obj.configure(dut, operation=operation)
        result = tcpg_entry_obj.configure(dut, operation=operation)
    else:
        result = tcpg_obj.unConfigure(dut)

    if result.ok():
        st.log('Pass: {} qos tc_to_pg_map passed'.format(mode))
        return True
    else:
        st.log('Fail: {} qos tc_to_pg_map failed'.format(mode))
        return False


@pytest.mark.savereboot
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtFpSoQoSCoSCfg001'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclCmFn001'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclCmFn002'])
@pytest.mark.inventory(testcases=['FtOpSoQosEcnCfg001'])
@pytest.mark.inventory(testcases=['FtOpSoQosWredCfg001'])
@pytest.mark.inventory(testcases=['ft_acl_configvalues_save_reload'])
@pytest.mark.inventory(testcases=['ft_ecn_config_db_to_running_config_after_save_and_reload'])
@pytest.mark.inventory(testcases=['ft_ecn_config_to_config_db_json_after_save_and_reboot'])
def test_ft_qos_config_mgmt_verifying_config_with_save_reboot():
    st.log("performing Config save")
    rb_obj.config_save(vars.D1)
    st.log("performing reboot")
    st.reboot(vars.D1)
    st.log("Checking whether config is loaded to running config from config_db after save and reboot")
    st.log("Checking for IPV4 ACL config after save and reboot")
    ipv4_acl_verify()
    st.log("Checking for IPV6 ACL config after save and reboot")
    ipv6_acl_verify()
    st.log("Checking for COS config after save and reboot")
    cos_config_verify()
    st.log("Checking for wred config after save and reboot")
    wred_verify()
    st.log("checking for ecn config after save and reboot")
    ecn_verify()
    st.log("configuration is successfully stored to config_db file after save and reboot")
    st.report_pass("test_case_passed")
