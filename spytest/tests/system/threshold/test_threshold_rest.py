# Threshold Feature FT REST test cases.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import pytest
import random
import re
import json

from spytest import st, SpyTestDict

import apis.system.basic as bcapi
import apis.system.threshold as tfapi
import apis.system.rest as rtapi
import apis.system.interface as intapi
import apis.system.box_services as bsapi

from utilities.common import make_list


@pytest.fixture(scope="module", autouse=True)
def threshold_feature_rest_module_hooks(request):
    global_vars_and_constants_init()
    tf_rest_package_checker()
    tf_rest_module_config()
    yield


@pytest.fixture(scope="function", autouse=True)
def threshold_feature_rest_func_hooks(request):
    verify_system_map_status(tf_rest_data.max_time_to_check_sys_maps[0], tf_rest_data.max_time_to_check_sys_maps[1])
    yield


def global_vars_and_constants_init():
    global tf_rest_data
    global vars
    vars = st.ensure_min_topology('D1')
    tf_rest_data = SpyTestDict()
    hw_constants = st.get_datastore(vars.D1, "constants")
    tf_rest_data.all_ports = intapi.get_all_interfaces(vars.D1, int_type='physical')
    # Global Vars
    tf_rest_data.platform = bcapi.get_hwsku(vars.D1)
    tf_rest_data.show_version = bcapi.show_version(vars.D1)
    tf_rest_data.feature = "bst"
    tf_rest_data.configure_bst_thresholds = "configure-bst-thresholds"
    tf_rest_data.configure_bst_multi_thresholds = "configure-bst-multi-thresholds"
    tf_rest_data.get_bst_thresholds = "get-bst-thresholds"
    tf_rest_data.clear_bst_thresholds = "clear-bst-thresholds"
    tf_rest_data.queues_to_check = ['COUNTERS_PG_NAME_MAP', 'COUNTERS_QUEUE_NAME_MAP']
    tf_rest_data.max_time_to_check_sys_maps = [150, 2]  # Seconds
    tf_rest_data.default_threshold_value = 0  # Percentage
    # Common Constants
    tf_rest_data.pg_headroom_un_supported_platforms = \
        hw_constants['THRESHOLD_FEATURE_PG_HEADROOM_UN_SUPPORTED_PLATFORMS']
    tf_rest_data.build_product_info = hw_constants['BUILD_BROADCOM_CLOUD_ADVANCED']+hw_constants['BUILD_BROADCOM_ENTERPRISE_ADVANCED']


def tf_rest_module_config():
    global dut_port
    device_ip = st.get_mgmt_ip(vars.D1)
    dut_port = random.sample(tf_rest_data.all_ports, k=5)
    st.log("Randomly Chosen interfaces - {}".format(dut_port))
    if not device_ip:
        st.error("Failed to get the DUT IP address.")
        report_result(0)


def tf_rest_package_checker():
    global tf_rest_supported
    tf_rest_supported = True
    st.log("Is Threshold REST supported in this Build? (tf_rest_supported) - {}".format(tf_rest_supported))


def tf_rest_support_checker():
    if tf_rest_supported:
        st.log("Threshold REST - Supported in this Build, Hence test proceeding...")
    else:
        st.log("Threshold REST - NOT Supported in this Build, Hence test moving to UnSupported...")
        st.report_unsupported('test_case_unsupported')


def verify_system_map_status(itter_count, delay):
    bsapi.get_system_uptime_in_seconds(vars.D1)
    if not tfapi.verify_hardware_map_status(vars.D1, tf_rest_data.queues_to_check, itter_count=itter_count,
                                            delay=delay):
        st.error('Required Threshold Feature Queues are not initialized in the DUT')
        report_result(0)
    if not tfapi.verify_port_table_port_config(vars.D1, itter_count=itter_count, delay=delay):
        st.error('Port table and Port config not initialized in the DUT')
        report_result(0)


def report_result(status):
    if status:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')


def get_threshold_from_rest_output(resp, threshold_type, buffer_type, port_alias, index):
    if any("/" in interface for interface in make_list(port_alias)):
        port_alias = st.get_other_names(vars.D1, make_list(port_alias))[0]
    st.log(resp)
    if threshold_type == 'priority-group' and buffer_type == 'shared':
        for each in resp['report'][0]['data']:
            if port_alias in each['port']:
                return each['data'][index][1]
    elif threshold_type == 'priority-group' and buffer_type == 'headroom':
        for each in resp['report'][0]['data']:
            if port_alias in each['port']:
                return each['data'][index][2]
    elif threshold_type == 'queue' and buffer_type == 'multicast' and port_alias == 'CPU':
        for each in resp['report'][0]['data']:
            if each[0] == index:
                return each[1]
    elif threshold_type == 'queue' and buffer_type in ['unicast', 'multicast']:
        for each in resp['report'][0]['data']:
            if each[1] == port_alias and each[2] == index:
                return each[3]
    else:
        st.error('No Match for threshold_type and buffer_type found')
    st.error("No Value found for Port:{} Index:{} in the rest data".format(port_alias, index))
    return None


def check_ports_from_rest_output(resp, threshold_type, buffer_type, dut_ports):
    if any("/" in interface for interface in make_list(dut_ports)):
        dut_ports = st.get_other_names(vars.D1, make_list(dut_ports))
    result = True
    if threshold_type == 'priority-group' and buffer_type in ['shared', 'headroom']:
        rest_ports = [each['port'] for each in resp['report'][0]['data']]

    elif threshold_type == 'queue' and buffer_type in ['unicast', 'multicast']:
        rest_ports = list(set([each[1] for each in resp['report'][0]['data']]))
    else:
        st.error('No Match for threshold_type and buffer_type found')
        return None

    for each in dut_ports:
        if each not in rest_ports:
            st.error(">>> Port '{}' information is *not* available in REST data of {} {}".
                     format(each, threshold_type, buffer_type))
            result = False
        else:
            st.debug("Port '{}' information is available in REST data".format(each))
    return result


def tf_config_common_call(call_type, th_value, **kwargs):
    """
    Common function to make both CLI and REST threshold feature calls
    """
    result2 = 1
    dut = kwargs['dut']
    if call_type != "REST_CLEAR":
        threshold_type = kwargs['threshold_type']
        buffer_type = kwargs['buffer_type']
        index_name = kwargs['index_name']
        port_alias = kwargs['port_alias']
        index = int(re.findall(r"\d+", kwargs['index_name'])[0])

    if call_type == "REST_GET" or call_type == 'REST_GET_PORTS_CHECK':
        st.banner("Verifying Threshold {} {} config via REST".format(threshold_type, buffer_type))
        if any("/" in interface for interface in make_list(port_alias)):
            port_alias = st.get_other_names(vars.D1, make_list(port_alias))[0]
        get_rest_data = tfapi.get_threshold_rest_data(threshold_type=threshold_type, buffer_type=buffer_type,
                                                      port=port_alias)
        rv_data = rtapi.send_rest_request(dut, tf_rest_data.feature, tf_rest_data.get_bst_thresholds, get_rest_data)
        if not rv_data:
            st.error("Failed to GET Threshold {} {} via REST".format(threshold_type, buffer_type))
            return 0
        if rv_data:
            resp = json.loads(rv_data.text)
            if call_type == 'REST_GET_PORTS_CHECK':
                st.banner("Validating interfaces in {} {} REST Data ".format(threshold_type, buffer_type))
                if not check_ports_from_rest_output(resp, threshold_type, buffer_type, tf_rest_data.all_ports):
                    result2 = 0
                if result2:
                    st.log("--> Success: Interface Validation of {} {}  REST DATA".format(threshold_type, buffer_type))
            get_value = get_threshold_from_rest_output(resp, threshold_type, buffer_type, port_alias, index)
            if get_value is None:
                return 0
            st.log("REST GET Threshold Value {} {} on Port:{}, Index:{}".format(get_value, type(get_value),
                                                                                port_alias, index))
            st.log("Configured Threshold Value {} {}".format(th_value, type(th_value)))
            if not get_value == int(th_value):
                st.error("Failed to Verify Threshold {} {} via REST".format(threshold_type, buffer_type))
                return 0
        st.log("--> Success: Verifying Threshold {} {} config via REST".format(threshold_type, buffer_type))
        return 1 and result2

    elif call_type == "REST_SET":
        st.banner("Configuring Threshold {} {} via REST".format(threshold_type, buffer_type))
        if any("/" in interface for interface in make_list(port_alias)):
            port_alias = st.get_other_names(vars.D1, make_list(port_alias))[0]
        set_rest_data = tfapi.set_threshold_rest_data(threshold_type=threshold_type, port_alias=port_alias,
                                                      index=index, buffer_type=buffer_type, value=th_value)
        if not rtapi.send_rest_request(dut, tf_rest_data.feature, tf_rest_data.configure_bst_thresholds, set_rest_data):
            st.error("Failed to SET Threshold {} {} via REST".format(threshold_type, buffer_type))
            return 0
        st.log("--> Success: Configuring Threshold {} {} via REST".format(threshold_type, buffer_type))
        return 1

    elif call_type == 'CLI_GET':
        st.banner("Verifying Threshold {} {} config via CLI".format(threshold_type, buffer_type))
        api_data = {'threshold_type': threshold_type, 'buffer_type': buffer_type,
                    'port_alias': port_alias, index_name: th_value}
        if not tfapi.verify_threshold(dut, **api_data):
            st.error("Failed to Verify Threshold {} {} via CLI".format(threshold_type, buffer_type))
            return 0
        st.log("--> Success: Verifying Threshold {} {} config via CLI".format(threshold_type, buffer_type))
        return 1

    elif call_type == 'REST_CLEAR':
        st.banner("Performing Clear BST thresholds via REST")
        if not rtapi.send_rest_request(dut, tf_rest_data.feature, tf_rest_data.clear_bst_thresholds, {}):
            st.error('REST: Clear BST thresholds call failed')
            return 0
        st.log("--> Success: Performing Clear thresholds via REST")
        return 1
    else:
        st.error("Unknown tf call_type : {}".format(call_type))
        return 0


def tf_unconfig():
    tfapi.clear_threshold(vars.D1, breach='all')
    tfapi.clear_threshold(vars.D1, threshold_type='priority-group', buffer_type='all', port_alias=dut_port[0])
    tfapi.clear_threshold(vars.D1, threshold_type='queue', buffer_type='all', port_alias=dut_port[0])
    tfapi.clear_threshold(vars.D1, threshold_type='queue', buffer_type='multicast', index=1, port_alias='CPU')


def tf_rest_config_testing(**kwargs):
    """
    Test Details:
    1. Config Threshold using REST
    2. Check Threshold config using REST
    3. Check Threshold config using CLI
    4. Clear Threshold config using REST
    5. Check for default Threshold config using REST
    5. Check for default Threshold config using CLI
    """
    tf_rest_support_checker()
    result = 1
    threshold_value = kwargs['threshold_value']
    default_threshold = 0

    if not tf_config_common_call('REST_SET', threshold_value, **kwargs):
        result = 0
    if not tf_config_common_call('REST_GET_PORTS_CHECK', threshold_value, **kwargs):
        result = 0
    if not tf_config_common_call('CLI_GET', threshold_value, **kwargs):
        result = 0
    if not tf_config_common_call('REST_CLEAR', threshold_value, **kwargs):
        result = 0
    if not tf_config_common_call('REST_GET', default_threshold, **kwargs):
        result = 0
    if not tf_config_common_call('CLI_GET', default_threshold, **kwargs):
        result = 0
    tf_unconfig()
    report_result(result)


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_rest
def test_ft_tf_config_priority_group_shared_rest():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    data = {'dut': vars.D1,
            'threshold_type': "priority-group",
            'buffer_type': 'shared',
            'index_name': 'pg2',
            'port_alias': dut_port[0],
            'threshold_value': 78
            }
    tf_rest_config_testing(**data)


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_rest
def test_ft_tf_config_priority_group_headroom_rest():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    if tf_rest_data.platform and tf_rest_data.platform.lower() in tf_rest_data.pg_headroom_un_supported_platforms:
        st.error("Threshold priority-group headroom is not supported for this platform ({})".
                 format(tf_rest_data.platform))
        st.report_unsupported('test_case_unsupported')

    data = {'dut': vars.D1,
            'threshold_type': "priority-group",
            'buffer_type': 'headroom',
            'index_name': 'pg4',
            'port_alias': dut_port[0],
            'threshold_value': 89
            }
    tf_rest_config_testing(**data)


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_rest
def test_ft_tf_config_queue_unicast_rest():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    data = {'dut': vars.D1,
            'threshold_type': "queue",
            'buffer_type': 'unicast',
            'index_name': 'uc0',
            'port_alias': dut_port[0],
            'threshold_value': 69
            }
    tf_rest_config_testing(**data)


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_rest
def test_ft_tf_config_queue_multicast_rest():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    data = {'dut': vars.D1,
            'threshold_type': "queue",
            'buffer_type': 'multicast',
            'index_name': 'mc1',
            'port_alias': dut_port[0],
            'threshold_value': 83
            }
    tf_rest_config_testing(**data)


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_rest
def test_ft_tf_config_multi_threshold_rest():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    tf_rest_support_checker()
    result = 1
    e_pg_sh_port1, e_pg_sh_queue1, e_pg_sh_queue_name1, e_pg_sh_th_value1 = dut_port[0], 3, 'pg3', 59
    _, _, e_pg_hr_queue_name1, e_pg_hr_th_value1 = dut_port[0], 3, 'pg3', 14
    e_uc_port1, e_uc_queue1, e_uc_queue_name1, e_uc_th_value1 = dut_port[0], 4, 'uc4', 50
    e_mc_port1, e_mc_queue1, e_mc_queue_name1, e_mc_th_value1 = dut_port[0], 1, 'mc1', 30
    e_cpu_port1, e_cpu_queue1, e_cpu_queue_name1, e_cpu_th_value1 = 'CPU', 1, 'mc1', 10

    set_rest_data = [
                    {"data": [{"data": [[e_pg_sh_queue1, e_pg_sh_th_value1, e_pg_hr_th_value1]],
                               "port": e_pg_sh_port1}], "realm": "ingress-port-priority-group"},
                    {"data": [[e_uc_port1, e_uc_queue1, e_uc_th_value1]], "realm": "egress-uc-queue"},
                    {"data": [[e_mc_port1, e_mc_queue1, e_mc_th_value1]], "realm": "egress-mc-queue"},
                    {"data": [[e_cpu_queue1, e_cpu_th_value1]], "realm": "egress-cpu-queue"}
                    ]

    # REST SET
    st.banner("Configuring Threshold {} via REST".format(tf_rest_data.configure_bst_multi_thresholds))
    if not rtapi.send_rest_request(vars.D1, tf_rest_data.feature, tf_rest_data.configure_bst_multi_thresholds,
                                   set_rest_data):
        st.error("Failed to SET {} via REST".format(tf_rest_data.configure_bst_multi_thresholds))
        result = 0
    else:
        st.log("--> Success: Configuring Threshold {} via REST".format(tf_rest_data.configure_bst_multi_thresholds))

    # REST GET and Verify
    if not tf_config_common_call('REST_GET', e_pg_sh_th_value1, dut=vars.D1, threshold_type="priority-group",
                                 buffer_type='shared', index_name=e_pg_sh_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('REST_GET', e_pg_hr_th_value1, dut=vars.D1, threshold_type="priority-group",
                                 buffer_type='headroom', index_name=e_pg_hr_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('REST_GET', e_uc_th_value1, dut=vars.D1, threshold_type="queue",
                                 buffer_type='unicast', index_name=e_uc_queue_name1, port_alias=e_uc_port1):
        result = 0
    if not tf_config_common_call('REST_GET', e_mc_th_value1, dut=vars.D1, threshold_type="queue",
                                 buffer_type='multicast', index_name=e_mc_queue_name1, port_alias=e_mc_port1):
        result = 0
    if not tf_config_common_call('REST_GET', e_cpu_th_value1, dut=vars.D1, threshold_type="queue",
                                 buffer_type='multicast', index_name=e_cpu_queue_name1, port_alias=e_cpu_port1):
        result = 0

    # CLI GET and Verify
    if not tf_config_common_call('CLI_GET', e_pg_sh_th_value1, dut=vars.D1, threshold_type="priority-group",
                                 buffer_type='shared', index_name=e_pg_sh_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('CLI_GET', e_pg_hr_th_value1, dut=vars.D1, threshold_type="priority-group",
                                 buffer_type='headroom', index_name=e_pg_hr_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('CLI_GET', e_uc_th_value1, dut=vars.D1, threshold_type="queue",
                                 buffer_type='unicast', index_name=e_uc_queue_name1, port_alias=e_uc_port1):
        result = 0
    if not tf_config_common_call('CLI_GET', e_mc_th_value1, dut=vars.D1, threshold_type="queue",
                                 buffer_type='multicast', index_name=e_mc_queue_name1, port_alias=e_mc_port1):
        result = 0
    if not tf_config_common_call('CLI_GET', e_cpu_th_value1, dut=vars.D1, threshold_type="queue",
                                 buffer_type='multicast', index_name=e_cpu_queue_name1, port_alias=e_cpu_port1):
        result = 0
    # REST Clear
    if not tf_config_common_call('REST_CLEAR', 0, dut=vars.D1):
        result = 0

    # REST GET and Verify
    if not tf_config_common_call('REST_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="priority-group", buffer_type='shared',
                                 index_name=e_pg_sh_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('REST_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="priority-group", buffer_type='headroom',
                                 index_name=e_pg_hr_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('REST_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="queue", buffer_type='unicast',
                                 index_name=e_uc_queue_name1, port_alias=e_uc_port1):
        result = 0
    if not tf_config_common_call('REST_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="queue", buffer_type='multicast',
                                 index_name=e_mc_queue_name1, port_alias=e_mc_port1):
        result = 0
    if not tf_config_common_call('REST_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="queue", buffer_type='multicast',
                                 index_name=e_cpu_queue_name1, port_alias=e_cpu_port1):
        result = 0

    # CLI GET and Verify
    if not tf_config_common_call('CLI_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="priority-group", buffer_type='shared',
                                 index_name=e_pg_sh_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('CLI_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="priority-group", buffer_type='headroom',
                                 index_name=e_pg_hr_queue_name1, port_alias=e_pg_sh_port1):
        result = 0
    if not tf_config_common_call('CLI_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="queue", buffer_type='unicast',
                                 index_name=e_uc_queue_name1, port_alias=e_uc_port1):
        result = 0
    if not tf_config_common_call('CLI_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="queue", buffer_type='multicast',
                                 index_name=e_mc_queue_name1, port_alias=e_mc_port1):
        result = 0

    if not tf_config_common_call('CLI_GET', tf_rest_data.default_threshold_value, dut=vars.D1,
                                 threshold_type="queue", buffer_type='multicast',
                                 index_name=e_cpu_queue_name1, port_alias=e_cpu_port1):
        result = 0
    tf_unconfig()
    report_result(result)


@pytest.mark.threshold_ft
@pytest.mark.threshold_ft_rest
def test_ft_tf_verification_of_sample_rest_call_on_build_used():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    if tf_rest_supported:
        st.log("Threshold REST - Supported in this Build, Hence test proceeding to check REST calls to work...")
        result = tf_config_common_call('REST_CLEAR', 0, dut=vars.D1)
        report_result(result)

    else:
        st.log("Threshold REST - NOT Supported in this Build, Hence test Proceeding to check REST calls to fail...")
        result = tf_config_common_call('REST_CLEAR', 0, dut=vars.D1)
        report_result(not result)
