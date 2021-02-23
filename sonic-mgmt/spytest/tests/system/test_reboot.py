import pytest
import random

from spytest import st, SpyTestDict

import apis.switching.vlan as vlan_obj
import apis.system.logging as log
import apis.system.basic as basic_obj
import apis.system.interface as intf_obj
import apis.system.reboot as reboot_obj
import apis.system.box_services as box

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def reboot_module_hooks(request):
    global vars
    data.iter_count = 3
    data.idle_sleep = 300
    data.max_vlan = 4093
    vars = st.ensure_min_topology("D1")
    if not st.is_feature_supported("vlan-range", vars.D1):
        # limit the number of VLANS so reduce run time
        data.max_vlan = 100
    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_vlan), config='add')
    data.version_data = basic_obj.get_hwsku(vars.D1)
    data.hw_constants_DUT = st.get_datastore(vars.D1, "constants")
    yield
    vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=False)


@pytest.fixture(scope="function", autouse=True)
def reboot_func_hooks(request,reboot_module_hooks):
    yield

def platform_check():
    if not data.version_data.lower() in data.hw_constants_DUT['HW_WATCHDOG_SUPPORTED_PLATFORMS']:
        st.log("--- Detected HW watchdog unsupported Platform..")
        st.report_unsupported("hw_watchdog_unsupported")


@pytest.mark.hard_reboot_mul_iter
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_sys_hard_reboot_multiple_iter():
    """
    Author : Sreenivasula Reddy <sreenivasula.reddy@broadcom.com>
    """
    st.log("Hard rebooting device for multiple iterations")
    for each_iter in range(1, data.iter_count + 1):
        st.log("Hard Reboot iteration number {}".format(each_iter))
        st.log("About to power off power to switch")
        st.do_rps(vars.D1, "Off")
        st.log("About to Power ON switch")
        st.do_rps(vars.D1, "On")
        intf_obj.poll_for_interfaces(vars.D1, iteration_count=180, delay=1)
    st.log("After hard reboot about to check 'show reboot-cause' reason")
    if not reboot_obj.get_reboot_cause(vars.D1):
        st.report_fail("verify_hard_reboot_show_reboot_cause_fail", vars.D1)
    intf_obj.poll_for_interfaces(vars.D1, iteration_count=180, delay=1)
    if not log.get_logging_count(vars.D1):
        st.report_fail("logs_are_not_getting_generated_after_reboot")
    st.report_pass('test_case_passed')


@pytest.mark.reboot_mul_iter
def test_ft_sys_soft_reboot_multiple_iter():
    '''
    Author : Sreenivasula Reddy <sreenivasula.reddy@broadcom.com>
    '''
    st.log("Performing save and soft-reboot")
    reboot_obj.config_save(vars.D1)
    st.log("Soft rebooting device for multiple iterations")
    for each_iter in range(1, data.iter_count +1):
        st.log("Reload iteration number {}".format(each_iter))
        st.log("About to reload the switch")
        st.reboot(vars.D1,"fast")
        intf_obj.poll_for_interfaces(vars.D1, iteration_count=180, delay=1)
    st.log("After reload about to check 'show platform summary'")
    if not basic_obj.get_hwsku(vars.D1):
        st.report_fail("After_soft_reboot_DUT_access_fail", data.iter_count)
    st.log("performing clearconfig operation")
    reboot_obj.config_reload(vars.D1)
    st.report_pass('test_case_passed')


@pytest.mark.bootup_logging_debug
def test_ft_sytem_bootup_logging_debug():
    """
    Author : Praveen Kumar Kota <praveenkumar.kota@broadcom.com>
    Testbed : D1 --- Mgmt Network
    Verify that no unwanted logs are shown on DUT console with logging level "Debug".
    """
    st.log("clearing the logging buffer")
    if not log.clear_logging(vars.D1):
        st.report_fail("failed_to_clear_logs", vars.D1)
    st.log("enabling logging level as debug")
    if not log.set_logging_severity(vars.D1, severity="Debug"):
        st.report_fail("logging_severity_level_change_failed", vars.D1)
    st.log("waiting the DUT to idle for sometime")
    st.wait(data.idle_sleep)
    log.set_logging_severity(vars.D1, severity="INFO")
    platform = basic_obj.get_hwsku(vars.D1)
    logs = ['in obtaining media setting for'] if platform.lower() in ['accton-as9716-32d'] else []
    if not log.check_for_logs_after_reboot(vars.D1, 'Error', log_severity=['DEBUG', 'INFO'], except_logs=logs):
        st.report_fail("logs_are_getting_generated_after_reboot", vars.D1)
    if not log.check_unwanted_logs_in_logging(vars.D1, user_filter=[]):
        st.report_fail("logs_are_getting_generated_after_reboot", vars.D1)
    st.report_pass("test_case_passed")


@pytest.mark.hw_watchdog
def test_ft_hw_watchdog():
    min_hw_watchdog_time = 180
    max_hw_watchdog_time = 370
    reboot_sleep = 60
    st.log("Verify whether feature is supported or not")
    platform_check()
    hw_watchdog_expiry = min_hw_watchdog_time + reboot_sleep
    st.log("Disabling the hw watchdog")
    if not box.hw_watchdog_config(vars.D1, mode='disable'):
        st.report_fail("hw_watchdog_disable_fail")
    st.log("Enabling the hw watchdog")
    if not box.hw_watchdog_config(vars.D1, mode='enable'):
        st.report_fail("hw_watchdog_enable_fail")
    st.log("Resetting the Hw watch daemon")
    if not box.hw_watchdog_config(vars.D1, mode='reset'):
        st.report_fail("hw_watchdog_reset_fail")
    st.log("Wait for watchdog timer to expire")
    st.wait(hw_watchdog_expiry)
    st.log("Getting status of hw watchdog")
    if not box.hw_watchdog_config(vars.D1, mode='status'):
        st.report_fail("hw_watchdog_status_fail")
    st.log("Get the hw watchdog reboot cause")
    if not reboot_obj.get_reboot_cause(vars.D1):
        st.report_fail("verify_hard_reboot_show_reboot_cause_fail")
    cause = reboot_obj.get_reboot_cause(vars.D1)
    cause =  cause[0]['message']
    if not cause == 'Hardware Watchdog Reset':
        if data.version_data.lower() in data.hw_constants_DUT['HW_WATCHDOG_REBOOT_CAUSE_SUPPORTED_PLATFORMS']:
            st.log("Reboot reason is invalid")
            st.report_tc_fail("ft_hw_watchdog_reset", 'test_case_id_failed')
        else:
            st.log("Reboot reason is invalid because platform not have reboot cause support specific to Hw watchdog")
    st.log("Getting timeout of hw watchdog")
    if not box.hw_watchdog_config(vars.D1, mode='timeout'):
        st.report_fail("hw_watchdog_timeout_fail")
    st.log("Verifying the running status of hw watchdog feature")
    if not box.hw_watchdog_config(vars.D1, mode='running_status'):
        st.report_fail("hw_watchdog_running_status")
    st.log("Generating kdump collections")
    if not box.hw_watchdog_config(vars.D1, mode='kdump'):
        st.report_fail("hw_watchdog_kdump_fail")
    if not reboot_obj.get_reboot_cause(vars.D1):
        st.report_fail("verify_hard_reboot_show_reboot_cause_fail")
    cause = reboot_obj.get_reboot_cause(vars.D1)
    cause = cause[0]['message']
    if not cause == 'Hardware Watchdog Reset':
        if data.version_data.lower() in data.hw_constants_DUT['HW_WATCHDOG_REBOOT_CAUSE_SUPPORTED_PLATFORMS']:
            st.log("Reboot reason is invalid")
            st.report_tc_fail("ft_hw_watchdog_reset", 'test_case_id_failed')
        else:
            st.log("Reboot reason is invalid because platform not have reboot cause support specific to Hw watchdog")
    st.log("Changing the timeout value and verifying watchdog feature")
    value = random.randint(min_hw_watchdog_time, max_hw_watchdog_time)
    st.log("configurung the timeout value and verifying the functionality")
    if not box.hw_watchdog_timeout_config(vars.D1, timeout_value=value):
        st.report_fail("hw_watchdog_timeout_fail")
    sleep_time = value + reboot_sleep
    if not box.hw_watchdog_config(vars.D1, mode='reset'):
        st.report_fail("hw_watchdog_reset_fail")
    st.log("Wait for watchdog timer to expire")
    st.wait(sleep_time)
    if not reboot_obj.get_reboot_cause(vars.D1):
        st.report_fail("verify_hard_reboot_show_reboot_cause_fail")
    cause = reboot_obj.get_reboot_cause(vars.D1)
    cause = cause[0]['message']
    if not cause == 'Hardware Watchdog Reset':
        if data.version_data.lower() in data.hw_constants_DUT['HW_WATCHDOG_REBOOT_CAUSE_SUPPORTED_PLATFORMS']:
            st.log("Reboot reason is invalid")
            st.report_tc_fail("ft_hw_watchdog_reset", 'test_case_id_failed')
        else:
            st.log("Reboot reason is invalid because platform not have reboot cause support specific to Hw watchdog")
    st.log("Changing back to default value")
    if not box.hw_watchdog_timeout_config(vars.D1, timeout_value=min_hw_watchdog_time):
        st.report_fail("hw_watchdog_timeout_fail")
    st.report_pass("test_case_passed")


def test_hw_watchdog_stop_start_service():
    st.log("Verify whether feature is supported or not")
    platform_check()
    st.log("Stopping the watchdog service")
    box.hw_watchdog_stop_service(vars.D1)
    st.log("verifying the status is in-active")
    output1 = box.hw_watch_service_isactive(vars.D1)
    if 'inactive' in output1:
        st.log("watchdog-control.service is stopped successfully on the platform")
    else:
        st.log("Unable to stop watchdog service on the platform ... Failing the UT")
        st.report_fail("operation_failed")
    st.log("starting the service")
    output = box.hw_watchdog_start_service(vars.D1)
    ret = [i for i in output if 'Error' in i]
    if ret:
        st.log("watchdog-control.service failed to start again")
        st.report_fail("operation_failed")
    else:
        st.log("watchdog-control.service started successfully")
        st.report_pass("operation_successful")

def test_hw_watchdog_warm_fast_reboot_cases():
    st.log("Verify whether feature is supported or not")
    platform_check()
    st.log("verifying the hw watchdog service is active or not")
    output1 = box.hw_watch_service_isactive(vars.D1)
    if 'active' in output1:
        st.log("watchdog-control.service is active on the platform")
    else:
        st.log("watchdog-control.service is not active on the platform")
        st.report_fail("operation_failed")
    st.log("performing reboot on the platform")
    st.reboot(vars.D1)
    output1 = box.hw_watch_service_isactive(vars.D1)
    if 'active' in output1:
        st.log("watchdog-control.service is active on the platform after reboot")
    else:
        st.log("watchdog-control.service is not active on the platform after reboot")
        st.report_fail("operation_failed")
    st.log("performing fast reboot on the platform")
    st.reboot(vars.D1, 'fast')
    output1 = box.hw_watch_service_isactive(vars.D1)
    if 'active' in output1:
        st.log("watchdog-control.service is active on the platform after fast reboot")
    else:
        st.log("watchdog-control.service is not active on the platform after fast reboot")
        st.report_fail("operation_failed")
    st.log("performing warm reboot on the platform")
    st.reboot(vars.D1, 'warm')
    output1 = box.hw_watch_service_isactive(vars.D1)
    if 'active' in output1:
        st.log("watchdog-control.service is active on the platform after warm reboot")
    else:
        st.log("watchdog-control.service is not active on the platform after warm reboot")
        st.report_fail("operation_failed")
    st.report_pass("test_case_passed")
