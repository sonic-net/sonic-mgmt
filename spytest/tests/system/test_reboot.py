import pytest

from spytest import st, SpyTestDict

import apis.switching.vlan as vlan_obj
import apis.system.logging as log
import apis.system.basic as basic_obj
import apis.system.interface as intf_obj
import apis.system.reboot as reboot_obj
import apis.system.logging as slog_obj

@pytest.fixture(scope="module", autouse=True)
def reboot_module_hooks(request):
    global vars
    global data
    data = SpyTestDict()
    data.iter_count = 3
    data.idle_sleep = 300
    data.max_vlan = 4093
    vars = st.get_testbed_vars()
    vars = st.ensure_min_topology("D1")
    vlan_obj.config_vlan_range(vars.D1, "1 {}".format(data.max_vlan), config='add')
    yield
    vlan_obj.clear_vlan_configuration(st.get_dut_names(), thread=False)


@pytest.fixture(scope="function", autouse=True)
def reboot_func_hooks(request,reboot_module_hooks):
    yield


@pytest.mark.hard_reboot_mul_iter
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_sys_hard_reboot_multiple_iter():
    """
    Author : Sreenivasula Reddy <sreenivasula.reddy@broadcom.com>
    """
    vars = st.ensure_min_topology("D1")
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
    if not slog_obj.get_logging_count(vars.D1):
        st.report_fail("logs_are_not_getting_generated_after_reboot")
    st.report_pass('test_case_passed')


@pytest.mark.reboot_mul_iter
def test_ft_sys_soft_reboot_multiple_iter():
    '''
    Author : Sreenivasula Reddy <sreenivasula.reddy@broadcom.com>
    '''
    vars = st.ensure_min_topology("D1")
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
    vars = st.ensure_min_topology("D1")
    st.log("clearing the logging buffer")
    if not log.clear_logging(vars.D1):
        st.report_fail("failed_to_clear_logs", vars.D1)
    st.log("enabling logging level as debug")
    if not log.set_logging_severity(vars.D1, severity="Debug"):
        st.report_fail("logging_severity_level_change_failed", vars.D1)
    st.log("waiting the DUT to idle for sometime")
    st.wait(data.idle_sleep)
    log.set_logging_severity(vars.D1, severity="INFO")
    if not log.check_unwanted_logs_in_logging(vars.D1, user_filter=[]):
        st.report_fail("logs_are_getting_generated_after_reboot", vars.D1)
    st.report_pass("test_case_passed")

