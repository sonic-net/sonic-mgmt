import pytest
from spytest import st
from spytest.dicts import SpyTestDict
import apis.system.logging as slog_obj
import utilities.utils as utils_obj
import apis.system.box_services as bsapi
@pytest.fixture(scope="module", autouse=True)
def logging_module_hooks(request):
    global vars
    vars = st.get_testbed_vars()
    global_vars()
    yield
@pytest.fixture(scope="function", autouse=True)
def logging_func_hooks(request):
    global_vars()
    yield
def global_vars():
    global data
    data = SpyTestDict()
    data.syslog_server = utils_obj.ensure_service_params(vars.D1, "syslog", "ip")

@pytest.mark.logs_after_system_reboot
@pytest.mark.regression
def test_ft_logging_verify_logs_after_system_reboot():
    """
    Author: Anil Kumar Kacharla <anilkumar.kacharla@broadcom.com>
    Referrence Topology :   Test bed ID:4 D1--Mgmt network
    Verify that  logs get generated upon system reboot.
    """
    st.log("Ensuring minimum topology")
    vars = st.ensure_min_topology("D1")
    data.count = '0'
    st.log("configuring syslog server in config_db file")
    slog_obj.config_syslog_server(vars.D1, [data.syslog_server])
    st.log("checking logging count")
    slog_obj.get_logging_count(vars.D1)
    count = slog_obj.get_logging_count(vars.D1)
    st.log("logging count:{}".format(count))
    st.log("performing system reboot")
    st.reboot(vars.D1,'fast')
    st.log("checking logs after  system reboot ")
    count = slog_obj.get_logging_count(vars.D1)
    if slog_obj.get_logging_count(vars.D1) == data.count:
        st.report_fail("logs_are_not_getting_generated_after_reboot")
    else:
        st.log("Logs are generated after reboot")
        st.log("logs count after reboot:{}".format(count))
    output = bsapi.generate_tech_support(vars.D1)
    if "Tar append operation failed" in output:
        st.report_fail("Tech_support_operation_failed")
    st.report_pass("test_case_passed")