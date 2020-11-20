import pytest

from spytest import st
import apis.system.basic as basic_obj

@pytest.fixture(scope="module", autouse=True)
def platform_monitoring_module_hooks(request):
    st.ensure_min_topology("D1D2:1")
    yield

@pytest.fixture(scope="function", autouse=True)
def platform_monitoring_func_hooks(request):
    yield

@pytest.mark.pmon_docker_restart
def test_ft_pmon_docker_restart():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the platform monitoring(pmon) works fine after docker restart
    Reference Test Bed : D1 --- Mgmt Network
    """
    vars = st.get_testbed_vars()
    service_name = "pmon"
    basic_obj.service_operations_by_systemctl(vars.D1, service_name, 'stop')
    basic_obj.service_operations_by_systemctl(vars.D1, service_name, 'restart')
    if not basic_obj.poll_for_system_status(vars.D1, service_name, 30, 1):
        st.report_fail("service_not_running", service_name)
    if not basic_obj.verify_service_status(vars.D1, service_name):
        st.report_fail("pmon_service_not_up")
    pmon_check= basic_obj.show_version(vars.D1)
    if not pmon_check:
        st.report_fail("pmon_show_command_fail")
    st.report_pass("test_case_passed")

