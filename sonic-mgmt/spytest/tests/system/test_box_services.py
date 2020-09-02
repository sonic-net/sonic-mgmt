import pytest
from spytest import st
import apis.system.box_services as boxserv_obj
import apis.system.basic as basic_obj

pytest.fixture(scope="module", autouse=True)
def box_service_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    yield

@pytest.fixture(scope="function", autouse=True)
def box_service_func_hooks(request):
    yield

@pytest.mark.system_box
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_system_uptime():
    """
    Author: Sreenivasula Reddy V <sreenivasula.reddy@broadcom.com>
    Validate 'show uptime' command
    """
    vars = st.get_testbed_vars()
    st.log("About to get system uptime in seconds")
    intial_uptime=int(boxserv_obj.get_system_uptime_in_seconds(vars.D1))
    st.log("initial_uptime: {}".format(intial_uptime))
    st.log("About to wait for 1 min")
    st.wait(60)
    uptime_after_1min=intial_uptime+int(60)
    st.log("uptime_after_1min: {}".format(uptime_after_1min))
    st.log("About to check system uptime after 60 sec")
    sys_uptime=int(boxserv_obj.get_system_uptime_in_seconds(vars.D1))
    st.log("sys_uptime: {}".format(sys_uptime))
    st.log("About to validate system uptime which should be greater than or equal to system uptime after 1 min")
    st.log("uptime_after_1min+60: {}".format(uptime_after_1min+60))
    st.log("Verifying {}<={}<={}".format(uptime_after_1min, sys_uptime, uptime_after_1min + 60))
    if uptime_after_1min<=sys_uptime<=uptime_after_1min+60:
        st.log("System Uptime is getting updated with correct value")
    else:
        st.report_fail("sytem_uptime_fail",vars.D1)
    st.report_pass("test_case_passed")

@pytest.mark.dhcp_relay_docker
def test_ft_dhcp_relay_docker_image():
    """"
    Author: Ramakrishnudu.Mangala <ramakrishnudu.mangala@broadcom.com>
    Verify DHCP Relay docker file is there in docker image.
    Test Bed :TB_16
    """
    vars = st.get_testbed_vars()
    st.log("verifying the docker images on DUT")
    if not basic_obj.verify_docker_ps(vars.D1, "docker-dhcp-relay:latest") :
        if not basic_obj.verify_docker_ps(vars.D1, "docker-dhcp-relay-dbg:latest"):
            st.report_fail("operation_failed")
    st.log("Verify DHCP Relay docker file is there in docker image")
    st.report_pass("test_case_passed")
