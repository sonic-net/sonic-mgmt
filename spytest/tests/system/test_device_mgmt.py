import pytest
import apis.routing.ip as ping_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
from spytest import st
from spytest.dicts import SpyTestDict

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def mgmt_module_hooks(request):
    # add things at the start of this module

    yield
    # add things at the end of this module"


@pytest.fixture(scope="function", autouse=True)
def mgmt_func_hooks(request):
    # add things at the start every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case
    yield

    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

@pytest.mark.static_ip_on_mgmt_intrf
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_ip_static_ip_on_mgmt_intrf():
    """
    Author:Karthik Kumar Goud Battula(karthikkumargoud.battula@broadcom.com)
    Scenario: Verify the configuration of static ip address on eth0 interface and check the reachability
    """
    result = True
    vars = st.ensure_min_topology("D1", "CONSOLE_ONLY")
    data.interface = 'eth0'
    intf_obj.enable_dhcp_on_interface(vars.D1, data.interface)
    st.wait(5)
    ip_address_list = basic_obj.get_ifconfig_inet(vars.D1, data.interface)
    if not ip_address_list:
        st.report_fail("DUT_does_not_have_IP_address")
    data.ip_address = ip_address_list[0]
    data.netmask = basic_obj.get_ifconfig(vars.D1, data.interface)[0]['netmask'][0]
    data.gateway = basic_obj.get_ifconfig_gateway(vars.D1, data.interface)
    intf_obj.config_static_ip_to_interface(vars.D1, data.interface, data.ip_address, data.netmask, data.gateway)
    st.log("Verify connectivity from DUT")
    if not ping_obj.ping(vars.D1, data.gateway):
        st.error("Ping is not successful for address {}".format(data.gateway))
        result= False
    intf_obj.delete_ip_on_interface_linux(vars.D1, data.interface, "{}/{}".format(data.ip_address, data.netmask))
    ip_address_list = basic_obj.get_ifconfig_inet(vars.D1, data.interface)
    if ip_address_list:
        st.error("DUT_have_IP_address {} {}".format(vars.D1, data.interface))
        result= False
    intf_obj.enable_dhcp_on_interface(vars.D1, data.interface)
    if not ping_obj.ping(vars.D1, data.gateway):
        st.error("Ping is not successful for address {}".format(data.gateway))
        result= False
    if not result:
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")
