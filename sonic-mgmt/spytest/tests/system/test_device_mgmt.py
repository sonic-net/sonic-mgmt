import pytest

from spytest import st, SpyTestDict

import apis.routing.ip as ping_obj
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj

data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def mgmt_module_hooks(request):
    vars = st.ensure_min_topology("D1", "CONSOLE_ONLY")
    data.dut = vars.D1
    st.set_module_params(tryssh=0)
    yield


@pytest.fixture(scope="function", autouse=True)
def mgmt_func_hooks(request):
    yield


@pytest.mark.static_ip_on_mgmt_intrf
@pytest.mark.community
@pytest.mark.community_pass
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['ft_ip_static_ip_on_mgmt_intrf'])
def test_ft_ip_static_ip_on_mgmt_intrf():
    """
    Author:Karthik Kumar Goud Battula(karthikkumargoud.battula@broadcom.com)
    Scenario: Verify the configuration of static ip address on eth0 interface and check the reachability
    """
    err_list = []
    data.interface = 'eth0'

    # ensure ip address from dhcp
    intf_obj.enable_dhcp_on_interface(data.dut, data.interface)
    st.wait(5)
    ip_address_list = basic_obj.get_ifconfig_inet(data.dut, data.interface)
    if not ip_address_list:
        st.report_fail("DUT_does_not_have_IP_address")

    # configure static ip address
    data.ip_address = ip_address_list[0]
<<<<<<< HEAD
    if '1.74' in data.ip_address:
        gateway = '1.74.23.200'
    if '192.168' in data.ip_address:
        gateway = data.ip_address.split('.')
        gateway[-1] = '1'
        gateway = '.'.join(gateway)
    command = "sudo ip route add 0.0.0.0/0 via {} dev {}".format(gateway, data.interface)
    st.config(vars.D1, command, skip_error_check=False)
    
    data.netmask = basic_obj.get_ifconfig(vars.D1, data.interface)[0]['netmask'][0]
    data.gateway = basic_obj.get_ifconfig_gateway(vars.D1, data.interface)
    intf_obj.config_static_ip_to_interface(vars.D1, data.interface, data.ip_address, data.netmask, data.gateway)
    st.log("Verify connectivity from DUT")
    if not ping_obj.ping(vars.D1, data.gateway):
        st.error("Ping is not successful for address {}".format(data.gateway))
        result= False
    intf_obj.delete_ip_on_interface_linux(vars.D1, data.interface, "{}/{}".format(data.ip_address, data.netmask))
    ip_address_list = basic_obj.get_ifconfig_inet(vars.D1, data.interface)
=======
    data.netmask = basic_obj.get_ifconfig(data.dut, data.interface)[0]['netmask'][0]
    data.gateway = basic_obj.get_ifconfig_gateway(data.dut, data.interface)
    intf_obj.config_static_ip_to_interface(data.dut, data.interface, data.ip_address, data.netmask, data.gateway)

    # verify ping with static ip address
    st.log("Verify connectivity from DUT", dut=data.dut)
    if not ping_obj.ping(data.dut, data.gateway):
        err = st.error("Ping is not successful for gateway {} with static IP".format(data.gateway))
        err_list.append(err)

    # unconfigure static ip address
    intf_obj.delete_ip_on_interface_linux(data.dut, data.interface, "{}/{}".format(data.ip_address, data.netmask))
    ip_address_list = basic_obj.get_ifconfig_inet(data.dut, data.interface)
>>>>>>> 2565f2608ec4e193959dd20e8d39fe4d913488f3
    if ip_address_list:
        err = st.error("DUT_have_IP_address {} {}".format(data.dut, data.interface))
        err_list.append(err)

    # revert back to DHCP and verify
    intf_obj.enable_dhcp_on_interface(data.dut, data.interface)
    if not ping_obj.ping(data.dut, data.gateway):
        err = st.error("Ping is not successful for gateway {} with DHCP IP".format(data.gateway))
        err_list.append(err)

    st.report_result(err_list)
