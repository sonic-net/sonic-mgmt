import pytest
import os
import apis.system.logging as slog
import apis.system.basic as basic_obj
from spytest import st
from utilities.parallel import exec_foreach
import tortuga_common_utils as common_obj

@pytest.fixture
def dhcpv4_relay_flag_config_unconfig():
    vars = st.get_testbed_vars()
    leaf0 = vars.D3
    leaf1 = vars.D4
    st.log("configuring flag for device {}".format(leaf0))
    st.config(leaf0, "redis-cli -n 4 hset 'DEVICE_METADATA|localhost' 'has_sonic_dhcpv4_relay' 'True'")
    basic_obj.service_operations_by_systemctl(leaf0,"dhcp_relay",'reset-failed')
    basic_obj.service_operations_by_systemctl(leaf0,"dhcp_relay",'restart')
    st.log("configuring flag for device {}".format(leaf1))
    st.config(leaf1, "redis-cli -n 4 hset 'DEVICE_METADATA|localhost' 'has_sonic_dhcpv4_relay' 'True'")
    basic_obj.service_operations_by_systemctl(leaf1,"dhcp_relay",'reset-failed')
    basic_obj.service_operations_by_systemctl(leaf1,"dhcp_relay",'restart')

    yield

    st.log("unconfiguring flag for device {}".format(leaf0))
    st.config(leaf0, "redis-cli -n 4 hdel 'DEVICE_METADATA|localhost' 'has_sonic_dhcpv4_relay'")
    basic_obj.service_operations_by_systemctl(leaf0,"dhcp_relay",'reset-failed')
    basic_obj.service_operations_by_systemctl(leaf0,"dhcp_relay",'restart')
    st.log("unconfiguring flag for device {}".format(leaf1))
    st.config(leaf1, "redis-cli -n 4 hdel 'DEVICE_METADATA|localhost' 'has_sonic_dhcpv4_relay'")
    basic_obj.service_operations_by_systemctl(leaf1,"dhcp_relay",'reset-failed')
    basic_obj.service_operations_by_systemctl(leaf1,"dhcp_relay",'restart')


def check_dhcp4relay_support(node):
    cmd = "docker exec dhcp_relay which dhcp4relay"
    output = st.config(node, cmd, skip_error_check=True)
    st.log("support for dhcp4relay:\n{}".format(output))
    return "dhcp4relay" in output
