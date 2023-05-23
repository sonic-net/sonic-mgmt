import pytest
import ipaddress
import sys
import re

from mx_utils import remove_vlan, get_vlan_config
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert, pytest_require

pytestmark = [
    pytest.mark.topology("mx"),
]

if sys.version_info.major == 3:
    UNICODE_TYPE = str
else:
    UNICODE_TYPE = unicode

TARGET_PRIVATE_NET = "172.17.0.0/24"
SUBNETS_PREFIX_LEN = 26
MAX_PREFIX_LEN = 32
IP_REG = r"\d+\.\d+\.\d+\.\d+/\d+"


def verify_private_ip_not_advertise(duthost, nbrhosts):
    # Restart bgp service, trigger bgp advertising
    duthost.shell("systemctl reset-failed bgp", module_ignore_errors=True)
    duthost.restart_service("bgp")
    pytest_assert(wait_until(100, 10, 10, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "bgp not started")

    # Generate subnets that shouldn't be advertised
    subnets = set()
    base_net = ipaddress.ip_network(UNICODE_TYPE(TARGET_PRIVATE_NET))
    base_net_prefix_len = int(TARGET_PRIVATE_NET.split("/")[1])
    for prefix_len in range(SUBNETS_PREFIX_LEN, MAX_PREFIX_LEN + 1):
        for subnet in base_net.subnets(prefixlen_diff=prefix_len-base_net_prefix_len):
            subnets.add(str(subnet))

    pattern = re.compile(IP_REG)
    for name, neighbor in nbrhosts.items():
        neighbor_conf = neighbor.get("conf")
        for intf_name, intf_config in neighbor_conf["interfaces"].items():
            # Be compatible with portchannel and non-portchannel topo
            if "Ethernet" not in intf_name and "Port-Channel" not in intf_name or "ipv4" not in intf_config:
                continue

            neighbor_ip = intf_config["ipv4"].split("/")[0]
            command_output = duthost.shell("show ip bgp nei {} advertised-routes".format(neighbor_ip))
            advertised_nets = set(pattern.findall(command_output["stdout"]))
            pytest_assert(len(subnets.intersection(advertised_nets)) == 0,
                          "private ips are advertised to {}".format(name))


@pytest.mark.parametrize("vlan_number", [4, 7])
def test_bgp_policy_private_ip(duthost, nbrhosts, setup_vlan, mx_common_setup_teardown,
                               vlan_number):
    dut_index_port, _, vlan_configs = mx_common_setup_teardown
    vlan_config = get_vlan_config(vlan_configs, vlan_number)
    pytest_require(vlan_config is not None, "Can't get {} vlan config".format(vlan_number))
    verify_private_ip_not_advertise(duthost, nbrhosts)
    remove_vlan(duthost, vlan_config, dut_index_port)
