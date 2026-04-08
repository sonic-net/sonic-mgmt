import pytest
import ipaddress

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common import constants

pytestmark = [
    pytest.mark.topology("t1-filterleaf-lag")
]


@pytest.fixture
def check_bgp_neighbor(duthost):
    """
    Validate all the bgp neighbors are established
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts['BGP_NEIGHBOR']['Vrf_Q10DDOS']
    pytest_assert(
        wait_until(300, 10, 0, duthost.check_bgp_session_state, bgp_neighbors),
        "bgp sessions {} are not up".format(bgp_neighbors)
    )


@pytest.fixture
def subintf_expected_config(duthosts, enum_frontend_dut_hostname, enum_asic_index, tbinfo):
    """
    Return expected config of the subinterfaces created from Minigraph.
    """
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_host = duthost.asic_instance(enum_asic_index)

    # Get interface runtime facts
    host_facts = asic_host.interface_facts()['ansible_facts']['ansible_interface_facts']

    # Get extended minigraph facts
    subinterfaces = {
        intf: facts
        for intf, facts in host_facts.items()
        if "." in intf
    }

    show_int_status = {intf["interface"]: intf for intf in duthost.show_and_parse("show interface status")}
    for subinterface, config in list(subinterfaces.items()):
        interface, vlan = subinterface.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)
        config["speed"] = show_int_status[interface]["speed"]
        config["mtu"] = show_int_status[interface]["mtu"]
        config["vlan"] = vlan
    return subinterfaces


def test_subinterface_status(duthost, subintf_expected_config):

    def verify_subintf_creation(subintf_config, success_show_sub_status):
        """Verify subintf existence after creation."""
        show_sub_status = {_["sub port interface"]: _ for _ in duthost.show_and_parse("show subinterfaces status")
                           if _["sub port interface"] in subintf_config}
        if len(show_sub_status) == len(list(subintf_config)):
            success_show_sub_status.append(show_sub_status)
            return True
        return False
    success_show_sub_status = []
    if not wait_until(20, 5, 0, verify_subintf_creation, subintf_expected_config, success_show_sub_status):
        pytest.fail("Failed to create subinterfaces")

    show_sub_status = success_show_sub_status[0]
    show_ip_interfaces = {_["interface"]: _ for _ in duthost.show_and_parse("show ip interface")
                          if _["interface"] in subintf_expected_config}

    for subintf, config in list(subintf_expected_config.items()):
        # verify show subinterface status after creation
        status = show_sub_status[subintf]
        pytest_assert(status.get("admin") == "up", "subinterface %s should be admin up" % subintf)
        pytest_assert(status.get("vlan") == config["vlan"],
                      "subinterface %s should have vlan %s, actual vlan %s"
                      % (subintf, config["vlan"], status.get("vlan")))
        pytest_assert(status.get("speed") == config["speed"],
                      "subinterface %s should have inherited speed as %s, actual speed %s"
                      % (subintf, config["speed"], status.get("speed")))
        pytest_assert(status.get("mtu") == config["mtu"],
                      "subinterface %s should have inherited mtu as %s, actual mtu %s"
                      % (subintf, config["mtu"], status.get("mtu")))
        pytest_assert(status.get("type") == "802.1q-encapsulation",
                      "subinterface %s should have type as 802.1q-encapsulation, actual type %s"
                      % (subintf, status.get("type")))

        # verify show ip interface status after creation
        if subintf not in show_ip_interfaces:
            pytest.fail("subinterface %s doesn't have IP address assigned as expected" % subintf)
        ip_status = show_ip_interfaces[subintf]
        ipv4 = config["ipv4"]["address"]
        netmask = config["ipv4"]["netmask"]
        cidr = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
        expected_ip = "{}/{}".format(ipv4, cidr)
        pytest_assert(ip_status.get("ipv4 address/mask") == expected_ip,
                      "subinterface %s should have IP address assigned as %s, actual IP address %s"
                      % (subintf, expected_ip, ip_status.get("ipv4 address/mask")))
