import json
import pytest

from tests.common import constants
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("t0", "t1")
]


@pytest.fixture
def subintf_expected_config(duthost, apply_config_on_the_dut):
    """Return expected config of the subinterfaces created."""
    subinterfaces = apply_config_on_the_dut["sub_ports"]
    show_int_status = {intf["interface"]: intf for intf in duthost.show_and_parse("show interface status")}

    for subinterface, config in list(subinterfaces.items()):
        interface, vlan = subinterface.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)
        config["speed"] = show_int_status[interface]["speed"]
        config["mtu"] = show_int_status[interface]["mtu"]
        config["vlan"] = vlan

    return subinterfaces


def test_subinterface_status(duthost, subintf_expected_config):
    """
    Verify subinterface status after creation/deletion.

    @param duthost: fixture duthost
    @param subintf_expected_config: fixture subintf_expected_config to get expected sub interfaces configuration

    1. add new subinterfaces
    2. verify new subinterfaces status via `show subinterface status`
    3. verify new subinterfaces IP address via `show ip/ipv6 interfaces`
    4. verify no syslog error during creation
    5. remove new subinterfaces
    6. verify subinterface removal via `show subinterface status`
    7. verify subinterface IP address removal via `show ip/ipv6 interfaces`
    8. verify no syslog error during removal
    """

    def _verify_subintf_creation(subintf_config, success_show_sub_status):
        """Verify subintf existence after creation."""
        show_sub_status = {_["sub port interface"]: _ for _ in duthost.show_and_parse("show subinterfaces status")
                           if _["sub port interface"] in subintf_config}
        if len(show_sub_status) == len(subintf_config):
            success_show_sub_status.append(show_sub_status)
            return True
        return False

    def _verify_subintf_removal(subintf_config):
        """Verify subintf existence after removal."""
        show_sub_status = {_["sub port interface"]: _ for _ in duthost.show_and_parse("show subinterfaces status")
                           if _["sub port interface"] in subintf_config}
        return len(show_sub_status) == 0

    def _remove_subintf(subintf_config):
        """Remove the created subintf from VLAN_SUB_INTERFACE table."""
        for subintf in subintf_config:
            entries = json.loads(duthost.shell("redis-dump -d 4 -k \"VLAN_SUB_INTERFACE|%s*\"" % subintf)["stdout"])
            for entry in entries:
                duthost.shell("redis-cli -n 4 del \"%s\"" % entry)

    # creation verification
    success_show_sub_status = []
    if not wait_until(20, 5, 0, _verify_subintf_creation, subintf_expected_config, success_show_sub_status):
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
        pytest_assert(ip_status.get("ipv4 address/mask") == config["ip"],
                      "subinterface %s should have IP address assigned as %s, actual IP address %s"
                      % (subintf, config["ip"], ip_status.get("ipv4 address/mask")))

    # deletion verification
    _remove_subintf(subintf_expected_config)
    if not wait_until(20, 5, 0, _verify_subintf_removal, subintf_expected_config):
        pytest.fail("Failed to remove subinterfaces")

    show_ip_interfaces = {_["interface"]: _ for _ in duthost.show_and_parse("show ip interface")
                          if _["interface"] in subintf_expected_config}

    for subintf in subintf_expected_config:
        # verify show ip interface status after removal
        pytest_assert(subintf not in show_ip_interfaces, "subinterface %s still have IP address assigned" % subintf)
