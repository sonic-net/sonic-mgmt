"""
Test zebra interface consistency after boot and config reload.

Validates that all Ethernet interfaces have valid (non-zero) ifindex in FRR's
zebra daemon. This guards against a race condition where the speed update timer
sets ZEBRA_INTERFACE_ACTIVE before RTM_NEWLINK assigns a real ifindex, causing
interfaces to be missing from zebra's per-NS ifindex rbtree.

See: https://github.com/sonic-net/sonic-buildimage/issues/XXXX
"""

import json
import logging
import pytest
import re

from tests.common import config_reload as config_reload_helper
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


def get_zebra_interface_data(duthost):
    """Get interface data from zebra via vtysh and return parsed JSON."""
    result = duthost.shell('docker exec bgp vtysh -c "show interface json"')
    return json.loads(result['stdout'])


def get_ethernet_interfaces(duthost):
    """Get list of Ethernet interface names from CONFIG_DB."""
    result = duthost.shell('sonic-db-cli CONFIG_DB keys "PORT|Ethernet*"')
    interfaces = []
    for line in result['stdout_lines']:
        match = re.match(r'PORT\|(Ethernet\d+)', line)
        if match:
            interfaces.append(match.group(1))
    return sorted(interfaces)


def check_interface_ifindex(duthost):
    """
    Verify all Ethernet interfaces have valid (non-zero) ifindex in zebra.

    Returns list of interfaces with ifindex == 0 (should be empty).
    """
    iface_data = get_zebra_interface_data(duthost)
    ethernet_interfaces = get_ethernet_interfaces(duthost)
    bad_interfaces = []

    for intf_name in ethernet_interfaces:
        if intf_name not in iface_data:
            logger.warning("Interface %s not found in zebra output", intf_name)
            bad_interfaces.append((intf_name, "missing"))
            continue

        ifindex = iface_data[intf_name].get('index', 0)
        if ifindex == 0:
            logger.error("Interface %s has ifindex=0 (IFINDEX_INTERNAL)", intf_name)
            bad_interfaces.append((intf_name, "ifindex=0"))

    return bad_interfaces


class TestZebraInterfaceConsistency:
    """Test suite for zebra interface ifindex consistency."""

    def test_interface_ifindex_after_boot(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """Verify all interfaces have valid ifindex after normal boot."""
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        bad = check_interface_ifindex(duthost)
        pytest_assert(
            len(bad) == 0,
            "Interfaces with invalid ifindex after boot: {}".format(bad)
        )

    def test_interface_ifindex_after_config_reload(self, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
        """Verify all interfaces have valid ifindex after config reload."""
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

        config_reload_helper(duthost, safe_reload=True, check_intf_up_ports=True)
        wait_critical_processes(duthost)

        bad = check_interface_ifindex(duthost)
        pytest_assert(
            len(bad) == 0,
            "Interfaces with invalid ifindex after config reload: {}".format(bad)
        )
