"""Small DHCP relay cleanup helpers that can be tested without a testbed."""

from tests.common.helpers.assertions import pytest_assert


def restart_standby_dhcp_service(duthost, restart_service, wait_for, interface_ready):
    """Restore the standby relay using its own configured DHCPv4 relay mode."""
    sonic_relay_enabled = duthost.shell(
        'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" "has_sonic_dhcpv4_relay"'
    )["stdout"].strip() == "True"
    relay_type = "sonic" if sonic_relay_enabled else "isc"
    restart_service(duthost, [relay_type])
    pytest_assert(
        wait_for(120, 5, 0, interface_ready, duthost, "{}-relay-agent".format(relay_type)),
        "DHCP relay interfaces are not ready on standby ToR {}".format(duthost.hostname))
