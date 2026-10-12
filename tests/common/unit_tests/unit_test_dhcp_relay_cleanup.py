"""Test the standby cleanup helper directly, without testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_dhcp_relay_cleanup.py -v
"""

from unittest.mock import Mock

import pytest

from tests.common.dhcp_relay_cleanup import restart_standby_dhcp_service


@pytest.fixture
def cleanup_context():
    standby = Mock(hostname="standby")
    restart_service = Mock()
    wait_for = Mock(return_value=True)
    interface_ready = Mock()
    return standby, restart_service, wait_for, interface_ready


@pytest.mark.parametrize("standby_flag, relay_type", [
    ("", "isc"),
    ("False\n", "isc"),
    ("True\n", "sonic"),
])
def test_cleanup_uses_standbys_configured_relay_mode(cleanup_context, standby_flag, relay_type):
    standby, restart_service, wait_for, interface_ready = cleanup_context
    standby.shell.return_value = {"stdout": standby_flag}

    restart_standby_dhcp_service(standby, restart_service, wait_for, interface_ready)

    standby.shell.assert_called_once_with(
        'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" "has_sonic_dhcpv4_relay"')
    restart_service.assert_called_once_with(standby, [relay_type])
    wait_for.assert_called_once_with(
        120, 5, 0, interface_ready, standby, "{}-relay-agent".format(relay_type))


def test_standby_config_read_failure_propagates(cleanup_context):
    standby, restart_service, wait_for, interface_ready = cleanup_context
    standby.shell.side_effect = RuntimeError("CONFIG_DB unavailable")

    with pytest.raises(RuntimeError, match="CONFIG_DB unavailable"):
        restart_standby_dhcp_service(standby, restart_service, wait_for, interface_ready)

    restart_service.assert_not_called()
    wait_for.assert_not_called()


def test_standby_restart_failure_propagates(cleanup_context):
    standby, restart_service, wait_for, interface_ready = cleanup_context
    standby.shell.return_value = {"stdout": "False"}
    restart_service.side_effect = AssertionError("dhcp_relay is not ready")

    with pytest.raises(AssertionError, match="dhcp_relay is not ready"):
        restart_standby_dhcp_service(standby, restart_service, wait_for, interface_ready)

    wait_for.assert_not_called()


def test_standby_socket_failure_propagates(cleanup_context):
    standby, restart_service, wait_for, interface_ready = cleanup_context
    standby.shell.return_value = {"stdout": "True"}
    wait_for.return_value = False

    with pytest.raises(pytest.fail.Exception, match="interfaces are not ready on standby ToR standby"):
        restart_standby_dhcp_service(standby, restart_service, wait_for, interface_ready)

    restart_service.assert_called_once_with(standby, ["sonic"])
    wait_for.assert_called_once_with(120, 5, 0, interface_ready, standby, "sonic-relay-agent")
