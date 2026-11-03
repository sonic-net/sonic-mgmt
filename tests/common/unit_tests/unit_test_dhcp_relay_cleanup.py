"""Exercise DHCP relay cleanup without importing testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_dhcp_relay_cleanup.py -v
"""

import ast
from pathlib import Path
from unittest.mock import Mock, call

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "dhcp_relay" / "test_dhcp_relay.py"
TEST_NAMES = [
    "test_dhcp_relay_default",
    "test_dhcp_relay_with_source_port_ip_in_relay_enabled",
]


def _assert(condition, message="DHCP relay check failed"):
    assert condition, message


@pytest.fixture
def cleanup_namespace():
    tree = ast.parse(MODULE_PATH.read_text())
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    namespace = {
        "restart_dhcp_service": Mock(),
        "check_interface_status": Mock(),
        "wait_until": Mock(return_value=True),
        "pytest_assert": _assert,
        "DUAL_TOR_MODE": "dual",
    }
    helper = functions["restart_standby_dhcp_service"]
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace, functions


@pytest.mark.parametrize("test_name", TEST_NAMES)
@pytest.mark.parametrize("testing_mode", ["single", "dual"])
@pytest.mark.parametrize("relay_agent", ["isc-relay-agent", "sonic-relay-agent"])
@pytest.mark.parametrize("standby_flag,standby_type", [
    ("", "isc"),
    ("False\n", "isc"),
    ("True\n", "sonic"),
])
def test_cleanup_uses_each_tors_relay_mode(
        cleanup_namespace, test_name, testing_mode, relay_agent, standby_flag, standby_type):
    """Both cleanup blocks preserve the active mode and inspect the standby's own config."""
    namespace, functions = cleanup_namespace
    active = Mock()
    standby = Mock()
    standby.shell.return_value = {"stdout": standby_flag}
    namespace.update(
        duthost=active, standby_duthost=standby, relay_agent=relay_agent,
        testing_mode=testing_mode, skip_dhcpmon=False)

    # Execute the real cleanup block, not a copy of its implementation.
    cleanup = functions[test_name].body[-1]
    assert isinstance(cleanup, ast.If) and ast.unparse(cleanup.test) == "not skip_dhcpmon"
    exec(compile(ast.Module(body=[cleanup], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)

    active_type = "sonic" if relay_agent == "sonic-relay-agent" else "isc"
    expected_restarts = [call(active, [active_type])]
    expected_checks = []
    if testing_mode == "dual":
        standby.shell.assert_called_once_with(
            'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" "has_sonic_dhcpv4_relay"')
        expected_restarts.append(call(standby, [standby_type]))
        expected_checks.append(call(
            120, 5, 0, namespace["check_interface_status"], standby, "{}-relay-agent".format(standby_type)))
    else:
        standby.shell.assert_not_called()
    expected_checks.append(call(120, 5, 0, namespace["check_interface_status"], active, relay_agent))
    assert namespace["restart_dhcp_service"].call_args_list == expected_restarts
    assert namespace["wait_until"].call_args_list == expected_checks


def test_standby_config_read_failure_propagates(cleanup_namespace):
    """A failed CONFIG_DB read must not silently select ISC or restart the service."""
    namespace, _ = cleanup_namespace
    standby = Mock()
    standby.shell.side_effect = RuntimeError("CONFIG_DB unavailable")
    with pytest.raises(RuntimeError, match="CONFIG_DB unavailable"):
        namespace["restart_standby_dhcp_service"](standby)
    namespace["restart_dhcp_service"].assert_not_called()
    namespace["wait_until"].assert_not_called()


def test_standby_readiness_failure_propagates(cleanup_namespace):
    """Keep the service-readiness gate and do not continue to socket checks after failure."""
    namespace, _ = cleanup_namespace
    standby = Mock()
    standby.shell.return_value = {"stdout": ""}
    namespace["restart_dhcp_service"].side_effect = AssertionError("dhcp_relay is not ready")
    with pytest.raises(AssertionError, match="dhcp_relay is not ready"):
        namespace["restart_standby_dhcp_service"](standby)
    namespace["wait_until"].assert_not_called()


def test_standby_socket_failure_propagates(cleanup_namespace):
    """A running relay with missing sockets must still fail cleanup."""
    namespace, _ = cleanup_namespace
    standby = Mock(hostname="standby")
    standby.shell.return_value = {"stdout": "True"}
    namespace["wait_until"].return_value = False
    with pytest.raises(AssertionError, match="interfaces are not ready on standby ToR standby"):
        namespace["restart_standby_dhcp_service"](standby)
