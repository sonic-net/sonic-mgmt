"""Unit tests for SNMP management address helpers."""

import ast
import ipaddress
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock


MODULE_PATH = Path(__file__).resolve().parents[2] / "helpers/snmp_helpers.py"
SOURCE = MODULE_PATH.read_text()
TREE = ast.parse(SOURCE)
FUNCTION_NAMES = {"resolve_snmp_host", "format_snmp_cli_target"}
FUNCTIONS = [
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name in FUNCTION_NAMES
]
NAMESPACE = {
    "ipaddress": ipaddress,
    "logger": MagicMock(),
}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)

resolve_snmp_host = NAMESPACE["resolve_snmp_host"]
format_snmp_cli_target = NAMESPACE["format_snmp_cli_target"]


def _make_duthost(ipv6_only, ansible_host="192.0.2.10", mgmt_ipv6="2001:db8::10"):
    inventory_host = SimpleNamespace(vars={"ansible_host": ansible_host})
    inventory_manager = MagicMock()
    inventory_manager.get_host.return_value = inventory_host
    return SimpleNamespace(
        hostname="dut",
        host=SimpleNamespace(options={"inventory_manager": inventory_manager}),
        is_ipv6_only_mgmt=lambda: ipv6_only,
        mgmt_ipv6=mgmt_ipv6,
    )


def test_resolve_snmp_host_preserves_ipv4_management_by_default():
    duthost = _make_duthost(ipv6_only=False)

    assert resolve_snmp_host(duthost, "192.0.2.10") == "192.0.2.10"


def test_resolve_snmp_host_uses_ipv6_management_in_ipv6_only_mode():
    duthost = _make_duthost(ipv6_only=True)

    assert resolve_snmp_host(duthost, "192.0.2.10") == "2001:db8::10"


def test_resolve_snmp_host_preserves_custom_target():
    duthost = _make_duthost(ipv6_only=True)

    assert resolve_snmp_host(duthost, "198.51.100.20") == "198.51.100.20"


def test_format_snmp_cli_target_wraps_ipv6_address():
    assert format_snmp_cli_target("2001:db8::10") == "udp6:[2001:db8::10]"


def test_format_snmp_cli_target_preserves_ipv4_and_hostname():
    assert format_snmp_cli_target("192.0.2.10") == "192.0.2.10"
    assert format_snmp_cli_target("dut.example.test") == "dut.example.test"
