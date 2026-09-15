"""Exercise CACL convergence and internal rule exceptions without a testbed."""

import ast
import logging
from pathlib import Path
from unittest.mock import Mock, call

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "cacl" / "test_cacl_application.py"


@pytest.fixture
def cacl_namespace():
    tree = ast.parse(MODULE_PATH.read_text())
    names = {"wait_for_expected_rules", "verify_cacl", "verify_nat_cacl"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {
        "CACL_RULE_SYNC_TIMEOUT": 1,
        "CACL_RULE_SYNC_INTERVAL": 0,
        "logger": Mock(spec=logging.Logger),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("command", ["iptables -S", "ip6tables -S"])
@pytest.mark.parametrize("asic_index", [None, 0])
def test_ignored_rules_converge_without_timeout(cacl_namespace, command, asic_index):
    """Internal exceptions must be applied inside the convergence predicate."""
    host = Mock()
    host.get_asic_or_sonic_host.return_value.command.return_value = {"stdout": "expected\ninternal"}
    cacl_namespace["wait_until"] = Mock(side_effect=lambda timeout, interval, delay, check: check())

    result = cacl_namespace["wait_for_expected_rules"](
        host, asic_index, command, ["expected"], ignored_rules=["internal"])

    assert result == (set(), set(), ["expected", "internal"])
    host.get_asic_or_sonic_host.assert_called_once_with(asic_index)
    host.get_asic_or_sonic_host.return_value.command.assert_called_once_with(command)
    cacl_namespace["logger"].error.assert_not_called()


@pytest.mark.parametrize("actual,expected,ignored,missing,unexpected", [
    ("internal", ["required"], ["internal", "required"], {"required"}, set()),
    ("expected\nextra\ninternal", ["expected"], ["internal"], set(), {"extra"}),
    ("expected\ninternal", ["expected"], [], set(), {"internal"}),
])
def test_timeout_preserves_real_rule_mismatches(cacl_namespace, actual, expected, ignored, missing, unexpected):
    """Ignoring extra rules must never hide missing requirements or unrelated extras."""
    host = Mock()
    host.get_asic_or_sonic_host.return_value.command.return_value = {"stdout": actual}
    cacl_namespace["wait_until"] = Mock(side_effect=lambda timeout, interval, delay, check: check())

    result = cacl_namespace["wait_for_expected_rules"](host, None, "iptables -S", expected, ignored_rules=ignored)

    assert result == (missing, unexpected, actual.split("\n"))
    cacl_namespace["logger"].error.assert_called_once()


def test_rules_can_converge_after_transient_mismatch(cacl_namespace):
    """Keep the upstream retry behavior and return the final observed rules."""
    host = Mock()
    host.get_asic_or_sonic_host.return_value.command.side_effect = [
        {"stdout": "old\ninternal"},
        {"stdout": "expected\ninternal"},
    ]

    def poll(timeout, interval, delay, check):
        assert not check()
        return check()

    cacl_namespace["wait_until"] = Mock(side_effect=poll)
    result = cacl_namespace["wait_for_expected_rules"](
        host, None, "iptables -S", ["expected"], ignored_rules=["internal"])

    assert result == (set(), set(), ["expected", "internal"])
    assert host.get_asic_or_sonic_host.return_value.command.call_count == 2
    cacl_namespace["logger"].error.assert_not_called()


def test_nat_rules_do_not_inherit_filter_exceptions(cacl_namespace):
    """NAT callers retain strict comparison without the filter-table exceptions."""
    host = Mock()
    cacl_namespace.update(
        generate_nat_expected_rules=Mock(return_value=(["v4"], ["v6"])),
        wait_for_expected_rules=Mock(return_value=(set(), set(), [])),
        pytest_assert=Mock(),
    )

    cacl_namespace["verify_nat_cacl"](host, None, None, {}, 0)

    assert cacl_namespace["wait_for_expected_rules"].call_args_list == [
        call(host, 0, "iptables -t nat -S", ["v4"]),
        call(host, 0, "ip6tables -t nat -S", ["v6"]),
    ]


def test_filter_callers_pass_separate_ipv4_ipv6_exceptions(cacl_namespace):
    """Both filter-table callers pass their own internal exception list."""
    host = Mock()
    cacl_namespace.update(
        generate_expected_rules=Mock(return_value=(["v4"], ["v6"])),
        wait_for_expected_rules=Mock(return_value=(set(), set(), [])),
        pytest_assert=Mock(),
        ignored_iptable_rules=["internal-v4"],
        ignored_ip6table_rules=["internal-v6"],
    )

    cacl_namespace["verify_cacl"](host, {}, None, None, {}, asic_index=0)

    assert cacl_namespace["wait_for_expected_rules"].call_args_list == [
        call(host, 0, "iptables -S", ["v4"], ignored_rules=["internal-v4"]),
        call(host, 0, "ip6tables -S", ["v6"], ignored_rules=["internal-v6"]),
    ]
