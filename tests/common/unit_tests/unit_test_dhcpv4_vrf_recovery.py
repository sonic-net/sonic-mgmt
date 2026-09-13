"""Exercise the VRF recovery fixture without importing testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_dhcpv4_vrf_recovery.py -v
"""

import ast
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "dhcp_relay" / "test_dhcpv4_relay.py"
TRANSIENT_ERRORS = [
    "ERR monit[883]: 'routeCheck' status failed (255)",
    "ERR route_check.py: Some routes have failed state in FRR",
    "ERR route_check.py: Some routes are not set offloaded in FRR",
]


@pytest.fixture
def recovery_context():
    tree = ast.parse(MODULE_PATH.read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "frr_recovery_after_vrf_unbind")
    function.decorator_list = []
    namespace = {"logger": Mock(), "wait_until": Mock()}
    # Execute the real fixture generator, without SONiC integration imports.
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    namespace["wait_until"].side_effect = lambda timeout, interval, delay, predicate: predicate()
    dut = Mock(hostname="dut")
    dut.shell.return_value = {"rc": 0}
    return namespace, dut


@pytest.mark.parametrize("route_check_rc", [0, 1])
def test_transient_ignores_survive_recovery_teardown(recovery_context, route_check_rc):
    namespace, dut = recovery_context
    dut.shell.return_value = {"rc": route_check_rc}
    analyzer = SimpleNamespace(ignore_regex=[r"existing unrelated ignore"])
    other_analyzer = SimpleNamespace(ignore_regex=[r"other DUT ignore"])
    original_list = analyzer.ignore_regex
    fixture = namespace["frr_recovery_after_vrf_unbind"](
        {"dut": dut}, "dut", {"dut": analyzer, "other": other_analyzer})

    next(fixture)
    dut.shell.assert_not_called()
    analyzer.ignore_regex.append(r"ignore added during test")
    with pytest.raises(StopIteration):
        next(fixture)

    # Model the later LogAnalyzer scan with no global routeCheck suppression.
    for message in TRANSIENT_ERRORS:
        assert any(re.search(pattern, message) for pattern in analyzer.ignore_regex)
    assert not any(re.search(pattern, "ERR unexpected failure") for pattern in analyzer.ignore_regex)
    assert analyzer.ignore_regex is original_list
    assert analyzer.ignore_regex[0] == r"existing unrelated ignore"
    assert analyzer.ignore_regex[-1] == r"ignore added during test"
    assert other_analyzer.ignore_regex == [r"other DUT ignore"]
    assert dut.shell.call_args_list == [
        call("sudo config bgp shutdown all", module_ignore_errors=True),
        call("sudo config bgp startup all", module_ignore_errors=True),
        call("sudo /usr/local/bin/route_check.py", module_ignore_errors=True),
    ]
    assert namespace["wait_until"].call_count == 1
    assert namespace["wait_until"].call_args.args[:3] == (180, 5, 0)
    assert namespace["logger"].warning.call_count == (1 if route_check_rc else 0)


@pytest.mark.parametrize("analyzers", [None, {}, {"other": SimpleNamespace(ignore_regex=[])}])
def test_recovery_without_selected_loganalyzer(recovery_context, analyzers):
    namespace, dut = recovery_context
    fixture = namespace["frr_recovery_after_vrf_unbind"]({"dut": dut}, "dut", analyzers)
    next(fixture)
    with pytest.raises(StopIteration):
        next(fixture)
    assert dut.shell.call_args_list == [
        call("sudo config bgp shutdown all", module_ignore_errors=True),
        call("sudo config bgp startup all", module_ignore_errors=True),
        call("sudo /usr/local/bin/route_check.py", module_ignore_errors=True),
    ]
    if analyzers:
        assert analyzers["other"].ignore_regex == []


def test_recovery_exception_propagates_without_removing_ignores(recovery_context):
    namespace, dut = recovery_context
    analyzer = SimpleNamespace(ignore_regex=[])
    fixture = namespace["frr_recovery_after_vrf_unbind"]({"dut": dut}, "dut", {"dut": analyzer})
    next(fixture)
    dut.shell.side_effect = RuntimeError("DUT connection failed")
    with pytest.raises(RuntimeError, match="DUT connection failed"):
        next(fixture)
    for message in TRANSIENT_ERRORS:
        assert any(re.search(pattern, message) for pattern in analyzer.ignore_regex)
    namespace["wait_until"].assert_not_called()
