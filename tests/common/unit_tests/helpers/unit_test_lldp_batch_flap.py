"""Hardware-independent regression coverage for LLDP flap behavior."""

import ast
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


@pytest.mark.parametrize("is_multi_asic", [False, True])
def test_batch_flap_preserves_platform_selection_and_management_coverage(is_multi_asic):
    """Batch single-ASIC ports, retain per-port multi-ASIC flaps, and never flap eth0."""
    source_path = Path(__file__).resolve().parents[3] / "lldp" / "test_lldp_syncd.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "test_lldp_entry_table_after_all_batched_flap"
    )
    module = ast.Module(body=[function], type_ignores=[])
    namespace_id = "0" if is_multi_asic else None
    ports = ["Ethernet0", "Ethernet4"]
    baseline = {"eth0", *ports}
    shutdown = Mock()
    convergence = Mock()
    groups = Mock(return_value={namespace_id: ports})
    duthost = SimpleNamespace(
        is_multi_asic=is_multi_asic,
        get_bgp_neighbors=lambda: {},
        check_bgp_session_state=Mock(return_value=True),
    )
    namespace = {
        "logger": Mock(),
        "group_interfaces_by_asic": groups,
        "_shutdown_startup_interface": shutdown,
        "wait_for_lldp_convergence": convergence,
        "LLDP_RECOVERY_NEIGHBOR_TIMEOUT": 90,
        "wait_until": Mock(return_value=True),
        "pytest_assert": Mock(),
    }
    exec(compile(module, str(source_path), "exec"), namespace)
    database = object()
    namespace[function.name]({"dut": duthost}, "dut", database, baseline, None)

    groups.assert_called_once_with(duthost, ports)
    expected_ports = ports if is_multi_asic else [",".join(ports)]
    assert shutdown.call_args_list == [
        call(duthost, port, namespace_id) for port in expected_ports
    ]
    assert convergence.call_count == 2
    assert all(args.args[:3] == (duthost, database, baseline) for args in convergence.call_args_list)
    namespace["wait_until"].assert_called_once_with(300, 10, 30, duthost.check_bgp_session_state, [])


@pytest.mark.parametrize(
    "test_name,ignore_timeout,ignore_status",
    [
        ("test_lldp_entry_table_content", False, False),
        ("test_lldp_entry_table_after_syncd_orchagent", False, False),
        ("test_lldp_entry_table_after_cont_flap", True, True),
        ("test_lldp_entry_table_after_all_batched_flap", True, True),
        ("test_lldp_entry_table_after_lldp_restart", False, True),
        ("test_lldp_entry_table_after_reboot", False, False),
    ],
)
def test_routecheck_timeout_suppression_is_limited_to_flap_tests(test_name, ignore_timeout, ignore_status):
    """Exercise each test's actual fixture chain without importing hardware dependencies."""
    source_path = Path(__file__).resolve().parents[3] / "lldp" / "test_lldp_syncd.py"
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    fixtures = {
        name: function for name, function in functions.items()
        if any(isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
               and decorator.func.attr == "fixture" for decorator in function.decorator_list)
    }
    namespace = {}
    for function in fixtures.values():
        function.decorator_list = []
    exec(compile(ast.Module(body=list(fixtures.values()), type_ignores=[]), str(source_path), "exec"), namespace)
    analyzers = {name: SimpleNamespace(ignore_regex=[]) for name in ("dut-a", "dut-b")}
    values = {
        "duthosts": [SimpleNamespace(hostname=name) for name in analyzers],
        "loganalyzer": analyzers,
    }

    def request_fixture(name):
        if name not in values:
            function = fixtures[name]
            values[name] = namespace[name](**{
                arg.arg: request_fixture(arg.arg) for arg in function.args.args
            })
        return values[name]

    for arg in functions[test_name].args.args:
        if arg.arg.startswith("ignore_") and arg.arg in fixtures:
            request_fixture(arg.arg)

    for analyzer in analyzers.values():
        patterns = analyzer.ignore_regex
        timeout = "ERR monit[915]: 'routeCheck' program timed out after 5.017 m. Killing program with pid 123113"
        status = "ERR monit[915]: 'routeCheck' status failed (1)"
        assert any(re.search(pattern, timeout) for pattern in patterns) == ignore_timeout
        assert any(re.search(pattern, status) for pattern in patterns) == ignore_status
        assert not any(re.search(pattern, "ERR monit[915]: 'otherCheck' program timed out") for pattern in patterns)
