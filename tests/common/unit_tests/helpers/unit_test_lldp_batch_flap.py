"""Hardware-independent regression coverage for LLDP batch-flap selection."""

import ast
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
