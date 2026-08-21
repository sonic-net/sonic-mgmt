"""Unit tests for sanity-check BGP recovery selection.

Run with::

    python3 -m pytest --noconftest \
        tests/common/unit_tests/plugins/sanity_check/unit_test_recover.py -v
"""

import ast
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3]
               / "plugins" / "sanity_check" / "recover.py")


def _load_recover_bgp():
    """Load the BGP helper without importing integration dependencies."""
    tree = ast.parse(MODULE_PATH.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_recover_bgp"
    )
    namespace = {
        "logging": logging,
        "neighbor_vm_restore": MagicMock(return_value="config_reload"),
        "re_announce_routes": MagicMock(return_value=None),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.fixture
def recover_bgp():
    """Return the helper and fresh dependency mocks."""
    namespace = _load_recover_bgp()
    return namespace["_recover_bgp"], namespace


def _make_inputs():
    dut = MagicMock()
    dut.hostname = "dut"
    dut.facts = {"num_asic": 1}
    ptfhost = MagicMock()
    localhost = MagicMock()
    nbrhosts = {"neighbor-a": MagicMock(), "neighbor-b": MagicMock()}
    tbinfo = {"topo": {"name": "t1-lag"}, "ptf_ip": "10.250.0.106"}
    return ptfhost, dut, localhost, nbrhosts, tbinfo


def test_missing_bgp_details_falls_back_to_config_reload(recover_bgp):
    """Unavailable BGP facts must not raise KeyError during recovery."""
    helper, namespace = recover_bgp
    ptfhost, dut, localhost, nbrhosts, tbinfo = _make_inputs()

    action = helper(
        ptfhost,
        dut,
        localhost,
        nbrhosts,
        tbinfo,
        {"failed": True, "check_item": "bgp", "host": "dut"},
    )

    assert action == "config_reload"
    namespace["re_announce_routes"].assert_not_called()
    namespace["neighbor_vm_restore"].assert_not_called()


@pytest.mark.parametrize("bgp_result", [
    {"no_v4_default_route": True},
    {"no_v6_default_route": True},
    {"no_v4_default_route": True, "no_v6_default_route": True},
])
def test_default_route_only_failure_reannounces_routes(
        recover_bgp, bgp_result):
    """Default-route-only failures retain the lightweight route recovery."""
    helper, namespace = recover_bgp
    ptfhost, dut, localhost, nbrhosts, tbinfo = _make_inputs()
    result = {
        "failed": True,
        "check_item": "bgp",
        "host": "dut",
        "bgp": bgp_result,
    }

    action = helper(ptfhost, dut, localhost, nbrhosts, tbinfo, result)

    assert action is None
    namespace["re_announce_routes"].assert_called_once_with(
        ptfhost,
        localhost,
        "t1-lag",
        "10.250.0.106",
        2,
    )
    namespace["neighbor_vm_restore"].assert_not_called()


def test_neighbor_failure_uses_existing_neighbor_restore(recover_bgp):
    """Neighbor failures retain the existing neighbor restoration path."""
    helper, namespace = recover_bgp
    ptfhost, dut, localhost, nbrhosts, tbinfo = _make_inputs()
    result = {
        "failed": True,
        "check_item": "bgp",
        "host": "dut",
        "bgp": {"down_neighbors": ["10.0.0.1"]},
    }

    action = helper(ptfhost, dut, localhost, nbrhosts, tbinfo, result)

    assert action == "config_reload"
    namespace["neighbor_vm_restore"].assert_called_once_with(
        dut, nbrhosts, tbinfo, result
    )
    namespace["re_announce_routes"].assert_not_called()
