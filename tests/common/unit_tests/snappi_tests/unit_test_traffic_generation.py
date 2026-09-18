"""Unit test for ``_are_macsec_flows_stopped`` in
``tests/common/snappi_tests/traffic_generation.py``.

The target module imports heavy sonic-mgmt/ixnetwork_restpy deps at import
time, so we extract the function under test (and the module-level threshold
constant it reads) via ``ast`` and exec them in an isolated namespace.

Run with::

    python3 -m pytest --noconftest \\
        tests/common/unit_tests/snappi_tests/unit_test_traffic_generation.py -v
"""

import ast
from pathlib import Path

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/snappi_tests/traffic_generation.py")


def _load(*names):
    """Extract the given top-level assignments/functions from MODULE_PATH
    and exec them together in an isolated namespace, so the function under
    test can see the module-level constant(s) it depends on."""
    tree = ast.parse(MODULE_PATH.read_text())
    wanted = set(names)
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in wanted for t in node.targets):
            nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in wanted:
            nodes.append(node)
    missing = wanted - {
        n.name if isinstance(n, ast.FunctionDef) else n.targets[0].id
        for n in nodes
    }
    if missing:
        raise LookupError(missing)
    ns = {}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(MODULE_PATH), "exec"), ns)
    return ns


_NS = _load("MACSEC_FLOW_STOPPED_RATE_THRESHOLD", "_are_macsec_flows_stopped")
are_macsec_flows_stopped = _NS["_are_macsec_flows_stopped"]
MACSEC_FLOW_STOPPED_RATE_THRESHOLD = _NS["MACSEC_FLOW_STOPPED_RATE_THRESHOLD"]


@pytest.mark.parametrize("transmit_states, expected", [
    ([], False),
    ([0], True),
    ([0, 1], True),
    ([1], True),
    ([2], False),
    ([0, 500], False),
    ([1, 1, 1], True),
])
def test_are_macsec_flows_stopped(transmit_states, expected):
    assert are_macsec_flows_stopped(transmit_states) is expected


def test_threshold_boundary_is_inclusive():
    """max(transmit_states) == threshold must count as stopped (<=, not <)."""
    assert MACSEC_FLOW_STOPPED_RATE_THRESHOLD == 1
    assert are_macsec_flows_stopped([MACSEC_FLOW_STOPPED_RATE_THRESHOLD]) is True
    assert are_macsec_flows_stopped([MACSEC_FLOW_STOPPED_RATE_THRESHOLD + 1]) is False
