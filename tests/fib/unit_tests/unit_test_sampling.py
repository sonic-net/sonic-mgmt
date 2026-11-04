"""Offline regressions for topology-scoped PTF sampling budgets."""

import ast
import itertools
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, mock_open, patch

import pytest


PTF_DIR = Path(__file__).resolve().parents[3] / "ansible/roles/test/files/ptftests"


def _load_classes(path, methods):
    namespace = {
        "BaseTest": object, "Iterable": Iterable, "itertools": itertools,
        "json": json, "logging": logging,
        "ptf": SimpleNamespace(dataplane_instance=None),
    }
    tree = ast.parse(path.read_text())
    classes = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in methods:
            # Avoid PTF/Scapy imports while executing the actual setup and sampling loops.
            node.body = [
                member for member in node.body
                if isinstance(member, ast.Assign)
                or isinstance(member, ast.FunctionDef) and member.name in methods[node.name]
            ]
            classes.append(node)
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("topology,override,expected", [
    ("ft2", None, 1000),
    ("t0", None, 2500),
    (None, None, 2500),
    ("ft2", 100, 400),
])
def test_fib_sampling_preserves_other_topologies_and_overrides(topology, override, expected):
    """Reduce only the FT2 default while retaining balancing checks and explicit overrides."""
    namespace = _load_classes(PTF_DIR / "fib_test.py", {"FibTest": {"setUp", "check_balancing"}})
    test = namespace["FibTest"]()
    test.test_params = {"fib_info_files": [], "ptf_test_port_map": "ports.json", "topo_type": topology}
    if override is not None:
        test.test_params["balancing_test_times"] = override
    with patch("builtins.open", mock_open(read_data="{}")):
        test.setUp()
    next_hop = Mock()
    next_hop.get_next_hop.return_value = [[0], [1], [2], [3]]
    test.get_src_and_exp_ports = Mock(return_value=(4, [[0, 1, 2, 3]], [next_hop]))
    test.check_ip_route = Mock(return_value=(0, True))
    test.check_hit_count_map = Mock()

    test.check_balancing([Mock()], 0)

    assert test.check_ip_route.call_count == expected
    test.check_hit_count_map.assert_called_once_with([[0], [1], [2], [3]], {0: expected}, 4)


def _ipinip_test(topology, nexthops):
    namespace = _load_classes(
        PTF_DIR / "py3/hash_test.py", {"HashTest": set(), "IPinIPHashTest": {"check_hash"}}
    )
    test = namespace["IPinIPHashTest"]()
    test.topo_type = topology
    test.topo_name = topology
    test.switch_type = "voq"
    test.is_v6_topo = False
    test.balancing_test_times = test.BALANCING_TEST_TIMES
    test.get_src_and_exp_ports = Mock(return_value=(nexthops, [list(range(nexthops))], [Mock()]))
    test.check_ip_route = Mock(return_value=(0, True))
    test.check_balancing = Mock()
    return test


@pytest.mark.parametrize("topology,nexthops,expected", [
    ("ft2", 126, 1000),
    ("ft2", 2, 500),
    ("ft2", 4, 1000),
    ("t0", 6, 1500),
])
def test_ipinip_negative_sample_cap(topology, nexthops, expected):
    """Cap wide FT2 negative tests without increasing smaller budgets or changing other topologies."""
    test = _ipinip_test(topology, nexthops)

    test.check_hash("inner_length")

    assert test.check_ip_route.call_count == expected
    test.check_balancing.assert_not_called()


def test_ipinip_negative_still_rejects_changed_egress():
    """Retain the negative assertion, including a change on the final capped sample."""
    test = _ipinip_test("ft2", 126)
    test.check_ip_route.side_effect = lambda *args: (int(test.check_ip_route.call_count == 1000), True)

    with pytest.raises(AssertionError):
        test.check_hash("inner_length")

    assert test.check_ip_route.call_count == 1000


def test_ipinip_positive_hash_keeps_balancing_budget():
    """Do not apply the negative-test cap to positive FT2 hash balancing."""
    test = _ipinip_test("ft2", 6)

    test.check_hash("src-ip")

    assert test.check_ip_route.call_count == 1500
    test.check_balancing.assert_called_once()
