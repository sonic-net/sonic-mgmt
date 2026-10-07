"""Exercise dual-ToR neighbor polling without importing testbed dependencies."""

import ast
from ipaddress import ip_address
from pathlib import Path
import sys
import traceback
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


TESTS_DIR = Path(__file__).resolve().parents[2]


def _assert(condition):
    assert condition


@pytest.fixture
def arp_namespace():
    clock = SimpleNamespace(now=0)

    def sleep(seconds):
        clock.now += seconds

    namespace = {
        "ip_address": ip_address, "logger": Mock(), "pytest": pytest,
        "pytest_assert": _assert, "REACHABLE": "REACHABLE",
        "sys": sys, "traceback": traceback,
        "time": SimpleNamespace(time=lambda: clock.now, sleep=sleep),
    }
    sources = [
        (TESTS_DIR / "common" / "utilities.py", {"wait_until"}),
        (TESTS_DIR / "arp" / "test_arp_dualtor.py",
         {"verify_neighbor_status", "test_standby_unsolicited_neigh_learning"}),
    ]
    # Execute the production functions while isolating Linux and testbed imports.
    for path, names in sources:
        tree = ast.parse(path.read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        assert {node.name for node in functions} == names
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    namespace["wait_until"] = Mock(wraps=namespace["wait_until"])
    return namespace, clock


@pytest.fixture(params=["192.0.2.1", "2001:db8::1"])
def neighbor(request):
    address = ip_address(request.param)
    family = "v4" if address.version == 4 else "v6"
    return address, family


def _arptable(address, family, state):
    table = {"v4": {}, "v6": {}}
    if state is not None:
        table[family][str(address)] = {"state": state}
    return {"ansible_facts": {"arptable": table}}


def test_missing_neighbor_returns_false(arp_namespace, neighbor):
    namespace, _ = arp_namespace
    address, family = neighbor
    dut = Mock(hostname="standby")
    dut.switch_arptable.return_value = _arptable(address, family, None)

    assert namespace["verify_neighbor_status"](dut, address, "REACHABLE") is False
    namespace["logger"].debug.assert_called_once_with(
        "Neighbor %s is not present on %s", address, "standby")
    namespace["logger"].error.assert_not_called()


@pytest.mark.parametrize("state,expected,result", [
    ("reachable", "REACHABLE", True),
    ("STALE", "REACHABLE", False),
    ("FAILED", "FAILED", True),
    ("INCOMPLETE", "INCOMPLETE", True),
])
def test_existing_neighbor_status_is_preserved(arp_namespace, neighbor, state, expected, result):
    namespace, _ = arp_namespace
    address, family = neighbor
    dut = Mock()
    dut.switch_arptable.return_value = _arptable(address, family, state)

    assert namespace["verify_neighbor_status"](dut, str(address), expected) is result


def test_neighbor_command_failure_propagates(arp_namespace, neighbor):
    namespace, _ = arp_namespace
    address, _ = neighbor
    dut = Mock()
    dut.switch_arptable.side_effect = RuntimeError("neighbor query failed")

    with pytest.raises(RuntimeError, match="neighbor query failed"):
        namespace["verify_neighbor_status"](dut, address, "REACHABLE")


@pytest.mark.parametrize("missing", ["family", "state"])
def test_malformed_neighbor_result_is_not_treated_as_missing(arp_namespace, neighbor, missing):
    namespace, _ = arp_namespace
    address, family = neighbor
    data = _arptable(address, family, "REACHABLE")
    if missing == "family":
        del data["ansible_facts"]["arptable"][family]
    else:
        del data["ansible_facts"]["arptable"][family][str(address)]["state"]
    dut = Mock()
    dut.switch_arptable.return_value = data

    with pytest.raises(KeyError):
        namespace["verify_neighbor_status"](dut, address, "REACHABLE")


@pytest.mark.parametrize("ready_at", [0, 7])
def test_standby_learning_allows_delayed_neighbor_and_exits_early(arp_namespace, neighbor, ready_at):
    namespace, clock = arp_namespace
    address, family = neighbor
    active = Mock()
    standby = Mock(hostname="standby", facts={"asic_type": "vpp"})
    active.switch_arptable.return_value = _arptable(address, family, "REACHABLE")
    standby.switch_arptable.side_effect = lambda: _arptable(
        address, family, "REACHABLE" if clock.now >= ready_at else None)

    namespace["test_standby_unsolicited_neigh_learning"](
        None, (None, address, "active-active"), None, None, active, standby, None)

    assert clock.now == ready_at
    assert [call.args[:3] for call in namespace["wait_until"].call_args_list] == [(5, 1, 0), (10, 1, 0)]
    active.shell.assert_any_call("docker exec -t swss supervisorctl start arp_update")
    standby.shell.assert_called_once_with("sudo ip neigh flush all")
    namespace["logger"].error.assert_not_called()


@pytest.mark.parametrize("state", [None, "STALE"])
def test_standby_learning_still_requires_reachable(arp_namespace, neighbor, state):
    namespace, clock = arp_namespace
    address, family = neighbor
    active = Mock()
    standby = Mock(hostname="standby", facts={"asic_type": "vpp"})
    active.switch_arptable.return_value = _arptable(address, family, "REACHABLE")
    standby.switch_arptable.return_value = _arptable(address, family, state)

    with pytest.raises(AssertionError):
        namespace["test_standby_unsolicited_neigh_learning"](
            None, (None, address, "active-active"), None, None, active, standby, None)

    assert clock.now == 10
    namespace["logger"].error.assert_not_called()
