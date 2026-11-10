"""Check seven-node addressing preflight and fixture cleanup without a DUT."""
import ast
import copy
import ipaddress
import json
import logging
from pathlib import Path
import shlex
import types

import pytest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "tests/isis/test_isis_cli_force10.py"


def load_setup():
    tree = ast.parse(SOURCE.read_text())
    tree.body = [node for node in tree.body
                 if not (isinstance(node, ast.ImportFrom) and node.module.startswith("tests.common"))]
    assertions = {}
    exec(compile((ROOT / "tests/common/helpers/assertions.py").read_text(), "assertions.py", "exec"), assertions)
    namespace = {"__name__": "force10_setup_under_test", "pytest_assert": assertions["pytest_assert"],
                 "wait_until": lambda *args: True, "logging": logging}
    exec(compile(tree, str(SOURCE), "exec"), namespace)
    return types.SimpleNamespace(**namespace)


class Node:
    def __init__(self, name, fail_at=None, counter=None):
        self.hostname = name
        self.rows = json.loads((ROOT / "ansible/vars/configdb_jsons/7nodes_force10" /
                                (name + ".json")).read_text())["INTERFACE"]
        self.calls = []
        self.fail_at = fail_at
        self.counter = counter if counter is not None else [0]

    def shell(self, command, **kwargs):
        self.calls.append(command)
        if "--var-json INTERFACE" in command:
            return {"rc": 0, "stdout": json.dumps(self.rows)}
        if "sonic-db-cli" in command:
            return {"rc": 0, "stdout": "true"}
        words = shlex.split(command)
        if words[:4] == ["sudo", "config", "interface", "ip"]:
            key = words[5] + "|" + words[6]
            if words[4] == "add":
                self.rows[key] = {}
                self.counter[0] += 1
                if self.counter[0] == self.fail_at:
                    return {"rc": 1, "stdout": "injected uncertain reply after write"}
            else:
                self.rows.pop(key, None)
        return {"rc": 0, "stdout": ""}


def nodes_for(module, fail_at=None):
    counter = [0]
    return {name: Node(name, fail_at, counter) for name in module.NODE_NETS}


def test_address_plan_follows_all_twelve_existing_ipv6_links():
    module = load_setup()
    nodes = nodes_for(module)
    plan = module._ipv4_underlay_plan(nodes)
    assert len(plan) == 24
    assert {(name, port) for name, port, _ in plan} == {
        (name, port) for name, ports in module.NODE_INTERFACES.items() for port in ports}
    for endpoints in module.FABRIC_LINKS:
        networks = []
        for name, port in endpoints:
            networks.append({ipaddress.ip_interface(key.split("|", 1)[1].strip()).network
                             for key in nodes[name].rows if key.startswith(port + "|")})
        assert networks[0] & networks[1], endpoints
    for node in nodes.values():
        assert all("--var-json INTERFACE" in command for command in node.calls)


def test_preexisting_exact_address_is_not_owned_by_fixture():
    module = load_setup()
    nodes = nodes_for(module)
    nodes["P1"].rows["Ethernet112|198.19.0.0/31"] = {}
    assert len(module._ipv4_underlay_plan(nodes)) == 23


def test_conflicting_address_on_unrelated_node_rejects_before_writes():
    module = load_setup()
    nodes = nodes_for(module)
    nodes["PE3"].rows["Ethernet24|198.19.0.0/24"] = {}
    with pytest.raises(pytest.fail.Exception, match="conflicts"):
        module._ipv4_underlay_plan(nodes)
    assert all("--var-json INTERFACE" in command for node in nodes.values() for command in node.calls)


@pytest.mark.parametrize("fail_at", [None, 1, 12, 23])
def test_fixture_restores_only_its_addresses_after_success_or_uncertain_failure(fail_at):
    module = load_setup()
    nodes = nodes_for(module, fail_at)
    nodes["P1"].rows["Ethernet112|198.19.0.0/31"] = {}
    before = {name: copy.deepcopy(node.rows) for name, node in nodes.items()}
    fixture = module.isis_force10_fabric.__wrapped__(
        nodes["P1"], {name: {"host": node} for name, node in nodes.items() if name != "P1"})
    if fail_at is None:
        assert next(fixture) == nodes
        with pytest.raises(StopIteration):
            next(fixture)
    else:
        with pytest.raises(pytest.fail.Exception, match="injected uncertain reply"):
            next(fixture)
    assert {name: node.rows for name, node in nodes.items()} == before


@pytest.mark.parametrize("protocol,selected,installed,fib,expected", [
    ("isis", True, True, True, True),
    ("isis", False, False, False, False),
    ("bgp", True, True, True, False),
    ("isis", True, False, True, False),
    ("isis", True, True, False, False),
])
def test_forwarding_requires_selected_installed_isis_path(protocol, selected, installed, fib, expected):
    module = load_setup()
    prefix = "2064:300::1f/128"
    route = {"protocol": protocol, "selected": selected, "installed": installed,
             "nexthops": [{"active": True, "fib": fib}]}
    node = types.SimpleNamespace(shell=lambda *args, **kwargs: {
        "rc": 0, "stdout": json.dumps({prefix: [route]})})
    assert module._route_is_installed(node, prefix) == expected


@pytest.mark.parametrize("fail", [False, True])
def test_bgp_endpoint_suppression_restores_original_values(fail):
    module = load_setup()
    state = {"P1": "true", "PE3": "false"}
    calls = []

    def host(name):
        def shell(command, **kwargs):
            calls.append((name, command))
            if " HSET " in command:
                state[name] = command.split()[-1]
            return {"rc": 0, "stdout": state[name]}
        return types.SimpleNamespace(shell=shell)

    nodes = {name: host(name) for name in state}
    try:
        with module._isis_forwarding_only(nodes):
            assert state == {"P1": "false", "PE3": "false"}
            if fail:
                raise RuntimeError("injected forwarding assertion failure")
    except RuntimeError:
        assert fail
    assert state == {"P1": "true", "PE3": "false"}
    assert not any(name == "PE3" and " HSET " in command for name, command in calls)


def test_bgp_restore_failure_still_attempts_other_endpoint():
    module = load_setup()
    state = {"P1": "true", "PE3": "true"}
    restored = []

    def host(name):
        def shell(command, **kwargs):
            if " HSET " in command:
                value = command.split()[-1]
                if value == "true":
                    restored.append(name)
                    if name == "PE3":
                        return {"rc": 1, "stdout": "injected restore failure"}
                state[name] = value
            return {"rc": 0, "stdout": state[name]}
        return types.SimpleNamespace(shell=shell)

    with pytest.raises(pytest.fail.Exception, match="PE3"):
        with module._isis_forwarding_only({name: host(name) for name in state}):
            assert set(state.values()) == {"false"}
    assert restored == ["PE3", "P1"]
    assert state["P1"] == "true"


def test_failed_native_route_command_is_not_success_even_with_json():
    module = load_setup()
    prefix = "100.1.0.31/32"
    route = {"protocol": "isis", "selected": True, "installed": True,
             "nexthops": [{"active": True, "fib": True}]}
    node = types.SimpleNamespace(shell=lambda *args, **kwargs: {
        "rc": 1, "stdout": json.dumps({prefix: [route]})})
    assert not module._route_is_installed(node, prefix)
