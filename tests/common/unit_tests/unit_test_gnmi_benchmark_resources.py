"""Exercise benchmark resource naming and ownership without a testbed.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_gnmi_benchmark_resources.py -v
"""

import ast
import fnmatch
import io
import ipaddress
import json
import shlex
import uuid
from contextlib import contextmanager, ExitStack, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "gnmi_benchmark" / "helpers.py"
RUN_ID = "deadbeef" * 4


@pytest.fixture
def helpers():
    tree = ast.parse(MODULE_PATH.read_text())
    names = {"_vnet_namespace", "route_resources", "_routes_removed", "_remove_routes", "_restore_config"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    namespace = {
        "contextmanager": contextmanager,
        "ExitStack": ExitStack,
        "ipaddress": ipaddress,
        "json": json,
        "logger": Mock(),
        "shlex": shlex,
        "uuid": SimpleNamespace(uuid4=lambda: uuid.UUID(RUN_ID)),
        "apply_gcu_patch": Mock(),
        "wait_until": Mock(return_value=True),
        "build_native_set_request": Mock(),
        "gnmi_pb2": Mock(),
        "BYPASS_METADATA": (("x-sonic-ss-bypass-validation", "true"),),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.fixture
def host():
    dut = Mock(is_multi_asic=False)
    dut.facts = {"asic_type": "cisco-8000"}
    dut.shell.return_value = {"rc": 0, "stdout": "0"}
    dut.get_running_config_facts.return_value = {
        "LOOPBACK_INTERFACE": {"Loopback0": {"10.1.0.32/32": {}}},
    }
    return dut


def redis_client(keys):
    client = Mock()
    client.scan_iter.side_effect = lambda match, **kwargs: iter(key for key in keys if fnmatch.fnmatchcase(key, match))
    client.exists.side_effect = lambda key: int(key in keys)
    client.delete.side_effect = lambda *deleted: keys.difference_update(deleted)
    return client


def run_redis_command(command, client, state_client=None):
    executable, option, script = shlex.split(command)
    assert (executable, option) == ("python3", "-c")
    output = io.StringIO()
    clients = {4: client, 6: state_client}
    redis_factory = Mock(side_effect=lambda **kwargs: clients[kwargs["db"]])
    with patch.dict("sys.modules", {"redis": SimpleNamespace(Redis=redis_factory)}):
        with redirect_stdout(output):
            exec(script, {})
    return {"rc": 0, "stdout": output.getvalue()}


@pytest.mark.parametrize("vnet_count", [1, 10, 11, 13, 100, 101, 1000, 1001, 10000, 10001, 100000, 100001, 256000])
def test_names_fit_linux_interface_limit(helpers, vnet_count):
    namespace = helpers["_vnet_namespace"](RUN_ID, vnet_count)
    names = {"{}_{}".format(namespace, index) for index in range(vnet_count)}
    assert namespace.startswith("Vnet")
    assert len(names) == vnet_count
    assert max(len(name.encode("ascii")) for name in names) <= 15


@pytest.mark.parametrize("asic_type", ["cisco-8000", "mellanox", None])
def test_resource_paths_share_bounded_namespace_and_keep_full_backup_id(helpers, host, asic_type):
    host.facts = {"asic_type": asic_type}
    stub = Mock()
    stub.Set.return_value = SimpleNamespace(message=SimpleNamespace(code=0), response=[])
    namespace = helpers["_vnet_namespace"](RUN_ID, 13)
    expected_vnets = {"{}_{}".format(namespace, index) for index in range(13)}

    with helpers["route_resources"](host, {1: 13}, 1, stub, 120) as prepared:
        assert len(prepared) == 13
        patch_items = helpers["apply_gcu_patch"].call_args.args[1]
        tunnel = next(item["value"] for item in patch_items if item["path"].startswith("/VXLAN_TUNNEL/"))
        assert tunnel == ({"src_ip": "10.1.0.32", "ttl_mode": "pipe"} if asic_type == "cisco-8000"
                          else {"src_ip": "10.1.0.32"})
        assert {item["path"][len("/VNET/"):] for item in patch_items
                if item["path"].startswith("/VNET/")} == expected_vnets
        writes = helpers["build_native_set_request"].call_args_list
        assert {key.split("|")[0] for write in writes for key in write.args[1]} == expected_vnets
        assert all(write.args[0] == ("CONFIG_DB", "localhost", "VNET_ROUTE_TUNNEL") for write in writes)
        assert stub.Set.call_count == 13

    host.shell.assert_any_call("cp -a /etc/sonic/config_db.json /tmp/VnetBenchmark" + RUN_ID + ".config_db.json")
    commands = [call.args[0] for call in host.shell.call_args_list]
    assert any("VNET_ROUTE_TUNNEL|" + namespace + "_*" in command for command in commands)
    assert any("--remove-destination" in command and RUN_ID in command for command in commands)


@pytest.mark.parametrize("resource", ["route", "vnet", "tunnel"])
def test_namespace_collision_aborts_before_mutation(helpers, host, resource):
    namespace = helpers["_vnet_namespace"](RUN_ID, 13)
    key = {
        "route": "VNET_ROUTE_TUNNEL|" + namespace + "_0|198.18.0.0/32",
        "vnet": "VNET|" + namespace + "_99",
        "tunnel": "VXLAN_TUNNEL|Tunnel" + namespace,
    }[resource]
    keys = {key}
    client = redis_client(keys)
    host.shell.side_effect = lambda command: run_redis_command(command, client)
    stub = Mock()

    with pytest.raises(ValueError, match="overlaps existing resources"):
        with helpers["route_resources"](host, {1: 13}, 1, stub, 120):
            pytest.fail("A colliding namespace must not be used")

    assert keys == {key}
    helpers["apply_gcu_patch"].assert_not_called()
    stub.Set.assert_not_called()
    client.delete.assert_not_called()
    assert host.shell.call_count == 2


def test_namespace_read_failure_aborts_before_mutation(helpers, host):
    host.shell.side_effect = [{"rc": 0, "stdout": "0"}, {"rc": 1, "stdout": ""}]
    with pytest.raises(RuntimeError, match="Unable to check generated benchmark namespace"):
        with helpers["route_resources"](host, {1: 13}, 1, Mock(), 120):
            pytest.fail("A failed namespace check must not be ignored")
    helpers["apply_gcu_patch"].assert_not_called()
    assert host.shell.call_count == 2


def test_cleanup_preserves_neighboring_namespaces(helpers, host):
    namespace = helpers["_vnet_namespace"](RUN_ID, 13)
    tunnel = "Tunnel" + namespace
    owned = {
        "VNET_ROUTE_TUNNEL|" + namespace + "_0|198.18.0.0/32",
        "VNET|" + namespace + "_0",
        "VXLAN_TUNNEL|" + tunnel,
    }
    unrelated = {
        "VNET_ROUTE_TUNNEL|" + namespace + "a_0|198.18.0.0/32",
        "VNET|" + namespace + "a_0",
        "VXLAN_TUNNEL|" + tunnel + "a",
    }
    keys = owned | unrelated
    client = redis_client(keys)
    host.shell.side_effect = lambda command, **kwargs: run_redis_command(command, client)

    def drained(timeout, interval, delay, condition, actual_host, name):
        assert (timeout, interval, delay) == (600, 5, 0)
        assert (condition, actual_host, name) == (helpers["_routes_removed"], host, namespace)
        assert keys == unrelated | {"VNET|" + namespace + "_0", "VXLAN_TUNNEL|" + tunnel}
        return True

    helpers["wait_until"].side_effect = drained
    helpers["_remove_routes"](host, namespace, tunnel)

    helpers["wait_until"].assert_called_once()
    assert keys == unrelated


@pytest.mark.parametrize("route_present,db,flags,omem,expected", [
    (False, "4", "PU", "0", True),
    (True, "4", "PU", "0", False),
    (False, "4", "PU", "1048576", False),
    (True, "4", "PU", "1048576", False),
    (False, "6", "PU", "1048576", True),
    (False, "4", "U", "1048576", True),
])
def test_cleanup_requires_owned_state_and_config_notifications_to_drain(
        helpers, host, route_present, db, flags, omem, expected):
    namespace = helpers["_vnet_namespace"](RUN_ID, 13)
    keys = {"VNET_ROUTE_TUNNEL_TABLE|" + namespace + "a_0|198.18.0.0/32"}
    if route_present:
        keys.add("VNET_ROUTE_TUNNEL_TABLE|" + namespace + "_0|198.18.0.0/32")
    client = redis_client(set())
    client.client_list.return_value = [{"db": db, "flags": flags, "omem": omem}]
    state_client = redis_client(keys)
    host.shell.side_effect = lambda command, **kwargs: run_redis_command(command, client, state_client)

    assert helpers["_routes_removed"](host, namespace) is expected
    client.delete.assert_not_called()
    state_client.delete.assert_not_called()


def test_cleanup_read_failure_is_not_success(helpers, host):
    host.shell.return_value = {"rc": 1, "stdout": ""}
    with pytest.raises(RuntimeError, match="Unable to check generated route cleanup"):
        helpers["_routes_removed"](host, "Vnetdeadbeef")


def test_cleanup_timeout_preserves_dependencies_and_restores_backup(helpers, host):
    helpers["wait_until"].return_value = False
    stub = Mock()
    stub.Set.return_value = SimpleNamespace(message=SimpleNamespace(code=0), response=[])

    with pytest.raises(RuntimeError, match="did not drain"):
        with helpers["route_resources"](host, {1: 1}, 1, stub, 120):
            pass

    commands = [call.args[0] for call in host.shell.call_args_list]
    assert not any("vnets=list(" in command for command in commands)
    assert any("--remove-destination" in command and RUN_ID in command for command in commands)


@pytest.mark.parametrize("failure", ["preload", "workload"])
def test_failure_still_cleans_resources_and_restores_backup(helpers, host, failure):
    stub = Mock()
    stub.Set.return_value = SimpleNamespace(message=SimpleNamespace(code=int(failure == "preload")), response=[])

    with pytest.raises(RuntimeError, match="Route preload failed|workload failed"):
        with helpers["route_resources"](host, {1: 1}, 1, stub, 120):
            raise RuntimeError("workload failed")

    helpers["wait_until"].assert_called_once()
    commands = [call.args[0] for call in host.shell.call_args_list]
    assert any("vnets=list(" in command for command in commands)
    assert any("--remove-destination" in command and RUN_ID in command for command in commands)
