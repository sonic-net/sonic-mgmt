"""Exercise benchmark resource ownership without DUT or gRPC dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_gnmi_benchmark_resources.py -v
"""

import ast
import fnmatch
import ipaddress
import json
import shlex
import sys
import uuid
from contextlib import contextmanager, ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "gnmi_benchmark" / "helpers.py"
RUN_ID = "0123456789abcdef0123456789abcdef"
NEXT_RUN_ID = "fedcba9876543210fedcba9876543210"


class Messages(list):
    def add(self, **kwargs):
        message = SimpleNamespace(elem=Messages(), **kwargs)
        self.append(message)
        return message


class GetRequest:
    ALL = 0

    def __init__(self, **kwargs):
        self.path = Messages()


@pytest.fixture
def helpers(monkeypatch):
    tree = ast.parse(MODULE_PATH.read_text())
    names = {"_route_namespace", "route_resources", "_remove_routes", "_restore_config"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == names
    namespace = {
        "ipaddress": ipaddress, "json": json, "shlex": shlex, "uuid": uuid,
        "contextmanager": contextmanager, "ExitStack": ExitStack,
        "gnmi_pb2": SimpleNamespace(GetRequest=GetRequest, JSON_IETF=4),
        "BYPASS_METADATA": (("x-sonic-ss-bypass-validation", "true"),),
        "apply_gcu_patch": Mock(),
        "build_native_set_request": lambda parts, payload: SimpleNamespace(parts=parts, payload=payload),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    monkeypatch.setattr(uuid, "uuid4", Mock(return_value=SimpleNamespace(hex=RUN_ID)))
    return namespace


@pytest.mark.parametrize("count", [1, 10, 11, 13, 100, 101, 1000, 1001, 10000, 10001, 100000, 100001, 256000])
def test_names_fit_linux_limit_for_entire_inventory(helpers, count):
    namespace, artifact = helpers["_route_namespace"]({}, count, [])
    names = {"{}_{}".format(namespace, index) for index in range(count)}
    assert len(names) == count
    assert all(name.isascii() and len(name.encode("ascii")) <= 15 for name in names)
    assert all(name.startswith("Vnet") for name in names)
    assert artifact == "VnetBenchmark" + RUN_ID


@pytest.mark.parametrize("count", [0, -1, 256001])
def test_invalid_inventory_is_rejected(helpers, count):
    with pytest.raises(ValueError, match="VNET count"):
        helpers["_route_namespace"]({}, count, [])
    uuid.uuid4.assert_not_called()


@pytest.mark.parametrize("table", ["VNET", "VRF", "VNET_ROUTE", "VNET_ROUTE_TUNNEL", "VXLAN_TUNNEL", "link"])
def test_collisions_retry_before_selecting_names(helpers, table):
    # Reject the entire occupied namespace, even an index outside this run.
    existing = "Vnet01234567_999"
    facts = {table: {existing: {}}}
    links = []
    if table == "VXLAN_TUNNEL":
        facts = {table: {"TunnelVnetBenchmark" + RUN_ID: {}}}
    elif table == "link":
        facts = {}
        links = [existing]
    uuid.uuid4.side_effect = [SimpleNamespace(hex=RUN_ID), SimpleNamespace(hex=NEXT_RUN_ID)]
    assert helpers["_route_namespace"](facts, 13, links) == (
        "Vnetfedcba98", "VnetBenchmark" + NEXT_RUN_ID)
    assert uuid.uuid4.call_count == 2


def test_namespace_exhaustion_fails_explicitly(helpers):
    with pytest.raises(RuntimeError, match="unused benchmark VNET namespace"):
        helpers["_route_namespace"]({"VNET": {"Vnet01234567_0": {}}}, 13, [])
    assert uuid.uuid4.call_count == 10


@pytest.mark.parametrize("count", [1, 13, 501, 256000])
def test_cleanup_deletes_only_exact_owned_keys(helpers, monkeypatch, count):
    namespace = "Vnetabcd"
    tunnel = "TunnelVnetBenchmark" + RUN_ID
    owned = {"{}_{}".format(namespace, index) for index in range(count)}
    preserved = {
        "VNET|Vnetabcd_00", "VNET|Vnetabcd_999999", "VNET|Vnetabcde_0",
        "VNET_ROUTE_TUNNEL|Vnetabcd_00|198.18.0.0/32",
        "VNET_ROUTE_TUNNEL|Vnetabcd_999999|198.18.0.0/32",
        "VNET_ROUTE_TUNNEL|Vnetabcde_0|198.18.0.0/32",
        "VXLAN_TUNNEL|" + tunnel + "_other",
    }
    keys = preserved | {"VNET|" + name for name in owned}
    keys.update("VNET_ROUTE_TUNNEL|{}|198.18.0.0/32".format(name) for name in owned)
    keys.add("VXLAN_TUNNEL|" + tunnel)
    deleted = []

    def delete(*batch):
        deleted.append(batch)
        keys.difference_update(batch)

    redis = Mock()
    redis.scan_iter.side_effect = lambda match: iter([key for key in keys if fnmatch.fnmatchcase(key, match)])
    redis.delete.side_effect = delete
    constructor = Mock(return_value=redis)
    monkeypatch.setitem(sys.modules, "redis", SimpleNamespace(Redis=constructor))

    def execute(command, **kwargs):
        executable, option, script = shlex.split(command)
        assert (executable, option) == ("python3", "-c")
        # Reconstructing names on the DUT avoids a shell argument per VNET.
        assert len(command) < 2048
        exec(compile(script, "<benchmark-cleanup>", "exec"), {})
        return {"rc": 0}

    host = Mock()
    host.shell.side_effect = execute
    helpers["_remove_routes"](host, namespace, tunnel, count)
    constructor.assert_called_once_with(unix_socket_path="/var/run/redis/redis.sock", db=4, decode_responses=True)
    assert keys == preserved
    assert all(0 < len(batch) <= 500 for batch in deleted)
    assert deleted[-1] == ("VXLAN_TUNNEL|" + tunnel,)


def test_cleanup_failure_is_not_silent(helpers):
    host = Mock()
    host.shell.return_value = {"rc": 1, "stderr": "cleanup failed"}
    with pytest.raises(RuntimeError, match="Unable to remove generated benchmark routes"):
        helpers["_remove_routes"](host, "Vnetabcd", "TunnelVnetBenchmark" + RUN_ID, 13)


@pytest.fixture
def resources(helpers):
    host = Mock(is_multi_asic=False)
    host.get_running_config_facts.return_value = {
        "LOOPBACK_INTERFACE": {"Loopback0": {"10.0.0.1/32": {}}},
        "VNET": {"VnetCustomer": {"vni": "10001"}},
    }

    def shell(command, **kwargs):
        if command == "ip -j link show":
            return {"rc": 0, "stdout": '[{"ifname":"Ethernet0"}]'}
        if command.startswith("python3 -c "):
            return {"rc": 0, "stdout": "1"}
        assert command.startswith("cp -a /etc/sonic/config_db.json ")
        return {"rc": 0}

    host.shell.side_effect = shell
    stub = Mock()
    stub.Set.return_value = SimpleNamespace(message=SimpleNamespace(code=0), response=[])
    cleanup = Mock()
    helpers["_remove_routes"] = cleanup.remove
    helpers["_restore_config"] = cleanup.restore
    return host, stub, cleanup


def test_setup_requests_and_cleanup_share_generated_names(helpers, resources):
    host, stub, cleanup = resources
    with helpers["route_resources"](host, {1: 1, 2: 2}, 1, stub, 5) as batches:
        patch = helpers["apply_gcu_patch"].call_args.args[1]
        entries = [entry for entry in patch if entry["path"].startswith("/VNET/")]
        names = [entry["path"].split("/")[-1] for entry in entries]
        assert names == ["Vnet012345678_{}".format(index) for index in range(3)]
        assert [entry["value"]["vni"] for entry in entries] == ["10002", "10003", "10004"]
        tunnel = "TunnelVnetBenchmark" + RUN_ID
        assert all(entry["value"]["vxlan_tunnel"] == tunnel for entry in entries)
        assert host.shell.call_args.args[0].endswith("/tmp/VnetBenchmark" + RUN_ID + ".config_db.json")
        assert stub.Set.call_count == 3
        assert [len(item.args[0].payload) for item in stub.Set.call_args_list] == [1, 2, 2]
        for item, name in zip(stub.Set.call_args_list, names):
            assert all(key.startswith(name + "|") for key in item.args[0].payload)
            assert item.kwargs == {"timeout": 5, "metadata": helpers["BYPASS_METADATA"]}
        measured = []
        for read, write in batches:
            assert [path.elem[-1].name for path in read.path] == list(write.payload)
            measured.extend(write.payload)
        assert measured == [
            names[1] + "|198.18.0.0/32", names[2] + "|198.18.0.0/32",
            names[1] + "|198.18.0.1/32", names[2] + "|198.18.0.1/32",
        ]
        assert cleanup.mock_calls == []
    assert cleanup.mock_calls == [
        call.remove(host, "Vnet012345678", tunnel, 3),
        call.restore(host, "/tmp/VnetBenchmark" + RUN_ID + ".config_db.json"),
    ]


@pytest.mark.parametrize("failure", ["gcu", "preload_rpc", "preload_response", "body"])
def test_partial_failure_keeps_cleanup_registered(helpers, resources, failure):
    host, stub, cleanup = resources
    if failure == "gcu":
        helpers["apply_gcu_patch"].side_effect = RuntimeError("GCU failed")
    elif failure == "preload_rpc":
        stub.Set.side_effect = [stub.Set.return_value, RuntimeError("RPC failed")]
    elif failure == "preload_response":
        stub.Set.side_effect = [
            stub.Set.return_value, SimpleNamespace(message=SimpleNamespace(code=1), response=[])]
    with pytest.raises(RuntimeError):
        with helpers["route_resources"](host, {1: 1, 2: 2}, 1, stub, 5):
            assert failure == "body"
            raise RuntimeError("body failed")
    assert cleanup.mock_calls == [
        call.remove(host, "Vnet012345678", "TunnelVnetBenchmark" + RUN_ID, 3),
        call.restore(host, "/tmp/VnetBenchmark" + RUN_ID + ".config_db.json"),
    ]


def test_cleanup_failure_still_restores_persistent_config(helpers, resources):
    host, stub, cleanup = resources
    cleanup.remove.side_effect = RuntimeError("cleanup failed")
    with pytest.raises(RuntimeError, match="cleanup failed"):
        with helpers["route_resources"](host, {1: 1, 2: 2}, 1, stub, 5):
            pass
    assert cleanup.mock_calls == [
        call.remove(host, "Vnet012345678", "TunnelVnetBenchmark" + RUN_ID, 3),
        call.restore(host, "/tmp/VnetBenchmark" + RUN_ID + ".config_db.json"),
    ]


@pytest.mark.parametrize("failure", ["links", "namespace"])
def test_allocation_failure_does_not_mutate(helpers, resources, failure):
    host, stub, cleanup = resources
    if failure == "links":
        host.shell.side_effect = [{"rc": 0, "stdout": "1"}, {"rc": 1}]
    else:
        host.get_running_config_facts.return_value["VRF"] = {"Vnet012345678_0": {}}
    with pytest.raises(RuntimeError):
        with helpers["route_resources"](host, {1: 1, 2: 2}, 1, stub, 5):
            pytest.fail("resource preparation should have failed")
    helpers["apply_gcu_patch"].assert_not_called()
    stub.Set.assert_not_called()
    assert cleanup.mock_calls == []
    assert all(not item.args[0].startswith("cp ") for item in host.shell.call_args_list)
