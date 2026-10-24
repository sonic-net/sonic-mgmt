"""Compatibility tests for narrowly gated cSONiC MACsec helpers."""

import ast
import json
from multiprocessing import Process
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock


class FakeCsonicHost:
    def __init__(self):
        self.commands = []

    def command(self, command):
        self.commands.append(command)
        return {"stdout": "[]"}


class FakeSonicHost:
    def __init__(self):
        self.commands = []

    def command(self, command):
        self.commands.append(command)
        return {"stdout": "[]"}


MODULE_PATH = Path(__file__).resolve().parents[2] / "macsec/macsec_helper.py"
TREE = ast.parse(MODULE_PATH.read_text())
FUNCTION_NAMES = {
    "submit_async_task",
    "wait_all_complete",
    "getns_prefix",
    "get_ipnetns_prefix",
    "get_mka_session",
}
NAMESPACE = {
    "CsonicHost": FakeCsonicHost,
    "Process": Process,
    "json": json,
    "process_queue": [],
}
exec(
    compile(
        ast.Module(
            body=[
                node for node in TREE.body
                if isinstance(node, ast.FunctionDef) and node.name in FUNCTION_NAMES
            ],
            type_ignores=[],
        ),
        str(MODULE_PATH),
        "exec",
    ),
    NAMESPACE,
)

submit_async_task = NAMESPACE["submit_async_task"]
wait_all_complete = NAMESPACE["wait_all_complete"]
getns_prefix = NAMESPACE["getns_prefix"]
get_ipnetns_prefix = NAMESPACE["get_ipnetns_prefix"]
get_mka_session = NAMESPACE["get_mka_session"]


def test_csonic_is_explicitly_single_namespace_without_sonic_contract():
    host = FakeCsonicHost()

    assert getns_prefix(host, "Ethernet1") == " "
    assert get_ipnetns_prefix(host, "Ethernet1") == " "


def test_regular_single_asic_contract_is_unchanged():
    host = SimpleNamespace(is_multi_asic=False)

    assert getns_prefix(host, "Ethernet1") == " "
    assert get_ipnetns_prefix(host, "Ethernet1") == " "


def test_regular_multi_asic_contract_is_unchanged():
    asic = SimpleNamespace(asic_index=3)
    host = SimpleNamespace(
        is_multi_asic=True,
        get_port_asic_instance=MagicMock(return_value=asic),
        get_namespace_from_asic_id=MagicMock(return_value="asic3"),
    )

    assert getns_prefix(host, "Ethernet12") == "-n asic3"
    assert get_ipnetns_prefix(host, "Ethernet12") == "sudo ip netns exec asic3"


def test_csonic_mka_query_runs_directly_inside_container():
    host = FakeCsonicHost()

    assert get_mka_session(host) == {}
    assert host.commands == ["ip -j macsec show"]


def test_sonic_mka_query_remains_inside_syncd_container():
    host = FakeSonicHost()

    assert get_mka_session(host) == {}
    assert host.commands == ["docker exec syncd ip -j macsec show"]


def _complete_successfully():
    return None


def test_legacy_async_worker_contract_is_retained():
    task = submit_async_task(_complete_successfully, ())
    wait_all_complete(timeout=2)

    assert task.exitcode == 0
    assert NAMESPACE["process_queue"] == []
