"""Focused regressions for MACsec namespace and async worker helpers."""

import ast
import json
import os
import signal
import subprocess
import sys
import time
from multiprocessing import Process
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


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
    "_run_async_task",
    "_signal_async_task",
    "_cancel_async_tasks",
    "submit_async_task",
    "wait_all_complete",
    "getns_prefix",
    "get_ipnetns_prefix",
    "get_mka_session",
}
NAMESPACE = {
    "CsonicHost": FakeCsonicHost,
    "Process": Process,
    "_PROCESS_TERMINATE_GRACE_SECONDS": 0.5,
    "json": json,
    "os": os,
    "process_queue": [],
    "signal": signal,
    "time": time,
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


def test_single_asic_compatible_host_without_multi_asic_attribute():
    host = SimpleNamespace()

    assert getns_prefix(host, "Ethernet1") == " "
    assert get_ipnetns_prefix(host, "Ethernet1") == " "


def test_multi_asic_host_still_uses_interface_namespace():
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


def test_sonic_mka_query_still_runs_inside_syncd_container():
    host = FakeSonicHost()

    assert get_mka_session(host) == {}
    assert host.commands == ["docker exec syncd ip -j macsec show"]


def _run_delayed_external_write(ready_path, result_path):
    subprocess.run([
        sys.executable,
        "-c",
        "import pathlib,time; pathlib.Path({!r}).write_text('ready'); "
        "time.sleep(0.5); pathlib.Path({!r}).write_text('late')".format(
            ready_path, result_path),
    ], check=True)


def test_timeout_cancels_external_command_before_rollback(tmp_path):
    ready = tmp_path / "ready"
    result = tmp_path / "late-write"
    task = submit_async_task(
        _run_delayed_external_write, (str(ready), str(result)))

    deadline = time.monotonic() + 2
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists(), "worker did not launch its external command"

    with pytest.raises(RuntimeError, match="timeout"):
        wait_all_complete(timeout=0.05)

    assert task.exitcode is not None
    time.sleep(0.7)
    assert not result.exists()
    assert NAMESPACE["process_queue"] == []
