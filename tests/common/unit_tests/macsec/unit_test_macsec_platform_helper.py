"""Focused tests for required MACsec commands across all endpoints."""

import ast
from collections import UserDict
from collections.abc import Mapping
from multiprocessing.pool import ThreadPool
from pathlib import Path

import pytest


class FakeEosHost:
    pass


MODULE_PATH = Path(__file__).resolve().parents[2] / "macsec/macsec_platform_helper.py"
TREE = ast.parse(MODULE_PATH.read_text())
NODE = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name == "global_cmd"
)
NAMESPACE = {
    "EosHost": FakeEosHost,
    "Mapping": Mapping,
    "ThreadPool": ThreadPool,
}
exec(compile(ast.Module(body=[NODE], type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)
global_cmd = NAMESPACE["global_cmd"]


class CommandHost:
    def __init__(self, hostname, result):
        self.hostname = hostname
        self.result = result
        self.commands = []

    def command(self, command):
        self.commands.append(command)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_global_cmd_requires_success_from_every_sonic_endpoint():
    dut = CommandHost("dut", UserDict({"rc": 0, "stdout": ""}))
    neighbor = CommandHost("neighbor", {"rc": 0, "stdout": ""})

    global_cmd(dut, {"neighbor": {"host": neighbor}}, "required command")

    assert dut.commands == ["required command"]
    assert neighbor.commands == ["required command"]


def test_global_cmd_surfaces_nonzero_and_exception_results():
    dut = CommandHost("dut", {"rc": 1, "stderr": "failed"})
    neighbor = CommandHost("neighbor", RuntimeError("transport failed"))

    with pytest.raises(AssertionError, match="Required MACsec command failed") as error:
        global_cmd(dut, {"neighbor": {"host": neighbor}}, "required command")

    message = str(error.value)
    assert "dut" in message
    assert "neighbor" in message
    assert "transport failed" in message


def test_global_cmd_skips_eos_neighbors():
    dut = CommandHost("dut", {"rc": 0})
    eos = FakeEosHost()

    global_cmd(dut, {"eos": {"host": eos}}, "required command")

    assert dut.commands == ["required command"]
