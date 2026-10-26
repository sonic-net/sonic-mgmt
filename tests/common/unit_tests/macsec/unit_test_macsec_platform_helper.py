"""Focused tests for required MACsec commands across all endpoints."""

import ast
import logging
import re
from collections import UserDict
from collections.abc import Mapping
from multiprocessing.pool import ThreadPool
from pathlib import Path

import pytest


class FakeEosHost:
    def __getattr__(self, name):
        raise RuntimeError("optional EOS shell credentials are unavailable")


MODULE_PATH = Path(__file__).resolve().parents[2] / "macsec/macsec_platform_helper.py"
TREE = ast.parse(MODULE_PATH.read_text())
FUNCTION_NAMES = {
    "global_cmd",
    "get_all_ifnames",
    "get_platform",
    "_runtime_port_name",
    "get_eth_ifname",
    "get_macsec_ifname",
    "get_lldp_list",
}
NODES = [
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name in FUNCTION_NAMES
]
NAMESPACE = {
    "EosHost": FakeEosHost,
    "Mapping": Mapping,
    "ThreadPool": ThreadPool,
    "logging": logging,
    "pytest": pytest,
    "re": re,
}
exec(compile(ast.Module(body=NODES, type_ignores=[]), str(MODULE_PATH), "exec"), NAMESPACE)
global_cmd = NAMESPACE["global_cmd"]
get_eth_ifname = NAMESPACE["get_eth_ifname"]
get_macsec_ifname = NAMESPACE["get_macsec_ifname"]
get_lldp_list = NAMESPACE["get_lldp_list"]


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


def test_runtime_port_mapping_bypasses_eos_optional_attributes():
    assert NAMESPACE["_runtime_port_name"](
        FakeEosHost(), "Ethernet1") == "Ethernet1"


class VirtualPortHost:
    def __init__(self, mapping=None):
        self.mapping = mapping or {}
        self.is_multi_asic = False

    def _interface_name(self, port_name):
        return self.mapping.get(port_name, port_name)

    def command(self, command):
        if command == "show platform summary":
            return {"stdout_lines": ["Platform: x86_64-kvm_x86_64-r0"]}
        if "ls /sys/class/net/" in command:
            return {"stdout_lines": [
                "eth0", "eth1", "eth2", "Ethernet1", "Ethernet2",
                "macsec_eth1", "macsec_eth2",
            ]}
        raise AssertionError("Unexpected command: {}".format(command))


def test_macsec_ifname_uses_converged_csonic_runtime_port_mapping():
    host = VirtualPortHost({"Ethernet1": "Ethernet2"})

    assert get_eth_ifname(host, "Ethernet1") == "eth2"
    assert get_macsec_ifname(host, "Ethernet1") == "macsec_eth2"


def test_macsec_ifname_keeps_stock_virtual_port_mapping():
    host = VirtualPortHost()

    assert get_eth_ifname(host, "Ethernet1") == "eth1"
    assert get_macsec_ifname(host, "Ethernet1") == "macsec_eth1"


def test_lldp_list_preserves_duplicate_converged_system_names():
    class LldpHost:
        def command(self, command):
            assert command == "show lldp table"
            return {"stdout_lines": [
                "Capability codes: (R) Router, (B) Bridge, (O) Other",
                "LocalPort RemoteDevice RemotePortID Capability RemotePortDescr",
                "--------- ------------ ------------ ---------- ---------------",
                "Ethernet112 ARISTA01T1 fortyGigE0/0 BR Ethernet1",
                "Ethernet116 ARISTA01T1 fortyGigE0/4 BR Ethernet2",
                "--------------------------------------------------",
                "Total entries displayed: 2",
            ]}

    result = get_lldp_list(LldpHost())

    assert {entry["localport"] for entry in result.values()} == {
        "Ethernet112", "Ethernet116",
    }
    assert all(entry["name"] == "ARISTA01T1" for entry in result.values())
