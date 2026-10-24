"""Compatibility tests for MACsec platform helpers."""

import ast
from multiprocessing.pool import ThreadPool
from pathlib import Path


class FakeCsonicHost:
    pass


class FakeEosHost:
    pass


MODULE_PATH = Path(__file__).resolve().parents[2] / "macsec/macsec_platform_helper.py"
TREE = ast.parse(MODULE_PATH.read_text())
FUNCTION_NAMES = {"global_cmd", "get_eth_ifname", "get_macsec_ifname"}
NAMESPACE = {
    "CsonicHost": FakeCsonicHost,
    "EosHost": FakeEosHost,
    "ThreadPool": ThreadPool,
    "logging": __import__("logging"),
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
global_cmd = NAMESPACE["global_cmd"]
get_eth_ifname = NAMESPACE["get_eth_ifname"]
get_macsec_ifname = NAMESPACE["get_macsec_ifname"]


class CommandHost:
    def __init__(self, result=None):
        self.result = result if result is not None else {"rc": 0}
        self.commands = []

    def command(self, command):
        self.commands.append(command)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def test_global_cmd_retains_legacy_fire_and_forget_result_semantics():
    dut = CommandHost({"rc": 1, "stderr": "ignored by legacy helper"})
    neighbor = CommandHost(RuntimeError("ignored worker exception"))

    global_cmd(dut, {"neighbor": {"host": neighbor}}, "required command")

    assert dut.commands == ["required command"]
    assert neighbor.commands == ["required command"]


def test_global_cmd_still_skips_eos_neighbors():
    dut = CommandHost()
    eos = FakeEosHost()

    global_cmd(dut, {"eos": {"host": eos}}, "required command")

    assert dut.commands == ["required command"]


def test_csonic_interface_mapping_is_explicitly_gated():
    host = FakeCsonicHost()
    host._kernel_interface_name = lambda port: "eth2"
    host._get_macsec_ifname = lambda port: "macsec_eth2"

    assert get_eth_ifname(host, "Ethernet4") == "eth2"
    assert get_macsec_ifname(host, "Ethernet4") == "macsec_eth2"


def test_regular_platform_path_remains_original():
    host = CommandHost()
    host.is_multi_asic = False
    NAMESPACE["get_platform"] = lambda candidate: "physical-platform"

    assert get_eth_ifname(host, "Ethernet4") == "Ethernet4"
    assert get_macsec_ifname(host, "Ethernet4") is None
