"""Verify sfputil low-power cleanup after partial test failures."""

import ast
import copy
from contextlib import ExitStack
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml


SOURCE = Path(__file__).resolve().parents[1] / "test_sfputil.py"
FUNCTION = next(
    node for node in ast.parse(SOURCE.read_text()).body
    if isinstance(node, ast.FunctionDef) and node.name == "test_check_sfputil_low_power_mode"
)


def run_lpmode_test(failure=None):
    states = {"Ethernet0": "off", "Ethernet4": "off"}
    writes = []
    finalizers = []
    reads = 0

    def command(cmd, **kwargs):
        nonlocal reads
        if cmd == "sudo sfputil show lpmode":
            reads += 1
            reported = dict(states)
            if failure == "verification" and reads == 2:
                reported["Ethernet0"] = "off"
            return {"rc": 0, "stdout_lines": ["", ""] + list(reported.items())}
        if cmd == "sudo sfputil show presence":
            return {"rc": 0, "stdout_lines": ["", ""] + [(port, "Present") for port in states]}
        if cmd.startswith("redis-cli"):
            return {"stdout": "OSFP"}
        _, _, _, state, port = cmd.split()
        writes.append((port, state))
        states[port] = state
        if failure == "command" and state == "on":
            raise RuntimeError("Simulated failure after applying mode")
        if failure == "cleanup" and port == "Ethernet4":
            raise RuntimeError("Simulated command or cleanup failure")
        return {"rc": 0}

    dut = Mock(hostname="dut", facts={"asic_type": "broadcom"}, command=command)
    dut.asic_instance.return_value = SimpleNamespace(get_docker_cmd=lambda cmd, _: cmd, cli_ns_option="")
    dut.shell.return_value = {"rc": 1}
    dut.get_extended_minigraph_facts.return_value = {"minigraph_ports": {}}
    dut.get_admin_up_ports.return_value = []
    namespace = {
        "ExitStack": ExitStack,
        "copy": copy,
        "logging": logging,
        "logger": logging.getLogger(__name__),
        "pytest": pytest,
        "time": Mock(),
        "cmd_sfp_show_lpmode": "sudo sfputil show lpmode",
        "cmd_sfp_set_lpmode": "sudo sfputil lpmode",
        "cmd_sfp_presence": "sudo sfputil show presence",
        "get_dev_conn": lambda *_: ({"Ethernet0": [0], "Ethernet4": [1]}, list(states)),
        "parse_output": dict,
        "wait_until": Mock(return_value=True),
        "check_interfaces_up": Mock(),
    }
    exec(compile(ast.Module(body=[FUNCTION], type_ignores=[]), str(SOURCE), "exec"), namespace)
    arguments = {
        "request": SimpleNamespace(addfinalizer=finalizers.append),
        "duthosts": {"dut": dut},
        "enum_rand_one_per_hwsku_frontend_hostname": "dut",
        "enum_frontend_asic_index": None,
        "conn_graph_facts": {},
        "tbinfo": {},
        "xcvr_skip_list": {"dut": []},
        "shutdown_ebgp": None,
        "port_list_with_flat_memory": {"dut": []},
    }
    return namespace[FUNCTION.name], arguments, states, writes, finalizers


@pytest.mark.parametrize("failure", ["command", "verification", "cleanup"])
def test_failed_lpmode_test_restores_every_attempted_port(failure):
    function, arguments, states, writes, finalizers = run_lpmode_test(failure)
    expected_error = AssertionError if failure == "verification" else RuntimeError
    with pytest.raises(expected_error):
        function(**arguments)

    if failure == "cleanup":
        with pytest.raises(RuntimeError, match="cleanup failure"):
            finalizers[0]()
    else:
        finalizers[0]()

    assert states == {"Ethernet0": "off", "Ethernet4": "off"}
    if failure == "command":
        assert writes == [("Ethernet0", "on"), ("Ethernet0", "off")]
    else:
        assert writes[-2:] == [("Ethernet4", "off"), ("Ethernet0", "off")]


def test_successful_lpmode_test_does_not_repeat_restoration():
    function, arguments, states, writes, finalizers = run_lpmode_test()
    function(**arguments)
    completed_writes = list(writes)

    finalizers[0]()

    assert writes == completed_writes
    assert states == {"Ethernet0": "off", "Ethernet4": "off"}


@pytest.mark.parametrize("topo_name,topo_type,platform,asic_type,expected_skip", [
    ("lt2-o256", "lt2", "generic", "broadcom", False),
    ("t2", "t2", "generic", "broadcom", True),
    ("ft2", "ft2", "generic", "broadcom", True),
    ("lt2-o256", "lt2", "x86_64-cel_e1031-r0", "cisco-8000", True),
    ("lt2-o256", "lt2", "generic", "nvidia-bluefield", True),
])
def test_reset_guard_distinguishes_lt2_from_existing_exclusions(
        topo_name, topo_type, platform, asic_type, expected_skip):
    source = Path(__file__).resolve().parents[3] / (
        "common/plugins/conditional_mark/tests_mark_conditions_platform_tests.yaml")
    conditions = yaml.safe_load(source.read_text())[
        "platform_tests/sfp/test_sfputil.py::test_check_sfputil_reset"]["skip"]["conditions"]
    facts = {
        "topo_name": topo_name,
        "topo_type": topo_type,
        "platform": platform,
        "asic_type": asic_type,
        "issue_open": True,
    }
    expressions = [condition.replace("https://github.com/sonic-net/sonic-mgmt/issues/6218", "issue_open")
                   for condition in conditions]
    assert any(eval(expression, {"__builtins__": {}}, facts) for expression in expressions) == expected_skip
