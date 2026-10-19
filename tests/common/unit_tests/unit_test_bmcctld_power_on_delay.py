"""Exercise BMC power-cycle sequencing without testbed dependencies."""

import ast
import logging
import re
import shlex
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "platform_tests" / "daemon" / "test_bmcctld.py"


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def power_cycle():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    test_class = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef) and node.name == "TestBmcctldDaemon")
    method = next(node for node in test_class.body
                  if isinstance(node, ast.FunctionDef) and node.name == "test_bmcctld_power_on_delay")
    dut = Mock(mgmt_ip="192.0.2.1")
    localhost = Mock()
    outlets = [
        {"pdu_name": "pdu-a", "outlet_id": "1", "outlet_on": True},
        {"pdu_name": "pdu-b", "outlet_id": "2", "outlet_on": True},
        {"pdu_name": "pdu-c", "outlet_id": "3", "outlet_on": False},
    ]
    pdu = Mock()
    pdu.get_outlet_status.return_value = outlets
    pdu.turn_off_outlet.return_value = True
    pdu.turn_on_outlet.return_value = True
    analyzer = Mock()
    analyzer.init.return_value = "power_cycle.marker"
    analyzer.analyze.return_value = {
        "match_messages": {"/host/bmc/event.log": ["STARTUP: issuing power_on"]},
    }
    readback = iter(["", "30"])

    def shell(command, **kwargs):
        if command.startswith("sonic-db-cli CONFIG_DB HGET "):
            return {"rc": 0, "stdout": next(readback)}
        if command == "show reboot-cause":
            return {"rc": 0, "stdout": "Power Loss"}
        return {"rc": 0, "stdout": ""}

    dut.shell.side_effect = shell
    namespace = {
        "ExitStack": ExitStack,
        "shlex": shlex,
        "re": re,
        "pytest": pytest,
        "pytest_assert": _assert,
        "logger": logging.getLogger(__name__),
        "BMC_EVENT_LOG": "/host/bmc/event.log",
        "CAUSE_POWER_LOSS": "power loss",
        "SONIC_SSH_PORT": 22,
        "get_switch_host_or_skip_test": Mock(return_value=Mock(hostname="switch-host")),
        "get_host_boot_id": Mock(side_effect=["before", "after"]),
        "make_bmc_loganalyzer": Mock(return_value=analyzer),
        "wait_for_startup": Mock(),
        "wait_critical_processes": Mock(),
        "wait_until": Mock(side_effect=lambda timeout, interval, delay, predicate: predicate()),
    }
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    events = Mock()
    for name, mock in (
        ("off", pdu.turn_off_outlet),
        ("on", pdu.turn_on_outlet),
        ("shutdown", localhost.wait_for),
        ("startup", namespace["wait_for_startup"]),
        ("healthy", namespace["wait_critical_processes"]),
    ):
        events.attach_mock(mock, name)
    return SimpleNamespace(
        run=lambda: namespace[method.name](SimpleNamespace(duthost=dut), localhost, Mock(return_value=pdu)),
        dut=dut, localhost=localhost, pdu=pdu, outlets=outlets, analyzer=analyzer,
        namespace=namespace, events=events,
    )


def test_power_cycle_orders_shutdown_and_recovery(power_cycle):
    """Restore active feeds and wait for readiness before evaluating startup logs."""
    power_cycle.run()
    assert power_cycle.events.mock_calls == [
        call.off(power_cycle.outlets[0]),
        call.off(power_cycle.outlets[1]),
        call.shutdown(host="192.0.2.1", port=22, state="stopped", delay=10, timeout=120),
        call.on(power_cycle.outlets[1]),
        call.on(power_cycle.outlets[0]),
        call.startup(power_cycle.dut, power_cycle.localhost, delay=10, timeout=600),
        call.healthy(power_cycle.dut, timeout=600),
    ]
    assert power_cycle.dut.shell.call_args_list[-2:] == [
        call("sonic-db-cli CONFIG_DB HDEL 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay"),
        call("sudo config save -y"),
    ]


@pytest.mark.parametrize("failure", ["off_false", "off_error", "shutdown", "on_false", "on_error"])
def test_power_cycle_restores_all_active_feeds_on_failure(power_cycle, failure):
    """A failed operation must not prevent attempts to restore the remaining feeds."""
    if failure == "off_false":
        power_cycle.pdu.turn_off_outlet.return_value = False
    elif failure == "off_error":
        power_cycle.pdu.turn_off_outlet.side_effect = RuntimeError("PDU offline")
    elif failure == "shutdown":
        power_cycle.localhost.wait_for.side_effect = RuntimeError("SSH stayed up")
    elif failure == "on_false":
        power_cycle.pdu.turn_on_outlet.side_effect = [False, True]
    else:
        power_cycle.pdu.turn_on_outlet.side_effect = [RuntimeError("PDU offline"), True]

    with pytest.raises((AssertionError, RuntimeError)):
        power_cycle.run()

    assert power_cycle.pdu.turn_on_outlet.call_args_list == [
        call(power_cycle.outlets[1]), call(power_cycle.outlets[0]),
    ]
    power_cycle.namespace["wait_for_startup"].assert_called_once()
    power_cycle.namespace["wait_critical_processes"].assert_called_once()
    power_cycle.analyzer.analyze.assert_not_called()
    assert power_cycle.dut.shell.call_args == call("sudo config save -y")


@pytest.mark.parametrize("boot_ids", [("", "after"), ("before", ""), ("before", "before")])
def test_power_cycle_requires_valid_changed_boot_id(power_cycle, boot_ids):
    """Missing or unchanged boot IDs must not be reported as missing startup messages."""
    power_cycle.namespace["get_host_boot_id"].side_effect = boot_ids
    with pytest.raises(AssertionError, match="boot ID|did not reboot"):
        power_cycle.run()
    power_cycle.analyzer.analyze.assert_not_called()
    if not boot_ids[0]:
        power_cycle.pdu.turn_off_outlet.assert_not_called()


@pytest.mark.parametrize("failure", ["reboot_cause", "marker"])
def test_power_cycle_reports_reboot_and_log_preconditions(power_cycle, failure):
    """Distinguish a wrong reboot cause or lost marker from missing startup messages."""
    original_shell = power_cycle.dut.shell.side_effect

    def shell(command, **kwargs):
        if failure == "reboot_cause" and command == "show reboot-cause":
            return {"rc": 0, "stdout": "User issued reboot"}
        if failure == "marker" and command.startswith("grep ") and kwargs.get("module_ignore_errors"):
            return {"rc": 1, "stdout": ""}
        return original_shell(command, **kwargs)

    power_cycle.dut.shell.side_effect = shell
    with pytest.raises(AssertionError, match="power-loss reboot|Cannot find start marker"):
        power_cycle.run()
    power_cycle.analyzer.analyze.assert_not_called()


@pytest.mark.parametrize("messages", [[], ["RACK_MANAGER: issuing power_on"], ["STARTUP: waiting"]])
def test_power_cycle_requires_startup_power_on_message(power_cycle, messages):
    """Only the startup dispatch message can satisfy the original assertion."""
    power_cycle.analyzer.analyze.return_value = {"match_messages": {"/host/bmc/event.log": messages}}
    with pytest.raises(AssertionError, match="issuing power_on.*not found"):
        power_cycle.run()


def test_power_cycle_restores_existing_delay(power_cycle):
    """Restore a pre-existing delay rather than deleting it."""
    original_shell = power_cycle.dut.shell.side_effect
    reads = iter(["15", "30"])

    def shell(command, **kwargs):
        if command.startswith("sonic-db-cli CONFIG_DB HGET "):
            return {"rc": 0, "stdout": next(reads)}
        return original_shell(command, **kwargs)

    power_cycle.dut.shell.side_effect = shell
    power_cycle.run()
    assert power_cycle.dut.shell.call_args_list[-2:] == [
        call("config chassis modules power-on-delay SWITCH-HOST 15"),
        call("sudo config save -y"),
    ]
