"""Exercise cooling-aware BMC startup assertions without testbed dependencies."""

import ast
import json
import logging
from pathlib import Path
import re
import shlex
import sys
from types import ModuleType
from unittest.mock import Mock, call, patch

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "platform_tests" / "daemon" / "test_bmcctld.py"
ONLINE = "STARTUP: Switch-Host already ONLINE (daemon restart); skipping boot sequence"
IMMEDIATE = "STARTUP: non-liquid-cooled system \u2014 immediate power_on, no additional checks"
DELAYED = "STARTUP: Switch-Host OFFLINE \u2014 issuing power_on"


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def startup_namespace():
    """Load the production helpers and integration method through AST."""
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
               and node.name in ("_startup_power_on_observed", "_assert_liquid_cooled_power_on_delay")]
    test_class = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                      and node.name == "TestBmcctldDaemon")
    method = next(node for node in test_class.body if isinstance(node, ast.FunctionDef)
                  and node.name == "test_bmcctld_power_on_delay")
    namespace = dict(json=json, re=re, pytest_assert=_assert, pytest=pytest,
                     logger=logging.getLogger(__name__), CAUSE_POWER_LOSS="power loss")
    exec(compile(ast.Module(body=helpers + [method], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("liquid,lines,expected", [
    (False, [ONLINE], True),
    (False, [IMMEDIATE], True),
    (False, [DELAYED], False),
    (True, [DELAYED], True),
    (True, [ONLINE], False),
    (True, [IMMEDIATE], False),
    (False, [], False),
    (True, [], False),
    (False, ["STARTUP: Critical leak or Rack Manager alert detected; NOT powering on Switch-Host"], False),
    (True, ["STARTUP: Rack Manager POWER_ON/POWER_OFF command executed during boot delay"], False),
    (False, ["STARTUP: SWITCH-HOST admin_status='down'; Switch-Host will remain powered off"], False),
    (True, ["Executing action 'power_on'"], False),
    (False, ["Failed issuing power_on"], False),
    (True, ["STARTUP: Switch-Host OFFLINE failed issuing power_on"], False),
    (False, ["STARTUP: non-liquid-cooled system failed immediate power_on, no additional checks"], False),
])
def test_startup_requires_cooling_specific_evidence(startup_namespace, liquid, lines, expected):
    """Missing, blocked, unrelated, and wrong-cooling startup entries cannot pass."""
    assert startup_namespace["_startup_power_on_observed"](lines, liquid) is expected


@pytest.mark.parametrize("uptime", [29.001, 30, 90])
def test_liquid_delay_uses_boot_uptime(startup_namespace, uptime):
    """Allow only sub-second truncation, and daemon startup after the delay expires."""
    journal = json.dumps({"MESSAGE": DELAYED, "__MONOTONIC_TIMESTAMP": str(int(uptime * 1000000))})
    startup_namespace["_assert_liquid_cooled_power_on_delay"](journal, 30)


@pytest.mark.parametrize("entries", [
    [],
    [{"MESSAGE": ONLINE, "__MONOTONIC_TIMESTAMP": "90000000"}],
    [{"MESSAGE": DELAYED, "__MONOTONIC_TIMESTAMP": "29000000"}],
    [{"MESSAGE": DELAYED, "__MONOTONIC_TIMESTAMP": "0"}],
    [{"MESSAGE": DELAYED, "__MONOTONIC_TIMESTAMP": "10000000"},
     {"MESSAGE": DELAYED, "__MONOTONIC_TIMESTAMP": "40000000"}],
])
def test_liquid_delay_rejects_missing_or_early_dispatch(startup_namespace, entries):
    """A later dispatch cannot hide an earlier unsafe startup power-on."""
    with pytest.raises(AssertionError):
        startup_namespace["_assert_liquid_cooled_power_on_delay"](
            "\n".join(json.dumps(entry) for entry in entries), 30)


@pytest.mark.parametrize("journal,error", [
    ("not JSON", json.JSONDecodeError),
    (json.dumps({"MESSAGE": DELAYED}), KeyError),
    (json.dumps({"MESSAGE": DELAYED, "__MONOTONIC_TIMESTAMP": "unknown"}), ValueError),
])
def test_liquid_delay_does_not_hide_invalid_evidence(startup_namespace, journal, error):
    """Malformed timing evidence must not silently disable the liquid-cooling check."""
    with pytest.raises(error):
        startup_namespace["_assert_liquid_cooled_power_on_delay"](journal, 30)


def _integration_context(namespace, cooling="False", startup=ONLINE):
    bmc, host, pdu, analyzer = Mock(), Mock(), Mock(), Mock()

    def shell(command, **kwargs):
        if "is_liquid_cooled" in command:
            return {"stdout": cooling}
        if command == "true":
            return {"rc": 1}
        if "HGET" in command:
            return {"stdout": "30"}
        if command == "show reboot-cause":
            return {"stdout": "Power Loss"}
        if command.startswith("journalctl"):
            return {"stdout": json.dumps({"MESSAGE": DELAYED, "__MONOTONIC_TIMESTAMP": "30000000"})}
        return {"stdout": ""}

    bmc.shell.side_effect = shell
    host.shell.return_value = {"stdout": "Power Loss"}
    pdu.get_outlet_status.return_value = [{"outlet_id": "1"}, {"outlet_id": "2"}]
    pdu.turn_off_outlet.return_value = True
    pdu.turn_on_outlet.return_value = True
    analyzer.analyze.return_value = {"match_messages": {"/host/bmc/event.log": [startup]}}
    namespace.update(
        get_switch_host_or_skip_test=Mock(return_value=host),
        get_host_boot_id=Mock(side_effect=["bmc-before", "host-before", "bmc-after", "host-after"]),
        make_bmc_loganalyzer=Mock(return_value=analyzer),
        wait_until=lambda timeout, interval, delay, condition: condition(),
        wait_critical_processes=Mock(),
        wait_host_on=Mock(return_value=True),
    )
    return Mock(duthost=bmc), host, pdu


@pytest.mark.parametrize("cooling,startup", [("False", ONLINE), ("False", IMMEDIATE), ("True", DELAYED)])
def test_integration_keeps_reboot_and_health_checks(startup_namespace, cooling, startup):
    """Execute each accepted path through the real test and require both reboot IDs and health."""
    instance, host, pdu = _integration_context(startup_namespace, cooling, startup)
    startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu))
    assert startup_namespace["get_host_boot_id"].call_count == 4
    startup_namespace["wait_host_on"].assert_called_once_with(host, timeout=600)
    assert pdu.turn_on_outlet.call_count == 2


@pytest.mark.parametrize("failure", ["bmc-id", "host-id", "health", "cause", "logs", "cooling", "pdu", "pdu-on"])
def test_integration_does_not_mask_failures(startup_namespace, failure):
    """Immediate startup is not a fallback for failed reboot evidence or host recovery."""
    instance, host, pdu = _integration_context(startup_namespace)
    if failure == "bmc-id":
        startup_namespace["get_host_boot_id"].side_effect = ["old", "host", "old"]
    elif failure == "host-id":
        startup_namespace["get_host_boot_id"].side_effect = ["old", "host", "new", "host"]
    elif failure == "health":
        startup_namespace["wait_host_on"].return_value = False
    elif failure == "cause":
        host.shell.return_value = {"stdout": "Non-Hardware"}
    elif failure == "logs":
        startup_namespace["make_bmc_loganalyzer"].return_value.analyze.return_value = {"match_messages": {}}
    elif failure == "cooling":
        instance, host, pdu = _integration_context(startup_namespace, cooling="unknown")
    elif failure == "pdu":
        pdu.turn_off_outlet.return_value = False
    elif failure == "pdu-on":
        pdu.turn_on_outlet.return_value = False
    with pytest.raises(AssertionError):
        startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu))
    if failure in ("pdu", "pdu-on"):
        assert pdu.turn_on_outlet.call_count == 2


@pytest.mark.parametrize("cooling", [True, False, "True", "False", None, 0, 1, [], {}])
def test_remote_cooling_probe_validates_type_before_printing(startup_namespace, cooling, capsys):
    """Execute the actual remote probe so string booleans cannot masquerade as bool."""
    instance, _, pdu = _integration_context(startup_namespace)
    startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu))
    command = instance.duthost.shell.call_args_list[0].args[0]
    script = shlex.split(command)[2]
    platform = ModuleType("sonic_platform")
    chassis = ModuleType("sonic_platform.chassis")
    chassis.Chassis = Mock()
    chassis.Chassis.return_value.is_liquid_cooled.return_value = cooling
    with patch.dict(sys.modules, {"sonic_platform": platform, "sonic_platform.chassis": chassis}):
        if isinstance(cooling, bool):
            exec(script, {})
            assert capsys.readouterr().out == f"{cooling}\n"
        else:
            with pytest.raises(AssertionError, match=r"Chassis.is_liquid_cooled\(\) must return bool"):
                exec(script, {})
            assert capsys.readouterr().out == ""


@pytest.mark.parametrize("results", [
    [RuntimeError("PDU connection failed"), True],
    [True, RuntimeError("PDU connection failed")],
    [RuntimeError("PDU connection failed"), False],
    [RuntimeError("PDU connection failed"), RuntimeError("PDU connection failed")],
])
def test_pdu_restoration_attempts_all_outlets_after_exception(startup_namespace, results):
    """Log controller exceptions and fail only after attempting every restoration."""
    instance, _, pdu = _integration_context(startup_namespace)
    startup_namespace["logger"] = Mock()
    pdu.turn_on_outlet.side_effect = results
    outlets = pdu.get_outlet_status.return_value
    failed_outlets = [outlet for outlet, result in zip(outlets, results) if result is not True]
    with pytest.raises(AssertionError) as failure:
        startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu))
    assert str(failure.value).splitlines()[0] == f"Failed to power on PDU outlets {failed_outlets}"
    assert pdu.turn_on_outlet.call_args_list == [call(outlet) for outlet in outlets]
    assert startup_namespace["logger"].exception.call_args_list == [
        call("Failed to restore PDU outlet %s", outlet)
        for outlet, result in zip(outlets, results) if isinstance(result, Exception)
    ]
    startup_namespace["wait_critical_processes"].assert_not_called()
