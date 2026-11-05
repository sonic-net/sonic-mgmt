"""Exercise cooling-aware BMC startup assertions without testbed dependencies."""

import ast
import json
import logging
from pathlib import Path
import re
from unittest.mock import MagicMock, Mock, call

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
    methods = [node for node in test_class.body if isinstance(node, ast.FunctionDef)
               and node.name in ("test_bmcctld_power_on_delay", "test_bmc_reboot_does_not_affect_switch_host")]
    namespace = dict(json=json, re=re, pytest_assert=_assert, pytest=pytest,
                     logger=logging.getLogger(__name__), CAUSE_POWER_LOSS="power loss")
    exec(compile(ast.Module(body=helpers + methods, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
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


def _integration_context(namespace, cooling=False, startup=ONLINE):
    bmc, host, pdu, analyzer = Mock(), Mock(), Mock(), Mock()

    def shell(command, **kwargs):
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
        chassis=Mock(),
        get_switch_host_or_skip_test=Mock(return_value=host),
        get_host_boot_id=Mock(side_effect=["bmc-before", "host-before", "bmc-after", "host-after"]),
        make_bmc_loganalyzer=Mock(return_value=analyzer),
        wait_until=lambda timeout, interval, delay, condition: condition(),
        wait_critical_processes=Mock(),
        wait_for_shutdown=Mock(),
        wait_for_startup=Mock(),
        wait_host_on=Mock(return_value=True),
    )
    namespace["chassis"].is_liquid_cooled.return_value = cooling
    return Mock(duthost=bmc), host, pdu


@pytest.mark.parametrize("cooling,startup", [(False, ONLINE), (False, IMMEDIATE), (True, DELAYED)])
def test_integration_keeps_reboot_and_health_checks(startup_namespace, cooling, startup):
    """Execute each accepted path through the real test and require both reboot IDs and health."""
    instance, host, pdu = _integration_context(startup_namespace, cooling, startup)
    conn = Mock()
    startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu), conn)
    startup_namespace["chassis"].is_liquid_cooled.assert_called_once_with(conn)
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
        startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu), Mock())
    if failure in ("pdu", "pdu-on"):
        assert pdu.turn_on_outlet.call_count == 2


@pytest.mark.parametrize("cooling", [True, False, "True", "False", None, 0, 1, [], {}])
def test_cooling_api_preserves_and_validates_boolean_type(startup_namespace, cooling):
    """Execute the existing JSON API wrapper; reject strings, integers, and null."""
    instance, _, pdu = _integration_context(startup_namespace, startup=DELAYED if cooling is True else ONLINE)
    api_path = Path(__file__).resolve().parents[1] / "helpers" / "platform_api" / "chassis.py"
    tree = ast.parse(api_path.read_text(encoding="utf-8"))
    helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
               and node.name in ("chassis_api", "is_liquid_cooled")]
    api_namespace = dict(json=json, logger=Mock())
    exec(compile(ast.Module(body=helpers, type_ignores=[]), str(api_path), "exec"), api_namespace)
    startup_namespace["chassis"].is_liquid_cooled = api_namespace["is_liquid_cooled"]
    conn = Mock()
    conn.getresponse.return_value.read.return_value = json.dumps({"res": cooling}).encode()
    if isinstance(cooling, bool):
        startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu), conn)
    else:
        with pytest.raises(AssertionError, match=r"Chassis.is_liquid_cooled\(\) must return a boolean"):
            startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu), conn)
        pdu.turn_off_outlet.assert_not_called()
        instance.duthost.shell.assert_not_called()
    conn.request.assert_called_once_with("POST", "/platform/chassis/is_liquid_cooled", json.dumps({"args": []}))


def test_cooling_api_failure_propagates_before_power_cycle(startup_namespace):
    """An API request failure cannot select the relaxed air-cooled policy."""
    instance, _, pdu = _integration_context(startup_namespace)
    startup_namespace["chassis"].is_liquid_cooled.side_effect = RuntimeError("Platform API unavailable")
    with pytest.raises(RuntimeError, match="Platform API unavailable"):
        startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu), Mock())
    pdu.turn_off_outlet.assert_not_called()
    instance.duthost.shell.assert_not_called()


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
        startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu), Mock())
    assert str(failure.value).splitlines()[0] == f"Failed to power on PDU outlets {failed_outlets}"
    assert pdu.turn_on_outlet.call_args_list == [call(outlet) for outlet in outlets]
    assert startup_namespace["logger"].exception.call_args_list == [
        call("Failed to restore PDU outlet %s", outlet)
        for outlet, result in zip(outlets, results) if isinstance(result, Exception)
    ]
    startup_namespace["wait_critical_processes"].assert_called_once_with(instance.duthost, timeout=600)


@pytest.mark.parametrize("failure", [None, "shutdown", "pdu-off", "pdu-off-exception", "pdu-on"])
def test_power_loss_recovers_before_config_cleanup(startup_namespace, failure):
    """Probe from localhost and recover SSH/services before any CONFIG_DB cleanup."""
    instance, _, pdu = _integration_context(startup_namespace)
    bmc = instance.duthost
    localhost = Mock()
    events = []
    online = True
    original_shell = bmc.shell.side_effect

    def shell(command, **kwargs):
        assert online, "AnsibleConnectionFailure: BMC is unreachable"
        if "power-on-delay" in command or "config save" in command:
            events.append(command)
        return original_shell(command, **kwargs)

    def power_off(outlet):
        nonlocal online
        online = False
        events.append("off")
        if failure == "pdu-off-exception":
            raise RuntimeError("PDU power-off failed")
        return failure != "pdu-off"

    def shutdown(duthost, controller, delay, timeout):
        assert duthost is bmc and controller is localhost
        assert delay == 10 and timeout == 120
        assert not online
        events.append("shutdown")
        if failure == "shutdown":
            raise RuntimeError("DUT did not shutdown")

    def startup(duthost, controller, delay, timeout):
        nonlocal online
        assert duthost is bmc and controller is localhost
        assert delay == 10 and timeout == 600
        assert pdu.turn_on_outlet.call_count == 2
        events.append("startup")
        online = True

    def healthy(duthost, timeout):
        assert duthost is bmc and timeout == 600 and online
        events.append("healthy")

    bmc.shell.side_effect = shell
    pdu.turn_off_outlet.side_effect = power_off
    if failure == "pdu-on":
        pdu.turn_on_outlet.side_effect = [False, True]
    startup_namespace["wait_for_shutdown"].side_effect = shutdown
    startup_namespace["wait_for_startup"].side_effect = startup
    startup_namespace["wait_critical_processes"].side_effect = healthy
    run = startup_namespace["test_bmcctld_power_on_delay"]
    if failure:
        error = RuntimeError if failure in ("shutdown", "pdu-off-exception") else AssertionError
        with pytest.raises(error):
            run(instance, localhost, Mock(return_value=pdu), Mock())
    else:
        run(instance, localhost, Mock(return_value=pdu), Mock())
    assert pdu.turn_on_outlet.call_args_list == [
        call(outlet) for outlet in pdu.get_outlet_status.return_value
    ]
    assert events[-4:] == [
        "startup", "healthy", "config chassis modules power-on-delay SWITCH-HOST 30", "sudo config save -y"
    ]
    bmc.shell.assert_any_call("sudo config save -y", module_ignore_errors=True)
    assert not any(args[0] == "true" for args, _ in bmc.shell.call_args_list)


@pytest.mark.parametrize("failure", ["ssh", "services"])
def test_failed_bmc_recovery_does_not_attempt_config_cleanup(startup_namespace, failure):
    """Report failed recovery without issuing cleanup commands to an unready BMC."""
    instance, _, pdu = _integration_context(startup_namespace)
    startup_namespace["logger"] = Mock()
    helper = "wait_for_startup" if failure == "ssh" else "wait_critical_processes"
    startup_namespace[helper].side_effect = RuntimeError("BMC recovery failed")
    with pytest.raises(RuntimeError, match="BMC recovery failed"):
        startup_namespace["test_bmcctld_power_on_delay"](instance, Mock(), Mock(return_value=pdu), Mock())
    assert pdu.turn_on_outlet.call_count == 2
    assert not any(kwargs.get("module_ignore_errors") for _, kwargs in instance.duthost.shell.call_args_list)
    startup_namespace["logger"].error.assert_called_once()


@pytest.mark.parametrize("failed", [False, True])
def test_power_loss_uses_localhost_ssh_probe(startup_namespace, failed):
    """Execute the shared shutdown helper; SSH loss must not run a remote command."""
    instance, _, pdu = _integration_context(startup_namespace)
    reboot_path = MODULE_PATH.parents[2] / "common" / "reboot.py"
    tree = ast.parse(reboot_path.read_text(encoding="utf-8"))
    nodes = [
        node for node in tree.body
        if (isinstance(node, ast.FunctionDef) and node.name == "wait_for_shutdown")
        or (isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id in ("SONIC_SSH_PORT", "SONIC_SSH_REGEX")
            for target in node.targets
        ))
    ]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(reboot_path), "exec"), startup_namespace)
    localhost = Mock()
    localhost.wait_for.return_value = MagicMock(is_failed=failed)
    run = startup_namespace["test_bmcctld_power_on_delay"]
    if failed:
        with pytest.raises(Exception, match="did not shutdown"):
            run(instance, localhost, Mock(return_value=pdu), Mock())
    else:
        run(instance, localhost, Mock(return_value=pdu), Mock())
    localhost.wait_for.assert_called_once_with(
        host=instance.duthost.mgmt_ip, port=22, state="absent",
        search_regex=startup_namespace["SONIC_SSH_REGEX"], delay=10, timeout=120,
        module_ignore_errors=True,
    )
    startup_namespace["wait_for_startup"].assert_called_once_with(
        instance.duthost, localhost, delay=10, timeout=600,
    )
    startup_namespace["wait_critical_processes"].assert_called_once_with(instance.duthost, timeout=600)


def _cold_reboot_context(namespace, original_delay):
    bmc, host, analyzer = Mock(), Mock(), Mock()
    bmc.shell.return_value = {"stdout": json.dumps({"MESSAGE": ONLINE})}
    bmc.critical_services_fully_started.return_value = True
    host.critical_services_fully_started.return_value = True
    analyzer.analyze.return_value = {"total": {"match": 1}}
    namespace.update(
        get_switch_host_or_skip_test=Mock(return_value=host),
        get_host_boot_id=Mock(side_effect=["host", "bmc-before", "bmc-after", "host"]),
        redis_hget=Mock(side_effect=["300", "300"]),
        CONFIG_DB="CONFIG_DB",
        reboot=Mock(),
        REBOOT_TYPE_COLD="cold",
        make_bmc_loganalyzer=Mock(return_value=analyzer),
        wait_until=lambda timeout, interval, delay, condition: condition(),
    )
    default_shell = bmc.shell.return_value

    def shell(command):
        if command.startswith("sonic-db-cli CONFIG_DB HGET"):
            return {"stdout": original_delay}
        if command == "show reboot-cause":
            return {"stdout": "User issued reboot command"}
        return default_shell

    bmc.shell.side_effect = shell
    return Mock(duthost=bmc), host


@pytest.mark.parametrize("original_delay", ["30", "0", ""])
def test_cold_reboot_ignores_explicit_delay_and_restores_config(startup_namespace, original_delay):
    """A saved nonzero delay is bypassed with positive evidence and host isolation."""
    instance, host = _cold_reboot_context(startup_namespace, original_delay)
    localhost = Mock()
    startup_namespace["test_bmc_reboot_does_not_affect_switch_host"](instance, localhost)
    startup_namespace["reboot"].assert_called_once_with(
        instance.duthost, localhost, reboot_type="cold", wait_for_ssh=True, safe_reboot=True)
    startup_namespace["make_bmc_loganalyzer"].return_value.analyze.assert_called_once_with(
        startup_namespace["make_bmc_loganalyzer"].return_value.init.return_value, fail=False)
    commands = [args.args[0] for args in instance.duthost.shell.call_args_list]
    assert commands[:2] == [
        "sonic-db-cli CONFIG_DB HGET 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay",
        "config chassis modules power-on-delay SWITCH-HOST 300",
    ]
    expected_restore = (f"config chassis modules power-on-delay SWITCH-HOST {original_delay}"
                        if original_delay else
                        "sonic-db-cli CONFIG_DB HDEL 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay")
    assert commands[-2:] == [expected_restore, "sudo config save -y"]
    assert commands.count("sudo config save -y") == 2
    assert startup_namespace["redis_hget"].call_count == 2
    assert startup_namespace["get_host_boot_id"].call_count == 4
    host.critical_services_fully_started.assert_called_once_with()


@pytest.mark.parametrize("failure", [
    "reboot", "bmc-health", "bmc-id", "host-id", "missing-id", "host-health",
    "not-set", "not-persisted", "power-loss", "event-log", "journal", "delay-applied",
])
def test_cold_reboot_rejects_bad_evidence_and_restores_delay(startup_namespace, failure):
    """Reboot, persistence, isolation, and delay failures cannot bypass restoration."""
    instance, host = _cold_reboot_context(startup_namespace, "30")
    shell = instance.duthost.shell.side_effect
    if failure == "reboot":
        startup_namespace["reboot"].side_effect = RuntimeError("Reboot failed")
    elif failure == "bmc-health":
        instance.duthost.critical_services_fully_started.return_value = False
    elif failure == "bmc-id":
        startup_namespace["get_host_boot_id"].side_effect = ["host", "bmc", "bmc", "host"]
    elif failure == "host-id":
        startup_namespace["get_host_boot_id"].side_effect = ["host", "bmc", "new-bmc", "new-host"]
    elif failure == "missing-id":
        startup_namespace["get_host_boot_id"].side_effect = ["host", "bmc", "", ""]
    elif failure == "host-health":
        host.critical_services_fully_started.return_value = False
    elif failure == "not-set":
        startup_namespace["redis_hget"].side_effect = ["0"]
    elif failure == "not-persisted":
        startup_namespace["redis_hget"].side_effect = ["300", "0"]
    elif failure == "power-loss":
        instance.duthost.shell.side_effect = lambda command: (
            {"stdout": "Power Loss"} if command == "show reboot-cause" else shell(command))
    elif failure == "event-log":
        startup_namespace["make_bmc_loganalyzer"].return_value.analyze.return_value = {"total": {"match": 0}}
    elif failure == "journal":
        instance.duthost.shell.side_effect = lambda command: (
            {"stdout": ""} if command.startswith("journalctl") else shell(command))
    elif failure == "delay-applied":
        journal = "\n".join(json.dumps({"MESSAGE": message}) for message in (
            ONLINE, "Waiting 300s before initial Switch-Host power-on check (SWITCH_HOST_POWER_ON_DELAY)"))
        instance.duthost.shell.side_effect = lambda command: (
            {"stdout": journal} if command.startswith("journalctl") else shell(command))
    with pytest.raises(RuntimeError if failure == "reboot" else AssertionError):
        startup_namespace["test_bmc_reboot_does_not_affect_switch_host"](instance, Mock())
    assert instance.duthost.shell.call_args_list[-2:] == [
        call("config chassis modules power-on-delay SWITCH-HOST 30"), call("sudo config save -y")
    ]


@pytest.mark.parametrize("snapshot,error", [
    (RuntimeError("Redis snapshot command failed"), RuntimeError),
    ({}, KeyError),
    ({"stdout": "invalid"}, AssertionError),
])
def test_cold_reboot_snapshot_failure_aborts_without_changing_config(startup_namespace, snapshot, error):
    """A failed or malformed snapshot cannot trigger HDEL or config save during cleanup."""
    instance, _ = _cold_reboot_context(startup_namespace, "30")
    instance.duthost.shell.side_effect = [snapshot]
    with pytest.raises(error):
        startup_namespace["test_bmc_reboot_does_not_affect_switch_host"](instance, Mock())
    instance.duthost.shell.assert_called_once_with(
        "sonic-db-cli CONFIG_DB HGET 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay")
    startup_namespace["redis_hget"].assert_not_called()
    startup_namespace["reboot"].assert_not_called()
    startup_namespace["make_bmc_loganalyzer"].assert_not_called()
