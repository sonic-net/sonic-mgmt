"""Exercise cooling-aware BMC startup assertions without testbed dependencies."""

import ast
from contextlib import contextmanager, ExitStack, nullcontext
import json
from pathlib import Path
import re
import sys
from unittest.mock import Mock, call

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
               and node.name in ("_startup_power_on_observed", "_assert_liquid_cooled_power_on_delay",
                                 "_restore_on_exit", "_critical_leak_power_off", "_bmcctld_syslog_messages")]
    test_class = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                      and node.name == "TestBmcctldDaemon")
    methods = [node for node in test_class.body if isinstance(node, ast.FunctionDef)
               and node.name in ("test_bmcctld_power_on_delay", "test_bmc_reboot_does_not_affect_switch_host",
                                 "test_bmcctld_event_trigger")]
    namespace = dict(json=json, re=re, pytest_assert=_assert, pytest=pytest,
                     sys=sys, contextmanager=contextmanager, ExitStack=ExitStack,
                     logger=Mock(), CAUSE_POWER_LOSS="power loss")
    exec(compile(ast.Module(body=helpers + methods, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


@pytest.fixture
def production_assert_namespace(startup_namespace):
    """Exercise cleanup with the real pytest failure type, without importing testbed dependencies."""
    assertion_path = MODULE_PATH.parents[2] / "common" / "helpers" / "assertions.py"
    tree = ast.parse(assertion_path.read_text(encoding="utf-8"))
    assertion = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "pytest_assert")
    exec(compile(ast.Module(body=[assertion], type_ignores=[]), str(assertion_path), "exec"), startup_namespace)
    return startup_namespace


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
        wait_host_on=Mock(return_value=True),
        get_ansible_ssh_port=Mock(return_value=None),
        wait_for_startup=Mock(),
    )
    namespace["chassis"].is_liquid_cooled.return_value = cooling
    return Mock(duthost=bmc), host, pdu


def _run_power_cycle(namespace, instance, pdu, conn=None, localhost=None, ansible_adhoc=None):
    localhost = localhost or Mock(wait_for=Mock(return_value={"failed": False}))
    namespace["test_bmcctld_power_on_delay"](
        instance, localhost, Mock(return_value=pdu), conn or Mock(), ansible_adhoc or Mock())


@pytest.mark.parametrize("cooling,startup", [(False, ONLINE), (False, IMMEDIATE), (True, DELAYED)])
def test_integration_keeps_reboot_and_health_checks(startup_namespace, cooling, startup):
    """Execute each accepted path through the real test and require both reboot IDs and health."""
    instance, host, pdu = _integration_context(startup_namespace, cooling, startup)
    conn = Mock()
    _run_power_cycle(startup_namespace, instance, pdu, conn=conn)
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
        _run_power_cycle(startup_namespace, instance, pdu)
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
        _run_power_cycle(startup_namespace, instance, pdu, conn=conn)
    else:
        with pytest.raises(AssertionError, match=r"Chassis.is_liquid_cooled\(\) must return a boolean"):
            _run_power_cycle(startup_namespace, instance, pdu, conn=conn)
        pdu.turn_off_outlet.assert_not_called()
        instance.duthost.shell.assert_not_called()
    conn.request.assert_called_once_with("POST", "/platform/chassis/is_liquid_cooled", json.dumps({"args": []}))


def test_cooling_api_failure_propagates_before_power_cycle(startup_namespace):
    """An API request failure cannot select the relaxed air-cooled policy."""
    instance, _, pdu = _integration_context(startup_namespace)
    startup_namespace["chassis"].is_liquid_cooled.side_effect = RuntimeError("Platform API unavailable")
    with pytest.raises(RuntimeError, match="Platform API unavailable"):
        _run_power_cycle(startup_namespace, instance, pdu)
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
        _run_power_cycle(startup_namespace, instance, pdu)
    assert str(failure.value).splitlines()[0] == f"Failed to power on PDU outlets {failed_outlets}"
    assert pdu.turn_on_outlet.call_args_list == [call(outlet) for outlet in outlets]
    assert startup_namespace["logger"].exception.call_args_list[:sum(isinstance(r, Exception) for r in results)] == [
        call("Failed to restore PDU outlet %s", outlet)
        for outlet, result in zip(outlets, results) if isinstance(result, Exception)
    ]
    startup_namespace["wait_critical_processes"].assert_called_once_with(instance.duthost, timeout=600)


def _cold_reboot_context(namespace, original_delay):
    bmc, host, analyzer = Mock(), Mock(), Mock()
    bmc.shell.return_value = {"stdout": f"Nov  1 00:00:00 bmc INFO pmon#bmcctld: {ONLINE}"}
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
    "not-set", "not-persisted", "power-loss", "event-log", "syslog", "delay-applied",
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
    elif failure == "syslog":
        instance.duthost.shell.side_effect = lambda command: (
            {"stdout": ""} if command.startswith("sudo zcat") else shell(command))
    elif failure == "delay-applied":
        syslog = "\n".join(f"Nov  1 00:00:00 bmc INFO pmon#bmcctld: {message}" for message in (
            ONLINE, "Waiting 300s before initial Switch-Host power-on check (SWITCH_HOST_POWER_ON_DELAY)"))
        instance.duthost.shell.side_effect = lambda command: (
            {"stdout": syslog} if command.startswith("sudo zcat") else shell(command))
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


@pytest.mark.parametrize("port", [None, 22, 2222, "2222"])
@pytest.mark.parametrize("probe", [{"failed": False}, {"failed": True, "msg": "Timeout"}, RuntimeError("Probe failed")])
def test_power_cycle_local_probe_and_recovery_order(startup_namespace, port, probe):
    """Probe the inventory endpoint locally, then restore every outlet before SSH/DB cleanup."""
    instance, _, pdu = _integration_context(startup_namespace)
    startup_namespace["get_ansible_ssh_port"].return_value = port
    localhost = Mock()
    if isinstance(probe, Exception):
        localhost.wait_for.side_effect = probe
    else:
        localhost.wait_for.return_value = probe
    events = Mock()
    events.attach_mock(pdu.turn_on_outlet, "power_on")
    events.attach_mock(startup_namespace["wait_for_startup"], "ssh")
    events.attach_mock(startup_namespace["wait_critical_processes"], "critical")
    events.attach_mock(instance.duthost.shell, "shell")
    if isinstance(probe, Exception):
        with pytest.raises(RuntimeError, match="Probe failed"):
            _run_power_cycle(startup_namespace, instance, pdu, localhost=localhost)
    elif probe["failed"]:
        with pytest.raises(AssertionError, match="BMC remained reachable"):
            _run_power_cycle(startup_namespace, instance, pdu, localhost=localhost)
    else:
        _run_power_cycle(startup_namespace, instance, pdu, localhost=localhost)
    localhost.wait_for.assert_called_once_with(
        host=instance.duthost.mgmt_ip, port=port or 22, state="stopped",
        delay=10, timeout=120, module_ignore_errors=True)
    recovery = [
        call.power_on(outlet) for outlet in pdu.get_outlet_status.return_value
    ] + [
        call.ssh(instance.duthost, localhost, delay=10, timeout=600, port=port or 22),
        call.critical(instance.duthost, timeout=600),
    ]
    first_on = events.mock_calls.index(recovery[0])
    assert events.mock_calls[first_on:first_on + len(recovery)] == recovery
    assert events.mock_calls[-2:] == [
        call.shell("config chassis modules power-on-delay SWITCH-HOST 30"), call.shell("sudo config save -y")]
    assert not any(c.args[0] == "true" for c in instance.duthost.shell.call_args_list)


@pytest.mark.parametrize("snapshot,error", [
    (RuntimeError("Snapshot failed"), RuntimeError), ({}, KeyError),
    ({"stdout": "bad"}, AssertionError),
])
def test_power_cycle_requires_valid_snapshot(startup_namespace, snapshot, error):
    """Never change configuration or power when the original delay is unknown."""
    instance, _, pdu = _integration_context(startup_namespace)
    instance.duthost.shell.side_effect = [snapshot]
    with pytest.raises(error):
        _run_power_cycle(startup_namespace, instance, pdu)
    assert instance.duthost.shell.call_count == 1
    pdu.turn_off_outlet.assert_not_called()


@pytest.mark.parametrize("original", ["", "0", "45"])
def test_power_cycle_restores_original_delay(startup_namespace, original):
    """Restore a present numeric delay or remove only the originally absent field."""
    instance, _, pdu = _integration_context(startup_namespace)
    shell = instance.duthost.shell.side_effect
    reads = 0

    def snapshot(command, **kwargs):
        nonlocal reads
        if "HGET" in command:
            reads += 1
            if reads == 1:
                return {"stdout": original}
        return shell(command, **kwargs)

    instance.duthost.shell.side_effect = snapshot
    _run_power_cycle(startup_namespace, instance, pdu)
    restore = (f"config chassis modules power-on-delay SWITCH-HOST {original}" if original else
               "sonic-db-cli CONFIG_DB HDEL 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay")
    assert instance.duthost.shell.call_args_list[-2:] == [call(restore), call("sudo config save -y")]


@pytest.mark.parametrize("primary", [False, True])
@pytest.mark.parametrize("failure", ["ssh", "critical", "restore", "save"])
def test_power_cycle_cleanup_errors_and_unrecovered_bmc(startup_namespace, primary, failure):
    """Keep the original validation error; fail cleanup alone and avoid DB access before recovery."""
    instance, _, pdu = _integration_context(startup_namespace)
    localhost = Mock(wait_for=Mock(return_value={"failed": primary}))
    if failure in ("ssh", "critical"):
        startup_namespace["wait_for_startup" if failure == "ssh" else "wait_critical_processes"].side_effect = (
            RuntimeError(failure))
    else:
        shell = instance.duthost.shell.side_effect
        saves = 0
        delay_sets = 0

        def cleanup_failure(command, **kwargs):
            nonlocal saves, delay_sets
            if command == "sudo config save -y":
                saves += 1
                if failure == "save" and saves == 2:
                    raise RuntimeError(failure)
            if command.startswith("config chassis modules power-on-delay"):
                delay_sets += 1
                if failure == "restore" and delay_sets == 2:
                    raise RuntimeError(failure)
            return shell(command, **kwargs)

        instance.duthost.shell.side_effect = cleanup_failure
    with pytest.raises(AssertionError if primary else RuntimeError,
                       match="BMC remained reachable" if primary else failure):
        _run_power_cycle(startup_namespace, instance, pdu, localhost=localhost)
    assert pdu.turn_on_outlet.call_count == 2
    startup_namespace["logger"].exception.assert_called()
    if failure in ("ssh", "critical"):
        commands = [c.args[0] for c in instance.duthost.shell.call_args_list]
        assert commands[-1] == "sudo config save -y"
        assert commands.count("sudo config save -y") == 1
        assert any("original power_on_delay='30'" in str(c)
                   for c in startup_namespace["logger"].exception.call_args_list)


def test_power_cycle_primary_failure_survives_outlet_failure(startup_namespace):
    """Both PDU restoration errors are reported without masking the failed shutdown check."""
    instance, _, pdu = _integration_context(startup_namespace)
    pdu.turn_on_outlet.side_effect = [RuntimeError("PDU failed"), False]
    localhost = Mock(wait_for=Mock(return_value={"failed": True}))
    with pytest.raises(AssertionError, match="BMC remained reachable"):
        _run_power_cycle(startup_namespace, instance, pdu, localhost=localhost)
    assert pdu.turn_on_outlet.call_count == 2
    startup_namespace["wait_for_startup"].assert_called_once()
    startup_namespace["wait_critical_processes"].assert_called_once()
    startup_namespace["logger"].error.assert_called_once()


@pytest.mark.parametrize("records,accepted", [
    (f"Nov  1 00:00:00 bmc INFO pmon#bmcctld: {ONLINE}", True),
    (f"2026-11-01T00:00:00+00:00 bmc bmcctld[42]: {ONLINE}", True),
    ("", False),
    (f"Nov  1 bmc ansible-ansible.legacy.shell: Invoked with _raw_params=bmcctld: {ONLINE}", False),
    (f"Nov  1 bmc ansible.builtin.command: Invoked with bmcctld: {ONLINE}", False),
    (f"Nov  1 bmc other-daemon: {ONLINE}", False),
    (f"Nov  1 bmc other-daemon: bmcctld: {ONLINE}", False),
    (f"Nov  1 bmc INFO pmon#bmcctld: {ONLINE}\n"
     "Nov  1 bmc INFO pmon#bmcctld: Waiting 300s (SWITCH_HOST_POWER_ON_DELAY)", False),
])
def test_cold_reboot_uses_real_syslog_without_host_journal(startup_namespace, records, accepted):
    """An empty host journal is harmless, but genuine startup evidence and no delay are mandatory."""
    instance, _ = _cold_reboot_context(startup_namespace, "30")
    shell = instance.duthost.shell.side_effect

    def logs(command):
        if command.startswith("journalctl"):
            return {"stdout": ""}
        if command == "sudo zcat -f /var/log/syslog*":
            return {"stdout": records}
        return shell(command)

    instance.duthost.shell.side_effect = logs
    if accepted:
        startup_namespace["test_bmc_reboot_does_not_affect_switch_host"](instance, Mock())
    else:
        with pytest.raises(AssertionError):
            startup_namespace["test_bmc_reboot_does_not_affect_switch_host"](instance, Mock())
    assert call("sudo zcat -f /var/log/syslog*") in instance.duthost.shell.call_args_list
    assert not any(c.args[0].startswith("journalctl") for c in instance.duthost.shell.call_args_list)


def _event_context(namespace, present, major_supported=False):
    bmc, host, analyzer = Mock(), Mock(), Mock()
    original = "graceful_shutdown"

    def shell(command, **kwargs):
        if "HEXISTS" in command:
            return {"stdout": "1" if present else "0"}
        if "HGET" in command:
            return {"stdout": original}
        return {"rc": 0, "stdout": "startup shutdown"}

    def analyze(*args, **kwargs):
        messages = {
            "bmcctld_event_trigger_major_leak": ["MAJOR SYSTEM LEAK detected"],
            "bmcctld_event_trigger_rack_mgr_major_alert": ["MAJOR RACK MGR ALERT"],
        }.get(analyzer.marker_prefix, [])
        return {"total": {"match": 1}, "match_messages": {"/host/bmc/event.log": messages}}

    bmc.shell.side_effect = shell
    bmc.get_pmon_daemon_status.return_value = ("RUNNING", 10)
    analyzer.analyze.side_effect = analyze
    namespace.update(
        CONFIG_DB="CONFIG_DB", STATE_DB="STATE_DB", SYSTEM_LEAK_STATUS_TABLE="SYSTEM_LEAK_STATUS",
        RACK_MANAGER_ALERT_TABLE="RACK_MANAGER_ALERT", BMC_EVENT_LOG="/host/bmc/event.log",
        CAUSE_POWER_DOWN_FROM_BMC="power down request from BMC",
        redis_hget=Mock(side_effect=lambda dut, db, key, field: {
            "admin_status": "up", "device_leak_status": "None"}[field]),
        redis_hset=Mock(return_value={"rc": 0}), redis_hdel=Mock(return_value={"rc": 0}), redis_del=Mock(),
        make_bmc_loganalyzer=Mock(return_value=analyzer),
        get_switch_host_or_skip_test=Mock(return_value=host), get_host_uptime=Mock(return_value="before"),
        is_major_leak_supported=Mock(return_value=major_supported), action_is_syslog_only=Mock(return_value=True),
        pause_pmon_daemon=Mock(side_effect=lambda *args: nullcontext()),
        wait_host_off=Mock(return_value=True), recover_switch_host_after_power_off=Mock(),
        verify_bmc_initiated_reboot=Mock(), time=Mock(),
    )
    return Mock(duthost=bmc), host, original


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("failure", [
    None, "configure", "stop-thermal", "inject", "validate", "restore-status", "restart-thermal",
    "recover-host", "verify", "restore-policy",
])
def test_event_trigger_restores_only_original_policy_field(startup_namespace, present, failure):
    """The actual trigger restores policy across configuration, injection, validation and cleanup failures."""
    instance, host, original = _event_context(startup_namespace, present)
    if failure == "configure":
        shell = instance.duthost.shell.side_effect

        def configure(command, **kwargs):
            if command == "config liquid-cool leak-action system critical power_off":
                raise RuntimeError("configure")
            return shell(command, **kwargs)

        instance.duthost.shell.side_effect = configure
    elif failure in ("inject", "restore-status"):
        injected = False

        def hset(duthost, db, key, **fields):
            nonlocal injected
            if fields.get("device_leak_status") == "CRITICAL":
                injected = True
                if failure == "inject":
                    return {"rc": 1, "stderr": "injection failed"}
            elif injected and fields.get("device_leak_status") == "None" and failure == "restore-status":
                return {"rc": 1, "stderr": "restoration failed"}
            return {"rc": 0}

        startup_namespace["redis_hset"].side_effect = hset
    elif failure == "validate":
        startup_namespace["wait_host_off"].return_value = False
    elif failure in ("stop-thermal", "restart-thermal"):
        shell = instance.duthost.shell.side_effect

        def thermal_failure(command, **kwargs):
            action = "stop" if failure == "stop-thermal" else "start"
            if command == f"docker exec pmon supervisorctl {action} thermalctld":
                return {"rc": 1, "stderr": failure}
            return shell(command, **kwargs)

        instance.duthost.shell.side_effect = thermal_failure
    elif failure in ("recover-host", "verify"):
        startup_namespace["recover_switch_host_after_power_off" if failure == "recover-host"
                          else "verify_bmc_initiated_reboot"].side_effect = RuntimeError(failure)
    elif failure == "restore-policy":
        if present:
            def policy_failure(duthost, db, key, **fields):
                return {"rc": 1 if key == "LEAK_CONTROL_POLICY|policy" else 0}
            startup_namespace["redis_hset"].side_effect = policy_failure
        else:
            startup_namespace["redis_hdel"].return_value = {"rc": 1}
    if failure:
        error = RuntimeError if failure in ("configure", "recover-host", "verify") else AssertionError
        with pytest.raises(error):
            startup_namespace["test_bmcctld_event_trigger"](instance)
    else:
        startup_namespace["test_bmcctld_event_trigger"](instance)
    if present:
        policy_calls = [c for c in startup_namespace["redis_hset"].call_args_list
                        if c.args[2] == "LEAK_CONTROL_POLICY|policy"]
        assert policy_calls == [call(
            instance.duthost, "CONFIG_DB", "LEAK_CONTROL_POLICY|policy", system_critical_leak_action=original)]
        startup_namespace["redis_hdel"].assert_not_called()
    else:
        startup_namespace["redis_hdel"].assert_called_once_with(
            instance.duthost, "CONFIG_DB", "LEAK_CONTROL_POLICY|policy", "system_critical_leak_action")
    if failure != "configure":
        startup_namespace["recover_switch_host_after_power_off"].assert_called_once_with(
            instance.duthost, host, context="after Trigger 2b")
        assert instance.duthost.shell.call_args_list.count(
            call("docker exec pmon supervisorctl start thermalctld")) == 1
    if failure in ("restore-status", "restart-thermal", "recover-host", "restore-policy"):
        startup_namespace["logger"].exception.assert_called()


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("major_supported", [False, True])
def test_event_trigger_preserves_cleanup_order(production_assert_namespace, present, failure, major_supported):
    """Clean up leak status, thermalctld and host before verification and policy restoration."""
    namespace = production_assert_namespace
    instance, host, original = _event_context(namespace, present, major_supported=major_supported)
    namespace["wait_host_off"].return_value = not failure
    operations = Mock()
    operations.attach_mock(namespace["redis_hset"], "hset")
    operations.attach_mock(namespace["redis_hdel"], "hdel")
    operations.attach_mock(instance.duthost.shell, "shell")
    operations.attach_mock(namespace["recover_switch_host_after_power_off"], "recover")
    operations.attach_mock(namespace["verify_bmc_initiated_reboot"], "verify")
    with pytest.raises(pytest.fail.Exception, match="Switch-Host did not power OFF") if failure else nullcontext():
        namespace["test_bmcctld_event_trigger"](instance)
    injected = call.hset(instance.duthost, "STATE_DB", "SYSTEM_LEAK_STATUS|system", device_leak_status="CRITICAL")
    restored = (
        call.hset(instance.duthost, "CONFIG_DB", "LEAK_CONTROL_POLICY|policy",
                  system_critical_leak_action=original) if present else
        call.hdel(instance.duthost, "CONFIG_DB", "LEAK_CONTROL_POLICY|policy", "system_critical_leak_action"))
    calls = operations.mock_calls
    expected = [
        call.hset(instance.duthost, "STATE_DB", "SYSTEM_LEAK_STATUS|system", device_leak_status="None"),
        call.shell("docker exec pmon supervisorctl start thermalctld"),
        call.recover(instance.duthost, host, context="after Trigger 2b"),
    ]
    if not failure:
        expected.append(call.verify(host, "before", "power down request from BMC"))
    expected.append(restored)
    assert calls[calls.index(injected) + 1:calls.index(restored) + 1] == expected
    if major_supported:
        assert call.hset(
            instance.duthost, "STATE_DB", "SYSTEM_LEAK_STATUS|system", device_leak_status="MAJOR") in calls
        if not failure:
            assert call.hset(
                instance.duthost, "STATE_DB", "RACK_MANAGER_ALERT|test_trigger_alert", severity="MAJOR") in calls


@pytest.mark.parametrize("exists,present", [
    ("0", False), ("1", True), ("False", False), ("True", True),
    ("false", False), ("true", True), (" False\n", False), (" True\n", True),
])
@pytest.mark.parametrize("failure", [False, True])
def test_leak_policy_snapshot_supports_cli_output_formats(startup_namespace, exists, present, failure):
    """Numeric and boolean HEXISTS output must restore the original field state on success or failure."""
    instance, _, original = _event_context(startup_namespace, present)
    instance.duthost.shell.side_effect = (
        [{"stdout": exists}] + ([{"stdout": original}] if present else []) + [{"rc": 0}])
    trigger = Mock(side_effect=RuntimeError("Trigger failed") if failure else None)
    with pytest.raises(RuntimeError, match="Trigger failed") if failure else nullcontext():
        with startup_namespace["_critical_leak_power_off"](instance.duthost):
            trigger()
    trigger.assert_called_once_with()
    expected_calls = [
        call("sonic-db-cli CONFIG_DB HEXISTS 'LEAK_CONTROL_POLICY|policy' system_critical_leak_action")]
    if present:
        expected_calls.append(
            call("sonic-db-cli CONFIG_DB HGET 'LEAK_CONTROL_POLICY|policy' system_critical_leak_action"))
        startup_namespace["redis_hset"].assert_called_once_with(
            instance.duthost, "CONFIG_DB", "LEAK_CONTROL_POLICY|policy", system_critical_leak_action=original)
        startup_namespace["redis_hdel"].assert_not_called()
    else:
        startup_namespace["redis_hdel"].assert_called_once_with(
            instance.duthost, "CONFIG_DB", "LEAK_CONTROL_POLICY|policy", "system_critical_leak_action")
        startup_namespace["redis_hset"].assert_not_called()
    expected_calls.append(call("config liquid-cool leak-action system critical power_off"))
    assert instance.duthost.shell.call_args_list == expected_calls


@pytest.mark.parametrize("snapshot,error", [
    (RuntimeError("Snapshot failed"), RuntimeError), ({}, KeyError), ({"stdout": "invalid"}, AssertionError),
    ({"stdout": ""}, AssertionError), ({"stdout": "2"}, AssertionError),
    ({"stdout": "1"}, KeyError), ({"stdout": "True"}, KeyError),
])
def test_leak_policy_snapshot_failure_never_changes_policy(startup_namespace, snapshot, error):
    """Failed existence/value snapshots must not configure or restore an unknown policy."""
    instance, _, _ = _event_context(startup_namespace, True)
    instance.duthost.shell.side_effect = [snapshot, {}]
    with pytest.raises(error):
        with startup_namespace["_critical_leak_power_off"](instance.duthost):
            pytest.fail("Invalid snapshot accepted")
    startup_namespace["redis_hset"].assert_not_called()
    startup_namespace["redis_hdel"].assert_not_called()
    assert not any("config liquid-cool" in c.args[0] for c in instance.duthost.shell.call_args_list)


@pytest.mark.parametrize("present", [False, True])
def test_leak_policy_cleanup_failure_preserves_primary_error(startup_namespace, present):
    """Log failed restoration, but retain the injection/validation failure as the raised error."""
    instance, _, _ = _event_context(startup_namespace, present)
    startup_namespace["redis_hset"].return_value = {"rc": 1}
    startup_namespace["redis_hdel"].side_effect = RuntimeError("Cleanup failed")
    primary_error = RuntimeError("Primary failure")
    trigger_failure = Mock(side_effect=primary_error)
    with pytest.raises(RuntimeError, match="Primary failure") as failure:
        with startup_namespace["_critical_leak_power_off"](instance.duthost):
            trigger_failure()
    assert failure.value is primary_error
    trigger_failure.assert_called_once_with()
    startup_namespace["logger"].exception.assert_called_once()


@pytest.mark.parametrize("failed_step", ["configure", "readback", "save", "pdu-off"])
def test_power_cycle_early_failure_restores_config_and_power(startup_namespace, failed_step):
    """Configuration and PDU exceptions still run the applicable cleanup stages."""
    instance, _, pdu = _integration_context(startup_namespace)
    shell = instance.duthost.shell.side_effect
    commands = {
        "configure": "config chassis modules power-on-delay SWITCH-HOST 30",
        "readback": "sonic-db-cli CONFIG_DB HGET 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay",
        "save": "sudo config save -y",
    }
    count = 0

    def fail_once(command, **kwargs):
        nonlocal count
        if command == commands.get(failed_step):
            count += 1
            if count == (2 if failed_step == "readback" else 1):
                raise RuntimeError(failed_step)
        return shell(command, **kwargs)

    instance.duthost.shell.side_effect = fail_once
    if failed_step == "pdu-off":
        pdu.turn_off_outlet.side_effect = RuntimeError("pdu-off")
    with pytest.raises(RuntimeError, match=failed_step):
        _run_power_cycle(startup_namespace, instance, pdu)
    assert instance.duthost.shell.call_args_list[-2:] == [
        call("config chassis modules power-on-delay SWITCH-HOST 30"), call("sudo config save -y")]
    if failed_step == "pdu-off":
        assert pdu.turn_on_outlet.call_count == 2
        startup_namespace["wait_for_startup"].assert_called_once()
        startup_namespace["wait_critical_processes"].assert_called_once()
    else:
        pdu.turn_off_outlet.assert_not_called()


def test_event_trigger_primary_error_survives_all_cleanup_failures(startup_namespace):
    """Run all cleanup layers despite failures and retain the original leak validation assertion."""
    instance, host, _ = _event_context(startup_namespace, False)
    startup_namespace["wait_host_off"].return_value = False
    injected = False

    def hset(duthost, db, key, **fields):
        nonlocal injected
        if fields.get("device_leak_status") == "CRITICAL":
            injected = True
        elif injected and fields.get("device_leak_status") == "None":
            return {"rc": 1}
        return {"rc": 0}

    startup_namespace["redis_hset"].side_effect = hset
    shell = instance.duthost.shell.side_effect

    def restart_failure(command, **kwargs):
        if command == "docker exec pmon supervisorctl start thermalctld":
            return {"rc": 1, "stderr": "restart failed"}
        return shell(command, **kwargs)

    instance.duthost.shell.side_effect = restart_failure
    startup_namespace["recover_switch_host_after_power_off"].side_effect = RuntimeError("recovery failed")
    startup_namespace["redis_hdel"].return_value = {"rc": 1}
    with pytest.raises(AssertionError, match="Switch-Host did not power OFF"):
        startup_namespace["test_bmcctld_event_trigger"](instance)
    assert instance.duthost.shell.call_args_list.count(
        call("docker exec pmon supervisorctl start thermalctld")) == 1
    startup_namespace["recover_switch_host_after_power_off"].assert_called_once_with(
        instance.duthost, host, context="after Trigger 2b")
    startup_namespace["redis_hdel"].assert_called_once()
    assert startup_namespace["logger"].exception.call_count == 4


@pytest.mark.parametrize("primary_type", [None, RuntimeError, pytest.fail.Exception, pytest.skip.Exception])
@pytest.mark.parametrize("cleanup_type", [RuntimeError, pytest.fail.Exception])
def test_cleanup_handles_pytest_failures_without_masking_primary(
        production_assert_namespace, primary_type, cleanup_type):
    """Cleanup failures override skips, but never replace an actual primary test failure."""
    namespace = production_assert_namespace
    primary = primary_type("Primary failure") if primary_type else None
    cleanup = cleanup_type("Cleanup failed")
    trigger_failure = Mock(side_effect=primary)
    restore = Mock(side_effect=cleanup)
    expected = primary if primary is not None and primary_type is not pytest.skip.Exception else cleanup
    with pytest.raises((type(expected), pytest.skip.Exception)) as failure:
        with namespace["_restore_on_exit"](restore, "test cleanup"):
            trigger_failure()
    assert failure.value is expected
    restore.assert_called_once_with()
    namespace["logger"].exception.assert_called_once()


def test_cleanup_preserves_skip_after_successful_restoration(production_assert_namespace):
    """A skip remains a skip when its registered cleanup succeeds."""
    namespace = production_assert_namespace
    skip = pytest.skip.Exception("No PDU controller")
    trigger = Mock(side_effect=skip)
    restore = Mock()
    with pytest.raises(pytest.skip.Exception) as outcome:
        with namespace["_restore_on_exit"](restore, "test cleanup"):
            trigger()
    assert outcome.value is skip
    restore.assert_called_once_with()
    namespace["logger"].exception.assert_not_called()


@pytest.mark.parametrize("original", ["", "45"])
@pytest.mark.parametrize("pdu_unavailable", [False, True])
@pytest.mark.parametrize("cleanup_stage,cleanup_type", [
    (None, None), ("restore", RuntimeError), ("save", pytest.fail.Exception),
])
def test_power_cycle_missing_pdu_reports_cleanup_failure(
        production_assert_namespace, original, pdu_unavailable, cleanup_stage, cleanup_type):
    """Missing-PDU skips must fail if restoring or saving the original delay fails."""
    namespace = production_assert_namespace
    instance, host, pdu = _integration_context(namespace)
    get_pdu = Mock(return_value=None)
    if pdu_unavailable:
        get_pdu.side_effect = RuntimeError("PDU unavailable")
    restore_command = (
        f"config chassis modules power-on-delay SWITCH-HOST {original}" if original else
        "sonic-db-cli CONFIG_DB HDEL 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay")
    cleanup_error = cleanup_type("Cleanup failed") if cleanup_type else None
    reads, saves = 0, 0

    def shell(command, **kwargs):
        nonlocal reads, saves
        if "HGET" in command:
            reads += 1
            return {"stdout": original if reads == 1 else "30"}
        if cleanup_stage == "restore" and command == restore_command:
            raise cleanup_error
        if command == "sudo config save -y":
            saves += 1
            if cleanup_stage == "save" and saves == 2:
                raise cleanup_error
        return {"stdout": ""}

    instance.duthost.shell.side_effect = shell
    with pytest.raises((cleanup_type or pytest.skip.Exception, pytest.skip.Exception)) as outcome:
        namespace["test_bmcctld_power_on_delay"](instance, Mock(), get_pdu, Mock(), Mock())
    if cleanup_error:
        assert outcome.value is cleanup_error
        namespace["logger"].exception.assert_called_once()
    else:
        assert "PDU controller" in str(outcome.value)
        namespace["logger"].exception.assert_not_called()
    get_pdu.assert_called_once_with(host)
    expected_commands = [
        "sonic-db-cli CONFIG_DB HGET 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay",
        "config chassis modules power-on-delay SWITCH-HOST 30",
        "sonic-db-cli CONFIG_DB HGET 'CHASSIS_MODULE|SWITCH-HOST' power_on_delay",
        "sudo config save -y", restore_command,
    ]
    if cleanup_stage != "restore":
        expected_commands.append("sudo config save -y")
    assert [c.args[0] for c in instance.duthost.shell.call_args_list] == expected_commands
    pdu.turn_off_outlet.assert_not_called()
    namespace["wait_for_startup"].assert_not_called()


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("primary_type", [None, RuntimeError, pytest.fail.Exception])
def test_policy_cleanup_uses_production_pytest_assert(production_assert_namespace, present, primary_type):
    """A failed HSET/HDEL restoration uses the actual assertion helper and preserves primary identity."""
    namespace = production_assert_namespace
    instance, _, _ = _event_context(namespace, present)
    namespace["redis_hset"].return_value = {"rc": 1}
    namespace["redis_hdel"].return_value = {"rc": 1}
    primary = primary_type("Primary failure") if primary_type else None
    trigger_failure = Mock(side_effect=primary)
    with pytest.raises(primary_type or pytest.fail.Exception) as failure:
        with namespace["_critical_leak_power_off"](instance.duthost):
            trigger_failure()
    if primary is not None:
        assert failure.value is primary
    else:
        assert "Failed to restore original system_critical_leak_action" in str(failure.value)
    namespace["logger"].exception.assert_called_once()


@pytest.mark.parametrize("primary", [False, True])
@pytest.mark.parametrize("cleanup_stage", ["restore-status", "restart-thermal", "recover-host", "restore-policy"])
def test_event_cleanup_preserves_real_pytest_failure(production_assert_namespace, primary, cleanup_stage):
    """Actual pytest assertions cannot be masked by status, thermal, host or policy cleanup failures."""
    namespace = production_assert_namespace
    instance, host, _ = _event_context(namespace, False)
    namespace["wait_host_off"].return_value = not primary
    injected = False

    def hset(duthost, db, key, **fields):
        nonlocal injected
        if fields.get("device_leak_status") == "CRITICAL":
            injected = True
        elif injected and fields.get("device_leak_status") == "None" and cleanup_stage == "restore-status":
            return {"rc": 1}
        return {"rc": 0}

    namespace["redis_hset"].side_effect = hset
    shell = instance.duthost.shell.side_effect

    def thermal_failure(command, **kwargs):
        if cleanup_stage == "restart-thermal" and command == "docker exec pmon supervisorctl start thermalctld":
            return {"rc": 1}
        return shell(command, **kwargs)

    instance.duthost.shell.side_effect = thermal_failure
    if cleanup_stage == "recover-host":
        namespace["recover_switch_host_after_power_off"].side_effect = pytest.fail.Exception("Recovery failed")
    elif cleanup_stage == "restore-policy":
        namespace["redis_hdel"].return_value = {"rc": 1}
    message = "Switch-Host did not power OFF" if primary else {
        "restore-status": "Failed to restore original system leak status",
        "restart-thermal": "Failed to start thermalctld",
        "recover-host": "Recovery failed",
        "restore-policy": "Failed to restore original system_critical_leak_action",
    }[cleanup_stage]
    with pytest.raises(pytest.fail.Exception, match=message):
        namespace["test_bmcctld_event_trigger"](instance)
    assert instance.duthost.shell.call_args_list.count(
        call("docker exec pmon supervisorctl start thermalctld")) == 1
    namespace["recover_switch_host_after_power_off"].assert_called_once_with(
        instance.duthost, host, context="after Trigger 2b")
    namespace["redis_hdel"].assert_called_once()
    namespace["logger"].exception.assert_called_once()


def test_checked_thermal_stop_failure_aborts_injection(production_assert_namespace):
    """A nonzero supervisorctl stop must abort injection but still attempt restart, host and policy cleanup."""
    namespace = production_assert_namespace
    instance, _, _ = _event_context(namespace, False)
    shell = instance.duthost.shell.side_effect

    def stop_failure(command, **kwargs):
        if command == "docker exec pmon supervisorctl stop thermalctld":
            return {"rc": 1, "stderr": "stop failed"}
        return shell(command, **kwargs)

    instance.duthost.shell.side_effect = stop_failure
    with pytest.raises(pytest.fail.Exception, match="Failed to stop thermalctld"):
        namespace["test_bmcctld_event_trigger"](instance)
    assert not any(c.kwargs.get("device_leak_status") == "CRITICAL"
                   for c in namespace["redis_hset"].call_args_list)
    assert instance.duthost.shell.call_args_list.count(
        call("docker exec pmon supervisorctl start thermalctld")) == 1
    namespace["recover_switch_host_after_power_off"].assert_called_once()
    namespace["redis_hdel"].assert_called_once()


@pytest.mark.parametrize("primary", [False, True])
def test_power_recovery_reports_real_pytest_failure(production_assert_namespace, primary):
    """Critical-process pytest failures are reported without unsafe database cleanup or lost primary errors."""
    namespace = production_assert_namespace
    instance, _, pdu = _integration_context(namespace)
    recovery_error = pytest.fail.Exception("Critical processes unhealthy")
    namespace["wait_critical_processes"].side_effect = recovery_error
    localhost = Mock(wait_for=Mock(return_value={"failed": primary}))
    with pytest.raises(pytest.fail.Exception) as failure:
        _run_power_cycle(namespace, instance, pdu, localhost=localhost)
    if primary:
        assert "BMC remained reachable" in str(failure.value)
    else:
        assert failure.value is recovery_error
    commands = [c.args[0] for c in instance.duthost.shell.call_args_list]
    assert commands.count("sudo config save -y") == 1
    assert pdu.turn_on_outlet.call_count == 2
    assert call("BMC recovery failed; original power_on_delay=%r", "30") in (
        namespace["logger"].exception.call_args_list)
