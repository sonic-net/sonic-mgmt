"""Focused tests for clock recovery without loading testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/clock/unit_tests \
        tests/clock/unit_tests/unit_test_clock_recovery.py -q
"""

import ast
import ipaddress
import json
import re
import shlex
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock

import pytest


CLOCK_DIR = Path(__file__).resolve().parents[1]
CONFTEST_PATH = CLOCK_DIR / "conftest.py"
NTP_UTILS_PATH = CLOCK_DIR / "ntp_utils.py"


def _load_functions(path, function_names, namespace):
    tree = ast.parse(path.read_text())
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    selected = [functions[name] for name in function_names]
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def _function_node(path, function_name):
    tree = ast.parse(path.read_text())
    return next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )


def _clock_namespace(*function_names):
    namespace = {
        "CLOCK_OFFSET_TOLERANCE": 5,
        "CLOCK_SOURCE_MAX_OFFSET": 60,
        "CLOCK_RECOVERY_TIMEOUT": 300,
        "CLOCK_RECOVERY_COMMAND_TIMEOUT": 120,
        "CLOCK_RECOVERY_LEASE": 1800,
        "CLOCK_RECOVERY_RETRY_INTERVAL": 60,
        "CLOCK_RECOVERY_LOCK_TIMEOUT": 30,
        "CLOCK_PTF_RECOVERY_TIMEOUT": 3600,
        "CLOCK_POST_RESTORE_SETTLE_TIME": 20,
        "contextmanager": contextmanager,
        "json": json,
        "logging": Mock(),
        "pytest": pytest,
        "shlex": shlex,
        "time": Mock(),
        "uuid": uuid,
        "RunAnsibleModuleFail": RuntimeError,
    }
    return _load_functions(CONFTEST_PATH, function_names, namespace)


def _ntp_namespace(*function_names):
    class NtpDaemon:
        CHRONY = "chrony"
        NTPSEC = "ntpsec"
        NTP = "ntp"

    namespace = {
        "NTP_SERVER_RECOVERY_LEASE": 1800,
        "NTP_SERVER_RECOVERY_RETRY_INTERVAL": 60,
        "NTP_SERVER_RECOVERY_COMMAND_TIMEOUT": 120,
        "NTP_SERVER_LOCK_TIMEOUT": 30,
        "NtpDaemon": NtpDaemon,
        "ipaddress": ipaddress,
        "re": re,
        "shlex": shlex,
        "uuid": uuid,
        "pytest_assert": assert_condition,
    }
    return _load_functions(NTP_UTILS_PATH, function_names, namespace)


def assert_condition(condition, message):
    assert condition, message


def _request(ntp_server=None):
    request = Mock()
    request.config.getoption.return_value = ntp_server
    return request


def test_clock_source_prefers_explicit_server():
    namespace = _clock_namespace("_get_ntp_config", "_clock_ntp_source")
    duthost = Mock()
    namespace["_validate_ntp_source"] = Mock()

    with namespace["_clock_ntp_source"](
            _request("192.0.2.10"), duthost, None, {}) as ntp_server:
        assert ntp_server == "192.0.2.10"

    namespace["_validate_ntp_source"].assert_called_once_with(duthost, "192.0.2.10")
    duthost.command.assert_not_called()


def test_clock_source_uses_configured_server_without_ptf():
    namespace = _clock_namespace("_get_ntp_config", "_clock_ntp_source")
    duthost = Mock()
    duthost.command.return_value = {"stdout": '{"time.example.com": {"iburst": true}}'}
    namespace["_check_ntp_source"] = Mock(return_value=(True, None))

    with namespace["_clock_ntp_source"](
            _request(), duthost, None, {}) as ntp_server:
        assert ntp_server == "time.example.com"


def test_clock_source_falls_back_to_ptf_when_configured_server_is_unreachable():
    namespace = _clock_namespace("_get_ntp_config", "_clock_ntp_source")
    duthost = Mock()
    duthost.command.return_value = {"stdout": '{"10.11.0.1": {}}'}
    duthost.dut_basic_facts.return_value = {
        "ansible_facts": {"dut_basic_facts": {"is_mgmt_ipv6_only": False}}
    }
    namespace["_check_ntp_source"] = Mock(
        return_value=(False, "NTP source 10.11.0.1 is not reachable")
    )
    namespace["_validate_ntp_source"] = Mock()
    ptfhost = Mock(mgmt_ip="192.0.2.20", mgmt_ipv6=None)

    @contextmanager
    def setup_ntp_server_context(ptf, **kwargs):
        yield ptf.mgmt_ip

    namespace["setup_ntp_server_context"] = setup_ntp_server_context
    with namespace["_clock_ntp_source"](
            _request(), duthost, ptfhost, {}) as ntp_server:
        assert ntp_server == "192.0.2.20"

    namespace["_validate_ntp_source"].assert_called_once_with(duthost, "192.0.2.20")


@pytest.mark.parametrize("ptfhost", [None, []])
def test_clock_source_skips_only_date_case_without_any_source(ptfhost):
    namespace = _clock_namespace("_get_ntp_config", "_clock_ntp_source")
    duthost = Mock()
    duthost.command.return_value = {"stdout": "{}"}

    with pytest.raises(pytest.skip.Exception, match="no PTF host"):
        with namespace["_clock_ntp_source"](_request(), duthost, ptfhost, {}):
            pass


def test_clock_source_uses_ptf_ipv6_for_ipv6_only_management():
    namespace = _clock_namespace("_get_ntp_config", "_clock_ntp_source")
    duthost = Mock()
    duthost.command.return_value = {"stdout": "{}"}
    duthost.dut_basic_facts.return_value = {
        "ansible_facts": {"dut_basic_facts": {"is_mgmt_ipv6_only": True}}
    }
    ptfhost = Mock(mgmt_ipv6="2001:db8::10")
    calls = []
    namespace["_validate_ntp_source"] = Mock()

    @contextmanager
    def setup_ntp_server_context(ptf, **kwargs):
        calls.append((ptf, kwargs))
        yield ptf.mgmt_ipv6

    namespace["setup_ntp_server_context"] = setup_ntp_server_context
    with namespace["_clock_ntp_source"](
            _request(), duthost, ptfhost, {}) as ntp_server:
        assert ntp_server == "2001:db8::10"

    assert calls[0][1]["ptf_use_ipv6"] is True


def test_source_is_rejected_before_mutation_when_clock_is_skewed():
    namespace = _clock_namespace("_check_ntp_source", "_validate_ntp_source")
    namespace["_get_clock_offset"] = Mock(return_value=61)

    with pytest.raises(pytest.skip.Exception, match="refusing to change"):
        namespace["_validate_ntp_source"](Mock(), "192.0.2.10")


def test_recovery_is_armed_before_preflight_or_timezone_mutation():
    restore_time = _function_node(CONFTEST_PATH, "restore_time")
    init_timezone = _function_node(CONFTEST_PATH, "init_timezone")

    restore_calls = [
        (node.func.id, node.lineno)
        for node in ast.walk(restore_time)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in {"_arm_recovery", "_run_recovery"}
    ]
    timezone_calls = [
        (ast.unparse(node.func), node.lineno)
        for node in ast.walk(init_timezone)
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) in {"_arm_recovery", "ClockUtils.run_cmd"}
    ]

    first_restore_call = min(restore_calls, key=lambda call: call[1])
    first_timezone_call = min(timezone_calls, key=lambda call: call[1])
    assert first_restore_call[0] == "_arm_recovery"
    assert first_timezone_call[0] == "_arm_recovery"


def test_fixtures_yield_recovery_refresh_callbacks():
    restore_time = ast.unparse(_function_node(CONFTEST_PATH, "restore_time"))
    init_timezone = ast.unparse(_function_node(CONFTEST_PATH, "init_timezone"))

    assert "yield refresh_recovery" in restore_time
    assert "yield refresh_recovery" in init_timezone


def test_clock_tests_refresh_recovery_during_mutations():
    tree = ast.parse((CLOCK_DIR / "test_clock.py").read_text())
    tests = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }

    timezone_test = ast.unparse(tests["test_config_clock_timezone"])
    date_test = ast.unparse(tests["test_config_clock_date"])

    assert timezone_test.count("refresh_recovery()") >= 2
    assert date_test.count("refresh_recovery()") >= 2


def test_clock_recovery_waits_for_post_restore_errors_to_settle():
    restore_time = ast.unparse(_function_node(CONFTEST_PATH, "restore_time"))

    verify_index = restore_time.rindex("_verify_clock_restoration")
    settle_index = restore_time.index(
        "time.sleep(CLOCK_POST_RESTORE_SETTLE_TIME)",
        verify_index
    )
    success_index = restore_time.index("recovery_verified = True", settle_index)

    assert verify_index < settle_index < success_index


def test_timezone_recovery_restores_config_db_and_system_timezone():
    namespace = _clock_namespace(
        "_install_retry_watchdog",
        "_install_timezone_recovery"
    )
    duthost = Mock()

    namespace["_install_timezone_recovery"](duthost, "Etc/UTC")

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    assert "config clock timezone Etc/UTC" in recovery_script
    assert "timedatectl set-timezone Etc/UTC" in recovery_script
    subprocess.run(["bash", "-n"], input=recovery_script, text=True, check=True)


def test_timezone_restoration_requires_matching_config_db_state():
    namespace = _clock_namespace("_timezone_is_expected")
    namespace["ClockUtils"] = Mock()
    namespace["ClockUtils"].verify_timezone_value.return_value = True
    namespace["_get_configured_timezone"] = Mock(return_value="Pacific/Kiritimati")

    assert not namespace["_timezone_is_expected"](
        Mock(), Mock(), "Etc/UTC"
    )


def test_unverified_armed_recovery_always_defers_ptf_cleanup():
    restore_time = ast.unparse(_function_node(CONFTEST_PATH, "restore_time"))

    assert "ntp_source_state['defer_cleanup'] = recovery_armed" in restore_time
    assert "_recovery_is_armed" not in restore_time


def test_dut_watchdog_is_monotonic_and_bounded():
    namespace = _clock_namespace("_install_retry_watchdog")
    duthost = Mock()
    recovery = {
        "script_path": "/tmp/recover.sh",
        "watchdog_path": "/tmp/watchdog.sh",
    }

    namespace["_install_retry_watchdog"](
        duthost,
        recovery,
        ["/tmp/recover.sh", "/tmp/watchdog.sh"]
    )

    watchdog = duthost.copy.call_args.kwargs["content"]
    assert "/proc/uptime" in watchdog
    assert "$SECONDS" not in watchdog
    assert "timeout --kill-after=10 120" in watchdog
    assert 'if [ "$now" -ge "$deadline" ]' in watchdog
    subprocess.run(["bash", "-n"], input=watchdog, text=True, check=True)


def test_dut_watchdog_stops_at_monotonic_deadline(tmp_path):
    namespace = _clock_namespace("_install_retry_watchdog")
    namespace["CLOCK_RECOVERY_LEASE"] = 2
    namespace["CLOCK_RECOVERY_RETRY_INTERVAL"] = 1
    namespace["CLOCK_RECOVERY_COMMAND_TIMEOUT"] = 1
    recovery_script = tmp_path / "recover.sh"
    recovery_script.write_text("#!/bin/bash\nexit 1\n")
    recovery_script.chmod(0o755)
    watchdog_path = tmp_path / "watchdog.sh"
    recovery = {
        "script_path": str(recovery_script),
        "watchdog_path": str(watchdog_path),
    }
    duthost = Mock()

    namespace["_install_retry_watchdog"](
        duthost,
        recovery,
        [str(recovery_script), str(watchdog_path)]
    )
    watchdog_path.write_text(duthost.copy.call_args.kwargs["content"])
    watchdog_path.chmod(0o755)

    result = subprocess.run(
        [str(watchdog_path)],
        text=True,
        capture_output=True,
        timeout=6
    )
    assert result.returncode == 1


def test_rearming_creates_new_timer_before_stopping_old_timer():
    namespace = _clock_namespace("_arm_recovery")
    duthost = Mock()
    recovery = {
        "unit_name": "sonic-mgmt-clock-recovery-test",
        "watchdog_path": "/tmp/watchdog.sh",
        "timer_units": [],
        "current_timer_unit": None,
    }

    namespace["_arm_recovery"](duthost, recovery)
    first_timer = recovery["current_timer_unit"]
    namespace["_arm_recovery"](duthost, recovery)
    second_timer = recovery["current_timer_unit"]

    assert first_timer != second_timer
    assert duthost.command.call_count == 2
    assert "RuntimeMaxSec=1980s" in duthost.command.call_args_list[1].args[0]
    assert "{}.timer".format(first_timer) in duthost.shell.call_args.args[0]


def test_ntp_server_accepts_hostnames_and_rejects_directives():
    namespace = _ntp_namespace("normalize_ntp_server", "get_ntp_one_shot_command")
    daemon = namespace["NtpDaemon"]

    command = namespace["get_ntp_one_shot_command"](
        Mock(), daemon.CHRONY, "time.example.com"
    )
    assert shlex.split(command)[-1] == "server time.example.com iburst"

    with pytest.raises(ValueError, match="Invalid NTP server"):
        namespace["normalize_ntp_server"]("time.example.com\nmakestep 1 -1")


def test_ptf_watchdog_and_lock_are_bounded():
    namespace = _ntp_namespace("_install_ntp_server_recovery")
    ptfhost = Mock()
    ptfhost.shell.return_value = {"rc": 0}
    ptfhost.command.return_value = {"rc": 0}

    namespace["_install_ntp_server_recovery"](
        ptfhost,
        "ntpsec",
        "/etc/ntpsec/ntp.conf",
        "/tmp/ntp.conf.backup",
        True,
        3600
    )

    recovery_script = ptfhost.copy.call_args.kwargs["content"]
    install_command = ptfhost.shell.call_args.args[0]
    assert "flock -w 30 -x 9" in recovery_script
    assert "/proc/uptime" in install_command
    assert "timeout --kill-after=10 120" in install_command
    assert 'if [ "$now" -ge "$deadline" ]' in install_command
    subprocess.run(["bash", "-n"], input=recovery_script, text=True, check=True)
    subprocess.run(["bash", "-n", "-c", install_command], check=True)


def test_direct_ptf_restore_is_bounded():
    namespace = _ntp_namespace("_restore_ntp_server")
    ptfhost = Mock()
    ptfhost.shell.return_value = {"rc": 0}
    recovery = {
        "script_path": "/tmp/recover.sh",
        "pid_path": "/tmp/recover.pid",
        "backup_path": "/tmp/ntp.conf.backup",
    }

    namespace["_restore_ntp_server"](ptfhost, recovery)

    restore_command = ptfhost.shell.call_args_list[0].args[0]
    assert "timeout --kill-after=10 120 /tmp/recover.sh" in restore_command
