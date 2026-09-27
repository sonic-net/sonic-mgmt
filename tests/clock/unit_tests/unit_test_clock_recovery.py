"""Focused tests for clock recovery without loading testbed dependencies.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/clock/unit_tests \
        tests/clock/unit_tests/unit_test_clock_recovery.py -q
"""

import ast
import ipaddress
import json
import os
import re
import signal
import shlex
import subprocess
import time
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
    class AnsibleConnectionFailure(Exception):
        pass

    class PytestAnsibleConnectionFailure(Exception):
        pass

    namespace = {
        "CLOCK_OFFSET_TOLERANCE": 5,
        "CLOCK_SOURCE_MAX_OFFSET": 60,
        "CLOCK_RECOVERY_TIMEOUT": 660,
        "CLOCK_RECOVERY_COMMAND_TIMEOUT": 420,
        "CLOCK_RECOVERY_KILL_AFTER": 150,
        "CLOCK_RECOVERY_LEASE": 1800,
        "CLOCK_RECOVERY_RETRY_INTERVAL": 60,
        "CLOCK_RECOVERY_LOCK_TIMEOUT": 30,
        "CLOCK_PTF_RECOVERY_TIMEOUT": 3600,
        "CLOCK_POST_RESTORE_SETTLE_TIME": 20,
        "CLOCK_TIMEZONE_SYNC_TIMEOUT": 120,
        "contextmanager": contextmanager,
        "json": json,
        "logging": Mock(),
        "pytest": pytest,
        "shlex": shlex,
        "time": Mock(),
        "uuid": uuid,
        "RunAnsibleModuleFail": RuntimeError,
        "AnsibleConnectionFailure": AnsibleConnectionFailure,
        "PytestAnsibleConnectionFailure": PytestAnsibleConnectionFailure,
        "RECOVERY_REFRESH_ERRORS": (
            RuntimeError,
            AnsibleConnectionFailure,
            PytestAnsibleConnectionFailure
        ),
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
        "NTP_SERVER_WATCHDOG_POLL_INTERVAL": 60,
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
    request = _request("192.0.2.10")

    with namespace["_clock_ntp_source"](request, duthost, {}) as ntp_server:
        assert ntp_server == "192.0.2.10"

    namespace["_validate_ntp_source"].assert_called_once_with(duthost, "192.0.2.10")
    duthost.command.assert_not_called()
    request.getfixturevalue.assert_not_called()


def test_clock_source_uses_configured_server_without_ptf():
    namespace = _clock_namespace("_get_ntp_config", "_clock_ntp_source")
    duthost = Mock()
    duthost.command.return_value = {"stdout": '{"time.example.com": {"iburst": true}}'}
    namespace["_check_ntp_source"] = Mock(return_value=(True, None))
    request = _request()

    with namespace["_clock_ntp_source"](request, duthost, {}) as ntp_server:
        assert ntp_server == "time.example.com"

    request.getfixturevalue.assert_not_called()


@pytest.mark.parametrize(
    "command_results, expected",
    [
        ([{"stdout": "True\n"}, {"stdout": "UTC\n"}], {"exists": True, "value": "UTC"}),
        ([{"stdout": "True\n"}, {"stdout": "\n"}], {"exists": True, "value": ""}),
        ([{"stdout": "False\n"}], {"exists": False, "value": None}),
        ([{"stdout": "1\n"}, {"stdout": "UTC\n"}], {"exists": True, "value": "UTC"}),
        ([{"stdout": "0\n"}], {"exists": False, "value": None}),
    ]
)
def test_get_configured_timezone_preserves_value_or_absence(command_results, expected):
    namespace = _clock_namespace("_get_configured_timezone")
    duthost = Mock()
    duthost.command.side_effect = command_results

    assert namespace["_get_configured_timezone"](duthost) == expected


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
    request = _request()
    request.getfixturevalue.return_value = ptfhost
    namespace["_get_optional_ptfhost"] = Mock(return_value=ptfhost)
    with namespace["_clock_ntp_source"](request, duthost, {}) as ntp_server:
        assert ntp_server == "192.0.2.20"

    namespace["_validate_ntp_source"].assert_called_once_with(duthost, "192.0.2.20")


@pytest.mark.parametrize("ptfhost", [None, []])
def test_clock_source_skips_only_date_case_without_any_source(ptfhost):
    namespace = _clock_namespace("_get_ntp_config", "_clock_ntp_source")
    duthost = Mock()
    duthost.command.return_value = {"stdout": "{}"}
    namespace["_get_optional_ptfhost"] = Mock(return_value=ptfhost)

    with pytest.raises(pytest.skip.Exception, match="no PTF host"):
        with namespace["_clock_ntp_source"](_request(), duthost, {}):
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
    namespace["_get_optional_ptfhost"] = Mock(return_value=ptfhost)
    with namespace["_clock_ntp_source"](
            _request(), duthost, {}) as ntp_server:
        assert ntp_server == "2001:db8::10"

    assert calls[0][1]["ptf_use_ipv6"] is True


@pytest.mark.parametrize("error_type", [KeyError, pytest.FixtureLookupError])
def test_optional_ptfhost_returns_none_for_missing_inventory_entry(error_type):
    namespace = _clock_namespace("_get_optional_ptfhost")
    request = Mock()
    if error_type is pytest.FixtureLookupError:
        error = error_type("ptfhost", request)
    else:
        error = error_type("ptf_host")
    request.getfixturevalue.side_effect = error

    assert namespace["_get_optional_ptfhost"](request) is None


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
    assert "ntp_source_state.get(" in restore_time_source()


def restore_time_source():
    return ast.unparse(_function_node(CONFTEST_PATH, "restore_time"))


def test_clock_recovery_waits_for_post_restore_errors_to_settle():
    restore_time = ast.unparse(_function_node(CONFTEST_PATH, "restore_time"))
    stable_verify = ast.unparse(
        _function_node(CONFTEST_PATH, "_verify_clock_restoration_stable")
    )

    assert restore_time.count("_verify_clock_restoration_stable") == 2
    first_verify_index = stable_verify.index("_verify_clock_restoration(*args)")
    settle_index = stable_verify.index(
        "time.sleep(CLOCK_POST_RESTORE_SETTLE_TIME)"
    )
    second_verify_index = stable_verify.rindex("_verify_clock_restoration(*args)")

    assert first_verify_index < settle_index < second_verify_index


def test_timezone_recovery_waits_for_post_restore_errors_to_settle():
    init_timezone = ast.unparse(_function_node(CONFTEST_PATH, "init_timezone"))
    stable_verify = ast.unparse(
        _function_node(CONFTEST_PATH, "_verify_timezone_restoration")
    )

    assert "_verify_timezone_restoration(" in init_timezone
    wait_index = stable_verify.index("wait_until(")
    settle_index = stable_verify.index(
        "time.sleep(CLOCK_POST_RESTORE_SETTLE_TIME)"
    )
    final_check_index = stable_verify.rindex("_timezone_is_expected(")

    assert wait_index < settle_index < final_check_index


def test_timezone_recovery_restores_config_db_and_system_timezone():
    namespace = _clock_namespace(
        "_get_timezone_config_restore_command",
        "_get_timezone_restore_commands",
        "_install_retry_watchdog",
        "_install_timezone_recovery"
    )
    duthost = Mock()

    namespace["_install_timezone_recovery"](
        duthost,
        "Etc/UTC",
        {"exists": True, "value": "UTC"}
    )

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    barrier_candidates_index = recovery_script.index(
        "for candidate in Pacific/Kiritimati Pacific/Pago_Pago"
    )
    barrier_wait_index = recovery_script.index(
        'wait_for_timezone "$barrier_timezone"'
    )
    assert (
        'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "timezone" UTC'
        in recovery_script
    )
    restore_index = recovery_script.rindex("restore_timezone_config || exit 1")
    configured_wait_index = recovery_script.rindex("wait_for_timezone UTC")
    system_restore_index = recovery_script.rindex("timedatectl set-timezone Etc/UTC")
    rsyslog_restart_index = recovery_script.rindex("systemctl restart rsyslog || true")
    assert 'wait_for_timezone "$barrier_timezone" || exit 1' in recovery_script
    assert "trap finish_timezone_restore EXIT" in recovery_script
    assert "trap 'exit 143' TERM" in recovery_script
    assert (
        barrier_candidates_index
        < barrier_wait_index
        < restore_index
        < configured_wait_index
        < system_restore_index
        < rsyslog_restart_index
    )
    subprocess.run(["bash", "-n"], input=recovery_script, text=True, check=True)


def test_timezone_recovery_restores_absent_config_db_field():
    namespace = _clock_namespace(
        "_get_timezone_config_restore_command",
        "_get_timezone_restore_commands",
        "_install_retry_watchdog",
        "_install_timezone_recovery"
    )
    duthost = Mock()

    namespace["_install_timezone_recovery"](
        duthost,
        "Etc/UTC",
        {"exists": False, "value": None}
    )

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    assert (
        'sonic-db-cli CONFIG_DB hdel "DEVICE_METADATA|localhost" "timezone"'
        in recovery_script
    )
    assert "timedatectl set-timezone Etc/UTC" in recovery_script
    assert 'wait_for_timezone "$barrier_timezone"' in recovery_script
    assert "wait_for_timezone ''" not in recovery_script
    subprocess.run(["bash", "-n"], input=recovery_script, text=True, check=True)


def test_timezone_recovery_restores_empty_config_db_field():
    namespace = _clock_namespace(
        "_get_timezone_config_restore_command",
        "_get_timezone_restore_commands",
        "_install_retry_watchdog",
        "_install_timezone_recovery"
    )
    duthost = Mock()

    namespace["_install_timezone_recovery"](
        duthost,
        "Etc/UTC",
        {"exists": True, "value": ""}
    )

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    assert (
        'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "timezone" \'\''
        in recovery_script
    )
    assert "wait_for_timezone ''" not in recovery_script
    subprocess.run(["bash", "-n"], input=recovery_script, text=True, check=True)


@pytest.mark.parametrize(
    "configured_timezone, expected_exists, expected_value",
    [
        ({"exists": True, "value": "UTC"}, True, "UTC\n"),
        ({"exists": False, "value": None}, False, None),
        ({"exists": True, "value": ""}, True, "\n"),
    ]
)
def test_timezone_recovery_waits_for_delayed_hostcfgd_before_restoring_alias(
        tmp_path, configured_timezone, expected_exists, expected_value):
    namespace = _clock_namespace(
        "_get_timezone_config_restore_command",
        "_get_timezone_restore_commands",
        "_install_retry_watchdog",
        "_install_timezone_recovery"
    )
    duthost = Mock()
    namespace["_install_timezone_recovery"](
        duthost,
        "Etc/UTC",
        configured_timezone
    )

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    recovery_script = re.sub(
        r"exec 9>/run/[^\n]+",
        "exec 9>{}".format(shlex.quote(str(tmp_path / "recovery.lock"))),
        recovery_script
    )
    recovery_path = tmp_path / "recovery.sh"
    recovery_path.write_text(recovery_script)
    recovery_path.chmod(0o755)

    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    system_timezone_path = tmp_path / "system-timezone"
    configured_timezone_path = tmp_path / "configured-timezone"
    applied_timezone_path = tmp_path / "applied-timezones"
    rsyslog_restart_path = tmp_path / "rsyslog-restarted"
    system_timezone_path.write_text("Pacific/Kiritimati\n")
    configured_timezone_path.write_text("Asia/Jerusalem\n")

    sonic_db_cli = bin_path / "sonic-db-cli"
    sonic_db_cli.write_text(
        """#!/bin/bash
if [ "$2" = "hset" ]; then
    value=$5
    printf '%s\\n' "$value" > "$CONFIGURED_TIMEZONE_PATH"
    if [ -n "$value" ]; then
        (
            sleep 0.2
            printf '%s\\n' "$value" >> "$APPLIED_TIMEZONE_PATH"
            printf '%s\\n' "$value" > "$SYSTEM_TIMEZONE_PATH"
        ) >/dev/null 2>&1 &
    fi
elif [ "$2" = "hdel" ]; then
    rm -f "$CONFIGURED_TIMEZONE_PATH"
fi
"""
    )
    sonic_db_cli.chmod(0o755)

    timedatectl = bin_path / "timedatectl"
    timedatectl.write_text(
        """#!/bin/bash
case "$1" in
    show)
        cat "$SYSTEM_TIMEZONE_PATH"
        ;;
    list-timezones)
        printf '%s\\n' Etc/UTC Pacific/Kiritimati Pacific/Pago_Pago UTC
        ;;
    set-timezone)
        printf '%s\\n' "$2" > "$SYSTEM_TIMEZONE_PATH"
        ;;
esac
"""
    )
    timedatectl.chmod(0o755)

    systemctl = bin_path / "systemctl"
    systemctl.write_text(
        """#!/bin/bash
if [ "$1" = "restart" ] && [ "$2" = "rsyslog" ]; then
    touch "$RSYSLOG_RESTART_PATH"
fi
"""
    )
    systemctl.chmod(0o755)

    env = os.environ.copy()
    env.update({
        "PATH": "{}:{}".format(bin_path, env["PATH"]),
        "SYSTEM_TIMEZONE_PATH": str(system_timezone_path),
        "CONFIGURED_TIMEZONE_PATH": str(configured_timezone_path),
        "APPLIED_TIMEZONE_PATH": str(applied_timezone_path),
        "RSYSLOG_RESTART_PATH": str(rsyslog_restart_path),
    })
    subprocess.run([str(recovery_path)], env=env, check=True, timeout=10)
    time.sleep(0.5)

    assert configured_timezone_path.exists() is expected_exists
    if expected_exists:
        assert configured_timezone_path.read_text() == expected_value
    assert system_timezone_path.read_text() == "Etc/UTC\n"
    assert applied_timezone_path.read_text().splitlines()[0] == "Pacific/Pago_Pago"
    assert rsyslog_restart_path.exists()


def test_timezone_recovery_signal_rolls_back_temporary_config(tmp_path):
    namespace = _clock_namespace(
        "_get_timezone_config_restore_command",
        "_get_timezone_restore_commands",
        "_install_retry_watchdog",
        "_install_timezone_recovery"
    )
    duthost = Mock()
    namespace["_install_timezone_recovery"](
        duthost,
        "Etc/UTC",
        {"exists": False, "value": None}
    )

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    recovery_script = re.sub(
        r"exec 9>/run/[^\n]+",
        "exec 9>{}".format(shlex.quote(str(tmp_path / "recovery.lock"))),
        recovery_script
    )
    recovery_path = tmp_path / "recovery.sh"
    recovery_path.write_text(recovery_script)
    recovery_path.chmod(0o755)

    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    system_timezone_path = tmp_path / "system-timezone"
    configured_timezone_path = tmp_path / "configured-timezone"
    system_timezone_path.write_text("Asia/Jerusalem\n")

    sonic_db_cli = bin_path / "sonic-db-cli"
    sonic_db_cli.write_text(
        """#!/bin/bash
if [ "$2" = "hset" ]; then
    printf '%s\\n' "$5" > "$CONFIGURED_TIMEZONE_PATH"
elif [ "$2" = "hdel" ]; then
    rm -f "$CONFIGURED_TIMEZONE_PATH"
fi
"""
    )
    sonic_db_cli.chmod(0o755)

    timedatectl = bin_path / "timedatectl"
    timedatectl.write_text(
        """#!/bin/bash
case "$1" in
    show)
        cat "$SYSTEM_TIMEZONE_PATH"
        ;;
    list-timezones)
        printf '%s\\n' Etc/UTC Pacific/Kiritimati Pacific/Pago_Pago
        ;;
    set-timezone)
        printf '%s\\n' "$2" > "$SYSTEM_TIMEZONE_PATH"
        ;;
esac
"""
    )
    timedatectl.chmod(0o755)

    systemctl = bin_path / "systemctl"
    systemctl.write_text("#!/bin/bash\nexit 0\n")
    systemctl.chmod(0o755)

    env = os.environ.copy()
    env.update({
        "PATH": "{}:{}".format(bin_path, env["PATH"]),
        "SYSTEM_TIMEZONE_PATH": str(system_timezone_path),
        "CONFIGURED_TIMEZONE_PATH": str(configured_timezone_path),
    })
    process = subprocess.Popen(
        [str(recovery_path)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    for _ in range(100):
        if configured_timezone_path.exists():
            break
        time.sleep(0.02)
    os.kill(process.pid, signal.SIGTERM)
    process.communicate(timeout=5)

    assert process.returncode == 143
    assert not configured_timezone_path.exists()
    assert system_timezone_path.read_text() == "Etc/UTC\n"


def test_clock_recovery_restores_exact_configured_timezone():
    namespace = _clock_namespace(
        "_get_timezone_config_restore_command",
        "_get_timezone_restore_commands",
        "_install_retry_watchdog",
        "_install_clock_recovery"
    )
    namespace["prepare_ntp_one_shot_config"] = Mock()
    namespace["get_ntp_one_shot_command"] = Mock(return_value="true")
    duthost = Mock()

    namespace["_install_clock_recovery"](
        duthost,
        "chrony",
        "192.0.2.10",
        "chrony",
        "Etc/UTC",
        {"exists": True, "value": "UTC"},
        "active"
    )

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    assert (
        'sonic-db-cli CONFIG_DB hset "DEVICE_METADATA|localhost" "timezone" UTC'
        in recovery_script
    )
    assert "wait_for_timezone UTC" in recovery_script
    assert "timedatectl set-timezone Etc/UTC" in recovery_script
    subprocess.run(["bash", "-n"], input=recovery_script, text=True, check=True)


def test_clock_recovery_signal_restores_ntp_service_before_exit(tmp_path):
    namespace = _clock_namespace(
        "_get_timezone_config_restore_command",
        "_get_timezone_restore_commands",
        "_install_retry_watchdog",
        "_install_clock_recovery"
    )
    namespace["prepare_ntp_one_shot_config"] = Mock()
    namespace["get_ntp_one_shot_command"] = Mock(return_value="sleep 2")
    duthost = Mock()
    namespace["_install_clock_recovery"](
        duthost,
        "chrony",
        "192.0.2.10",
        "chrony",
        "Etc/UTC",
        {"exists": False, "value": None},
        "active"
    )

    recovery_script = duthost.copy.call_args_list[0].kwargs["content"]
    recovery_script = re.sub(
        r"exec 9>/run/[^\n]+",
        "exec 9>{}".format(shlex.quote(str(tmp_path / "recovery.lock"))),
        recovery_script
    )
    recovery_path = tmp_path / "recovery.sh"
    recovery_path.write_text(recovery_script)
    recovery_path.chmod(0o755)

    bin_path = tmp_path / "bin"
    bin_path.mkdir()
    service_log_path = tmp_path / "service.log"
    systemctl = bin_path / "systemctl"
    systemctl.write_text(
        """#!/bin/bash
printf '%s\\n' "$*" >> "$SERVICE_LOG_PATH"
"""
    )
    systemctl.chmod(0o755)

    env = os.environ.copy()
    env.update({
        "PATH": "{}:{}".format(bin_path, env["PATH"]),
        "SERVICE_LOG_PATH": str(service_log_path),
    })
    process = subprocess.Popen(
        [str(recovery_path)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    for _ in range(100):
        if service_log_path.exists():
            break
        time.sleep(0.02)
    os.kill(process.pid, signal.SIGTERM)
    process.communicate(timeout=5)

    assert process.returncode == 143
    assert service_log_path.read_text().splitlines() == [
        "stop chrony",
        "start chrony",
    ]


def test_timezone_restoration_requires_matching_config_db_state():
    namespace = _clock_namespace("_timezone_is_expected")
    namespace["ClockUtils"] = Mock()
    namespace["ClockUtils"].verify_timezone_value.return_value = True
    namespace["_get_configured_timezone"] = Mock(
        return_value={"exists": True, "value": "Pacific/Kiritimati"}
    )

    assert not namespace["_timezone_is_expected"](
        Mock(), Mock(), "Etc/UTC", {"exists": True, "value": "UTC"}
    )


def test_unverified_armed_recovery_always_defers_ptf_cleanup():
    restore_time = ast.unparse(_function_node(CONFTEST_PATH, "restore_time"))

    assert "ntp_source_state['defer_cleanup'] = True" in restore_time
    assert "recovery_status['armed'] = True" in restore_time
    assert "if cleanup_verified:" in restore_time
    assert "ntp_source_state['defer_cleanup'] = False" in restore_time
    arm_state_index = restore_time.index("recovery_status['armed'] = True")
    defer_index = restore_time.index("ntp_source_state['defer_cleanup'] = True")
    arm_call_index = restore_time.index("_arm_recovery(duthost, recovery)")
    assert arm_state_index < defer_index < arm_call_index


def test_ptf_refresh_connection_failure_isolated_from_dut_recovery():
    namespace = _clock_namespace("_try_refresh_ptf_recovery")
    recovery_state = {
        "defer_cleanup": False,
        "refresh": Mock(
            side_effect=namespace["PytestAnsibleConnectionFailure"]("PTF unreachable")
        )
    }

    assert not namespace["_try_refresh_ptf_recovery"](recovery_state)
    assert recovery_state["defer_cleanup"] is True


def test_remove_recovery_requires_all_units_to_be_stopped():
    namespace = _clock_namespace("_remove_recovery")
    duthost = Mock()
    duthost.shell.return_value = {"rc": 1}
    recovery = {
        "script_path": "/tmp/recover.sh",
        "watchdog_path": "/tmp/watchdog.sh",
        "lock_path": "/run/recover.lock",
        "timer_units": ["recover-a", "recover-b"],
        "current_timer_unit": "recover-b",
    }

    assert not namespace["_remove_recovery"](duthost, recovery)
    assert recovery["current_timer_unit"] == "recover-b"
    assert recovery["timer_units"] == ["recover-a", "recover-b"]
    cleanup_command = duthost.shell.call_args.args[0]
    assert 'unit_is_stopped "$unit.timer"' in cleanup_command
    assert 'unit_is_stopped "$unit.service"' in cleanup_command
    assert 'if [ "$cleanup_ok" -ne 1 ]' in cleanup_command
    assert 'systemctl stop "$unit.timer" "$unit.service"' not in cleanup_command
    subprocess.run(["bash", "-n", "-c", cleanup_command], check=True)


def test_remove_recovery_clears_state_only_after_verified_cleanup():
    namespace = _clock_namespace("_remove_recovery")
    duthost = Mock()
    duthost.shell.return_value = {"rc": 0}
    recovery = {
        "script_path": "/tmp/recover.sh",
        "watchdog_path": "/tmp/watchdog.sh",
        "lock_path": "/run/recover.lock",
        "timer_units": ["recover-a"],
        "current_timer_unit": "recover-a",
    }

    assert namespace["_remove_recovery"](duthost, recovery)
    assert recovery["current_timer_unit"] is None
    assert recovery["timer_units"] == []


def test_dut_watchdog_is_monotonic_and_bounded():
    namespace = _clock_namespace("_install_retry_watchdog")
    duthost = Mock()
    recovery = {
        "script_path": "/tmp/recover.sh",
        "watchdog_path": "/tmp/watchdog.sh",
    }

    namespace["_install_retry_watchdog"](duthost, recovery)

    watchdog = duthost.copy.call_args.kwargs["content"]
    assert "/proc/uptime" in watchdog
    assert "$SECONDS" not in watchdog
    assert "timeout --kill-after=150 420" in watchdog
    assert 'if [ "$now" -ge "$deadline" ]' in watchdog
    assert "rm -f" not in watchdog
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

    namespace["_install_retry_watchdog"](duthost, recovery)
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
    assert "RuntimeMaxSec=2490s" in duthost.command.call_args_list[1].args[0]
    assert "--on-active=660s" in duthost.command.call_args_list[1].args[0]
    retire_command = duthost.shell.call_args.args[0]
    assert "{}.timer".format(first_timer) in retire_command
    assert "systemctl stop {}.timer".format(first_timer) in retire_command
    assert "systemctl stop {}.service".format(first_timer) not in retire_command
    assert "{}.timer --property=ActiveState".format(first_timer) in retire_command
    assert "{}.service --property=ActiveState".format(first_timer) in retire_command
    assert '[ "$service_active" = "failed" ]' not in retire_command
    subprocess.run(["bash", "-n", "-c", retire_command], check=True)


def test_ambiguous_timer_creation_is_tracked_before_ansible_returns():
    namespace = _clock_namespace("_arm_recovery")
    duthost = Mock()
    duthost.command.side_effect = namespace["AnsibleConnectionFailure"](
        "reply lost after timer creation"
    )
    recovery = {
        "unit_name": "sonic-mgmt-clock-recovery-test",
        "watchdog_path": "/tmp/watchdog.sh",
        "timer_units": [],
        "current_timer_unit": None,
    }

    with pytest.raises(namespace["AnsibleConnectionFailure"]):
        namespace["_arm_recovery"](duthost, recovery)

    assert len(recovery["timer_units"]) == 1
    assert recovery["current_timer_unit"] == recovery["timer_units"][0]


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
    assert "sonic-mgmt-ntp-server-recovery-" in install_command
    assert "sleep 1" in install_command
    assert "ps -o stat=" in install_command
    subprocess.run(["bash", "-n"], input=recovery_script, text=True, check=True)
    subprocess.run(["bash", "-n", "-c", install_command], check=True)


def test_ptf_watchdog_refresh_updates_deadline_without_pid_replacement():
    namespace = _ntp_namespace("_refresh_ntp_server_recovery")
    ptfhost = Mock()
    recovery = {
        "pid_path": "/tmp/recover.pid",
        "deadline_path": "/tmp/recover.deadline",
        "owner_path": "/tmp/recover.owner",
        "recovery_id": "owner-id",
        "lock_path": "/tmp/recover.lock",
        "recovery_timeout": 3600,
    }

    namespace["_refresh_ntp_server_recovery"](ptfhost, recovery)

    refresh_command = ptfhost.shell.call_args.args[0]
    assert "flock -w 30 -x 9" in refresh_command
    assert "setsid sh -c" not in refresh_command
    assert 'kill -- -"$old_pid"' not in refresh_command
    assert "mv -f" in refresh_command
    assert "sleep 1; watchdog_is_live" in refresh_command
    subprocess.run(["bash", "-n", "-c", refresh_command], check=True)


def test_ptf_watchdog_refresh_extends_live_process_deadline(tmp_path):
    namespace = _ntp_namespace("_refresh_ntp_server_recovery")
    owner_path = tmp_path / "recover.owner"
    pid_path = tmp_path / "recover.pid"
    deadline_path = tmp_path / "recover.deadline"
    lock_path = tmp_path / "recover.lock"
    owner_path.write_text("owner-id\n")
    old_watchdog = subprocess.Popen(["setsid", "sh", "-c", "sleep 60"])
    pid_path.write_text("{}\n".format(old_watchdog.pid))
    deadline_path.write_text("1\n")

    class LocalHost:
        @staticmethod
        def shell(command):
            result = subprocess.run(
                ["bash", "-c", command],
                text=True,
                capture_output=True
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr)
            return {
                "rc": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

    recovery = {
        "pid_path": str(pid_path),
        "deadline_path": str(deadline_path),
        "owner_path": str(owner_path),
        "recovery_id": "owner-id",
        "lock_path": str(lock_path),
        "recovery_timeout": 3600,
    }
    try:
        namespace["_refresh_ntp_server_recovery"](LocalHost(), recovery)

        assert int(pid_path.read_text().strip()) == old_watchdog.pid
        assert int(deadline_path.read_text().strip()) > 1
        os.kill(old_watchdog.pid, 0)
    finally:
        if old_watchdog.poll() is None:
            os.killpg(old_watchdog.pid, signal.SIGKILL)
            old_watchdog.wait(timeout=5)


def test_ptf_watchdog_refresh_rejects_dead_process(tmp_path):
    namespace = _ntp_namespace("_refresh_ntp_server_recovery")
    owner_path = tmp_path / "recover.owner"
    pid_path = tmp_path / "recover.pid"
    deadline_path = tmp_path / "recover.deadline"
    lock_path = tmp_path / "recover.lock"
    owner_path.write_text("owner-id\n")
    dead_watchdog = subprocess.Popen(["setsid", "sh", "-c", "true"])
    dead_watchdog.wait(timeout=5)
    pid_path.write_text("{}\n".format(dead_watchdog.pid))
    deadline_path.write_text("1\n")

    class LocalHost:
        @staticmethod
        def shell(command):
            result = subprocess.run(
                ["bash", "-c", command],
                text=True,
                capture_output=True
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr)
            return {"rc": result.returncode}

    recovery = {
        "pid_path": str(pid_path),
        "deadline_path": str(deadline_path),
        "owner_path": str(owner_path),
        "recovery_id": "owner-id",
        "lock_path": str(lock_path),
        "recovery_timeout": 3600,
    }

    with pytest.raises(RuntimeError):
        namespace["_refresh_ntp_server_recovery"](LocalHost(), recovery)

    assert deadline_path.read_text() == "1\n"


def test_ptf_watchdog_refresh_signal_keeps_existing_watchdog_and_valid_deadline(tmp_path):
    namespace = _ntp_namespace("_refresh_ntp_server_recovery")
    owner_path = tmp_path / "recover.owner"
    pid_path = tmp_path / "recover.pid"
    deadline_path = tmp_path / "recover.deadline"
    lock_path = tmp_path / "recover.lock"
    owner_path.write_text("owner-id\n")
    watchdog = subprocess.Popen(["setsid", "sh", "-c", "sleep 60"])
    pid_path.write_text("{}\n".format(watchdog.pid))
    deadline_path.write_text("1\n")

    class InterruptingLocalHost:
        @staticmethod
        def shell(command):
            process = subprocess.Popen(
                ["bash", "-c", command],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            for _ in range(100):
                if deadline_path.read_text() != "1\n":
                    break
                time.sleep(0.02)
            os.kill(process.pid, signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            raise RuntimeError(stderr)

    recovery = {
        "pid_path": str(pid_path),
        "deadline_path": str(deadline_path),
        "owner_path": str(owner_path),
        "recovery_id": "owner-id",
        "lock_path": str(lock_path),
        "recovery_timeout": 3600,
    }
    try:
        with pytest.raises(RuntimeError):
            namespace["_refresh_ntp_server_recovery"](
                InterruptingLocalHost(),
                recovery
            )

        assert int(pid_path.read_text().strip()) == watchdog.pid
        assert int(deadline_path.read_text().strip()) > 1
        os.kill(watchdog.pid, 0)
        assert not list(tmp_path.glob("recover.deadline.*.tmp"))
    finally:
        if watchdog.poll() is None:
            os.killpg(watchdog.pid, signal.SIGKILL)
            watchdog.wait(timeout=5)


def test_direct_ptf_restore_is_bounded():
    namespace = _ntp_namespace("_restore_ntp_server")
    ptfhost = Mock()
    ptfhost.shell.return_value = {"rc": 0}
    recovery = {
        "script_path": "/tmp/recover.sh",
        "pid_path": "/tmp/recover.pid",
        "deadline_path": "/tmp/recover.deadline",
        "backup_path": "/tmp/ntp.conf.backup",
    }

    namespace["_restore_ntp_server"](ptfhost, recovery)

    restore_command = ptfhost.shell.call_args_list[0].args[0]
    assert "timeout --kill-after=10 120 /tmp/recover.sh" in restore_command
