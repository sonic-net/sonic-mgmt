"""Offline regressions: pytest --noconftest tests/tacacs/unit_tests/unit_test_accounting.py.

The unit_test_ prefix excludes this fake-host suite from CI impacted-area DUT
scheduling. Broad pytest discovery still matches it via tests/pytest.ini; run
it explicitly with --noconftest to avoid inheriting lab autouse fixtures.
"""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


pytestmark = [pytest.mark.topology("any")]

SOURCE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("accounting", SOURCE / "accounting.py")
accounting = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(accounting)


def record(command="grep", user="rw", local=False):
    if local:
        return ("INFO audisp-tacplus: Audisp-tacplus: Accounting: user: {}, x, command: /usr/bin/{}, "
                "type: 2, task ID: 123\n").format(user, command)
    return "date\t{}\tport\tcmd=/usr/bin/{}\ttask_id=123\n".format(user, command)


@pytest.fixture
def clock(monkeypatch):
    clock = SimpleNamespace(now=0.)

    def advance(seconds):
        clock.now += seconds

    monkeypatch.setattr(accounting, "time", SimpleNamespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(accounting, "Event", lambda: SimpleNamespace(wait=advance))
    clock.advance = advance
    return clock


class Host:
    def __init__(self, clock, events=(), latency=0, initial=""):
        self.clock = clock
        self.events = list(events)
        self.data = initial
        self.identity = [1, 2]
        self.latency = latency
        self.calls = []
        self.failure = None
        self.enforce_timeout = False

    def shell(self, command, **kwargs):
        self.calls.append((self.clock.now, command))
        budget = float(shlex.split(command)[2][:-1])
        if self.enforce_timeout and self.latency > budget:
            self.clock.advance(budget)
            return {"rc": 137}
        self.clock.advance(self.latency)
        while self.events and self.events[0][0] <= self.clock.now:
            _, action, value = self.events.pop(0)
            if action == "append":
                self.data += value
            elif action == "replace":
                self.data = value
            elif action == "rotate":
                self.identity[1] += 1
            elif action == "fail":
                self.failure = value
        if self.failure:
            return self.failure
        offset = int(shlex.split(shlex.split(command)[-1])[-1])
        data = self.data.encode()
        return {"rc": 0, "stdout": json.dumps({
            "identity": self.identity, "size": len(data),
            "prefix": hashlib.sha256(data[:offset]).hexdigest(),
            "digest": hashlib.sha256(data).hexdigest(), "text": data[offset:].decode()})}


def cursor(clock, **kwargs):
    host = Host(clock, **kwargs)
    result = accounting.LogCursor(host, "/var/log/test")
    accounting.capture_logs([result])
    return result


def verify(cursors, commands=("grep",), **kwargs):
    accounting.verify_accounting(cursors, "rw", commands, timeout=10, absence_window=8, **kwargs)


@pytest.mark.parametrize("arrival", [1, 9.9])
def test_prompt_and_near_deadline_positive(clock, arrival):
    log = cursor(clock, events=[(arrival, "append", record())])
    verify([log], interval=0.1)
    assert clock.now >= arrival + 8


def test_missing_positive(clock):
    log = cursor(clock)
    with pytest.raises(accounting.MissingAccounting):
        verify([log])
    assert clock.now == 10


def test_late_positive_is_not_accepted(clock):
    log = cursor(clock, events=[(11, "append", record())])
    log.host.latency = 11
    with pytest.raises(accounting.MissingAccounting):
        verify([log])
    assert clock.now == 22
    assert len(log.host.calls) == 3  # boundary + slow read + expiry reconciliation


@pytest.mark.parametrize("arrival", [8.9, 9])
def test_late_forbidden_even_on_final_sample(clock, arrival):
    log = cursor(clock, events=[(1, "append", record()), (arrival, "append", record(user="other"))])
    with pytest.raises(AssertionError, match="Unexpected"):
        verify([log])


def test_two_logs_share_full_absence_window(clock):
    logs = [cursor(clock, events=[(1, "append", record())]) for _ in range(2)]
    verify(logs)
    assert clock.now == 9  # positive at 1 + ONE full 8s window, not 16s
    assert all(log.host.calls[-1][0] >= 9 for log in logs)


def test_every_source_sampled_after_window_when_reads_cross_boundary(clock):
    logs = [cursor(clock, events=[(1, "append", record())]) for _ in range(2)]
    for log in logs:
        log.host.latency = 2
    verify(logs)
    # Positives complete t=4; window ends t=12. Both last reads start after 12.
    assert all(log.host.calls[-1][0] >= 12 for log in logs)


def test_stale_records_do_not_satisfy_command(clock):
    log = cursor(clock, initial=record())
    with pytest.raises(accounting.MissingAccounting):
        verify([log])


@pytest.mark.parametrize("copies,passes", [(1, False), (2, True)])
def test_duplicate_commands_require_multiple_records(clock, copies, passes):
    log = cursor(clock, events=[(1, "append", record() * copies)])
    if passes:
        verify([log], commands=["grep", "grep"])
    else:
        with pytest.raises(accounting.MissingAccounting, match="grep"):
            verify([log], commands=["grep", "grep"])


def test_unrelated_command_cannot_satisfy_expected(clock):
    log = cursor(clock, events=[(1, "append", record("pgrep"))])
    with pytest.raises(accounting.MissingAccounting):
        verify([log])


@pytest.mark.parametrize("action,value", [("rotate", ""), ("replace", ""), ("replace", "different old data\n" * 9)],
                         ids=["rotate", "truncate", "rewrite-regrow"])
def test_rotation_truncation_and_regrowth_fail_closed(clock, action, value):
    log = cursor(clock, initial="old\n", events=[(1, action, value)])
    with pytest.raises(AssertionError, match="rotated/truncated/rewritten"):
        verify([log])


@pytest.mark.parametrize("failure", [{"rc": 1}, {"rc": 0, "failed": True}, {}, {"rc": 0, "stdout": "bad json"}])
def test_read_errors_are_not_absence(clock, failure):
    log = cursor(clock, events=[(1, "append", record())])
    log.host.failure = failure or {"failed": True}
    with pytest.raises((AssertionError, ValueError)):
        verify([log])


def test_remote_budget_counts_call_latency(clock):
    log = cursor(clock)
    log.host.latency = 4
    with pytest.raises(accounting.MissingAccounting):
        verify([log])
    assert clock.now == 14  # positive budget + bounded final reconciliation
    budgets = [float(shlex.split(cmd)[2][:-1]) for _, cmd in log.host.calls[1:]]
    assert budgets == [accounting.LOG_READ_TIMEOUT] * 3


def test_final_read_failure_cannot_pass_absence(clock):
    log = cursor(clock, events=[(1, "append", record()), (9, "fail", {"rc": 124})])
    with pytest.raises(AssertionError, match="read failed"):
        verify([log])


def test_partial_forbidden_record_cannot_pass(clock):
    log = cursor(clock, events=[(1, "append", record()), (8, "append", "other incomplete")])
    with pytest.raises(AssertionError, match="Incomplete"):
        verify([log])


def test_local_record_and_user_filters(clock):
    log = cursor(clock, events=[(1, "append", record(local=True))])
    log.local = True
    verify([log])
    log.lines.append(record(user="other", local=True))
    with pytest.raises(AssertionError, match="Unexpected"):
        log.counts("rw", ["grep"])


def test_remote_snapshot_script_reads_real_file(tmp_path):
    path = tmp_path / "accounting.log"
    path.write_text("old\n" + record())
    output = subprocess.check_output([sys.executable, "-c", accounting.READ_LOG, str(path), "4"], text=True)
    result = json.loads(output)
    assert result["text"] == record()
    assert result["prefix"] == hashlib.sha256(b"old\n").hexdigest()


def functions():
    tree = ast.parse((SOURCE / "test_accounting.py").read_text())
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


@pytest.mark.parametrize("name", ["test_accounting_tacacs_only_all_tacacs_server_down",
                                  "test_accounting_tacacs_and_local_all_tacacs_server_down",
                                  "test_accounting_tacacs_only_some_tacacs_server_down"])
def test_cleanup_after_assertion_failure(name):
    cleanup = next(node for node in functions()[name].body if isinstance(node, ast.Try))
    host = Mock()
    namespace = {"ptfhost": host, "duthost": host, "rw_user_client": Mock(), "tacacs_creds": {},
                 "invalid_tacacs_server_ip": "127.0.0.1", "cleanup_tacacs_log": Mock(),
                 "stop_tacacs_server": Mock(return_value=True),
                 "start_tacacs_server": Mock(return_value=True), "pytest_assert": lambda value, msg: value}
    for helper in ["ssh_run_command", "check_tacacs_accounting", "check_local_accounting"]:
        namespace[helper] = Mock(side_effect=AssertionError("injected verification failure"))
    with pytest.raises(AssertionError, match="injected"):
        exec(compile(ast.Module(body=[cleanup], type_ignores=[]), "cleanup", "exec"), namespace)
    if "some_tacacs" in name:
        host.shell.assert_called_once_with("sudo config tacacs delete 127.0.0.1")
    else:
        namespace["start_tacacs_server"].assert_called_once_with(host)


def test_command_argument_cannot_impersonate_executable(clock):
    log = cursor(clock, events=[(1, "append", record("echo grep"))])
    with pytest.raises(accounting.MissingAccounting):
        verify([log])


def test_local_retry_preserves_readiness_and_reexecutes_only_on_missing():
    node = functions()["check_local_accounting"]
    names = ["change_and_wait_aaa_config_update", "cleanup_tacacs_log", "capture_logs",
             "ssh_run_command", "LogCursor", "logger"]
    namespace = {name: Mock() for name in names}
    namespace.update(MissingAccounting=accounting.MissingAccounting, LOCAL_TIMEOUT=120)
    namespace["LogCursor"].return_value.pending = ""
    namespace["verify_accounting"] = Mock(side_effect=[accounting.MissingAccounting("missing"), None])
    exec(compile(ast.Module(body=[node], type_ignores=[]), "local helper", "exec"), namespace)
    namespace["check_local_accounting"](Mock(), {"tacacs_rw_user": "rw"}, "grep", "config", Mock(), Mock())
    for name in ["change_and_wait_aaa_config_update", "cleanup_tacacs_log", "ssh_run_command", "capture_logs"]:
        assert namespace[name].call_count == 2
    namespace["verify_accounting"].reset_mock(side_effect=True)
    namespace["verify_accounting"].side_effect = AssertionError("forbidden")
    with pytest.raises(AssertionError, match="forbidden"):
        namespace["check_local_accounting"](Mock(), {"tacacs_rw_user": "rw"}, "grep", "config", Mock(), Mock())
    assert namespace["verify_accounting"].call_count == 1


@pytest.mark.parametrize("local", [True, False], ids=["local", "remote"])
@pytest.mark.parametrize("user", ["rw", "other"], ids=["expected-user", "forbidden-user"])
def test_missing_positive_cannot_retry_away_partial_record(clock, local, user):
    node = functions()["check_local_accounting"]
    hosts = [Host(clock), Host(clock)]
    partial = record(user=user, local=local).rstrip("\n")
    hosts[0 if local else 1].events = [(1, "append", partial)]
    cursors = []

    def make_cursor(host, path, local=False):
        log = accounting.LogCursor(host, path, local=local)
        cursors.append(log)
        return log

    def cleanup(*args):
        # A retry would discard the partial record and let later positives
        # pass. Model that failure mode, not merely a mocked retry exception.
        for host in hosts:
            host.data = ""
            if namespace["cleanup_tacacs_log"].call_count > 1:
                host.events = [(clock.now + 1, "append", record(local=host is hosts[0]))]

    namespace = {name: Mock() for name in ["change_and_wait_aaa_config_update", "ssh_run_command", "logger"]}
    namespace.update(MissingAccounting=accounting.MissingAccounting, LOCAL_TIMEOUT=10,
                     LogCursor=make_cursor, capture_logs=accounting.capture_logs,
                     cleanup_tacacs_log=Mock(side_effect=cleanup))
    namespace["verify_accounting"] = lambda logs, username, commands, timeout: accounting.verify_accounting(
        logs, username, commands, timeout=timeout, absence_window=1)
    hosts[0].command = Mock(return_value={})
    exec(compile(ast.Module(body=[node], type_ignores=[]), "local helper", "exec"), namespace)
    with pytest.raises(AssertionError, match="Incomplete accounting record"):
        namespace["check_local_accounting"](
            hosts[0], {"tacacs_rw_user": "rw"}, "grep", "config", hosts[1], Mock(), tacacs=True)
    assert cursors[0 if local else 1].pending == partial
    assert len(cursors) == 2  # no second attempt/boundary capture
    for name in ["change_and_wait_aaa_config_update", "cleanup_tacacs_log", "ssh_run_command"]:
        assert namespace[name].call_count == 1
    assert clock.now == 10


def test_exit_record_does_not_double_count_command(clock):
    log = cursor(clock, events=[(1, "append", record() + record("grep exit=2"))])
    with pytest.raises(accounting.MissingAccounting):
        verify([log], commands=["grep", "grep"])


def test_failed_server_restart_surfaces():
    node = functions()["test_accounting_tacacs_only_all_tacacs_server_down"]
    cleanup = next(node for node in node.body if isinstance(node, ast.Try))

    def assert_true(value, message):
        assert value, message

    namespace = {"ptfhost": Mock(), "rw_user_client": Mock(), "ssh_run_command": Mock(),
                 "stop_tacacs_server": Mock(return_value=True),
                 "start_tacacs_server": Mock(return_value=False), "pytest_assert": assert_true}
    with pytest.raises(AssertionError, match="failed to restart"):
        exec(compile(ast.Module(body=[cleanup], type_ignores=[]), "cleanup", "exec"), namespace)


@pytest.mark.parametrize("prefix", ["INFO audisp-tacplus: ", "INFO audisp-tacplus: Audisp-tacplus: "])
def test_local_forbidden_and_positive_share_realistic_prefix_grammar(clock, prefix):
    log = cursor(clock)
    log.local = True
    line = record(local=True).replace("INFO audisp-tacplus: Audisp-tacplus: ", prefix)
    log.lines = [line]
    assert log.counts("rw", ["grep"])["grep"] == 1
    log.lines.append(line.replace("user: rw,", "user: other,"))
    with pytest.raises(AssertionError, match="Unexpected"):
        log.counts("rw", ["grep"])


@pytest.mark.parametrize("prefix", ["INFO audisp-tacplus: ", "INFO audisp-tacplus: Audisp-tacplus: "])
@pytest.mark.parametrize("argument", ["sudo sed", "ansible.legacy.command Invoked"])
def test_local_noise_substrings_cannot_hide_forbidden_user(clock, prefix, argument):
    forbidden = record("echo " + argument, user="other", local=True).replace(
        "INFO audisp-tacplus: Audisp-tacplus: ", prefix)
    log = cursor(clock, events=[(1, "append", record(local=True) + forbidden)])
    log.local = True
    # Exercise the complete verifier with a valid positive alongside the
    # forbidden record: silently dropping the latter would falsely pass.
    with pytest.raises(AssertionError, match="Unexpected accounting records"):
        verify([log])
    with pytest.raises(AssertionError, match="Unexpected accounting records"):
        log.counts("rw", ["grep"])


@pytest.mark.parametrize("prefix", ["INFO audisp-tacplus: ", "INFO audisp-tacplus: Audisp-tacplus: "])
@pytest.mark.parametrize("argument", ["sudo sed", "ansible.legacy.command Invoked"])
def test_local_expected_user_noise_substrings_are_still_accounted(clock, prefix, argument):
    command = "echo " + argument
    line = record(command, local=True).replace("INFO audisp-tacplus: Audisp-tacplus: ", prefix)
    log = cursor(clock, events=[(1, "append", line)])
    log.local = True
    verify([log], commands=[command])
    assert log.counts("rw", [command]) == {command: 1}
    assert not log.counts("rw", ["grep"])


@pytest.mark.parametrize("noise", [
    "INFO ansible.legacy.command Invoked with _raw_params=sudo sed -n 1p /var/log/syslog\n",
    "INFO sudo: admin : COMMAND=/usr/bin/sed -n 1p /var/log/syslog\n",
    "INFO audisp-tacplus: unrelated diagnostic mentioning sudo sed\n",
])
def test_local_nonaccounting_noise_does_not_affect_verification(clock, noise):
    log = cursor(clock, events=[(1, "append", noise + record(local=True))])
    log.local = True
    verify([log])
    assert log.counts("rw", ["grep"]) == {"grep": 1}


def test_local_comma_in_command_is_not_field_delimiter(clock):
    log = cursor(clock)
    log.local = True
    log.lines = [record("grep,NOT_ACTUAL_GREP", local=True)]
    assert not log.counts("rw", ["grep"])


def test_malformed_local_accounting_fails_closed(clock):
    log = cursor(clock)
    log.local = True
    log.lines = ["INFO audisp-tacplus: Audisp-tacplus: Accounting: user: other, broken"]
    with pytest.raises(AssertionError, match="Malformed"):
        log.counts("rw", ["grep"])


def test_absence_sampling_can_cross_boundary_with_enforced_remote_timeout(clock):
    log = cursor(clock, events=[(1, "append", record())])
    log.host.latency = 1.3
    log.host.enforce_timeout = True
    verify([log])
    boundary = 1.3 + 8
    assert any(start < boundary < start + 1.3 for start, _ in log.host.calls)
    assert log.host.calls[-1][0] >= boundary
    assert all(float(shlex.split(cmd)[2][:-1]) == accounting.LOG_READ_TIMEOUT
               for _, cmd in log.host.calls[2:])


@pytest.mark.parametrize("raises", [False, True])
@pytest.mark.parametrize("name", ["test_accounting_tacacs_only_all_tacacs_server_down",
                                  "test_accounting_tacacs_and_local_all_tacacs_server_down"])
def test_failed_stop_still_restarts_and_does_not_run_outage_command(name, raises):
    cleanup = next(node for node in functions()[name].body if isinstance(node, ast.Try))

    def assert_true(value, message):
        assert value, message

    namespace = {"ptfhost": Mock(), "stop_tacacs_server": Mock(return_value=False),
                 "start_tacacs_server": Mock(return_value=True), "pytest_assert": assert_true,
                 "ssh_run_command": Mock(), "check_local_accounting": Mock()}
    if raises:
        namespace["stop_tacacs_server"].side_effect = RuntimeError("stop failed")
    with pytest.raises((AssertionError, RuntimeError), match="stop"):
        exec(compile(ast.Module(body=[cleanup], type_ignores=[]), "cleanup", "exec"), namespace)
    namespace["start_tacacs_server"].assert_called_once_with(namespace["ptfhost"])
    namespace["ssh_run_command"].assert_not_called()
    namespace["check_local_accounting"].assert_not_called()


def local_helper(clock, execute, tacacs=True):
    """Use actual cursors/verifier/helper; mock only readiness, cleanup and SSH."""
    hosts = [Host(clock), Host(clock)]
    logs = []

    def make_cursor(host, path, local=False):
        log = accounting.LogCursor(host, path, local=local)
        logs.append(log)
        return log

    def cleanup(*args):
        for host in hosts:
            host.data = ""
            host.events = []
            host.latency = 0

    namespace = {name: Mock() for name in ["change_and_wait_aaa_config_update", "logger"]}
    namespace.update(MissingAccounting=accounting.MissingAccounting, LOCAL_TIMEOUT=10,
                     LogCursor=make_cursor, capture_logs=accounting.capture_logs,
                     cleanup_tacacs_log=Mock(side_effect=cleanup))
    namespace["ssh_run_command"] = Mock(side_effect=lambda *args: execute(hosts, namespace))
    namespace["verify_accounting"] = lambda cursors, username, commands, timeout: accounting.verify_accounting(
        cursors, username, commands, timeout=timeout, absence_window=1)
    hosts[0].command = Mock(return_value={})
    node = functions()["check_local_accounting"]
    exec(compile(ast.Module(body=[node], type_ignores=[]), "local helper", "exec"), namespace)
    namespace["run"] = lambda: namespace["check_local_accounting"](
        hosts[0], {"tacacs_rw_user": "rw"}, "grep", "config", hosts[1], Mock(), tacacs=tacacs)
    return namespace, hosts, logs


def test_positive_expiry_with_enforced_timeout_retries_actual_helper(clock):
    def execute(hosts, namespace):
        if namespace["ssh_run_command"].call_count == 1:
            hosts[0].latency = 3.1
            hosts[0].enforce_timeout = True
        else:
            for i, host in enumerate(hosts):
                host.events = [(clock.now + 1, "append", record(local=i == 0))]

    namespace, hosts, logs = local_helper(clock, execute)
    namespace["run"]()
    assert namespace["ssh_run_command"].call_count == 2
    assert namespace["cleanup_tacacs_log"].call_count == 2
    assert len(logs) == 4


@pytest.mark.parametrize("source", [0, 1], ids=["local", "remote"])
@pytest.mark.parametrize("partial", [False, True], ids=["forbidden", "partial"])
def test_expiry_reconciliation_cannot_discard_unread_evidence(clock, source, partial):
    def execute(hosts, namespace):
        hosts[0].latency = 3.1
        hosts[0].enforce_timeout = True
        line = record(user="other", local=source == 0)
        if partial:
            line = line.rstrip("\n")
        # Third local read crosses t=10. Even the already-read local source
        # needs reconciliation: this record arrives after that read at t=11.3.
        hosts[source].events = [(12, "append", line)]

    namespace, hosts, logs = local_helper(clock, execute)
    with pytest.raises(AssertionError, match="Incomplete" if partial else "Unexpected") as error:
        namespace["run"]()
    assert not isinstance(error.value, accounting.MissingAccounting)
    assert namespace["cleanup_tacacs_log"].call_count == 1
    assert len(logs) == 2
    assert hosts[source].data


@pytest.mark.parametrize("failure", [{"rc": 1}, {"rc": 137}, {"rc": 124}, {"rc": 0, "failed": True}])
@pytest.mark.parametrize("phase", ["positive", "absence", "reconcile"])
def test_read_errors_never_retry_actual_helper(clock, failure, phase):
    def execute(hosts, namespace):
        if phase == "positive":
            hosts[0].failure = failure
        elif phase == "absence":
            hosts[0].events = [(0, "append", record(local=True)), (1, "fail", failure)]
        else:
            hosts[0].events = [(10, "fail", failure)]

    namespace, hosts, logs = local_helper(clock, execute, tacacs=False)
    with pytest.raises(AssertionError, match="read failed") as error:
        namespace["run"]()
    assert not isinstance(error.value, accounting.MissingAccounting)
    assert namespace["cleanup_tacacs_log"].call_count == 1


def test_late_positive_from_bounded_read_does_not_pass(clock):
    log = cursor(clock, events=[(11, "append", record())])
    log.host.latency = 11
    log.host.enforce_timeout = True
    with pytest.raises(accounting.MissingAccounting, match="deadline"):
        verify([log])
    assert log.counts("rw", ["grep"]) == {"grep": 1}


def test_normal_missing_stops_after_six_attempts_actual_helper(clock):
    namespace, hosts, logs = local_helper(clock, lambda *args: None)
    with pytest.raises(accounting.MissingAccounting):
        namespace["run"]()
    assert len(logs) == 12
    for name in ["cleanup_tacacs_log", "change_and_wait_aaa_config_update", "ssh_run_command"]:
        assert namespace[name].call_count == 6
    assert clock.now == 60


@pytest.mark.parametrize("phase", ["boundary", "positive", "absence", "reconcile"])
def test_transport_exception_is_not_missing(clock, phase):
    log = cursor(clock)
    original = log.host.shell

    def shell(command, **kwargs):
        failure_at = {"boundary": 0, "positive": 0, "absence": 1, "reconcile": 10}[phase]
        if clock.now >= failure_at:
            raise RuntimeError("transport unavailable")
        return original(command, **kwargs)

    if phase == "absence":
        log.host.events = [(0, "append", record())]
    log.host.shell = shell
    with pytest.raises(RuntimeError, match="transport unavailable"):
        if phase == "boundary":
            accounting.capture_logs([log])
        else:
            verify([log])


@pytest.mark.parametrize("phase", ["boundary", "positive", "absence", "reconcile"])
def test_read_budget_kill_is_hard_failure_in_every_phase(clock, phase):
    def execute(hosts, namespace):
        host = hosts[0]
        host.enforce_timeout = True
        if phase == "positive":
            host.latency = 81
        elif phase == "absence":
            host.events = [(0, "append", record(local=True))]
        elif phase == "reconcile":
            host.latency = 3.1

    namespace, hosts, logs = local_helper(clock, execute, tacacs=False)
    original = hosts[0].shell

    def shell(command, **kwargs):
        if phase == "boundary" or (phase == "absence" and clock.now >= 1) or (
                phase == "reconcile" and clock.now > 10):
            hosts[0].latency = 81
            hosts[0].enforce_timeout = True
        return original(command, **kwargs)

    hosts[0].shell = shell
    with pytest.raises(AssertionError, match="read failed") as error:
        namespace["run"]()
    assert not isinstance(error.value, accounting.MissingAccounting)
    assert namespace["cleanup_tacacs_log"].call_count == 1
    assert namespace["ssh_run_command"].call_count == (0 if phase == "boundary" else 1)


def test_expiry_sweep_has_one_shared_budget(clock):
    logs = [cursor(clock) for _ in range(2)]
    for log in logs:
        log.host.latency = 41
        log.host.enforce_timeout = True
    with pytest.raises(AssertionError, match="read failed") as error:
        verify(logs)
    assert not isinstance(error.value, accounting.MissingAccounting)
    assert clock.now == 41 + accounting.LOG_READ_TIMEOUT
    assert float(shlex.split(logs[1].host.calls[-1][1])[2][:-1]) == 39


def test_late_reconciliation_transport_fails_hard(clock):
    log = cursor(clock)
    log.host.latency = 81  # Transport can exceed even the subprocess budget.
    with pytest.raises(AssertionError, match="reconciliation exceeded") as error:
        verify([log])
    assert not isinstance(error.value, accounting.MissingAccounting)
    assert len(log.host.calls) == 3


def test_expiry_sweep_never_accepts_new_positive(clock):
    log = cursor(clock, events=[(10, "append", record())])
    with pytest.raises(accounting.MissingAccounting):
        verify([log])
    assert log.counts("rw", ["grep"]) == {"grep": 1}
