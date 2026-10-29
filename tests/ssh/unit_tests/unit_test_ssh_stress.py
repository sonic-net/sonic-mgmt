"""Focused regressions for SSH stress calibration and recovery helpers.

Run with::

    python3 -m pytest -q --noconftest \
        --confcutdir=tests/ssh/unit_tests \
        tests/ssh/unit_tests/unit_test_ssh_stress.py
"""

import importlib.util
import io
import os
import pwd
import shlex
import subprocess
import sys
import threading
import time
import types
import uuid
from pathlib import Path

import pytest


pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnknownMarkWarning"
)

MODULE_PATH = Path(__file__).resolve().parents[1] / "test_ssh_stress.py"
HELPER_PATH = (
    Path(__file__).resolve().parents[1]
    / "files"
    / "ssh_stress_command.py"
)


def _load_helper_module():
    spec = importlib.util.spec_from_file_location(
        "unit_target_ssh_stress_command", HELPER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_target_module():
    assertions = types.ModuleType("tests.common.helpers.assertions")

    def pytest_assert(condition, message):
        if not condition:
            raise AssertionError(message)

    assertions.pytest_assert = pytest_assert
    utilities = types.ModuleType("tests.common.utilities")
    utilities.wait_until = lambda *args, **kwargs: True
    stubs = {
        "tests.common.helpers.assertions": assertions,
        "tests.common.utilities": utilities,
    }
    originals = {name: sys.modules.get(name) for name in stubs}
    try:
        sys.modules.update(stubs)
        spec = importlib.util.spec_from_file_location(
            "unit_target_ssh_stress", MODULE_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in originals.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


@pytest.fixture(scope="module")
def ssh_stress():
    return _load_target_module()


@pytest.fixture
def command_helper():
    return _load_helper_module()


def _install_fake_clock(ssh_stress, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        ssh_stress.time,
        "sleep",
        lambda seconds: now.__setitem__(0, now[0] + seconds),
    )
    return now


def test_command_baselines_use_matching_preestablished_clients(
    ssh_stress, monkeypatch
):
    clients = [object(), object()]
    command_pairs = [("add-a", "del-a"), ("add-b", "del-b")]
    durations = {
        "add-a": 0.4,
        "del-a": 0.5,
        "add-b": 0.6,
        "del-b": 0.7,
    }
    calls = []

    def run_command(client, command, timeout=None):
        assert timeout == ssh_stress.CALIBRATION_COMMAND_TIMEOUT
        calls.append((client, command))
        return 0, durations[command]

    monkeypatch.setattr(ssh_stress, "BASELINE_ITERATIONS", 2)
    monkeypatch.setattr(ssh_stress, "_run_command", run_command)
    monkeypatch.setattr(ssh_stress.time, "sleep", lambda _seconds: None)

    result = ssh_stress._get_baseline_times(clients, command_pairs, 0)

    assert result == [(0.4, 0.5), (0.6, 0.7)]
    assert calls == [
        (clients[0], "add-a"),
        (clients[0], "del-a"),
        (clients[0], "add-a"),
        (clients[0], "del-a"),
        (clients[1], "add-b"),
        (clients[1], "del-b"),
        (clients[1], "add-b"),
        (clients[1], "del-b"),
    ]


def test_setup_cleans_partial_artifacts_when_helper_copy_fails(ssh_stress):
    removed = []

    class FakeDut:
        def template(self, **_kwargs):
            pass

        def copy(self, **_kwargs):
            raise RuntimeError("copy failed")

        def file(self, path, state):
            assert state == "absent"
            removed.append(path)

    with pytest.raises(RuntimeError, match="copy failed"):
        ssh_stress._install_stress_artifacts(
            FakeDut(), "/tmp/ssh-helper.py"
        )

    assert removed == ["/tmp/acl.json", "/tmp/ssh-helper.py"]


def test_nested_vrf_route_is_detected_in_config_facts(ssh_stress):
    routes = {
        "default": {
            ssh_stress.STRESS_ROUTE_PREFIX: {
                "nexthop": "10.0.0.1",
            }
        }
    }

    assert ssh_stress._config_has_key_component(
        routes, ssh_stress.STRESS_ROUTE_PREFIX
    )
    assert not ssh_stress._config_has_key_component(routes, "192.0.2.0/24")


def test_quiescence_reads_portchannel_carrier_from_interface_facts(
    ssh_stress, monkeypatch
):
    portchannel = "PortChannel101"

    class FakeDut:
        hostname = "dut"
        link = True

        def config_facts(self, **_kwargs):
            return {
                "ansible_facts": {
                    "PORTCHANNEL": {
                        portchannel: {"admin_status": "up"},
                    },
                    "STATIC_ROUTE": {},
                    "ACL_RULE": {},
                }
            }

        def interface_facts(self):
            return {
                "ansible_facts": {
                    "ansible_interface_facts": {
                        portchannel: {"link": self.link},
                    }
                }
            }

        def is_interface_status_up(self, _interface):
            pytest.fail("physical-port status API used for a PortChannel")

    dut = FakeDut()
    monkeypatch.setattr(
        ssh_stress,
        "_control_plane_is_healthy",
        lambda *_args, **_kwargs: True,
    )

    assert ssh_stress._stress_state_is_quiescent(
        dut, [portchannel], {}, portchannel
    )
    dut.link = False
    assert not ssh_stress._stress_state_is_quiescent(
        dut, [portchannel], {}, portchannel
    )


def _fake_runner(channel):
    transport = types.SimpleNamespace(
        open_session=lambda **_kwargs: channel
    )
    command_ssh = types.SimpleNamespace(get_transport=lambda: transport)
    return types.SimpleNamespace(
        command_ssh=command_ssh,
        command_helper="/tmp/helper.py",
        command_state_root="/tmp/state",
        username="admin",
    )


def test_remote_helper_runs_as_root_but_command_uses_ssh_user(ssh_stress):
    runner = types.SimpleNamespace(
        command_helper="/tmp/helper.py",
        command_state_root="/tmp/state",
        username="admin",
    )

    remote = ssh_stress._remote_run_command(
        runner, "0" * 32, "sudo config bgp startup all"
    )

    assert remote.startswith("sudo -n python3 ")
    assert "run --run-user admin" in remote


def test_run_command_enforces_deadline_despite_periodic_output(
    ssh_stress, monkeypatch
):
    now = [0.0]
    cancelled = []

    class FakeChannel:
        def __init__(self):
            self.closed = False

        def settimeout(self, _timeout):
            pass

        def exec_command(self, _command):
            pass

        def recv_ready(self):
            return True

        def recv(self, _size):
            now[0] += 0.4
            return b"still running\n"

        def recv_stderr_ready(self):
            return False

        def recv_stderr(self, _size):
            raise AssertionError("stderr was not ready")

        def exit_status_ready(self):
            return False

        def close(self):
            self.closed = True

    channel = FakeChannel()
    runner = _fake_runner(channel)
    monkeypatch.setattr(ssh_stress, "COMMAND_TIMEOUT", 1)
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        ssh_stress,
        "_reserve_remote_command",
        lambda _runner, _token, _deadline: None,
    )
    monkeypatch.setattr(
        ssh_stress,
        "_cancel_remote_command",
        lambda _runner, token: cancelled.append(token),
    )

    with pytest.raises(ssh_stress.socket.timeout, match="within 1 seconds"):
        ssh_stress._run_command(runner, "noisy-command")

    assert channel.closed
    assert len(cancelled) == 1
    assert now[0] > 1


def test_run_command_fences_a_blocked_exec_request(ssh_stress, monkeypatch):
    release_dispatch = threading.Event()
    cancelled = []

    class FakeChannel:
        closed = False

        def settimeout(self, _timeout):
            pass

        def exec_command(self, _command):
            release_dispatch.wait(1)

        def close(self):
            self.closed = True
            release_dispatch.set()

    channel = FakeChannel()
    runner = _fake_runner(channel)
    monkeypatch.setattr(ssh_stress, "COMMAND_TIMEOUT", 0.05)
    monkeypatch.setattr(
        ssh_stress,
        "_reserve_remote_command",
        lambda _runner, _token, _deadline: None,
    )
    monkeypatch.setattr(
        ssh_stress,
        "_cancel_remote_command",
        lambda _runner, token: cancelled.append(token),
    )

    with pytest.raises(ssh_stress.socket.timeout, match="within 0.05 seconds"):
        ssh_stress._run_command(runner, "blocked-dispatch")

    assert channel.closed
    assert len(cancelled) == 1


def test_run_command_drains_output_and_returns_status(ssh_stress, monkeypatch):
    stdout_chunks = [b"ok\n"]
    stderr_chunks = [b"warning\n"]

    class FakeChannel:
        closed = False
        eof_received = True

        def settimeout(self, _timeout):
            pass

        def exec_command(self, _command):
            pass

        def recv_ready(self):
            return bool(stdout_chunks)

        def recv(self, _size):
            return stdout_chunks.pop(0)

        def recv_stderr_ready(self):
            return bool(stderr_chunks)

        def recv_stderr(self, _size):
            return stderr_chunks.pop(0)

        def exit_status_ready(self):
            return True

        def recv_exit_status(self):
            return 0

        def close(self):
            self.closed = True

    channel = FakeChannel()
    runner = _fake_runner(channel)
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(
        ssh_stress,
        "_reserve_remote_command",
        lambda _runner, _token, _deadline: None,
    )

    assert ssh_stress._run_command(
        runner, "successful-command"
    ) == (0.0, 0.0)
    assert stdout_chunks == []
    assert stderr_chunks == []
    assert channel.closed


def test_run_command_waits_for_output_after_exit_status(
    ssh_stress, monkeypatch
):
    stdout_chunks = [b"trailing output\n"]
    cancelled = []

    class FakeChannel:
        closed = False
        eof_received = False

        def __init__(self):
            self.status_received = False
            self.post_status_checks = 0

        def settimeout(self, _timeout):
            pass

        def exec_command(self, _command):
            pass

        def recv_ready(self):
            if not self.status_received:
                return False
            self.post_status_checks += 1
            if self.post_status_checks == 1:
                return False
            if stdout_chunks:
                return True
            self.eof_received = True
            return False

        def recv(self, _size):
            return stdout_chunks.pop(0)

        def recv_stderr_ready(self):
            return False

        def recv_stderr(self, _size):
            raise AssertionError("stderr was not ready")

        def exit_status_ready(self):
            return True

        def recv_exit_status(self):
            self.status_received = True
            return 1

        def close(self):
            self.closed = True

    channel = FakeChannel()
    runner = _fake_runner(channel)
    monkeypatch.setattr(ssh_stress, "COMMAND_POLL_INTERVAL", 0)
    monkeypatch.setattr(ssh_stress.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        ssh_stress,
        "_reserve_remote_command",
        lambda _runner, _token, _deadline: None,
    )
    monkeypatch.setattr(
        ssh_stress,
        "_cancel_remote_command",
        lambda _runner, token: cancelled.append(token),
    )

    with pytest.raises(AssertionError, match="trailing output"):
        ssh_stress._run_command(runner, "failed-command")

    assert stdout_chunks == []
    assert len(cancelled) == 1
    assert channel.closed


def test_run_command_duration_includes_eof_drain(ssh_stress, monkeypatch):
    now = [10.0]
    stdout_chunks = [b"trailing output\n"]

    class FakeChannel:
        closed = False
        eof_received = False

        def __init__(self):
            self.status_received = False
            self.post_status_checks = 0

        def settimeout(self, _timeout):
            pass

        def exec_command(self, _command):
            pass

        def recv_ready(self):
            if not self.status_received:
                return False
            self.post_status_checks += 1
            if self.post_status_checks == 1:
                return False
            if stdout_chunks:
                return True
            self.eof_received = True
            return False

        def recv(self, _size):
            return stdout_chunks.pop(0)

        def recv_stderr_ready(self):
            return False

        def recv_stderr(self, _size):
            raise AssertionError("stderr was not ready")

        def exit_status_ready(self):
            return True

        def recv_exit_status(self):
            self.status_received = True
            return 0

        def close(self):
            self.closed = True

    channel = FakeChannel()
    runner = _fake_runner(channel)
    monkeypatch.setattr(ssh_stress, "COMMAND_POLL_INTERVAL", 0.1)
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        ssh_stress.time,
        "sleep",
        lambda seconds: now.__setitem__(0, now[0] + seconds),
    )
    monkeypatch.setattr(
        ssh_stress,
        "_reserve_remote_command",
        lambda _runner, _token, _deadline: None,
    )

    dispatch_duration, completion_duration = ssh_stress._run_command(
        runner, "successful-command"
    )

    assert dispatch_duration == 0
    assert completion_duration == pytest.approx(0.1)
    assert stdout_chunks == []
    assert channel.closed


def test_process_start_time_parsing_allows_spaces_in_command_name(
    command_helper,
):
    fields_three_through_twenty_two = [str(value) for value in range(3, 23)]
    stat_line = "123 (command name with spaces) {}".format(
        " ".join(fields_three_through_twenty_two)
    )

    assert command_helper._parse_process_start_time(stat_line) == "22"


def test_cancel_all_fences_a_reserved_late_dispatch(
    command_helper, monkeypatch, tmp_path
):
    token = uuid.uuid4().hex
    command_helper.reserve_command(str(tmp_path), token)
    assert command_helper.cancel_all(str(tmp_path)) == 0
    monkeypatch.setattr(
        command_helper.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail(
            "cancelled token launched a remote mutation"
        ),
    )
    encoded = command_helper.base64.b64encode(b"echo mutation").decode()

    assert command_helper.run_command(
        str(tmp_path),
        token,
        encoded,
        stdout=io.BytesIO(),
        stderr=io.BytesIO(),
    ) == 124


def test_cancel_waits_for_late_mutation_before_restoration(
    command_helper, monkeypatch, tmp_path
):
    token = uuid.uuid4().hex
    started = tmp_path / "started"
    late = tmp_path / "late"
    restored = tmp_path / "restored"
    script = (
        "import pathlib,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "pathlib.Path({!r}).write_text('started'); "
        "time.sleep(2); pathlib.Path({!r}).write_text('late')"
    ).format(str(started), str(late))
    command = "python3 -c {}".format(repr(script))
    encoded = command_helper.base64.b64encode(command.encode()).decode()
    result = []
    monkeypatch.setattr(command_helper, "TERMINATE_GRACE", 0.1)
    monkeypatch.setattr(command_helper, "CANCEL_WAIT", 2)

    runner = threading.Thread(
        target=lambda: result.append(command_helper.run_command(
            str(tmp_path),
            token,
            encoded,
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        ))
    )
    runner.start()
    deadline = time.monotonic() + 1
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()

    command_helper.cancel_command(str(tmp_path), token)
    restored.write_text("restored")
    runner.join(1)

    assert not runner.is_alive()
    assert restored.exists()
    assert not late.exists()
    assert result and result[0] != 0


def test_failed_group_fence_retains_owner_metadata(
    command_helper, monkeypatch, tmp_path
):
    token = uuid.uuid4().hex

    class FakeProcess:
        pid = 12345
        returncode = 0

        def communicate(self):
            return b"", b""

        def poll(self):
            return self.returncode

    monkeypatch.setattr(
        command_helper.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(),
    )
    monkeypatch.setattr(
        command_helper, "_process_start_time", lambda _pid: "1"
    )
    monkeypatch.setattr(
        command_helper,
        "_terminate_process_group",
        lambda _pid: (_ for _ in ()).throw(
            RuntimeError("process group still alive")
        ),
    )

    with pytest.raises(RuntimeError, match="process group still alive"):
        command_helper.run_command(
            str(tmp_path),
            token,
            command_helper.base64.b64encode(b"true").decode(),
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )

    directory = tmp_path / token
    assert (directory / "owner.json").exists()
    assert not (directory / "done.json").exists()


def test_normal_completion_fences_background_descendants(
    command_helper, monkeypatch, tmp_path
):
    token = uuid.uuid4().hex
    started = tmp_path / "background-started"
    late = tmp_path / "background-late"
    child = (
        "import pathlib,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "pathlib.Path({!r}).write_text('started'); "
        "time.sleep(1); pathlib.Path({!r}).write_text('late')"
    ).format(str(started), str(late))
    parent = (
        "import pathlib,subprocess,time; "
        "subprocess.Popen(['python3','-c',{!r}], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "deadline=time.monotonic()+1; "
        "path=pathlib.Path({!r}); "
        "exec(\"while not path.exists() and time.monotonic() < deadline:\\n"
        "    time.sleep(0.01)\")"
    ).format(child, str(started))
    encoded = command_helper.base64.b64encode(
        "python3 -c {}".format(shlex.quote(parent)).encode()
    ).decode()
    monkeypatch.setattr(command_helper, "TERMINATE_GRACE", 0.1)

    assert command_helper.run_command(
        str(tmp_path),
        token,
        encoded,
        stdout=io.BytesIO(),
        stderr=io.BytesIO(),
    ) == 0

    assert started.exists()
    time.sleep(1.1)
    assert not late.exists()


def test_fallback_fences_descendants_after_leader_exits(
    command_helper, monkeypatch, tmp_path
):
    started = tmp_path / "fallback-started"
    late = tmp_path / "fallback-late"
    child = (
        "import pathlib,signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "pathlib.Path({!r}).write_text('started'); "
        "time.sleep(1); pathlib.Path({!r}).write_text('late')"
    ).format(str(started), str(late))
    parent = (
        "import subprocess,time; "
        "subprocess.Popen(['python3','-c',{!r}], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        "time.sleep(0.1)"
    ).format(child)
    leader = subprocess.Popen(
        ["python3", "-c", parent], start_new_session=True
    )
    start_time = command_helper._process_start_time(leader.pid)
    leader.wait(timeout=1)
    deadline = time.monotonic() + 1
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()
    monkeypatch.setattr(command_helper, "TERMINATE_GRACE", 0.1)

    command_helper._terminate_owned_process(leader.pid, start_time)

    time.sleep(1.1)
    assert not late.exists()
    assert not command_helper._process_group_alive(leader.pid)


def test_wrapper_owns_cancellation_until_process_group_is_gone(
    command_helper, tmp_path
):
    token = uuid.uuid4().hex
    started = tmp_path / "wrapper-started"
    late = tmp_path / "wrapper-late"
    script = (
        "import pathlib,time; "
        "pathlib.Path({!r}).write_text('started'); "
        "time.sleep(2); pathlib.Path({!r}).write_text('late')"
    ).format(str(started), str(late))
    encoded = command_helper.base64.b64encode(
        "python3 -c {}".format(repr(script)).encode()
    ).decode()
    username = pwd.getpwuid(os.getuid()).pw_name
    process = subprocess.Popen(
        [
            sys.executable,
            str(HELPER_PATH),
            "--state-root",
            str(tmp_path),
            "run",
            "--run-user",
            username,
            token,
            encoded,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 1
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started.exists()

    command_helper.cancel_command(str(tmp_path), token)
    process.communicate(timeout=1)

    assert process.returncode != 0
    assert not late.exists()


def test_worker_rolls_back_a_timed_out_mutation(ssh_stress, monkeypatch):
    calls = []
    stop_event = ssh_stress.threading.Event()
    start_event = ssh_stress.threading.Event()
    start_event.set()

    def run_command(_ssh, command):
        calls.append(command)
        if command == "add":
            raise ssh_stress.socket.timeout("timed out")
        return 0, 0

    monkeypatch.setattr(ssh_stress, "_run_command", run_command)
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: 0)

    ssh_stress.work(
        types.SimpleNamespace(close=lambda: None),
        ("add", "del"),
        ssh_stress.queue.Queue(),
        0,
        types.SimpleNamespace(wait=lambda: None),
        start_event,
        stop_event,
        [300.0],
        [[], []],
    )

    assert calls == ["add", "del"]


def test_worker_uses_baseline_scaled_timeout_for_mutation_and_rollback(
    ssh_stress, monkeypatch
):
    calls = []
    stop_event = ssh_stress.threading.Event()
    start_event = ssh_stress.threading.Event()
    start_event.set()

    def run_command(_ssh, command, timeout):
        calls.append((command, timeout))
        if command == "add":
            stop_event.set()
        return 0, 1

    monkeypatch.setattr(ssh_stress, "_run_command", run_command)
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: 0)

    ssh_stress.work(
        types.SimpleNamespace(close=lambda: None),
        ("add", "del"),
        ssh_stress.queue.Queue(),
        0,
        types.SimpleNamespace(wait=lambda: None),
        start_event,
        stop_event,
        [300.0],
        [[], []],
        (101.0, 60),
    )

    assert calls == [("add", 101.0), ("del", 60)]


def test_worker_retries_a_timed_out_initial_bgp_restore(
    ssh_stress, monkeypatch
):
    calls = []
    stop_event = ssh_stress.threading.Event()
    start_event = ssh_stress.threading.Event()
    start_event.set()

    def run_command(_ssh, command):
        calls.append(command)
        if len(calls) == 1:
            raise ssh_stress.socket.timeout("timed out")
        return 0, 0

    monkeypatch.setattr(ssh_stress, "_run_command", run_command)
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: 0)

    ssh_stress.work(
        types.SimpleNamespace(close=lambda: None),
        (ssh_stress.START_BGP_NBRS, ssh_stress.STOP_BGP_NBRS),
        ssh_stress.queue.Queue(),
        0,
        types.SimpleNamespace(wait=lambda: None),
        start_event,
        stop_event,
        [300.0],
        [[], []],
    )

    assert calls == [
        ssh_stress.START_BGP_NBRS,
        ssh_stress.START_BGP_NBRS,
    ]


def test_worker_does_not_rollback_without_a_remote_fence(
    ssh_stress, monkeypatch
):
    calls = []
    stop_event = ssh_stress.threading.Event()
    start_event = ssh_stress.threading.Event()
    start_event.set()

    def run_command(_ssh, command):
        calls.append(command)
        raise ssh_stress._RemoteCommandFenceError("fence unavailable")

    monkeypatch.setattr(ssh_stress, "_run_command", run_command)
    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: 0)

    ssh_stress.work(
        types.SimpleNamespace(close=lambda: None),
        ("add", "del"),
        ssh_stress.queue.Queue(),
        0,
        types.SimpleNamespace(wait=lambda: None),
        start_event,
        stop_event,
        [300.0],
        [[], []],
    )

    assert calls == ["add"]


def test_thread_join_budget_allows_command_fence_and_rollback(ssh_stress):
    assert ssh_stress.THREAD_JOIN_TIMEOUT >= (
        2 * (
            ssh_stress.MAX_COMMAND_TIMEOUT
            + ssh_stress.COMMAND_CANCEL_TIMEOUT
        )
        + 10
    )


def test_fast_host_retains_twenty_cycle_cap(ssh_stress):
    command_pairs = [
        ("add-{}".format(ind), "del-{}".format(ind))
        for ind in range(5)
    ]
    requirements = ssh_stress._derive_stress_requirements(
        command_pairs,
        [(1.0, 1.0)] * 5,
        command_settle_time=1,
    )

    assert all(
        requirement["required_cycles"] == 20
        for requirement in requirements
    )
    assert all(
        requirement["command_timeouts"] == (60, 60)
        for requirement in requirements
    )


def test_slow_host_gets_baseline_scaled_limits_and_inconclusive_result(
    ssh_stress
):
    command_pairs = [
        ("add-{}".format(ind), "del-{}".format(ind))
        for ind in range(5)
    ]
    baseline_times = [(20.0, 10.0)] + [(1.0, 1.0)] * 4
    requirements = ssh_stress._derive_stress_requirements(
        command_pairs, baseline_times, command_settle_time=1
    )

    assert requirements[0]["command_budgets"] == (101.0, 51.0)
    assert requirements[0]["command_timeouts"] == (101.0, 60)
    assert requirements[0]["required_cycles"] == 1
    with pytest.raises(pytest.skip.Exception, match="INFRASTRUCTURE_LIMITED"):
        ssh_stress._require_meaningful_stress_evidence(
            command_pairs, requirements
        )


def test_adaptive_command_timeout_retains_hard_ceiling(ssh_stress):
    command_pairs = [
        ("add-{}".format(ind), "del-{}".format(ind))
        for ind in range(5)
    ]
    requirements = ssh_stress._derive_stress_requirements(
        command_pairs,
        [(100.0, 100.0)] + [(1.0, 1.0)] * 4,
        command_settle_time=1,
    )

    assert requirements[0]["command_budgets"] == (180, 180)
    assert requirements[0]["command_timeouts"] == (180, 180)


def test_stress_progress_accepts_baseline_derived_cycle_floor(
    ssh_stress
):
    command_pairs = [("add", "del")]
    baseline_times = [(0.50, 0.40)]
    stress_durations = [[[2.60] * 3, [2.54] * 3]]
    requirements = [{
        "required_cycles": 3,
        "serial_cycle_duration": 0.90,
        "allowed_cycle_duration": 5.50,
        "command_budgets": (3.50, 3.00),
        "command_timeouts": (60, 60),
    }]

    ssh_stress._assert_stress_progress(
        command_pairs, baseline_times, stress_durations, requirements
    )


@pytest.mark.parametrize("sample_counts", [(3, 2), (2, 3)])
def test_stress_progress_rejects_incomplete_baseline_derived_floor(
    ssh_stress, sample_counts
):
    stress_durations = [[
        [0.50] * sample_counts[0],
        [0.40] * sample_counts[1],
    ]]
    requirements = [{
        "required_cycles": 3,
        "serial_cycle_duration": 0.90,
        "allowed_cycle_duration": 5.50,
        "command_budgets": (3.50, 3.00),
        "command_timeouts": (60, 60),
    }]

    with pytest.raises(AssertionError, match="completed only 2 full cycles"):
        ssh_stress._assert_stress_progress(
            [("add", "del")],
            [(0.50, 0.40)],
            stress_durations,
            requirements,
        )


def test_unmatched_final_command_does_not_count_as_an_extra_cycle(ssh_stress):
    commands = ("add", "del")
    durations = [[0.50] * 21, [0.40] * 20]

    assert ssh_stress._completed_stress_cycles(commands, durations) == 20


def test_bgp_cycle_counts_only_shutdowns_restored_inside_window(ssh_stress):
    commands = (ssh_stress.START_BGP_NBRS, ssh_stress.STOP_BGP_NBRS)

    assert ssh_stress._completed_stress_cycles(
        commands, [[0.50] * 21, [0.40] * 20]
    ) == 20
    assert ssh_stress._completed_stress_cycles(
        commands, [[0.50] * 20, [0.40] * 20]
    ) == 19


def test_completion_after_stress_deadline_is_not_recorded(ssh_stress):
    durations = [[], []]

    assert not ssh_stress._record_stress_completion(
        durations, 0, 2.50, completed_at=301, deadline=300
    )
    assert durations == [[], []]


def test_worker_does_not_dispatch_after_stress_deadline(
    ssh_stress, monkeypatch
):
    now = iter([300.0])
    run_commands = []
    stop_event = ssh_stress.threading.Event()
    start_event = ssh_stress.threading.Event()
    start_event.set()

    monkeypatch.setattr(ssh_stress.time, "monotonic", lambda: next(now))
    monkeypatch.setattr(
        ssh_stress,
        "_run_command",
        lambda _ssh, command: run_commands.append(command),
    )

    ssh_stress.work(
        types.SimpleNamespace(close=lambda: None),
        ("add", "del"),
        ssh_stress.queue.Queue(),
        0,
        types.SimpleNamespace(wait=lambda: None),
        start_event,
        stop_event,
        [300.0],
        [[], []],
    )

    assert run_commands == []


def test_nearest_rank_p95_remains_a_diagnostic(ssh_stress):
    values = list(range(1, 54))

    assert ssh_stress._nearest_rank_percentile(values, 0.95) == 51


def test_usage_baseline_is_median_of_current_samples(ssh_stress, monkeypatch):
    readings = iter([
        (0.30, 0.90),
        (0.10, 0.20),
        (0.20, 0.40),
    ])
    monkeypatch.setattr(
        ssh_stress, "get_system_stats", lambda _duthost: next(readings)
    )

    assert ssh_stress._get_usage_baseline(object(), 3) == (0.20, 0.40)


def test_monitor_rejects_sample_read_across_phase_reset(ssh_stress):
    stop_event = ssh_stress.threading.Event()
    failures = ssh_stress.queue.Queue()
    ready = ssh_stress.threading.Event()
    metrics = ssh_stress._new_usage_metrics()
    read_blocked = ssh_stress.threading.Event()
    release_read = ssh_stress.threading.Event()
    high_sample = "0 0 1 1 9 9 0 0 0 0 0 0 45 45 10 0 0\n"

    class FakeChannel:
        def close(self):
            pass

    class FakeStdout:
        channel = FakeChannel()

        def __init__(self):
            self.read_count = 0

        def readline(self):
            self.read_count += 1
            if self.read_count == 1:
                return "procs -----------memory---------- ---swap--\n"
            if self.read_count == 2:
                return high_sample  # vmstat's since-boot sample is discarded
            if self.read_count == 3:
                read_blocked.set()
                assert release_read.wait(1)
                return high_sample
            stop_event.set()
            return ""

    stdout = FakeStdout()

    class FakeSSH:
        def exec_command(self, *_args, **_kwargs):
            return None, stdout, None

    monitor_thread = ssh_stress.threading.Thread(
        target=ssh_stress.monitor_system,
        args=(FakeSSH(), stop_event, failures, ready, metrics),
    )
    monitor_thread.start()
    assert read_blocked.wait(1)

    ssh_stress._reset_usage_peaks(metrics, 0.20, 0.30)
    release_read.set()
    monitor_thread.join(1)

    assert not monitor_thread.is_alive()
    assert failures.empty()
    assert ready.is_set()
    assert metrics["max_mem"] == 0.20
    assert metrics["max_cpu"] == 0.30


def test_recovery_accepts_first_reading_within_threshold(
    ssh_stress, monkeypatch
):
    readings = iter([
        (0.20, 0.20),
        (0.31, 0.31),
    ])
    sample_count = 0

    def get_stats(_duthost):
        nonlocal sample_count
        sample_count += 1
        return next(readings)

    monkeypatch.setattr(ssh_stress, "get_system_stats", get_stats)
    monkeypatch.setattr(ssh_stress, "HEALTH_RECOVERY_TIMEOUT", 30)
    _install_fake_clock(ssh_stress, monkeypatch)

    ssh_stress.run_post_test_system_check(
        0.10, 0.10, object(), 0.80, 0.90
    )

    assert sample_count == 1


def test_recovery_rejects_readings_outside_threshold(
    ssh_stress, monkeypatch
):
    readings = iter([
        (0.31, 0.31),
        (0.32, 0.32),
        (0.33, 0.33),
        (0.34, 0.34),
    ])
    sample_count = 0

    def get_stats(_duthost):
        nonlocal sample_count
        sample_count += 1
        return next(readings)

    monkeypatch.setattr(ssh_stress, "get_system_stats", get_stats)
    monkeypatch.setattr(ssh_stress, "HEALTH_RECOVERY_TIMEOUT", 25)
    _install_fake_clock(ssh_stress, monkeypatch)

    with pytest.raises(AssertionError, match="did not return within 20 points"):
        ssh_stress.run_post_test_system_check(
            0.10, 0.10, object(), 0.80, 0.90
        )

    assert sample_count == 4


def test_recovery_rejects_samples_completed_after_deadline(
    ssh_stress, monkeypatch
):
    sample_starts = []
    sample_completions = []
    monkeypatch.setattr(ssh_stress, "HEALTH_RECOVERY_TIMEOUT", 16)
    now = _install_fake_clock(ssh_stress, monkeypatch)

    def get_stats(_duthost):
        sample_starts.append(now[0])
        now[0] += 2
        sample_completions.append(now[0])
        if now[0] > ssh_stress.HEALTH_RECOVERY_TIMEOUT:
            return 0.10, 0.10
        return 0.31, 0.31

    monkeypatch.setattr(ssh_stress, "get_system_stats", get_stats)

    with pytest.raises(AssertionError, match="did not return within 20 points"):
        ssh_stress.run_post_test_system_check(
            0.10, 0.10, object(), 0.80, 0.90
        )

    assert sample_starts == [5, 10, 15]
    assert sample_completions == [7, 12, 17]
