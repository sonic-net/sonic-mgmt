"""Focused regressions for SSH stress calibration and recovery helpers.

Run with::

    python3 -m pytest -q --noconftest \
        --confcutdir=tests/ssh/unit_tests \
        tests/ssh/unit_tests/unit_test_ssh_stress.py
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest


pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnknownMarkWarning"
)

MODULE_PATH = Path(__file__).resolve().parents[1] / "test_ssh_stress.py"


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

    def run_command(client, command):
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


def test_stress_progress_accepts_sustained_cycles_despite_high_p95(
    ssh_stress, monkeypatch
):
    monkeypatch.setattr(ssh_stress, "MIN_STRESS_CYCLES", 20)
    monkeypatch.setattr(ssh_stress, "STRESS_DURATION", 300)
    command_pairs = [("add", "del")]
    baseline_times = [(0.50, 0.40)]
    stress_durations = [[
        [2.60] * 20,
        [2.54] * 20,
    ]]

    # The delete p95 is 6.35x its serial median. That ratio is diagnostic;
    # the hard invariant is sustained completion of full command-pair cycles.
    ssh_stress._assert_stress_progress(
        command_pairs, baseline_times, stress_durations
    )


@pytest.mark.parametrize("sample_counts", [(20, 19), (19, 20)])
def test_stress_progress_rejects_incomplete_cycle_floor(
    ssh_stress, monkeypatch, sample_counts
):
    monkeypatch.setattr(ssh_stress, "MIN_STRESS_CYCLES", 20)
    monkeypatch.setattr(ssh_stress, "STRESS_DURATION", 300)
    stress_durations = [[
        [0.50] * sample_counts[0],
        [0.40] * sample_counts[1],
    ]]

    with pytest.raises(AssertionError, match="completed only 19 full cycles"):
        ssh_stress._assert_stress_progress(
            [("add", "del")], [(0.50, 0.40)], stress_durations
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


def test_recovery_requires_consecutive_readings(ssh_stress, monkeypatch):
    readings = iter([
        (0.20, 0.20),  # recovered once
        (0.31, 0.31),  # one spike resets the streak
        (0.20, 0.20),
        (0.19, 0.19),
        (0.18, 0.18),
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

    assert sample_count == 5


def test_recovery_rejects_one_lucky_minimum_within_bounded_window(
    ssh_stress, monkeypatch
):
    readings = iter([
        (0.20, 0.20),
        (0.31, 0.31),
        (0.19, 0.19),
        (0.32, 0.32),
    ])
    sample_count = 0

    def get_stats(_duthost):
        nonlocal sample_count
        sample_count += 1
        return next(readings)

    monkeypatch.setattr(ssh_stress, "get_system_stats", get_stats)
    monkeypatch.setattr(ssh_stress, "HEALTH_RECOVERY_TIMEOUT", 25)
    _install_fake_clock(ssh_stress, monkeypatch)

    with pytest.raises(AssertionError, match="3 consecutive readings"):
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
        return 0.10, 0.10

    monkeypatch.setattr(ssh_stress, "get_system_stats", get_stats)

    with pytest.raises(AssertionError, match="3 consecutive readings"):
        ssh_stress.run_post_test_system_check(
            0.10, 0.10, object(), 0.80, 0.90
        )

    assert sample_starts == [5, 10, 15]
    assert sample_completions == [7, 12, 17]
