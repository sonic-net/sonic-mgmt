"""Isolated regressions for SSH-stress completion limits and failure handling."""

import ast
from concurrent.futures import ThreadPoolExecutor
import logging
import queue
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "test_ssh_stress.py"
HELPERS = {
    "_restore_command", "_setup_stress", "_run_command", "_get_baseline_times",
    "_get_concurrent_baseline_times", "work", "test_ssh_stress",
}


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def stress_helpers():
    tree = ast.parse(MODULE_PATH.read_text())
    selected = [
        node for node in tree.body
        if (
            isinstance(node, ast.FunctionDef) and node.name in HELPERS
        ) or (
            isinstance(node, ast.Assign)
            and all(
                isinstance(target, ast.Name) and target.id.isupper()
                for target in node.targets
            )
        )
    ]
    namespace = {
        "ThreadPoolExecutor": ThreadPoolExecutor,
        "done": False,
        "max_cpu": 0,
        "max_mem": 0,
        "logging": logging,
        "queue": queue,
        "pytest_assert": _assert,
        "time": SimpleNamespace(sleep=Mock(), time=Mock()),
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace


def _context(helpers, asic_type):
    duthost = Mock(hostname="dut", facts={"asic_type": asic_type})
    duthost.host.options = {
        "variable_manager": SimpleNamespace(extra_vars={}),
    }
    duthost.config_facts.return_value = {
        "ansible_facts": {"PORTCHANNEL": {"PortChannel101": {}}},
    }
    duthost.get_bgp_neighbors_per_asic.return_value = {
        "asic0": {"10.0.0.1": {}, "fc00::1": {}},
    }
    request = Mock()
    request.getfixturevalue.return_value = {
        "sonicadmin_user": "test-user", "sonicadmin_password": "test-password",
    }
    return helpers["_setup_stress"](duthost, request)


@pytest.mark.parametrize("asic_type, concurrent, settle", [
    ("vpp", True, 1), ("vs", False, 0), ("broadcom", False, 0),
])
def test_concurrent_baselines_are_vpp_only(stress_helpers, asic_type, concurrent, settle):
    context = _context(stress_helpers, asic_type)

    assert context["concurrent_baselines"] is concurrent
    assert context["command_settle_time"] == settle
    assert len(context["command_pairs"]) == 5


@pytest.mark.parametrize("asic_type", ["vpp", "vs"])
def test_baseline_mode_and_worker_wiring(stress_helpers, asic_type):
    context = _context(stress_helpers, asic_type)
    ssh = Mock()
    ssh.exec_command.return_value = (None, Mock(), Mock())
    thread = Mock()
    stress_helpers.update({
        "threading": SimpleNamespace(Thread=thread),
        "monitor_system": Mock(),
        "start_SSH_connection": Mock(return_value=ssh),
        "_get_baseline_times": Mock(return_value=[(0.44, 0.44)] * 5),
        "_get_concurrent_baseline_times": Mock(return_value=[(0.44, 0.44)] * 5),
        "get_system_stats": Mock(return_value=(0.2, 0.2)),
        "run_post_test_system_check": Mock(),
    })

    stress_helpers["test_ssh_stress"]({"dut": Mock()}, "dut", context)

    workers = [
        call.kwargs["args"] for call in thread.call_args_list
        if call.kwargs["target"] is stress_helpers["work"]
    ]
    assert len(workers) == 5
    assert [args[1] for args in workers] == context["command_pairs"]
    assert all(args[-1] == context["command_settle_time"] for args in workers)
    concurrent = asic_type == "vpp"
    assert stress_helpers["_get_concurrent_baseline_times"].call_count == int(concurrent)
    assert stress_helpers["_get_baseline_times"].call_count == int(not concurrent)
    stress_helpers["time"].sleep.assert_any_call(300)
    assert stress_helpers["run_post_test_system_check"].call_count == 2
    assert stress_helpers["start_SSH_connection"].call_count == (20 if concurrent else 21)


@pytest.mark.parametrize("bgp_pair", [False, True])
def test_baseline_samples_alternate_and_restore(stress_helpers, bgp_pair):
    commands = (
        (stress_helpers["START_BGP_NBRS"], stress_helpers["STOP_BGP_NBRS"])
        if bgp_pair else ("add", "remove")
    )
    results = [(0, 1), (0, 2)] * 5 + ([(0, 1)] if bgp_pair else [])
    run = Mock(side_effect=results)
    stress_helpers["_run_command"] = run
    ssh = Mock()

    assert stress_helpers["_get_baseline_times"](ssh, [commands], 1) == [(1, 2)]
    expected = list(commands) * 5 + ([commands[0]] if bgp_pair else [])
    assert [call.args[1] for call in run.call_args_list] == expected
    assert stress_helpers["time"].sleep.call_count == len(expected)


def test_concurrent_baselines_use_independent_sessions_and_preserve_order(stress_helpers):
    pairs = [("add-{}".format(i), "remove-{}".format(i)) for i in range(5)]
    barrier = threading.Barrier(5, timeout=3)
    connections = []

    def connect(*args):
        ssh = Mock()
        connections.append(ssh)
        return ssh

    def measure(ssh, command_pairs, settle):
        assert len(command_pairs) == 1
        assert settle == 1
        barrier.wait()
        index = int(command_pairs[0][0].split("-")[-1])
        return [(index + 0.1, index + 0.2)]

    connect_mock = Mock(side_effect=connect)
    stress_helpers.update({
        "start_SSH_connection": connect_mock,
        "_get_baseline_times": measure,
    })
    result = stress_helpers["_get_concurrent_baseline_times"](
        "127.0.0.1", pairs, "test-user", "test-password", 1,
    )

    assert result == [(i + 0.1, i + 0.2) for i in range(5)]
    assert connect_mock.call_count == 5
    assert all(call.args == (
        "127.0.0.1", "test-user", "test-password",
    ) for call in connect_mock.call_args_list)
    assert len({id(ssh) for ssh in connections}) == 5
    for ssh in connections:
        ssh.close.assert_called_once_with()


def test_baseline_error_propagates_and_closes_sessions(stress_helpers):
    pairs = [("add-{}".format(i), "remove-{}".format(i)) for i in range(5)]
    barrier = threading.Barrier(5, timeout=3)
    connections = []

    def connect(*args):
        ssh = Mock()
        connections.append(ssh)
        return ssh

    def measure(ssh, command_pairs, settle):
        barrier.wait()
        if command_pairs[0] == pairs[0]:
            raise AssertionError("command failed with rc=7")
        return [(1, 2)]

    stress_helpers.update({
        "start_SSH_connection": connect,
        "_get_baseline_times": measure,
    })
    with pytest.raises(AssertionError, match="rc=7"):
        stress_helpers["_get_concurrent_baseline_times"](
            "127.0.0.1", pairs, "test-user", "test-password", 1,
        )
    assert len(connections) == 5
    for ssh in connections:
        ssh.close.assert_called_once_with()


def _run_worker(helpers, completion, baseline, settle):
    ssh = Mock()
    commands = (helpers["ADD_PORTCHANNEL"], helpers["REMOVE_PORTCHANNEL"])
    failures = queue.Queue()
    calls = []

    def run(connection, command):
        assert connection is ssh
        calls.append(command)
        helpers["done"] = True
        if len(calls) == 1:
            if isinstance(completion, Exception):
                raise completion
            return 0, completion
        return 0, 0.1

    helpers.update({
        "_run_command": run,
        "start_SSH_connection": Mock(return_value=ssh),
    })
    helpers["work"](
        "127.0.0.1", commands, (baseline, baseline),
        "test-user", "test-password", failures, settle,
    )
    return list(failures.queue), calls, ssh


@pytest.mark.parametrize("baseline, settle, completion, failed", [
    (0.59, 1, 3.51, True),
    (2.10, 1, 3.51, False),
    (0.57, 1, 2.77, True),
    (1.72, 1, 2.77, False),
    (1.2, 1, 4.599, False),
    (1.2, 1, 4.6, True),
    (1.2, 1, 6.0, True),
    (0.44, 0, 1.319, False),
    (0.44, 0, 1.32, True),
    (0.44, 0, 2.78, True),
])
def test_completion_limit_and_rollback(
    stress_helpers, baseline, settle, completion, failed,
):
    failures, calls, ssh = _run_worker(
        stress_helpers, completion, baseline, settle,
    )

    assert bool(failures) is failed
    assert calls == [
        stress_helpers["ADD_PORTCHANNEL"], stress_helpers["REMOVE_PORTCHANNEL"],
    ]
    if failed:
        limit = 3 * baseline + settle
        assert "limit {:.2f}s".format(limit) in failures[0]
    ssh.close.assert_called_once_with()


def test_command_error_is_reported(stress_helpers):
    failures, calls, ssh = _run_worker(
        stress_helpers, AssertionError("command failed with rc=7"),
        0.44, 1,
    )

    assert len(failures) == 1
    assert "rc=7" in failures[0]
    assert calls[-1] == stress_helpers["REMOVE_PORTCHANNEL"]
    ssh.close.assert_called_once_with()


def test_rollback_error_is_reported(stress_helpers):
    ssh = Mock()
    failures = queue.Queue()
    stress_helpers.update({
        "start_SSH_connection": Mock(return_value=ssh),
        "_run_command": Mock(side_effect=[
            RuntimeError("command failed"), RuntimeError("rollback failed"),
        ]),
    })
    stress_helpers["work"](
        "127.0.0.1", ("add", "remove"), (0.44, 0.44),
        "test-user", "test-password", failures, 1,
    )

    assert failures.qsize() == 2
    assert "command failed" in failures.get_nowait()
    assert "rollback failed" in failures.get_nowait()
    ssh.close.assert_called_once_with()


@pytest.mark.parametrize("exit_status", [0, 7])
def test_run_command_waits_for_completion_and_requires_success(stress_helpers, exit_status):
    ssh, stdout, stderr = Mock(), Mock(), Mock()
    stdout.readlines.return_value = ["output"]
    stderr.readlines.return_value = ["error"] if exit_status else []
    stdout.channel.recv_exit_status.return_value = exit_status
    ssh.exec_command.return_value = (None, stdout, stderr)
    stress_helpers["time"].time.side_effect = [1, 1.03, 3.78]

    if exit_status:
        with pytest.raises(AssertionError, match="rc=7"):
            stress_helpers["_run_command"](ssh, "command")
    else:
        assert stress_helpers["_run_command"](ssh, "command") == pytest.approx((0.03, 2.78))
    ssh.exec_command.assert_called_once_with("command", timeout=60)
    stdout.readlines.assert_called_once_with()
    stderr.readlines.assert_called_once_with()
    stdout.channel.recv_exit_status.assert_called_once_with()
