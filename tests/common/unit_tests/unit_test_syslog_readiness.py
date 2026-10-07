"""Offline regressions for run_syslog's capture gate, not DUT packet tests.

Run with python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
    tests/common/unit_tests/unit_test_syslog_readiness.py -v
"""

import ast
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


COMMON_DIR = Path(__file__).resolve().parents[1]
PCAP = "/tmp/test_syslog_tcpdump.pcap"
SERVER_A = "192.0.2.1"
SERVER_B = "2001:db8::1"


def _load_functions(path, names, namespace):
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)


def _assert(condition, message):
    assert condition, message


@pytest.fixture
def capture():
    # Run the actual helper and wait_until, with a clock that charges each SSH
    # probe's latency. AST loading avoids Linux/testbed-only import dependencies.
    clock = SimpleNamespace(now=0.0)

    def advance(seconds):
        clock.now += seconds

    fake_time = SimpleNamespace(time=lambda: clock.now, sleep=advance)
    namespace = {
        "logger": Mock(), "pytest": pytest, "pytest_assert": _assert,
        "time": fake_time, "monotonic": lambda: clock.now, "os": os,
        "DUT_PCAP_FILEPATH": PCAP, "DOCKER_TMP_PATH": "/tmp/",
        "TCPDUMP_START_TIMEOUT": 20, "TCPDUMP_CAPTURE_TIMEOUT": 40,
        "check_dummy_addr_and_default_route": Mock(), "_check_pcap": Mock(return_value=True),
    }
    _load_functions(COMMON_DIR / "utilities.py", ["wait_until"], namespace)
    _load_functions(COMMON_DIR / "helpers" / "syslog_helpers.py", ["run_syslog"], namespace)
    state = SimpleNamespace(
        clock=clock, advance=advance, namespace=namespace, header_at=0, exit_at=40,
        probe_latency=0, launch_latency=0, probes=0, emitted_at=None, logger_error=False,
        pool=Mock(), result=Mock(), dut=Mock(hostname="dut", os_version="202605"),
    )
    state.result.ready.side_effect = lambda: clock.now >= state.exit_at
    state.result.get.return_value = {"rc": 1, "stderr": "capture failed"}

    def shell(command, **kwargs):
        assert "pgrep" not in command
        if kwargs.get("module_async"):
            assert command == (
                'sudo timeout 40 tcpdump -U -y LINUX_SLL -i any -s0 -A -w '
                '{} "udp and port 514"'.format(PCAP)
            )
            advance(state.launch_latency)
            return state.pool, state.result
        if command.startswith("test -s "):
            state.probes += 1
            advance(state.probe_latency)
            return {"rc": 0 if clock.now >= state.header_at else 1}
        if command.startswith("logger --priority"):
            state.emitted_at = clock.now
            if state.logger_error:
                raise RuntimeError("logger failed")
        return {"rc": 0}

    state.dut.shell.side_effect = shell
    return state


def _run(state):
    state.namespace["run_syslog"](state.dut, SERVER_A, SERVER_B, {"IPv4": True, "IPv6": True})


def _check_cleanup(state):
    state.pool.close.assert_called_once_with()
    state.pool.join.assert_called_once_with()
    for server in [SERVER_A, SERVER_B]:
        state.dut.shell.assert_any_call("sudo config syslog del {}".format(server))
    state.dut.command.assert_any_call("sudo ip -4 rule del from all to {} pref 1 lookup default".format(SERVER_A))
    state.dut.command.assert_any_call("sudo ip -6 rule del from all to {} pref 2 lookup default".format(SERVER_B))


@pytest.mark.parametrize("header_at", [0, 3, 19])
def test_header_gate_waits_for_launch_without_settling_sleep(capture, header_at):
    capture.header_at = header_at
    _run(capture)
    assert capture.emitted_at == header_at
    assert capture.emitted_at < capture.exit_at - 20
    capture.dut.fetch.assert_called_once_with(src=PCAP, dest="/tmp/")
    _check_cleanup(capture)


@pytest.mark.parametrize("header_at", [0, 100])
def test_completed_capture_fails_even_if_header_exists(capture, header_at):
    capture.header_at = header_at
    capture.exit_at = 0
    with pytest.raises(pytest.fail.Exception, match="tcpdump exited.*capture failed"):
        _run(capture)
    assert capture.probes == 0
    assert capture.emitted_at is None
    capture.dut.fetch.assert_not_called()
    _check_cleanup(capture)


def test_capture_exit_during_ssh_is_rechecked(capture):
    capture.probe_latency = 2
    capture.exit_at = 1
    with pytest.raises(pytest.fail.Exception, match="tcpdump exited"):
        _run(capture)
    assert capture.probes == 1
    assert capture.emitted_at is None
    _check_cleanup(capture)


@pytest.mark.parametrize("probe_latency,expected_probes", [(0, 40), (3, 6), (25, 1)])
def test_elapsed_deadline_counts_ssh_time(capture, probe_latency, expected_probes):
    capture.header_at = 100
    capture.probe_latency = probe_latency
    with pytest.raises(AssertionError, match="did not become ready within 20s"):
        _run(capture)
    assert capture.probes == expected_probes
    assert capture.emitted_at is None
    _check_cleanup(capture)


def test_header_arriving_after_deadline_is_not_accepted(capture):
    capture.probe_latency = 21
    with pytest.raises(AssertionError, match="did not become ready within 20s"):
        _run(capture)
    assert capture.emitted_at is None
    _check_cleanup(capture)


def test_launch_latency_is_included_in_deadline(capture):
    capture.launch_latency = 21
    with pytest.raises(AssertionError, match="did not become ready within 20s"):
        _run(capture)
    assert capture.probes == 0
    assert capture.emitted_at is None
    _check_cleanup(capture)


def test_async_exception_propagates_with_cleanup(capture):
    capture.exit_at = 0
    capture.result.get.side_effect = RuntimeError("async launch failed")
    with pytest.raises(RuntimeError, match="async launch failed"):
        _run(capture)
    assert capture.emitted_at is None
    _check_cleanup(capture)


def test_logger_failure_still_joins_capture_and_restores_config(capture):
    capture.logger_error = True
    with pytest.raises(RuntimeError, match="logger failed"):
        _run(capture)
    _check_cleanup(capture)


def test_join_failure_still_restores_config(capture):
    capture.pool.join.side_effect = RuntimeError("join failed")
    with pytest.raises(RuntimeError, match="join failed"):
        _run(capture)
    _check_cleanup(capture)
