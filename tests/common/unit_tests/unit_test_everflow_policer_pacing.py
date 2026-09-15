"""Exercise the EverflowPolicerTest send-pacing helpers without PTF.

ansible/roles/test/files/acstests/everflow_policer_test.py imports ptf, which
is not available in this unit-test environment. The pacing helpers have no
ptf dependency, so each is extracted via ast and exec'd in isolation to test
it directly.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
        tests/common/unit_tests/unit_test_everflow_policer_pacing.py -v
"""

import ast
import time
from pathlib import Path
from unittest.mock import Mock, call

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[3]
    / "ansible" / "roles" / "test" / "files" / "acstests" / "everflow_policer_test.py"
)


def _load_function(name):
    tree = ast.parse(MODULE_PATH.read_text())
    func = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    # Both helpers' "sleep=time.sleep" / "monotonic=time.monotonic" default
    # arguments are evaluated when the def statement executes, so "time" must
    # be present in the namespace.
    namespace = {"time": time}
    exec(compile(ast.Module(body=[func], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace[name]


def _get_method_ast(class_name, method_name):
    tree = ast.parse(MODULE_PATH.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    return next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method_name)


@pytest.fixture
def send_packets_paced():
    return _load_function("_send_packets_paced")


@pytest.fixture
def send_packets_paced_for_duration():
    return _load_function("_send_packets_paced_for_duration")


class FakeClock:
    """Deterministic monotonic()/sleep() pair: sleep() advances the fake clock,
    monotonic() never advances on its own. No real delay occurs."""

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_paced_send_batches_10000_in_batches_of_60_with_40_final(send_packets_paced):
    send_batch = Mock()
    sleep = Mock()

    send_packets_paced(
        send_batch, total_packets=10000, batch_size=60, batch_interval=0.01, sleep=sleep)

    counts = [c.args[0] for c in send_batch.call_args_list]
    assert counts == [60] * 166 + [40]
    assert sum(counts) == 10000
    assert sleep.call_args_list == [call(0.01)] * 166


def test_paced_send_exact_multiple_has_no_short_final_batch(send_packets_paced):
    send_batch = Mock()

    send_packets_paced(
        send_batch, total_packets=120, batch_size=60, batch_interval=0.01, sleep=Mock())

    counts = [c.args[0] for c in send_batch.call_args_list]
    assert counts == [60, 60]


def test_paced_duration_send_caps_final_sleep_to_remaining_duration(send_packets_paced_for_duration):
    clock = FakeClock()
    send_batch = Mock()
    sleep = Mock(side_effect=clock.sleep)

    tx_pkts = send_packets_paced_for_duration(
        send_batch, duration=0.025, batch_size=60, batch_interval=0.01,
        sleep=sleep, monotonic=clock.monotonic)

    counts = [c.args[0] for c in send_batch.call_args_list]
    assert counts == [60, 60, 60]                  # exact batch size, every call
    assert tx_pkts == 180                           # returned count matches what was sent

    sleep_values = [c.args[0] for c in sleep.call_args_list]
    # Final sleep is capped to what's left of duration, not a full batch_interval.
    assert sleep_values == pytest.approx([0.01, 0.01, 0.005])
    assert clock.now == pytest.approx(0.025)


def test_check_mirrored_flow_uses_both_pacing_helpers_and_no_direct_send():
    method = _get_method_ast("EverflowPolicerTest", "checkMirroredFlow")

    # Only walk top-level statements, skipping nested defs (match_payload,
    # send_batch) so their calls -- including the one legitimate direct
    # testutils.send_packet() inside send_batch() -- aren't counted here.
    calls = []
    for statement in method.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls.extend(node for node in ast.walk(statement) if isinstance(node, ast.Call))

    helper_names = {call.func.id for call in calls if isinstance(call.func, ast.Name)}
    assert "_send_packets_paced" in helper_names
    assert "_send_packets_paced_for_duration" in helper_names

    direct_send_packet_calls = [
        call for call in calls
        if isinstance(call.func, ast.Attribute) and call.func.attr == "send_packet"
    ]
    assert direct_send_packet_calls == []
