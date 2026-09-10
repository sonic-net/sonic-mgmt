"""Exercise the EverflowPolicerTest original-flow send pacing without PTF.

ansible/roles/test/files/acstests/everflow_policer_test.py imports ptf, which
is not available in this unit-test environment. The module-level
_send_original_flow_paced() helper has no ptf dependency, so it is extracted
via ast and exec'd in isolation to test it directly.

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


def _load_send_original_flow_paced():
    tree = ast.parse(MODULE_PATH.read_text())
    func = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_send_original_flow_paced"
    )
    # The helper's "sleep=time.sleep" default argument is evaluated when the
    # def statement executes, so "time" must be present in the namespace.
    namespace = {"time": time}
    exec(compile(ast.Module(body=[func], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["_send_original_flow_paced"]


@pytest.fixture
def send_original_flow_paced():
    return _load_send_original_flow_paced()


def test_paced_send_batches_10000_in_60s_with_40_final_batch(send_original_flow_paced):
    send_batch = Mock()
    sleep = Mock()

    send_original_flow_paced(
        send_batch, total_packets=10000, batch_size=60, batch_interval=0.01, sleep=sleep)

    counts = [c.args[0] for c in send_batch.call_args_list]
    assert counts == [60] * 166 + [40]
    assert sum(counts) == 10000
    assert sleep.call_args_list == [call(0.01)] * 166


def test_paced_send_exact_multiple_has_no_short_final_batch(send_original_flow_paced):
    send_batch = Mock()

    send_original_flow_paced(
        send_batch, total_packets=120, batch_size=60, batch_interval=0.01, sleep=Mock())

    counts = [c.args[0] for c in send_batch.call_args_list]
    assert counts == [60, 60]
