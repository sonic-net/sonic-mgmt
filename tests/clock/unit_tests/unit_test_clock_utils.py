"""Exercise ClockUtils.run_cmd's Ansible failure-output selection without importing
sonic-mgmt's full test dependency chain (sonic-net/sonic-mgmt#27844).

test_clock.py transitively pulls in tests/common/__init__.py, which drags in
ansible, scapy, paramiko, netmiko, etc. None of that is needed to exercise
run_cmd's stdout/stderr/msg selection logic, so this test extracts just that
function's AST from the real source file (the same technique used by
unit_test_dhcp_relay_cleanup.py) and executes it against minimal fakes for its
only two external names: 'allure' and 'RunAnsibleModuleFail'.

Run with::

    python3 -m pytest --noconftest --confcutdir=tests/clock/unit_tests \
        tests/clock/unit_tests/unit_test_clock_utils.py -v
"""

import ast
import logging
from contextlib import nullcontext
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "test_clock.py"


class _FakeRunAnsibleModuleFail(Exception):
    """Stand-in for tests.common.errors.RunAnsibleModuleFail (no ansible dependency)."""

    def __init__(self, msg, results=None):
        super().__init__(msg)
        self.results = results


class _FakeAllure:
    @staticmethod
    def step(title):
        return nullcontext()


@pytest.fixture(scope="module")
def run_cmd():
    """Compile and return the real run_cmd function body, isolated from ClockUtils/test_clock.py."""
    tree = ast.parse(MODULE_PATH.read_text())
    class_node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "ClockUtils")
    func_node = next(n for n in class_node.body if isinstance(n, ast.FunctionDef) and n.name == "run_cmd")
    func_node.decorator_list = []  # drop @staticmethod; we call the plain function directly

    namespace = {
        "logging": logging,
        "allure": _FakeAllure(),
        "RunAnsibleModuleFail": _FakeRunAnsibleModuleFail,
    }
    exec(compile(ast.Module(body=[func_node], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["run_cmd"]


class _FakeDuthosts:
    """Minimal stand-in for the duthosts fixture: duthosts[0].hostname and duthosts.command()."""

    hostname = "test-dut"

    def __init__(self, command_exc):
        self._command_exc = command_exc

    def __getitem__(self, index):
        return self

    def command(self, cmd):
        raise self._command_exc


def _run_cmd_with_results(run_cmd, results):
    duthosts = _FakeDuthosts(_FakeRunAnsibleModuleFail("run module command failed", results))
    with pytest.raises(Exception) as exc_info:
        run_cmd(duthosts, "some command", raise_err=True)
    return str(exc_info.value)


def test_run_cmd_prefers_stdout_over_stderr_and_msg(run_cmd):
    err = _run_cmd_with_results(run_cmd, {"stdout": "stdout text", "stderr": "stderr text", "msg": "msg text"})
    assert err == "stdout text"


def test_run_cmd_prefers_stderr_over_msg_when_stdout_empty(run_cmd):
    err = _run_cmd_with_results(run_cmd, {"stdout": "", "stderr": "stderr text", "msg": "msg text"})
    assert err == "stderr text"


def test_run_cmd_falls_back_to_msg_when_stdout_and_stderr_empty(run_cmd):
    # This is the exact failure mode from #27844: a missing binary leaves stdout/stderr
    # empty and only sets 'msg'; run_cmd must surface it instead of raising with ''.
    err = _run_cmd_with_results(
        run_cmd, {"stdout": "", "stderr": "", "msg": "[Errno 2] No such file or directory: 'ntpdate'"})
    assert err == "[Errno 2] No such file or directory: 'ntpdate'"


def test_run_cmd_tolerates_missing_msg_key(run_cmd):
    # Not every Ansible module failure sets 'msg'; must not raise KeyError.
    err = _run_cmd_with_results(run_cmd, {"stdout": "", "stderr": ""})
    assert err == ""
