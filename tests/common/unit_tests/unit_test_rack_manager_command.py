"""Offline regressions for the RACK_MANAGER_COMMAND helpers in bmc_utils.

Run with python3 -m pytest --noconftest --confcutdir=tests/common/unit_tests \
    tests/common/unit_tests/unit_test_rack_manager_command.py -v
"""

import ast
import fnmatch
import logging
import re
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest


COMMON_DIR = Path(__file__).resolve().parents[1]
STATE_DB = "STATE_DB"
HELPERS = ["rack_manager_command_keys", "_wait_until_or_raise", "wait_for_rack_manager_command",
           "wait_for_no_new_rack_manager_command"]


def _load(path, names, namespace):
    # Pull module-level constants and the named functions without importing the
    # module, which drags in Ansible/paramiko testbed dependencies.
    tree = ast.parse(path.read_text())
    nodes = [node for node in tree.body
             if (isinstance(node, ast.FunctionDef) and node.name in names)
             or (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id.startswith("RACK_MANAGER_COMMAND_"))]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)


def _assert(condition, message):
    if not condition:
        pytest.fail(message)


class FakeStateDb:
    """STATE_DB rows plus rows that appear, or KEYS failures, on a given poll."""

    def __init__(self, rows=None):
        self.rows = dict(rows or {})
        self.pending = []
        self.failures = {}
        self.polls = 0

    def publish_on_poll(self, poll, key, command):
        self.pending.append((poll, key, command))

    def fail_on_poll(self, poll, failure):
        # failure is a shell result dict to return, or an exception to raise.
        self.failures[poll] = failure

    def shell(self, cmd, module_ignore_errors=False):
        # Same shape as the Ansible shell module result on a SonicHost.
        assert module_ignore_errors
        match = re.fullmatch(r"sonic-db-cli (\S+) KEYS '(.+)'", cmd)
        assert match and match.group(1) == STATE_DB, cmd
        self.polls += 1
        failure = self.failures.get(self.polls)
        if isinstance(failure, BaseException):
            raise failure
        if failure is not None:
            return failure
        for poll, key, command in [p for p in self.pending if p[0] <= self.polls]:
            self.rows[key] = {"command": command}
            self.pending.remove((poll, key, command))
        keys = [key for key in self.rows if fnmatch.fnmatchcase(key, match.group(2))]
        return {"rc": 0, "failed": False, "stdout": "\n".join(keys), "stderr": ""}

    def hget(self, duthost, db, key, field):
        return self.rows.get(key, {}).get(field, "")


@pytest.fixture
def helpers():
    clock = SimpleNamespace(now=0.0)

    def advance(seconds):
        clock.now += seconds

    db = FakeStateDb()
    namespace = {
        "logger": logging.getLogger(__name__), "pytest": pytest, "sys": sys, "traceback": traceback,
        "time": SimpleNamespace(time=lambda: clock.now, sleep=advance),
        "STATE_DB": STATE_DB, "redis_hget": db.hget, "pytest_assert": _assert,
    }
    _load(COMMON_DIR / "utilities.py", ["wait_until"], namespace)
    _load(COMMON_DIR / "platform" / "bmc_utils.py", HELPERS, namespace)
    namespace["db"] = db
    namespace["dut"] = SimpleNamespace(shell=db.shell)
    namespace["clock"] = clock
    return SimpleNamespace(**namespace)


def test_status_helper_removed():
    tree = ast.parse((COMMON_DIR / "platform" / "bmc_utils.py").read_text())
    names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert "wait_for_rack_manager_command_status" not in names
    assert set(HELPERS) <= names


def test_default_windows(helpers):
    assert helpers.RACK_MANAGER_COMMAND_PUBLISH_TIMEOUT == 120
    assert helpers.RACK_MANAGER_COMMAND_ABSENCE_WINDOW == 5
    assert helpers.RACK_MANAGER_COMMAND_TABLE == "RACK_MANAGER_COMMAND"


def test_keys_snapshot_ignores_other_tables(helpers):
    helpers.db.rows = {"RACK_MANAGER_COMMAND|CMD_1": {"command": "POWER_ON"},
                       "HOST_STATE|switch-host": {"device_power_state": "POWER_ON"}}
    assert helpers.rack_manager_command_keys(helpers.dut) == {"RACK_MANAGER_COMMAND|CMD_1"}


def test_match_skips_unrelated_new_rows_and_preexisting_match(helpers):
    helpers.db.rows = {"RACK_MANAGER_COMMAND|CMD_1": {"command": "GRACEFUL_SHUT"}}
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)
    helpers.db.rows["RACK_MANAGER_COMMAND|CMD_2"] = {"command": "POWER_ON"}
    helpers.db.rows["RACK_MANAGER_COMMAND|CMD_3"] = {"command": "GRACEFUL_SHUT"}

    key = helpers.wait_for_rack_manager_command(helpers.dut, pre_keys, "GRACEFUL_SHUT")

    assert key == "RACK_MANAGER_COMMAND|CMD_3"


def test_match_waits_for_serialized_publish(helpers):
    # The bridge holds a request until the previous command finishes, so the
    # row can land well after the POST returned.
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)
    helpers.db.publish_on_poll(helpers.db.polls + 60, "RACK_MANAGER_COMMAND|CMD_7", "POWER_CYCLE")

    key = helpers.wait_for_rack_manager_command(helpers.dut, pre_keys, "POWER_CYCLE")

    assert key == "RACK_MANAGER_COMMAND|CMD_7"
    assert 0 < helpers.clock.now < helpers.RACK_MANAGER_COMMAND_PUBLISH_TIMEOUT


def test_match_times_out_when_only_other_commands_appear(helpers):
    helpers.db.rows = {"RACK_MANAGER_COMMAND|CMD_1": {"command": "POWER_ON"}}
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)
    helpers.db.rows["RACK_MANAGER_COMMAND|CMD_2"] = {"command": "POWER_OFF"}

    key = helpers.wait_for_rack_manager_command(helpers.dut, pre_keys, "POWER_ON", timeout=10)

    assert key is None
    assert helpers.clock.now >= 10


def test_no_new_row_holds_for_window(helpers):
    helpers.db.rows = {"RACK_MANAGER_COMMAND|CMD_1": {"command": "POWER_ON"}}
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)

    assert helpers.wait_for_no_new_rack_manager_command(helpers.dut, pre_keys) is True
    assert helpers.clock.now >= helpers.RACK_MANAGER_COMMAND_ABSENCE_WINDOW


def test_no_new_row_detects_any_new_row(helpers):
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)
    helpers.db.publish_on_poll(helpers.db.polls + 3, "RACK_MANAGER_COMMAND|CMD_9", "POWER_CYCLE")

    assert helpers.wait_for_no_new_rack_manager_command(helpers.dut, pre_keys) is False


KEYS_FAILED = {"rc": 1, "failed": True, "stdout": "", "stderr": "Connection refused"}


def test_successful_empty_keys_is_valid(helpers):
    assert helpers.rack_manager_command_keys(helpers.dut) == set()
    assert helpers.wait_for_no_new_rack_manager_command(helpers.dut, set()) is True


def test_failed_keys_snapshot_raises(helpers):
    # An empty pre-snapshot would make every existing row look new.
    helpers.db.rows = {"RACK_MANAGER_COMMAND|CMD_1": {"command": "POWER_ON"}}
    helpers.db.fail_on_poll(1, KEYS_FAILED)

    with pytest.raises(pytest.fail.Exception, match="Connection refused"):
        helpers.rack_manager_command_keys(helpers.dut)


def test_failed_keys_does_not_pass_negative(helpers):
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)
    helpers.db.fail_on_poll(helpers.db.polls + 2, KEYS_FAILED)

    with pytest.raises(pytest.fail.Exception, match="rc=1"):
        helpers.wait_for_no_new_rack_manager_command(helpers.dut, pre_keys)


def test_polling_exception_does_not_pass_negative(helpers):
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)
    helpers.db.fail_on_poll(helpers.db.polls + 1, RuntimeError("ssh dropped"))

    with pytest.raises(RuntimeError, match="ssh dropped"):
        helpers.wait_for_no_new_rack_manager_command(helpers.dut, pre_keys)


def test_failed_keys_during_positive_poll_raises(helpers):
    pre_keys = helpers.rack_manager_command_keys(helpers.dut)
    helpers.db.fail_on_poll(helpers.db.polls + 1, KEYS_FAILED)
    helpers.db.publish_on_poll(helpers.db.polls + 2, "RACK_MANAGER_COMMAND|CMD_5", "POWER_ON")

    with pytest.raises(pytest.fail.Exception, match="rc=1"):
        helpers.wait_for_rack_manager_command(helpers.dut, pre_keys, "POWER_ON")
