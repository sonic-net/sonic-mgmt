"""Offline checks for service restoration; NTP synchronization needs a DUT."""

import importlib.util
from pathlib import Path
import sys
import types
from unittest.mock import Mock, patch

import pytest


def _load_helper():
    utilities = types.ModuleType("tests.common.utilities")
    utilities.wait_until = Mock(return_value=True)
    assertions = types.ModuleType("tests.common.helpers.assertions")
    assertions.pytest_assert = lambda condition, message: (
        None if condition else pytest.fail(message)
    )
    path = Path(__file__).resolve().parents[2] / "helpers" / "ntp_helper.py"
    spec = importlib.util.spec_from_file_location("ntp_lifecycle_helper", path)
    helper = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {
        "tests.common.utilities": utilities,
        "tests.common.helpers.assertions": assertions,
    }):
        spec.loader.exec_module(helper)
    return helper


def test_chrony_restored_after_one_shot_command_fails():
    helper = _load_helper()
    failure = RuntimeError("one-shot command failed")
    dut = Mock()
    dut.command.side_effect = failure

    with pytest.raises(RuntimeError) as raised:
        helper.run_ntp(dut, helper.NtpDaemon.CHRONY)

    assert raised.value is failure
    dut.service.assert_called_with(name="chrony", state="restarted")
    assert helper.wait_until.call_count == 0


def test_chrony_restored_before_sync_status_check():
    helper = _load_helper()
    dut = Mock()

    def check_sync(*args):
        dut.service.assert_called_with(name="chrony", state="restarted")
        return False

    helper.wait_until.side_effect = check_sync

    with pytest.raises(pytest.fail.Exception, match="NTP not in sync"):
        helper.run_ntp(dut, helper.NtpDaemon.CHRONY)


def test_one_shot_does_not_run_after_native_service_start_fails():
    helper = _load_helper()
    failure = RuntimeError("native service startup failed")
    dut = Mock()

    def service(**kwargs):
        if kwargs["state"] == "restarted":
            raise failure

    dut.service.side_effect = service

    with pytest.raises(RuntimeError) as raised:
        helper.run_ntp(dut, helper.NtpDaemon.CHRONY)

    assert raised.value is failure
    dut.command.assert_not_called()
