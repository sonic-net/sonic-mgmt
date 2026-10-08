"""Regression tests for the power-off reboot PSU precheck."""

import json

import pytest

from tests.platform_tests import test_power_off_reboot


pytestmark = [pytest.mark.topology("any")]


class _FakeDut:
    def __init__(self, entries=None, rc=0, stdout=None):
        self.entries = entries or []
        self.rc = rc
        self.stdout = stdout
        self.commands = []

    def command(self, command, module_ignore_errors=False):
        self.commands.append((command, module_ignore_errors))
        return {
            "rc": self.rc,
            "stdout": self.stdout if self.stdout is not None else json.dumps(self.entries),
        }


def _pdu(watts, outlet_on=True):
    return {"outlet_on": outlet_on, "output_watts": watts}


def test_positive_pdu_watts_do_not_query_dut():
    dut = _FakeDut()

    status = test_power_off_reboot._validate_psu_power(dut, "PSU1", [_pdu("18.2")])

    assert status is None
    assert dut.commands == []


def test_zero_pdu_watts_accept_present_healthy_dut_psu():
    dut = _FakeDut([
        {"name": "PSU 1", "presence": True, "status": "OK"},
        {"name": "PSU 2", "presence": "true", "status": "OK"},
    ])

    status = test_power_off_reboot._validate_psu_power(dut, "PSU2", [_pdu("0")])

    assert status["psu2"]["status"] == "OK"
    assert dut.commands == [(test_power_off_reboot.PSU_STATUS_CMD, True)]


def test_zero_pdu_watts_reject_unhealthy_dut_psu():
    dut = _FakeDut([{"name": "PSU2", "presence": True, "status": "NOT OK"}])

    with pytest.raises(pytest.fail.Exception, match="presence=True status=NOT OK"):
        test_power_off_reboot._validate_psu_power(dut, "PSU2", [_pdu("0")])


def test_powered_off_outlet_is_rejected_even_with_positive_watts():
    dut = _FakeDut()

    with pytest.raises(pytest.fail.Exception, match="No mapped PDU outlet is ON"):
        test_power_off_reboot._validate_psu_power(dut, "PSU1", [_pdu("18", outlet_on=False)])


def test_powered_off_meter_does_not_mask_zero_watts_on_active_outlet():
    dut = _FakeDut([{"name": "PSU1", "presence": True, "status": "NOT OK"}])

    with pytest.raises(pytest.fail.Exception, match="presence=True status=NOT OK"):
        test_power_off_reboot._validate_psu_power(
            dut,
            "PSU1",
            [_pdu("18", outlet_on=False), _pdu("0", outlet_on=True)],
        )


def test_invalid_pdu_watts_are_rejected():
    dut = _FakeDut()

    with pytest.raises(pytest.fail.Exception, match="Invalid PDU output_watts"):
        test_power_off_reboot._validate_psu_power(dut, "PSU1", [_pdu("not-a-number")])


def test_malformed_dut_psu_json_is_rejected():
    dut = _FakeDut(stdout="not-json")

    with pytest.raises(pytest.fail.Exception, match="Failed to parse"):
        test_power_off_reboot._validate_psu_power(dut, "PSU1", [_pdu("0")])
