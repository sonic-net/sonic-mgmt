"""Exercise the power-off helper without importing testbed dependencies."""

import ast
from pathlib import Path
from unittest.mock import Mock, call

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "platform_tests" / "test_power_off_reboot.py"


@pytest.fixture
def power_off_helper():
    tree = ast.parse(MODULE_PATH.read_text())
    helper = next(node for node in tree.body
                  if isinstance(node, ast.FunctionDef) and node.name == "_power_off_reboot_helper")
    operations = Mock()
    operations.pdu.get_outlet_status.return_value = []
    namespace = {"logging": Mock(), "time": operations.clock}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), str(MODULE_PATH), "exec"), namespace)
    return namespace["_power_off_reboot_helper"], operations


@pytest.mark.parametrize("delay", [5, 15, 60, 27])
@pytest.mark.parametrize("outlet_count,power_on_indices", [
    (1, [0]),
    (2, [0]),
    (2, [1]),
    (2, [0, 1]),
    (4, [2, 3]),
])
def test_power_off_delay_precedes_every_power_on(power_off_helper, delay, outlet_count, power_on_indices):
    """Honor the requested delay after shutdown and before any outlet is restored."""
    helper, operations = power_off_helper
    outlets = [{"outlet_id": index} for index in range(outlet_count)]
    power_on_seq = [outlets[index] for index in power_on_indices]
    kwargs = {
        "pdu_ctrl": operations.pdu,
        "all_outlets": outlets,
        "power_on_seq": power_on_seq,
        "delay_time": delay,
    }

    helper(kwargs, operations.event)

    assert operations.mock_calls == (
        [call.pdu.turn_off_outlet(outlet) for outlet in outlets]
        + [call.event.wait(), call.pdu.get_outlet_status(), call.clock.sleep(delay)]
        + [call.pdu.turn_on_outlet(outlet) for outlet in power_on_seq]
        + [call.event.clear()]
    )


def test_each_cycle_uses_its_own_delay(power_off_helper):
    """Read the configured delay separately for each power cycle."""
    helper, operations = power_off_helper
    outlet = {"outlet_id": 1}
    kwargs = {"pdu_ctrl": operations.pdu, "all_outlets": [outlet], "power_on_seq": [outlet]}

    for delay in [5, 15]:
        kwargs["delay_time"] = delay
        helper(kwargs, operations.event)

    assert operations.mock_calls == [
        call.pdu.turn_off_outlet(outlet),
        call.event.wait(),
        call.pdu.get_outlet_status(),
        call.clock.sleep(5),
        call.pdu.turn_on_outlet(outlet),
        call.event.clear(),
        call.pdu.turn_off_outlet(outlet),
        call.event.wait(),
        call.pdu.get_outlet_status(),
        call.clock.sleep(15),
        call.pdu.turn_on_outlet(outlet),
        call.event.clear(),
    ]


@pytest.mark.parametrize("failure_point", ["shutdown", "delay"])
def test_failed_wait_does_not_power_on(power_off_helper, failure_point):
    """Do not restore outlets or clear the event if a required wait fails."""
    helper, operations = power_off_helper
    outlet = {"outlet_id": 1}
    kwargs = {
        "pdu_ctrl": operations.pdu,
        "all_outlets": [outlet],
        "power_on_seq": [outlet],
        "delay_time": 15,
    }
    wait = operations.event.wait if failure_point == "shutdown" else operations.clock.sleep
    wait.side_effect = RuntimeError("wait interrupted")

    with pytest.raises(RuntimeError, match="wait interrupted"):
        helper(kwargs, operations.event)

    operations.pdu.turn_on_outlet.assert_not_called()
    operations.event.clear.assert_not_called()
    if failure_point == "shutdown":
        operations.clock.sleep.assert_not_called()


def test_missing_delay_fails_before_cutting_power(power_off_helper):
    """Reject an incomplete helper request before changing outlet state."""
    helper, operations = power_off_helper
    outlet = {"outlet_id": 1}
    kwargs = {"pdu_ctrl": operations.pdu, "all_outlets": [outlet], "power_on_seq": [outlet]}

    with pytest.raises(KeyError, match="delay_time"):
        helper(kwargs, operations.event)

    assert operations.mock_calls == []
