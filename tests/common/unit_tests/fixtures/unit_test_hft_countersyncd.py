"""Unit coverage of countersyncd container selection and process control.

Run with python3 -m pytest --noconftest <this file> -v.
"""

import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def utilities(monkeypatch):
    def pytest_assert(condition, message):
        assert condition, message

    stubs = {
        name: types.ModuleType(name) for name in (
            "ptf", "ptf.testutils", "natsort", "tests.common.utilities",
            "tests.common.helpers.assertions",
        )
    }
    stubs["natsort"].natsorted = sorted
    stubs["tests.common.utilities"].wait_until = (
        lambda timeout, interval, delay, func, *args: func(*args)
    )
    stubs["tests.common.helpers.assertions"].pytest_assert = pytest_assert
    for name, module in stubs.items():
        monkeypatch.setitem(sys.modules, name, module)
    path = Path(__file__).resolve().parents[3] / "high_frequency_telemetry" / "utilities.py"
    spec = importlib.util.spec_from_file_location("unit_target_hft_utilities", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("exists,container", [("0", "swss"), ("1", "hft")])
def test_container_selected_by_feature_not_running_state(utilities, exists, container):
    dut = MagicMock()
    dut.shell.return_value = {"rc": 0, "stdout": exists}
    assert utilities.get_countersyncd_container(dut) == container
    dut.shell.assert_called_once_with(
        "sonic-db-cli CONFIG_DB EXISTS 'FEATURE|hft'", module_ignore_errors=False,
    )


def test_invalid_feature_probe_does_not_fall_back_to_swss(utilities):
    dut = MagicMock()
    dut.shell.return_value = {"rc": 0, "stdout": "unexpected"}
    with pytest.raises(AssertionError, match="Invalid HFT feature probe"):
        utilities.get_countersyncd_container(dut)


@pytest.mark.parametrize("container", ["swss", "hft"])
def test_verify_supervisor_and_actual_process_in_selected_container(utilities, container):
    dut = MagicMock()
    dut.shell.side_effect = [
        {"rc": 0, "stdout": "countersyncd RUNNING pid 42, uptime 0:01:00"},
        {"rc": 0, "stdout": "/usr/bin/countersyncd --enable-otel --otel-endpoint=http://localhost:4317"},
    ]
    assert utilities.ensure_countersyncd_daemon(dut, container)
    commands = [call.args[0] for call in dut.shell.call_args_list]
    assert all(command.startswith(f"docker exec {container} ") for command in commands)
    assert "/proc/$pid/cmdline" in commands[1]


@pytest.mark.parametrize("command", ["/usr/bin/countersyncd", "/usr/bin/countersyncd --enable-otel-invalid"])
def test_verify_rejects_missing_otel_flag(utilities, command):
    dut = MagicMock()
    dut.shell.side_effect = [
        {"rc": 0, "stdout": "countersyncd RUNNING pid 42"},
        {"rc": 0, "stdout": command},
    ]
    with pytest.raises(AssertionError, match="must use --enable-otel"):
        utilities.ensure_countersyncd_daemon(dut, "hft")


def test_stopped_hft_does_not_probe_swss(utilities):
    dut = MagicMock()
    dut.shell.side_effect = [
        {"rc": 0, "stdout": "1"},
        {"rc": 1, "stdout": "", "stderr": "container hft is not running"},
    ]
    with pytest.raises(AssertionError, match="RUNNING"):
        utilities.ensure_countersyncd_daemon(dut)
    assert not any("swss" in call.args[0] for call in dut.shell.call_args_list)


@pytest.mark.parametrize("container,exists", [("swss", "0"), ("hft", "1")])
def test_restart_only_selected_supervisor_process(utilities, container, exists):
    dut = MagicMock()
    pid = 42

    def shell(command, **kwargs):
        nonlocal pid
        if "EXISTS" in command:
            return {"rc": 0, "stdout": exists}
        assert command.startswith(f"docker exec {container} ")
        if "restart countersyncd" in command:
            pid = 43
        if "status countersyncd" in command:
            return {"rc": 0, "stdout": f"countersyncd RUNNING pid {pid}"}
        if "supervisorctl pid countersyncd" in command and "sh -c" not in command:
            return {"rc": 0, "stdout": str(pid)}
        return {"rc": 0, "stdout": "/usr/bin/countersyncd --enable-otel"}

    dut.shell.side_effect = shell
    assert utilities.restart_countersyncd_daemon(dut) == (42, 43)
    dut.shell.assert_any_call(
        f"docker exec {container} supervisorctl restart countersyncd", module_ignore_errors=True,
    )
