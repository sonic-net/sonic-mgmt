"""Unit tests for HFT fixture lifecycle helpers.

Run with::

    python3 -m pytest --noconftest \
        tests/common/unit_tests/fixtures/unit_test_hft_conftest.py -v
"""

import importlib.util
import sys
import types
from enum import Enum
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from _pytest.outcomes import OutcomeException


MODULE_PATH = (Path(__file__).resolve().parents[3]
               / "high_frequency_telemetry" / "conftest.py")


def _load_target_module():
    common_utilities = types.ModuleType("tests.common.utilities")
    common_utilities.wait_until = lambda *args, **kwargs: True

    counter_profiles = types.ModuleType(
        "tests.high_frequency_telemetry.counter_profiles"
    )

    class CounterObjectType(Enum):
        PORT = "port"
        BUFFER_POOL = "buffer_pool"
        INGRESS_PRIORITY_GROUP = "ingress_priority_group"
        QUEUE = "queue"

    counter_profiles.CounterObjectType = CounterObjectType
    counter_profiles.get_support_counter_list = lambda *args, **kwargs: ()

    utilities = types.ModuleType("tests.high_frequency_telemetry.utilities")
    utilities.InfluxDbSink = object
    for name in (
        "cleanup_hft_config",
        "enable_otel_collector",
        "ensure_countersyncd_daemon",
        "get_available_ports",
        "get_configured_buffer_pools",
        "get_configured_buffer_queue_objects",
        "get_configured_queue_objects",
        "install_otel_collector_config",
        "is_otel_image_available",
        "render_otel_collector_config",
        "restart_otel_service",
        "setup_influxdb",
        "start_influxdb",
        "stop_influxdb",
        "stop_otel_collector",
    ):
        setattr(utilities, name, lambda *args, **kwargs: None)

    stubs = {
        "tests.common.utilities": common_utilities,
        "tests.high_frequency_telemetry.counter_profiles": counter_profiles,
        "tests.high_frequency_telemetry.utilities": utilities,
    }
    originals = {name: sys.modules.get(name) for name in stubs}
    try:
        sys.modules.update(stubs)
        spec = importlib.util.spec_from_file_location(
            "unit_target_hft_conftest", MODULE_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in originals.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


@pytest.fixture(scope="module")
def hft_conftest():
    return _load_target_module()


@pytest.mark.parametrize("state,rc", [
    ("STOPPED", 3),
    ("EXITED", 3),
    ("FATAL", 3),
])
def test_collector_status_recognizes_explicit_stopped_states(
        hft_conftest, state, rc):
    status = {"rc": rc, "stdout": f"otel {state} details", "stderr": ""}
    assert hft_conftest._collector_running_from_status(status) is False


def test_collector_status_recognizes_running(hft_conftest):
    status = {
        "rc": 0,
        "stdout": "otel RUNNING pid 123, uptime 0:01:00",
        "stderr": "",
    }
    assert hft_conftest._collector_running_from_status(status) is True


@pytest.mark.parametrize("result,expected", [
    ({"rc": 0, "stdout": "true", "stderr": ""}, True),
    ({"rc": 0, "stdout": "false", "stderr": ""}, False),
    ({"rc": 1, "stdout": "", "stderr": "No such object: otel"}, False),
])
def test_otel_container_status_recognizes_explicit_results(
        hft_conftest, result, expected):
    duthost = MagicMock()
    duthost.shell.return_value = result
    assert hft_conftest._get_otel_container_running(duthost) is expected


def test_otel_container_status_rejects_probe_errors(hft_conftest):
    duthost = MagicMock()
    duthost.shell.return_value = {
        "rc": 1,
        "stdout": "",
        "stderr": "Cannot connect to the Docker daemon",
    }
    with pytest.raises(pytest.fail.Exception):
        hft_conftest._get_otel_container_running(duthost)


@pytest.mark.parametrize("status", [
    {"rc": 4, "stdout": "", "stderr": "connection failed"},
    {"rc": 0, "stdout": "otel STARTING", "stderr": ""},
    {"rc": 0, "stdout": "otel STOPPED", "stderr": ""},
    {"rc": 0, "stdout": "malformed", "stderr": ""},
    {"rc": 3, "stdout": "otel RUNNING", "stderr": ""},
])
def test_collector_status_rejects_unknown_results(hft_conftest, status):
    with pytest.raises(pytest.fail.Exception):
        hft_conftest._collector_running_from_status(status)


def test_cleanup_runner_attempts_all_steps_and_keeps_first_error(
        hft_conftest, monkeypatch):
    calls = []
    first_error = RuntimeError("first")

    def first_step():
        calls.append("first")
        raise first_error

    def second_step():
        calls.append("second")
        raise ValueError("second")

    def final_step():
        calls.append("final")

    log_exception = MagicMock()
    monkeypatch.setattr(hft_conftest.logger, "exception", log_exception)
    result = hft_conftest._run_cleanup_steps([
        ("first", first_step),
        ("second", second_step),
        ("final", final_step),
    ])

    assert calls == ["first", "second", "final"]
    assert result is first_error
    assert log_exception.call_count == 2


def test_cleanup_runner_captures_pytest_failures(
        hft_conftest, monkeypatch):
    calls = []

    def failing_step():
        calls.append("failing")
        pytest.fail("cleanup failed")

    def final_step():
        calls.append("final")

    monkeypatch.setattr(hft_conftest.logger, "exception", MagicMock())
    result = hft_conftest._run_cleanup_steps([
        ("failing", failing_step),
        ("final", final_step),
    ])

    assert calls == ["failing", "final"]
    assert isinstance(result, OutcomeException)
