"""Unit tests for HFT fixture lifecycle helpers.

Run with::

    python3 -m pytest --noconftest \
        tests/common/unit_tests/fixtures/unit_test_hft_conftest.py -v
"""

import base64
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
        "get_countersyncd_container",
        "install_otel_collector_config",
        "is_otel_image_available",
        "render_otel_collector_config",
        "restart_countersyncd_daemon",
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
    with pytest.raises(AssertionError):
        hft_conftest._get_otel_container_running(duthost)


@pytest.mark.parametrize("status", [
    {"rc": 4, "stdout": "", "stderr": "connection failed"},
    {"rc": 0, "stdout": "otel STARTING", "stderr": ""},
    {"rc": 0, "stdout": "otel STOPPED", "stderr": ""},
    {"rc": 0, "stdout": "malformed", "stderr": ""},
    {"rc": 3, "stdout": "otel RUNNING", "stderr": ""},
])
def test_collector_status_rejects_unknown_results(hft_conftest, status):
    with pytest.raises(AssertionError):
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


@pytest.fixture
def hft_duthost(hft_conftest, monkeypatch):
    duthost = MagicMock()
    duthost.original_state = "disabled"
    duthost.running = False
    duthost.stat.return_value = {"stat": {"exists": True, "mode": "0640"}}
    duthost.slurp.return_value = {
        "content": base64.b64encode(b"# original\nCOUNTERSYNCD_LOG_LEVEL=debug\n").decode(),
    }

    def shell(command, **kwargs):
        if "HGETALL" in command:
            return {"stdout_lines": ["state", duthost.original_state, "auto_restart", "enabled"]}
        if "HKEYS" in command:
            return {"stdout_lines": ["state", "auto_restart", "new_field"]}
        if "feature state hft enabled" in command:
            duthost.running = True
        if "feature state hft disabled" in command:
            duthost.running = False
        return {"rc": 0, "stdout": ""}

    duthost.shell.side_effect = shell
    monkeypatch.setattr(hft_conftest, "get_countersyncd_container", lambda dut: "hft")
    monkeypatch.setattr(hft_conftest, "_get_container_running", lambda dut, name: dut.running)
    monkeypatch.setattr(hft_conftest, "ensure_countersyncd_daemon", MagicMock(return_value=True))
    monkeypatch.setattr(hft_conftest, "wait_until", lambda timeout, interval, delay, func, *args: func(*args))
    return duthost


@pytest.mark.parametrize("state", ["disabled", "enabled", "always_enabled"])
def test_standalone_hft_config_and_state_restored(hft_conftest, hft_duthost, state):
    dut = hft_duthost
    dut.original_state = state
    dut.running = state != "disabled"
    with hft_conftest._configured_countersyncd(dut):
        content = dut.copy.call_args.kwargs["content"]
        assert "COUNTERSYNCD_LOG_LEVEL=debug" in content
        assert "COUNTERSYNCD_ENABLE_OTEL=true" in content
        assert "COUNTERSYNCD_OTEL_ENDPOINT=http://localhost:4317" in content
        assert dut.running

    assert dut.copy.call_args.kwargs == {
        "content": "# original\nCOUNTERSYNCD_LOG_LEVEL=debug\n",
        "dest": hft_conftest.HFT_CONFIG_PATH, "mode": "0640",
    }
    assert dut.running == (state != "disabled")
    commands = [call.args[0] for call in dut.shell.call_args_list]
    assert "redis-cli -n 4 HDEL 'FEATURE|hft' new_field" in commands
    assert f"redis-cli -n 4 HSET 'FEATURE|hft' state {state} auto_restart enabled" in commands
    assert not any("docker exec swss" in command for command in commands)


def test_hft_restored_after_setup_failure(hft_conftest, hft_duthost, monkeypatch):
    monkeypatch.setattr(hft_conftest, "ensure_countersyncd_daemon",
                        MagicMock(side_effect=RuntimeError("export not enabled")))
    with pytest.raises(RuntimeError, match="export not enabled"):
        with hft_conftest._configured_countersyncd(hft_duthost):
            pytest.fail("must not yield")
    assert not hft_duthost.running
    assert hft_duthost.copy.call_args.kwargs["content"].startswith("# original\n")


def test_hft_restored_after_test_failure(hft_conftest, hft_duthost):
    with pytest.raises(RuntimeError, match="test failed"):
        with hft_conftest._configured_countersyncd(hft_duthost):
            raise RuntimeError("test failed")
    assert not hft_duthost.running
    assert hft_duthost.copy.call_args.kwargs["content"] == "# original\nCOUNTERSYNCD_LOG_LEVEL=debug\n"


def test_hft_cleanup_continues_if_config_restore_fails(hft_conftest, hft_duthost, monkeypatch):
    hft_duthost.copy.side_effect = [None, RuntimeError("restore failed")]
    monkeypatch.setattr(hft_conftest.logger, "exception", MagicMock())
    with pytest.raises(RuntimeError, match="restore failed"):
        with hft_conftest._configured_countersyncd(hft_duthost):
            pass
    assert not hft_duthost.running
    assert "HSET 'FEATURE|hft'" in hft_duthost.shell.call_args.args[0]


def test_hft_cleanup_does_not_mask_active_failure(hft_conftest, hft_duthost, monkeypatch):
    hft_duthost.copy.side_effect = [None, RuntimeError("restore failed")]
    monkeypatch.setattr(hft_conftest.logger, "exception", MagicMock())
    with pytest.raises(RuntimeError, match="test failed"):
        with hft_conftest._configured_countersyncd(hft_duthost):
            raise RuntimeError("test failed")
    assert not hft_duthost.running


def test_hft_created_config_removed(hft_conftest, hft_duthost):
    hft_duthost.stat.return_value = {"stat": {"exists": False}}
    with hft_conftest._configured_countersyncd(hft_duthost):
        pass
    hft_duthost.shell.assert_any_call(
        f"sudo rm -f {hft_conftest.HFT_CONFIG_PATH}", module_ignore_errors=False,
    )


def test_hft_test_settings_precede_existing_disabled_settings(hft_conftest, hft_duthost):
    original = "COUNTERSYNCD_ENABLE_OTEL=false\nCOUNTERSYNCD_OTEL_ENDPOINT=http://other:4317\n"
    hft_duthost.slurp.return_value = {"content": base64.b64encode(original.encode()).decode()}
    with hft_conftest._configured_countersyncd(hft_duthost):
        content = hft_duthost.copy.call_args.kwargs["content"]
        assert content.startswith("COUNTERSYNCD_ENABLE_OTEL=true\n"
                                  "COUNTERSYNCD_OTEL_ENDPOINT=http://localhost:4317\n")
        assert content.endswith(original)
    assert hft_duthost.copy.call_args.kwargs["content"] == original


def test_hft_always_disabled_skips_without_mutation(hft_conftest, hft_duthost):
    hft_duthost.original_state = "always_disabled"
    with pytest.raises(pytest.skip.Exception):
        with hft_conftest._configured_countersyncd(hft_duthost):
            pytest.fail("must not yield")
    hft_duthost.copy.assert_not_called()


def test_hft_enabled_but_stopped_fails_without_mutation(hft_conftest, hft_duthost):
    hft_duthost.original_state = "enabled"
    with pytest.raises(pytest.fail.Exception, match="not running"):
        with hft_conftest._configured_countersyncd(hft_duthost):
            pytest.fail("must not yield")
    hft_duthost.copy.assert_not_called()


def test_legacy_countersyncd_is_not_reconfigured(hft_conftest, monkeypatch):
    dut = MagicMock()
    verify = MagicMock()
    monkeypatch.setattr(hft_conftest, "get_countersyncd_container", lambda dut: "swss")
    monkeypatch.setattr(hft_conftest, "ensure_countersyncd_daemon", verify)
    with hft_conftest._configured_countersyncd(dut):
        pass
    verify.assert_called_once_with(dut)
    dut.shell.assert_not_called()
    dut.copy.assert_not_called()
