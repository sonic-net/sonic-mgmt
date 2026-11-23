"""Unit tests for HFT fixture lifecycle helpers.

Run with::

    python3 -m pytest --noconftest \
        tests/common/unit_tests/fixtures/unit_test_hft_conftest.py -v
"""

import importlib.util
import json
import sys
import types
from enum import Enum
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from _pytest.outcomes import OutcomeException


pytest_plugins = ["pytester"]
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


def _baseline(state="enabled"):
    return {"hft_state": state, "original_config": "original collector config", "original_state": state,
            "original_collector_running": state == "enabled", "otel_feature_existed": True}


@pytest.fixture
def lifecycle(hft_conftest, monkeypatch):
    dut, ptf, files = MagicMock(), MagicMock(), {}

    def copy(dest, content, force=True, **kwargs):
        if not force and dest in files:
            return {"changed": False}
        files[dest] = content
        return {"changed": True}

    dut.copy.side_effect = copy
    dut.file.side_effect = lambda path, state: files.pop(path, None) if state == "absent" else None
    monkeypatch.setattr(hft_conftest, "_read_config", lambda host, path: files.get(path))
    monkeypatch.setattr(hft_conftest, "start_influxdb", ptf.start)
    monkeypatch.setattr(hft_conftest, "stop_influxdb", ptf.stop)
    return hft_conftest, dut, ptf, files


@pytest.fixture
def dut_actions(hft_conftest, monkeypatch):
    """Record mutations: restoring the same feature state still disrupts the original process."""
    actions = MagicMock()
    for name in ("_remove_hft_container", "_start_test_hft", "cleanup_hft_config", "_restore_hft_feature",
                 "_restore_otel", "enable_otel_collector", "stop_otel_collector"):
        monkeypatch.setattr(hft_conftest, name, getattr(actions, name))
    return actions


@pytest.mark.parametrize("failure", ["port 8181 in use", "unhealthy sink", "full baseline write", "lost copy reply"])
def test_failed_admission_preserves_original_hft_profile_and_collector(
        lifecycle, dut_actions, failure):
    hft, dut, ptf, files = lifecycle
    baseline = _baseline()
    files[hft.OTEL_CONFIG_PATH] = baseline["original_config"]
    error = pytest.fail.Exception(failure) if failure == "port 8181 in use" else RuntimeError(failure)
    save = dut.copy.side_effect

    def publish(dest, content, **kwargs):
        assert dest == hft.OTEL_BASELINE
        if json.loads(content).get("sink_only"):
            return save(dest, content, **kwargs)
        assert json.loads(content) == baseline
        if failure == "lost copy reply":
            save(dest, content, **kwargs)
        raise error

    def start(host, port):
        assert host is ptf and port == 8181
        assert json.loads(files[hft.OTEL_BASELINE]).get("sink_only")
        if failure in ("port 8181 in use", "unhealthy sink"):
            raise error
        return 123

    dut.copy.side_effect = publish
    ptf.start.side_effect = start
    hosts = {"dut": dut}
    services = hft.hft_test_services.__wrapped__(ptf, hosts, "dut", baseline)
    request = MagicMock()
    request.getfixturevalue.side_effect = lambda name: next(services) if name == "hft_test_services" else None
    with pytest.raises(type(error)) as caught:
        next(hft.hft_influxdb.__wrapped__(request, ptf, {}, hosts, "dut", {}))
    assert caught.value is error
    assert not dut_actions.mock_calls
    assert files == {hft.OTEL_CONFIG_PATH: baseline["original_config"]}
    expected_pid = 123 if failure in ("full baseline write", "lost copy reply") else None
    ptf.stop.assert_called_once_with(ptf, expected_pid)


@pytest.mark.parametrize("failure", ["disable failed", "session still present"])
def test_remaining_session_stops_test_resources_without_reconnecting(lifecycle, dut_actions, monkeypatch, failure):
    hft, dut, ptf, files = lifecycle
    baseline = _baseline()
    files[hft.OTEL_BASELINE] = json.dumps(baseline)
    if failure == "disable failed":
        dut_actions.cleanup_hft_config.side_effect = pytest.fail.Exception(failure)
    # Even when CONFIG_DB cleanup succeeds, a surviving STATE_DB session prevents reconnecting.
    dut.command.return_value = {"stdout": "HIGH_FREQUENCY_TELEMETRY_SESSION_TABLE|live|PORT"}
    monkeypatch.setattr(hft, "wait_until", lambda timeout, interval, delay, probe, *args: probe(*args))
    monkeypatch.setattr(hft.logger, "exception", MagicMock())
    with pytest.raises(pytest.fail.Exception, match="disable failed|sessions still exist"):
        hft._finish_hft_run(dut, ptf, baseline, pid=123)
    dut_actions._remove_hft_container.assert_called_once_with(dut)
    ptf.stop.assert_called_once_with(ptf, 123)
    dut_actions._restore_hft_feature.assert_not_called()
    dut_actions._restore_otel.assert_not_called()
    assert json.loads(files[hft.OTEL_BASELINE]) == baseline


def _run_unsupported_case(pytester, monkeypatch, hft, dut, ptf):
    monkeypatch.setitem(sys.modules, "unit_target_hft_conftest", hft)
    bed = types.ModuleType("unit_testbed")
    fixture = pytest.fixture(scope="module")
    bed.duthosts = fixture(lambda: {"dut": dut})
    bed.enum_rand_one_per_hwsku_hostname = fixture(lambda: "dut")
    bed.ptfhost = fixture(lambda: ptf)
    bed.tbinfo = fixture(lambda: {})
    pytester.makepyfile("""
        import pytest
        from unit_target_hft_conftest import CounterObjectType, recover_interrupted_hft, skip_unsupported_hft_test

        @pytest.mark.hft_requirements(CounterObjectType.PORT, counter="unsupported")
        def test_case(skip_unsupported_hft_test):
            pytest.fail("Unsupported case reached test body")
    """)
    monkeypatch.setenv("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    pytester.runpytest_inprocess("-q", "-o", "markers=hft_requirements", plugins=[bed]).assert_outcomes(skipped=1)


@pytest.mark.parametrize("original_hft", [None, "sink_only", "enabled", "disabled"],
                         ids=["clean", "sink_only", "enabled", "disabled"])
def test_recovery_precedes_capability_skip(lifecycle, dut_actions, monkeypatch, pytester, original_hft):
    hft, dut, ptf, files = lifecycle
    if original_hft == "sink_only":
        files[hft.OTEL_BASELINE] = json.dumps(dict(_baseline(), sink_only=True))
    elif original_hft is not None:
        baseline = _baseline(original_hft)
        ptf.start.return_value = 123
        monkeypatch.setattr(hft, "_feature_fields", MagicMock(side_effect=RuntimeError("collector probe failed")))
        dut_actions._restore_otel.side_effect = [RuntimeError("restore failed"), None]
        with pytest.raises(RuntimeError):
            next(hft.hft_test_services.__wrapped__(ptf, {"dut": dut}, "dut", baseline))
        assert json.loads(files[hft.OTEL_BASELINE]) == baseline
        dut_actions._restore_hft_feature.assert_not_called()
        dut_actions.reset_mock()
        ptf.reset_mock()

    def unsupported(host, counter_type):
        assert hft.OTEL_BASELINE not in files  # Recovery must finish before this per-case probe.
        return ()

    monkeypatch.setattr(hft, "get_support_counter_list", unsupported)
    _run_unsupported_case(pytester, monkeypatch, hft, dut, ptf)
    if original_hft is None:
        assert not dut_actions.mock_calls and not dut.method_calls and not ptf.method_calls
    elif original_hft == "sink_only":
        assert not dut_actions.mock_calls and not ptf.start.called
        ptf.stop.assert_called_once_with(ptf, None)
    else:
        assert ptf.stop.called and not ptf.start.called
        dut_actions._restore_otel.assert_called_once_with(dut, baseline)
        dut_actions._restore_hft_feature.assert_called_once_with(dut, original_hft)
