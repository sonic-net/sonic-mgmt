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
        "get_available_ports",
        "get_configured_buffer_pools",
        "get_configured_buffer_queue_objects",
        "get_configured_queue_objects",
        "get_running_countersyncd_pid",
        "is_otel_image_available",
        "render_otel_collector_config",
        "restart_countersyncd_daemon",
        "restart_otel_service",
        "setup_influxdb",
        "start_influxdb",
        "stop_owned_influxdb",
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


@pytest.mark.parametrize("output,expected", [
    ("1234:running", ("1234", "running")),
    ("1234:exited", ("1234", "exited")),
    ("1234:paused", ("1234", "paused")),
    ("1234:restarting", ("1234", "restarting")),
    ("", (None, "absent")),
])
def test_otel_container_status_recognizes_explicit_results(
        hft_conftest, output, expected):
    duthost = MagicMock()
    duthost.shell.return_value = {"stdout": output}
    assert tuple(hft_conftest._otel_container(duthost)) == expected


def test_otel_container_status_rejects_probe_errors(hft_conftest):
    duthost = MagicMock()
    duthost.shell.side_effect = RuntimeError("Cannot connect to the Docker daemon")
    with pytest.raises(RuntimeError, match="Cannot connect"):
        hft_conftest._otel_container(duthost)


def test_multi_asic_gate_precedes_transaction(hft_conftest, monkeypatch):
    dut = MagicMock(is_multi_asic=True)
    claim = MagicMock()
    monkeypatch.setattr(hft_conftest.transaction, "claim", claim)
    with pytest.raises(pytest.skip.Exception, match="single ASIC"):
        next(hft_conftest.skip_unsupported_hft_platform.__wrapped__(MagicMock(), {"dut": dut}, "dut"))
    claim.assert_not_called()
    dut.command.assert_not_called()


@pytest.mark.parametrize("pending", [False, True])
def test_down_port_case_recovers_only_a_pending_transaction(hft_conftest, monkeypatch, pending):
    dut = MagicMock(is_multi_asic=False)
    dut.interface_facts.return_value = {"ansible_facts": {"ansible_interface_link_down_ports": ["Ethernet0"]}}
    req = MagicMock()
    req.node.get_closest_marker.return_value = types.SimpleNamespace(
        args=(hft_conftest.CounterObjectType.PORT,), kwargs={"oper_up_port": True})
    monkeypatch.setattr(hft_conftest.transaction, "active_work", lambda host: object() if pending else None)
    events = []
    req.getfixturevalue.side_effect = events.append

    def ports(*args, **kwargs):
        events.append("check ports")
        return ["Ethernet0"]

    monkeypatch.setattr(hft_conftest, "get_available_ports", ports)
    monkeypatch.setattr(hft_conftest, "get_support_counter_list", lambda *a: ["IF_IN_OCTETS"])
    with pytest.raises(pytest.skip.Exception, match="No operationally up"):
        hft_conftest.skip_unsupported_hft_test.__wrapped__(req, {"dut": dut}, "dut", {})
    assert events == (["skip_unsupported_hft_platform"] if pending else []) + ["check ports"]


def test_profile_cleanup_failure_keeps_original_exporters_isolated(hft_conftest):
    tx = MagicMock()
    tx.load.return_value = {"ptf_ip": "127.0.0.1"}

    def call(action, *args):
        if action == "clean-profiles":
            raise RuntimeError("profile conflict")
        return ""

    tx.call.side_effect = call
    with pytest.raises(RuntimeError, match="profile conflict"):
        hft_conftest._recover_transaction(tx, MagicMock())
    calls = [c.args[0] for c in tx.call.call_args_list]
    assert "restore" not in calls and "restore-otel" not in calls and "finish" not in calls


@pytest.mark.parametrize("masked", ["otel", "hft"])
def test_masked_enabled_unit_skips_before_setup(hft_conftest, monkeypatch, masked):
    dut = MagicMock()

    def read(argv):
        return {"stdout": "masked-runtime" if masked + ".service" in argv else ""}

    dut.command.side_effect = read
    monkeypatch.setattr(hft_conftest, "_supported_hft_state", lambda _: "enabled")
    monkeypatch.setattr(hft_conftest, "_read_feature", lambda *a: {"state": "enabled"})
    with pytest.raises(pytest.skip.Exception, match=f"Enabled {masked} unit is masked"):
        hft_conftest._snapshot_platform(dut, MagicMock())
    dut.shell.assert_not_called()


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
