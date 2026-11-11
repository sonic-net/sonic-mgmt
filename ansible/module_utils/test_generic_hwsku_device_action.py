"""Offline regressions for the native SONiC action boundary and recovery bytes."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace

import pytest


PATH = Path(__file__).resolve().parents[1] / "library/generic_hwsku_device_action.py"
SPEC = importlib.util.spec_from_file_location("generic_hwsku_device_action", PATH)
action = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(action)


@pytest.fixture
def device(tmp_path, monkeypatch):
    baseline = {"DEVICE_METADATA": {"localhost": {"platform": "synthetic-platform", "hwsku": "Base"}},
                "PORT": {"Ethernet9": {"speed": "100000"}}}
    startup_bytes = (json.dumps(dict(baseline, ORIGINAL_STARTUP={"value": "distinct"}), indent=2) + "\n").encode()
    startup = tmp_path / "config_db.json"
    startup.write_bytes(startup_bytes)
    candidate = copy.deepcopy(baseline)
    candidate["PORT"] = {"Ethernet7": {"speed": "100000", "subport": "2"}}
    request = {
        "baseline": {"running": copy.deepcopy(baseline), "startup": action.startup_snapshot(startup)},
        "candidates": {"add": candidate},
    }
    source = tmp_path / "installed-source.json"
    source.write_text("{}")
    request["source_sha256"] = {str(source): hashlib.sha256(source.read_bytes()).hexdigest()}
    directory = tmp_path / "private"
    directory.mkdir()
    state = {"running": copy.deepcopy(baseline), "reloads": 0,
             "native_reload": action.reload_config, "reload_logs": []}
    monkeypatch.setattr(action, "read_running", lambda: copy.deepcopy(state["running"]))
    monkeypatch.setattr(action, "validate_config", lambda config, original: None)
    monkeypatch.setattr(action.os, "chown", lambda *args: None, raising=False)

    def reload_config(path, log_path, verify_before_reload=None):
        if verify_before_reload:
            verify_before_reload()
        state["reloads"] += 1
        state["reload_logs"].append(log_path)
        log_path.write_text("synthetic reload " + str(state["reloads"]))
        state["running"] = json.loads(path.read_text())

    monkeypatch.setattr(action, "reload_config", reload_config)
    return request, directory, startup, startup_bytes, state


def test_native_stage_repeat_and_restore_keep_distinct_original_startup(device):
    """A repeat must not re-snapshot the candidate or replace startup with original running."""
    request, directory, startup, original_startup, state = device
    action.stage(request, directory, startup)
    candidate = request["candidates"]["add"]
    action.perform("running", request["baseline"]["running"], candidate, "scenario:add:running",
                   request, directory, startup, directory)
    assert startup.read_bytes() == original_startup
    next_startup = {"bytes_base64": base64.b64encode(json.dumps(candidate).encode()).decode(),
                    "metadata": copy.deepcopy(request["baseline"]["startup"]["metadata"])}
    action.perform("startup", request["baseline"]["startup"], next_startup, "scenario:add:startup",
                   request, directory, startup, directory)
    assert startup.read_bytes() != original_startup
    action.stage(request, directory, startup)
    saved = json.loads((directory / "request.json").read_text())
    assert saved["baseline"]["startup"]["bytes_base64"] == request["baseline"]["startup"]["bytes_base64"]
    action.perform("running", candidate, request["baseline"]["running"], "scenario:restore:running",
                   request, directory, startup, directory)
    action.perform("startup", next_startup, request["baseline"]["startup"], "scenario:restore:startup",
                   request, directory, startup, directory)
    assert state["running"] == request["baseline"]["running"]
    assert startup.read_bytes() == original_startup
    assert json.loads((directory / "startup-receipt.json").read_text())["completed"]


def test_native_action_rejects_unexplained_running_or_startup_drift(device):
    """A stage is not authority to overwrite a later external configuration change."""
    request, directory, startup, original_startup, state = device
    action.stage(request, directory, startup)
    state["running"]["EXTERNAL_CHANGE"] = {"value": "preserve"}
    with pytest.raises(action.DeviceActionError, match="running drift"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"], "scenario:add:running",
                       request, directory, startup, directory)
    assert state["reloads"] == 0 and startup.read_bytes() == original_startup
    state["running"] = copy.deepcopy(request["baseline"]["running"])
    startup.write_bytes(b"external startup edit")
    with pytest.raises(action.DeviceActionError, match="startup drift"):
        action.perform("startup", request["baseline"]["startup"], request["baseline"]["startup"],
                       "scenario:add:startup", request, directory, startup, directory)
    assert startup.read_bytes() == b"external startup edit" and state["reloads"] == 0


def test_failed_native_reload_retains_its_state_for_compensation(device, monkeypatch):
    """A command failure after a write remains a failed action with recoverable original bytes."""
    request, directory, startup, original_startup, state = device
    action.stage(request, directory, startup)
    original_reload = action.reload_config

    def failed_reload(path, log_path, verify_before_reload=None):
        original_reload(path, log_path, verify_before_reload)
        raise action.DeviceActionError("injected post-write failure")

    monkeypatch.setattr(action, "reload_config", failed_reload)
    with pytest.raises(action.DeviceActionError, match="post-write failure"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"], "scenario:add:running",
                       request, directory, startup, directory)
    assert (directory / "running-intent.json").exists()
    receipt = json.loads((directory / "running-receipt.json").read_text())
    assert not receipt["completed"] and receipt["operation_id"] == "scenario:add:running"
    assert receipt["observed_sha256"] == action.digest(state["running"])
    archived = [path for path in directory.glob("running-*-receipt.json")
                if json.loads(path.read_text())["operation_id"] == "scenario:add:running"]
    assert len(archived) == 1
    failed_receipt, first_log = archived[0].read_bytes(), state["reload_logs"][0]
    first_output = first_log.read_bytes()
    monkeypatch.setattr(action, "reload_config", original_reload)
    action.perform("running", state["running"], request["baseline"]["running"], "scenario:restore:running",
                   request, directory, startup, directory)
    assert state["running"] == request["baseline"]["running"] and startup.read_bytes() == original_startup
    assert archived[0].read_bytes() == failed_receipt and first_log.read_bytes() == first_output
    assert state["reload_logs"][1] != first_log


def test_native_restore_failure_retains_the_original_request(device, monkeypatch):
    """An incomplete restore must never emit a restored receipt or discard original snapshots."""
    request, directory, startup, original_startup, state = device
    action.stage(request, directory, startup)
    action.perform("running", request["baseline"]["running"], request["candidates"]["add"], "scenario:add:running",
                   request, directory, startup, directory)

    def failed_restore(path, log_path, verify_before_reload=None):
        raise action.DeviceActionError("injected restore failure")

    monkeypatch.setattr(action, "reload_config", failed_restore)
    with pytest.raises(action.DeviceActionError, match="restore failure"):
        action.perform("running", state["running"], request["baseline"]["running"], "scenario:restore:running",
                       request, directory, startup, directory)
    assert not json.loads((directory / "running-receipt.json").read_text())["completed"]
    assert json.loads((directory / "request.json").read_text()) == request


def test_installed_source_drift_blocks_before_a_native_reload(device):
    request, directory, startup, original_startup, state = device
    action.stage(request, directory, startup)
    Path(next(iter(request["source_sha256"]))).write_text("different installed source")
    with pytest.raises(action.DeviceActionError, match="changed after collection"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"], "scenario:add:running",
                       request, directory, startup, directory)
    assert state["reloads"] == 0 and startup.read_bytes() == original_startup


def test_undeclared_startup_side_effect_is_not_a_success(device, monkeypatch):
    request, directory, startup, original_startup, state = device
    action.stage(request, directory, startup)
    original_reload = action.reload_config

    def side_effect(path, log_path, verify_before_reload=None):
        original_reload(path, log_path, verify_before_reload)
        startup.write_text('{"unexpected":"startup-write"}')

    monkeypatch.setattr(action, "reload_config", side_effect)
    with pytest.raises(action.DeviceActionError, match="undeclared startup resource"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"], "scenario:add:running",
                       request, directory, startup, directory)
    assert not json.loads((directory / "running-receipt.json").read_text())["completed"]


@pytest.mark.parametrize("message", [
    "System is not up. Retry later or use -f to avoid system checks",
    "SwSS container is not ready. Retry later or use -f to avoid system checks",
])
def test_native_reload_retries_only_verified_prewrite_readiness_rejections(device, monkeypatch, message):
    request, directory, startup, original_startup, state = device
    calls, waits = [], []
    rejected = ("Acquired lock on /etc/sonic/reload.lock\n" + message
                + "\nReleased lock on /etc/sonic/reload.lock\n").encode()

    def run(arguments, **keywords):
        calls.append(arguments)
        if len(calls) == 1:
            return SimpleNamespace(returncode=1, stdout=rejected)
        state["running"] = json.loads(Path(arguments[-1]).read_text())
        return SimpleNamespace(returncode=0, stdout=b"config reload completed\n")

    monkeypatch.setattr(action, "reload_config", state["native_reload"])
    monkeypatch.setattr(action.subprocess, "run", run)
    monkeypatch.setattr(time, "sleep", waits.append)
    action.perform("running", request["baseline"]["running"], request["candidates"]["add"],
                   "scenario:add:running", request, directory, startup, directory)
    assert len(calls) == 2 and calls[0] == calls[1] and "-f" not in calls[0]
    assert waits == [5] and startup.read_bytes() == original_startup
    receipt = json.loads((directory / "running-receipt.json").read_text())
    output = Path(receipt["reload_log"]).read_bytes()
    assert receipt["completed"] and rejected in output and b"config reload completed" in output


@pytest.mark.parametrize("returncode,output,mutate", [
    (2, b"SwSS container is not ready. Retry later or use -f to avoid system checks\n", False),
    (1, b"Configuration was changed\n"
     b"SwSS container is not ready. Retry later or use -f to avoid system checks\n", True),
])
def test_native_reload_does_not_retry_other_or_potentially_applied_failures(
        device, monkeypatch, returncode, output, mutate):
    request, directory, startup, original_startup, state = device
    calls = []

    def run(arguments, **keywords):
        calls.append(arguments)
        if mutate:
            state["running"] = copy.deepcopy(request["candidates"]["add"])
        return SimpleNamespace(returncode=returncode, stdout=output)

    def forbidden_wait(seconds):
        raise AssertionError("A non-readiness failure must not be retried")

    monkeypatch.setattr(action, "reload_config", state["native_reload"])
    monkeypatch.setattr(action.subprocess, "run", run)
    monkeypatch.setattr(time, "sleep", forbidden_wait)
    with pytest.raises(action.DeviceActionError, match="config reload failed"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"],
                       "scenario:add:running", request, directory, startup, directory)
    assert len(calls) == 1 and startup.read_bytes() == original_startup
    receipt = json.loads((directory / "running-receipt.json").read_text())
    assert not receipt["completed"] and receipt["observed_sha256"] == action.digest(state["running"])


@pytest.mark.parametrize("drift", ["running", "startup", "source"])
def test_native_reload_rechecks_frozen_state_and_sources_before_retry(device, monkeypatch, drift):
    request, directory, startup, original_startup, state = device
    calls = []

    def run(arguments, **keywords):
        calls.append(arguments)
        if drift == "running":
            state["running"]["EXTERNAL_CHANGE"] = {"preserve": "yes"}
        elif drift == "startup":
            startup.write_bytes(b"external startup edit")
        else:
            Path(next(iter(request["source_sha256"]))).write_text("external source edit")
        return SimpleNamespace(
            returncode=1, stdout=b"SwSS container is not ready. Retry later or use -f to avoid system checks\n")

    monkeypatch.setattr(action, "reload_config", state["native_reload"])
    monkeypatch.setattr(action.subprocess, "run", run)
    with pytest.raises(action.DeviceActionError, match="drift|changed"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"],
                       "scenario:add:running", request, directory, startup, directory)
    assert len(calls) == 1 and not json.loads((directory / "running-receipt.json").read_text())["completed"]


def test_native_reload_readiness_wait_is_bounded_and_keeps_failure_evidence(device, monkeypatch):
    request, directory, startup, original_startup, state = device
    calls, clock = [], [0]
    output = b"SwSS container is not ready. Retry later or use -f to avoid system checks\n"

    def run(arguments, **keywords):
        calls.append(arguments)
        return SimpleNamespace(returncode=1, stdout=output)

    def wait(seconds):
        assert 0 < seconds <= 5
        clock[0] += 300

    monkeypatch.setattr(action, "reload_config", state["native_reload"])
    monkeypatch.setattr(action.subprocess, "run", run)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", wait)
    with pytest.raises(action.DeviceActionError, match="readiness.*converge"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"],
                       "scenario:add:running", request, directory, startup, directory)
    assert len(calls) == 1 and state["running"] == request["baseline"]["running"]
    receipt = json.loads((directory / "running-receipt.json").read_text())
    assert not receipt["completed"] and output in Path(receipt["reload_log"]).read_bytes()


def test_native_media_guard_waits_for_xcvrd_to_repopulate_missing_evidence(monkeypatch):
    expected = {"Ethernet512": {"type": "SFP/SFP+/SFP28", "nominal_bit_rate": "103"}}
    readings = iter([{}, {"type": "SFP/SFP+/SFP28"}, expected["Ethernet512"]])
    waits = []
    database = SimpleNamespace(connect=lambda name: None, get_all=lambda *args: next(readings))
    monkeypatch.setattr(action.time, "sleep", waits.append)
    action.verify_media_sources(expected, database)
    assert waits == [5, 5]


def test_native_reload_does_not_write_after_its_source_guard_consumes_the_deadline(device, monkeypatch):
    request, directory, startup, original_startup, state = device
    clock, calls = [0], []
    path = directory / "candidate.json"
    path.write_text(json.dumps(request["candidates"]["add"]))
    monkeypatch.setattr(action.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(action.subprocess, "run", lambda *args, **kwargs: (
        calls.append(args) or SimpleNamespace(returncode=0, stdout=b"unexpected late write")))

    def verify():
        clock[0] = 300

    with pytest.raises(action.DeviceActionError, match="readiness.*converge"):
        state["native_reload"](path, directory / "reload.log", verify)
    assert not calls and startup.read_bytes() == original_startup


def test_native_media_guard_does_not_wait_for_a_positive_module_change(monkeypatch):
    database = SimpleNamespace(connect=lambda name: None, get_all=lambda *args: {"nominal_bit_rate": "255"})
    waits = []
    monkeypatch.setattr(action.time, "sleep", waits.append)
    with pytest.raises(action.DeviceActionError, match="transceiver changed"):
        action.verify_media_sources({"Ethernet512": {"nominal_bit_rate": "103"}}, database)
    assert not waits


def test_native_media_guard_missing_evidence_has_a_bounded_failure(monkeypatch):
    clock, waits = [0], []
    database = SimpleNamespace(connect=lambda name: None, get_all=lambda *args: {})

    def wait(seconds):
        waits.append(seconds)
        clock[0] += 300

    monkeypatch.setattr(action.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(action.time, "sleep", wait)
    with pytest.raises(action.DeviceActionError, match="transceiver.*unavailable"):
        action.verify_media_sources({"Ethernet512": {"nominal_bit_rate": "103"}}, database)
    assert waits == [5]


def test_native_media_wait_rechecks_installed_bytes_before_any_write(device, monkeypatch):
    request, directory, startup, original_startup, state = device
    expected = {"Ethernet512": {"nominal_bit_rate": "103"}}
    request["media_sources"] = expected
    readings = iter([{}, expected["Ethernet512"]])
    database = SimpleNamespace(connect=lambda name: None, get_all=lambda *args: next(readings))
    verify = action.verify_media_sources
    monkeypatch.setattr(action, "verify_media_sources", lambda evidence: verify(evidence, database))
    monkeypatch.setattr(action.time, "sleep", lambda seconds: Path(
        next(iter(request["source_sha256"]))).write_text("installed bytes changed during readiness wait"))
    with pytest.raises(action.DeviceActionError, match="Installed image/platform/parser changed"):
        action.perform("running", request["baseline"]["running"], request["candidates"]["add"],
                       "scenario:add:running", request, directory, startup, directory)
    assert state["reloads"] == 0 and startup.read_bytes() == original_startup


def test_native_capture_failure_retains_the_guard_error_without_returning_success(tmp_path, monkeypatch):
    root = tmp_path / "native"
    directory = root / "scenario" / "synthetic-device"
    directory.mkdir(parents=True)
    (directory / "request.json").write_text("{}")
    module = SimpleNamespace(params={
        "device": "synthetic-device", "scenario": "scenario", "action": "capture",
        "kind": "running", "destination": str(tmp_path / "result.json"), "operation_id": None})

    def failed(**arguments):
        raise RuntimeError(arguments["msg"])

    def unexpected_success(**arguments):
        raise AssertionError("A failed native guard must not return success")

    def blocked(request):
        raise action.DeviceActionError("synthetic frozen-media source rejection")

    module.fail_json, module.exit_json = failed, unexpected_success
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=2))
    monkeypatch.setitem(sys.modules, "ansible.module_utils.basic", SimpleNamespace(
        AnsibleModule=lambda **arguments: module))
    monkeypatch.setattr(action.socket, "gethostname", lambda: "synthetic-device")
    monkeypatch.setattr(action, "Path", lambda path: root if path == "/var/lib/sonic-generic" else Path(path))
    monkeypatch.setattr(action, "verify_sources", blocked)
    with pytest.raises(RuntimeError, match="frozen-media source rejection"):
        action.main()
    files = list(directory.glob("failure-*.json"))
    assert len(files) == 1
    receipt = json.loads(files[0].read_text())
    assert receipt["action"] == "capture" and receipt["kind"] == "running"
    assert receipt["error"] == "synthetic frozen-media source rejection"
    assert receipt["error_type"] == "DeviceActionError" and "request" not in receipt
