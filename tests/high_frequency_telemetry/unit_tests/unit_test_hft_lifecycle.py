"""Regression tests for HFT recovery; run without a DUT using pytest --noconftest."""
import fcntl
import json
import os
import select
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.high_frequency_telemetry.files import hft_container as hft
from tests.high_frequency_telemetry.files import hft_sink
from tests.high_frequency_telemetry import transaction as controller


FLAGS = ["--enable-otel", "--otel-endpoint=http://localhost:4317"]


@pytest.mark.parametrize("original", [
    ["--enable-counter-db", "-o", "--otel-endpoint", "http://old:4317", "--log-level=warn"],
    ["--enable-counter-db", "--enable-otel", "--otel-endpoint=http://old:4317", "--log-level=warn"],
])
def test_override_only_otel(original):
    before = original.copy()
    assert hft.with_otel_args(original, FLAGS) == ["--enable-counter-db", "--log-level=warn", *FLAGS]
    assert original == before


@pytest.mark.parametrize("original", [["-ol"], ["--", "-o"], ["--otel-endpoint", "--other"]])
def test_refuse_ambiguous_cmd(original):
    with pytest.raises(RuntimeError):
        hft.with_otel_args(original, FLAGS)


@pytest.mark.parametrize("state", ["disabled", "enabled", "always_enabled"])
@pytest.mark.parametrize("fail_start", [False, True])
def test_original_container_restored_after_install_or_start_failure(tmp_path, monkeypatch, state, fail_start):
    # Simulate only the external Docker/service calls. The journal, rename, setup
    # and restore decisions below are the same functions executed on the DUT.
    client, containers = Mock(), {}
    current_state = state

    class Container:
        def __init__(self, name, ident, cmd, labels, running=False):
            self.id, self.name, self.labels = ident, name, labels
            self.attrs = {"Config": {"Cmd": cmd}, "HostConfig": {"AutoRemove": False}, "State": {"Running": running}}
            containers[ident] = self

        @property
        def status(self):
            return "running" if self.attrs["State"]["Running"] else "exited"

        def reload(self):
            pass

        def rename(self, name):
            self.name = name

        def remove(self):
            assert self.status != "running"
            del containers[self.id]

        def stop(self, timeout=10):
            self.attrs["State"]["Running"] = False

    def get(name):
        return next((c for c in containers.values() if name in (c.id, c.name)), None)

    def command(*argv):
        if argv[:2] == ("sonic-db-cli", "CONFIG_DB"):
            return "local" if argv[-1] == "set_owner" else current_state
        if argv[:2] == ("systemctl", "show") and "UnitFileState" in argv:
            return "enabled"
        if argv == ("systemctl", "stop", "hft.service"):
            get("hft").stop()
            return ""
        raise AssertionError(argv)

    def start(*args):
        container = get("hft")
        if fail_start and hft.OWNER_LABEL in container.labels:
            raise RuntimeError("injected start failure")
        container.attrs["State"]["Running"] = True

    def change(service, expected, value):
        nonlocal current_state
        assert current_state == expected
        current_state = value

    client.containers.get.side_effect = get
    client.containers.list.side_effect = lambda **kw: [c for c in containers.values() if c.labels]
    monkeypatch.setattr(hft, "lookup", lambda client, name: get(name))
    monkeypatch.setattr(hft, "command", command)
    monkeypatch.setattr(hft, "check_hwsku", lambda container: None)
    monkeypatch.setattr(hft, "disabled_policy", lambda service: "masked")
    monkeypatch.setattr(hft, "restore_disabled_policy", lambda *a, **kw: None)
    monkeypatch.setattr(hft, "change_feature_state", change)
    monkeypatch.setattr(hft, "start_service", start)
    monkeypatch.setattr(hft, "wait_for_feature", start)
    monkeypatch.setattr(hft, "create_with_args", lambda c, s, n, a: Container(n, "test-id", a, {hft.OWNER_LABEL: n}))
    stored_cmd = ["--enable-counter-db", "--otel-endpoint=old"]
    original = Container("hft", "original-id", stored_cmd, {}, running=state != "disabled")
    if fail_start:
        with pytest.raises(RuntimeError, match="injected"):
            hft.install(client, tmp_path, state, FLAGS)
    else:
        hft.install(client, tmp_path, state, FLAGS)
        assert get("hft").attrs["Config"]["Cmd"] == ["--enable-counter-db", *FLAGS]
    hft.restore(client, tmp_path)
    assert current_state == state and list(containers.values()) == [original]
    assert get("hft").id == "original-id" and original.attrs["Config"]["Cmd"] == stored_cmd
    assert (original.status == "running") == (state != "disabled")


def test_recovery_refuses_operator_feature_policy(tmp_path, monkeypatch):
    hft.save(tmp_path / "before.json", {"original": None, "state": "disabled", "enable_armed": True})
    command = Mock(side_effect=["local", "always_disabled"])
    monkeypatch.setattr(hft, "command", command)
    with pytest.raises(RuntimeError, match="changed outside"):
        hft.restore(Mock(), tmp_path)
    assert all(c.args[0] == "sonic-db-cli" for c in command.call_args_list)


def test_closed_owner_cannot_create_a_late_profile(tmp_path, monkeypatch):
    work = tmp_path / "sonic-mgmt-hft-case"
    work.mkdir()
    monkeypatch.setattr(hft, "ACTIVE", tmp_path / "active")
    monkeypatch.setattr(hft, "LEGACY_LOCK", tmp_path / "legacy")
    hft.transaction("claim", work, "original", ["controller"])
    hft.transaction("take", work, "original", ["new-owner", "new controller"])
    with pytest.raises(RuntimeError, match="owner changed"):
        hft.transaction("profile-create", work, "original", ["late-case"])
    with pytest.raises(RuntimeError, match="closing"):
        hft.transaction("profile-create", work, "new-owner", ["late-case"])
    (work / "profile.json").write_text(json.dumps({"name": "still-active"}))
    for action in ("restore", "restore-otel"):
        with pytest.raises(RuntimeError, match="profile is still armed"):
            hft.transaction(action, work, "new-owner", [])


def test_controller_lock_releases_after_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    dut = SimpleNamespace(hostname="unit-test-dut")
    fail_setup = Mock(side_effect=RuntimeError("setup failed"))

    with pytest.raises(RuntimeError, match="setup failed"):
        with controller.controller_lock(dut):
            with pytest.raises(pytest.fail.Exception, match="Another HFT test"):
                with controller.controller_lock(dut):
                    pass
            fail_setup()
    # A second independent open can now acquire the same kernel lock.
    with controller.controller_lock(dut):
        pass


def test_cleanup_before_delayed_sink_launch(tmp_path, monkeypatch):
    monkeypatch.setattr(hft_sink, "ROOT", tmp_path)
    node = "sonic-mgmt-hft-delayed"
    hft_sink.lifecycle("prepare", node, 8181)
    hft_sink.lifecycle("stop", node, 8181)
    with pytest.raises(FileNotFoundError):
        hft_sink.lifecycle("start", node, 8181)
    hft_sink.lifecycle("stop", node, 8181)
    assert not list(tmp_path.iterdir())


def test_rejected_otel_enable_disarms_intent(tmp_path, monkeypatch):
    original = {"state": "disabled", "set_owner": "local"}
    snapshot = {"original_state": "disabled", "original_feature": original}
    monkeypatch.setattr(hft, "otel_fields", lambda: original)
    cas = Mock(side_effect=hft.FeatureConflict("owner changed"))
    monkeypatch.setattr(hft, "change_feature_state", cas)
    with pytest.raises(hft.FeatureConflict):
        hft.enable_otel(Mock(), tmp_path, snapshot)
    cas.assert_called_once_with("otel", "disabled", "enabled")
    assert not (tmp_path / "otel-enable.json").exists()


def test_collector_config_checks_destination_before_rename(tmp_path, monkeypatch):
    work = tmp_path / "sonic-mgmt-hft-unit"
    work.mkdir()
    config = tmp_path / "otel-config.yml"
    config.write_text("original\n")
    config.chmod(0o640)
    monkeypatch.setattr(hft, "OTEL_CONFIG", config)
    (work / "otel.json").write_text(json.dumps({"otel_config": ["original\n", "0640"]}))
    (work / "config.owner").write_text("test\n")
    check = Mock(side_effect=hft.FeatureConflict("OTEL transferred"))
    with pytest.raises(hft.FeatureConflict):
        hft.install_collector_config(work, "owner", before_replace=check)
    assert config.read_text() == "original\n"
    assert not list(tmp_path.glob("*.tmp"))


def test_child_process_inherits_directory_fence(tmp_path):
    # An independently opened descriptor must contend with the inherited lock,
    # even after the helper has closed its own copy. Use pipes, not timing sleeps.
    started_r, started_w = os.pipe()
    release_r, release_w = os.pipe()
    lock_fd = os.open(tmp_path, os.O_DIRECTORY)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    probe = f"import os; os.write({started_w}, b'1'); os.read({release_r}, 1)"

    def child():
        token = hft.FENCE_FDS.set((lock_fd, started_w, release_r))
        try:
            hft.command(sys.executable, "-c", probe)
        finally:
            hft.FENCE_FDS.reset(token)

    thread = threading.Thread(target=child)
    thread.start()
    try:
        assert select.select([started_r], [], [], 5)[0] and os.read(started_r, 1) == b"1"
        os.close(lock_fd)
        contender = os.open(tmp_path, os.O_DIRECTORY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(release_w, b"1")
            thread.join(5)
            assert not thread.is_alive()
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)
    finally:
        os.close(release_w)
        thread.join(5)
        for fd in (started_r, started_w, release_r):
            os.close(fd)


def test_operator_config_edit_during_publication_survives_setup_and_recovery(tmp_path, monkeypatch):
    work = tmp_path / "sonic-mgmt-hft-case"
    work.mkdir()
    config = tmp_path / "otel-config.yml"
    config.write_text("original\n")
    config.chmod(0o640)
    monkeypatch.setattr(hft, "OTEL_CONFIG", config)
    (work / "otel.json").write_text(json.dumps({"otel_config": ["original\n", "0640"]}))
    (work / "config.owner").write_text("test\n")
    with pytest.raises(hft.CollectorConfigChanged):
        hft.install_collector_config(work, "owner", before_replace=lambda: config.write_text("operator\n"))
    with pytest.raises(hft.CollectorConfigChanged):
        hft.check_service_config(work)

    snapshot = {"original_state": "enabled", "original_feature": {"state": "enabled"},
                "original_collector_running": True}
    current = Mock(status="running")
    monkeypatch.setattr(hft, "check_otel", lambda *a: current)
    monkeypatch.setattr(hft, "otel_fields", lambda: {"state": "enabled"})
    monkeypatch.setattr(hft, "collector_running", lambda c: True)
    service = Mock(return_value="enabled")
    monkeypatch.setattr(hft, "command", service)
    hft.restore_otel(None, work, snapshot)
    service.assert_not_called()
    assert config.read_text() == "operator\n"

    # Once this run has touched the process, restore liveness but keep the operator's file.
    hft.save(work / "collector-activity.json", True)
    hft.restore_otel(None, work, snapshot)
    assert ("systemctl", "restart", "otel.service") in [call.args for call in service.call_args_list]
    assert config.read_text() == "operator\n"


def test_rollback_after_chmod_reloads_original_bytes_with_operator_permissions(tmp_path, monkeypatch):
    config = tmp_path / "otel.yml"
    config.write_text("operator endpoint\n")
    config.chmod(0o644)
    monkeypatch.setattr(hft, "OTEL_CONFIG", config)
    snapshot = {"otel_config": [config.read_text(), "0644"], "original_feature": {"state": "enabled"},
                "original_state": "enabled", "original_collector_running": True}
    hft.save(tmp_path / "otel.json", snapshot)
    (tmp_path / "config.owner").write_text("test endpoint\n")
    hft.install_collector_config(tmp_path, "owner")
    hft.check_service_config(tmp_path)
    hft.save(tmp_path / "collector-activity.json", True)
    config.chmod(0o440)  # The bytes still point at the fixture sink.
    loaded = []

    def systemctl(*args):
        if args == ("systemctl", "restart", "otel.service"):
            loaded.append((config.read_text(), config.stat().st_mode & 0o777))
        return "enabled"

    monkeypatch.setattr(hft, "command", systemctl)
    monkeypatch.setattr(hft, "check_otel", lambda *a: Mock(status="running"))
    monkeypatch.setattr(hft, "otel_fields", lambda: {"state": "enabled"})
    monkeypatch.setattr(hft, "collector_running", lambda c: True)
    hft.restore_otel(None, tmp_path, snapshot)
    assert loaded == [("operator endpoint\n", 0o440)]


def test_rollback_does_not_checkpoint_an_unverified_managed_file(tmp_path, monkeypatch):
    config = tmp_path / "otel.yml"
    operator = tmp_path / "managed.yml"
    operator.write_text("test endpoint\n")
    config.symlink_to(operator)
    monkeypatch.setattr(hft, "OTEL_CONFIG", config)
    snapshot = {"otel_config": ["original\n", "0644"], "original_feature": {"state": "enabled"},
                "original_state": "enabled", "original_collector_running": True}
    hft.save(tmp_path / "otel.json", snapshot)
    hft.save(tmp_path / "collector-target.json", hft.config_digest(operator.read_bytes()))
    monkeypatch.setattr(hft, "check_otel", lambda *a: Mock(status="running"))
    monkeypatch.setattr(hft, "otel_fields", lambda: {"state": "enabled"})
    monkeypatch.setattr(hft, "collector_running", lambda c: True)
    with pytest.raises(hft.CollectorConfigChanged, match="managed"):
        hft.restore_otel(None, tmp_path, snapshot)
    assert config.is_symlink() and operator.read_text() == "test endpoint\n"


@pytest.mark.parametrize("ident,label", [
    ("original-id", None), ("foreign-id", "sonic-mgmt-hft-unit"), ("candidate-id", "someone-else"),
])
def test_queue_restart_refuses_wrong_identity(tmp_path, monkeypatch, ident, label):
    work = tmp_path / "sonic-mgmt-hft-unit"
    work.mkdir()
    hft.save(work / "before.json", {"candidate": "candidate-id"})
    ct = Mock(id=ident, labels={hft.OWNER_LABEL: label}, status="running")
    monkeypatch.setattr(hft, "lookup", lambda *a: ct)
    commands = Mock()
    monkeypatch.setattr(hft, "command", commands)
    with pytest.raises(RuntimeError, match="outside this run"):
        hft.restart_countersyncd(None, work)
    commands.assert_not_called()


def test_failed_start_must_not_acknowledge_a_pending_disable(monkeypatch):
    state = {"reported": "failed", "policy": "disabled"}

    def finish_disable(_):
        state.update(reported="disabled", policy="masked")

    def command(*argv):
        if argv[:2] == ("sonic-db-cli", "CONFIG_DB"):
            return "disabled"
        if argv[:2] == ("sonic-db-cli", "STATE_DB"):
            return state["reported"]
        if argv[:2] == ("systemctl", "show"):
            return "inactive" if "ActiveState" in argv else state["policy"]
        assert argv == ("systemctl", "unmask", "hft.service")
        state["policy"] = "disabled"
        return ""

    monkeypatch.setattr(hft, "command", command)
    monkeypatch.setattr(hft.time, "sleep", finish_disable)
    hft.restore_disabled_policy("hft", "disabled", enabled_by_test=True)
    assert state == {"reported": "disabled", "policy": "disabled"}
