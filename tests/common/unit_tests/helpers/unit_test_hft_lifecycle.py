"""Recovery must preserve the original identity, command and feature policy on partial setup."""
import json
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
    monkeypatch.setattr(hft, "restore_disabled_policy", lambda *a: None)
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
    with pytest.raises(RuntimeError):
        with controller.controller_lock(dut) as file:
            with pytest.raises(pytest.fail.Exception, match="Another HFT test"):
                with controller.controller_lock(dut):
                    pytest.fail("duplicate owner")
            raise RuntimeError("setup failed")
    assert file.closed
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
