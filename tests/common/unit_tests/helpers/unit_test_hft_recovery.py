"""Ownership regressions for interrupted HFT runs; no DUT or Docker daemon required."""
import json

import pytest
from tests.high_frequency_telemetry.files import hft_container as helper


@pytest.fixture
def gates(tmp_path, monkeypatch):
    active, runtime = tmp_path / "active", tmp_path / "runtime"
    monkeypatch.setattr(helper, "ACTIVE", active)
    monkeypatch.setattr(helper, "LEGACY_LOCK", runtime)
    return active, runtime


def test_contender_does_not_unlink_owner(tmp_path, gates):
    a, b = [tmp_path / ("sonic-mgmt-hft-" + name) for name in ("a", "b")]
    a.mkdir()
    b.mkdir()
    helper.transaction("claim", a, "first", ["controller A"])
    with pytest.raises(FileExistsError):
        helper.transaction("claim", b, "other", ["controller B"])
    assert all(link.resolve() == a for link in gates)
    assert json.loads((a / "owner.json").read_text())["id"] == "first"


def test_recovery_handoff_fences_delayed_cleanup(tmp_path, gates):
    work = tmp_path / "sonic-mgmt-hft-original"
    work.mkdir()
    helper.transaction("claim", work, "interrupted", ["controller A"])
    gates[1].unlink()  # /run was lost, but the persistent transaction and helper survived.
    helper.transaction("take", work, "interrupted", ["successor", "controller B"])
    with pytest.raises(RuntimeError, match="owner changed"):
        helper.transaction("finish", work, "interrupted", [])
    assert all(link.resolve() == work for link in gates)
    helper.transaction("finish", work, "successor", [])
    assert not work.exists() and not any(link.is_symlink() for link in gates)


def test_collector_config_refuses_intervening_edit(tmp_path, monkeypatch):
    work = tmp_path / "sonic-mgmt-hft-test"
    work.mkdir()
    config = tmp_path / "otel_config.yml"
    monkeypatch.setattr(helper, "OTEL_CONFIG", config)
    (work / "otel.json").write_text(json.dumps({"otel_config": ["original\n", "0640"]}))
    (work / "config.owner").write_text("test\n")
    config.write_text("operator change\n")
    config.chmod(0o640)
    with pytest.raises(RuntimeError, match="outside this transaction"):
        helper.install_collector_config(work, "owner")
    assert config.read_text() == "operator change\n"
    assert not list(work.glob("config-*"))


def test_otel_field_ownership():
    snap = {"original_state": "disabled", "original_feature": {"state": "disabled", "auto_restart": "enabled"}}
    # Only state was test-written. An operator owns unrelated values and new fields.
    helper.check_otel_fields(snap, {"state": "enabled", "auto_restart": "disabled", "new": "keep"}, True)
    with pytest.raises(RuntimeError, match="outside"):
        helper.check_otel_fields(snap, {"state": "always_enabled"}, True)
    snap["original_feature"] = {}
    with pytest.raises(RuntimeError, match="outside"):
        helper.check_otel_fields(snap, {**helper.CREATED_OTEL_FIELDS, "auto_restart": "disabled"}, True)


def test_finish_requires_all_armed_recovery_steps(tmp_path, gates):
    work = tmp_path / "sonic-mgmt-hft-test"
    work.mkdir()
    helper.transaction("claim", work, "owner", ["controller"])
    (work / "sink.json").write_text('{}')
    helper.transaction("close", work, "owner", [])
    helper.transaction("done", work, "owner", ["profiles"])
    with pytest.raises(RuntimeError, match="not completed"):
        helper.transaction("finish", work, "owner", [])
    assert gates[0].resolve() == work
    helper.transaction("done", work, "owner", ["sink"])
    helper.transaction("finish", work, "owner", [])
