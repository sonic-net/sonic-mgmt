"""Offline unit tests for FrrConfigModeMigrator's backup/restore bookkeeping (no DUT)."""
import json

import pytest

from tests.common.helpers.frr.frr_parity_compat import (
    GATED_GLOBAL_LINES,
    gated_globals_missing_from_image,
    strip_unsupported_by_image,
)
from tests.common.helpers.frr.frr_config_mode_migrator import (
    FrrConfigModeMigrator,
    FrrTranslationError,
    CONFIG_DB_FILE,
    GOLDEN_CFG_FILE,
    GOLDEN_CFG_ORIGIN_FILE,
    SWITCHED_MARKER_FILE,
    _BAK_SUFFIX,
)

pytestmark = [
    pytest.mark.topology('any')
]

CONFIG_BAK = CONFIG_DB_FILE + _BAK_SUFFIX
GOLDEN_BAK = GOLDEN_CFG_FILE + _BAK_SUFFIX
ORIGIN_BAK = GOLDEN_CFG_ORIGIN_FILE + _BAK_SUFFIX


class FakeDutHost(object):
    """Minimal duthost stand-in: tracks which files exist and what shell ran."""

    hostname = "fake-dut"

    def __init__(self, files=(), config_db_tables=(), backup_tables=()):
        self.files = set(files)
        self.config_db_tables = list(config_db_tables)
        self.backup_tables = list(backup_tables)
        self.commands = []

    def is_file_existed(self, path):
        return path in self.files

    def shell(self, cmd, module_ignore_errors=False):
        self.commands.append(cmd)
        if "CONFIG_DB KEYS" in cmd:
            return {"rc": 0, "stdout": "\n".join(self.config_db_tables)}
        if cmd.startswith("sudo cat ") and cmd.split()[-1] == CONFIG_BAK:
            return {"rc": 0, "stdout": json.dumps({t: {} for t in self.backup_tables})}
        parts = cmd.split()
        if "cp" in parts or "touch" in parts:
            self.files.add(parts[-1])
        if "rm" in parts:
            for path in parts:
                self.files.discard(path)
        return {"rc": 0, "stdout": ""}

    def ran(self, needle):
        return any(needle in c for c in self.commands)


def test_to_traditional_restores_from_backup_file_without_local_flag():
    """A fresh migrator must restore from a backup file it did not create itself."""
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_BAK])
    migrator = FrrConfigModeMigrator(dut)
    assert migrator._backed_up is False

    assert migrator.to_traditional() is True
    assert dut.ran("cp {0} {1}".format(CONFIG_BAK, CONFIG_DB_FILE))
    assert dut.ran("cp {0} {1}".format(GOLDEN_BAK, GOLDEN_CFG_FILE))
    assert dut.ran("config reload")


def test_to_traditional_without_backup_reports_no_restore():
    dut = FakeDutHost(files=[CONFIG_DB_FILE])
    assert FrrConfigModeMigrator(dut).to_traditional() is False
    assert not dut.ran("config reload")


def test_recover_interrupted_run_restores_and_cleans_up():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_BAK,
                             SWITCHED_MARKER_FILE])
    migrator = FrrConfigModeMigrator(dut)

    assert migrator.recover_interrupted_run() is True
    assert dut.ran("cp {0} {1}".format(CONFIG_BAK, CONFIG_DB_FILE))
    assert dut.ran("rm -f")
    assert CONFIG_BAK not in dut.files


# Only the switch marker means a switch happened; backups alone (taken at session start) do not.
@pytest.mark.parametrize("files", [
    [CONFIG_DB_FILE, GOLDEN_CFG_FILE],
    [CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_BAK],
], ids=["no-backups", "backups-but-no-marker"])
def test_recover_interrupted_run_is_noop_without_marker(files):
    dut = FakeDutHost(files=files)
    assert FrrConfigModeMigrator(dut).recover_interrupted_run() is False
    assert dut.commands == []


def test_backup_never_overwrites_a_previous_runs_backup():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE])
    migrator = FrrConfigModeMigrator(dut)

    migrator._backup()
    assert migrator._backed_up is True
    assert not dut.ran("cp {0} {1}".format(CONFIG_DB_FILE, CONFIG_BAK))


def test_adopted_config_backup_still_takes_missing_golden_backups():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE])
    FrrConfigModeMigrator(dut)._backup()
    assert not dut.ran("cp {0} {1}".format(CONFIG_DB_FILE, CONFIG_BAK))
    assert GOLDEN_BAK in dut.files
    assert ORIGIN_BAK in dut.files


# Residue = frr-only tables left after a restore that the pre-switch backup did not have.
@pytest.mark.parametrize("tables,backup_tables,present,absent_after", [
    (["BGP_NEIGHBOR", "BGP_GLOBALS", "BGP_NEIGHBOR_AF", "PORT"], [], ["BGP_GLOBALS", "BGP_NEIGHBOR_AF"], []),
    (["BGP_NEIGHBOR", "BGP_GLOBALS", "BGP_PEER_GROUP_AF", "PORT"], ["BGP_GLOBALS"], ["BGP_PEER_GROUP_AF"],
     ["BGP_GLOBALS"]),
], ids=["no-baseline", "baseline-is-not-a-blanket-exemption"])
def test_restore_raises_on_frr_residue(tables, backup_tables, present, absent_after):
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK], config_db_tables=tables, backup_tables=backup_tables)
    with pytest.raises(FrrTranslationError) as excinfo:
        FrrConfigModeMigrator(dut).to_traditional()
    for table in present:
        assert table in str(excinfo.value)
    for table in absent_after:
        assert table not in str(excinfo.value).split("did not have:")[1]


@pytest.mark.parametrize("tables,backup_tables", [
    (["BGP_NEIGHBOR", "BGP_PEER_GROUP", "BGP_DEVICE_GLOBAL", "PORT"], []),
    (["BGP_NEIGHBOR", "BGP_GLOBALS", "BGP_NEIGHBOR_AF", "PORT"], ["BGP_GLOBALS", "BGP_NEIGHBOR_AF"]),
], ids=["clean-traditional", "frr-tables-the-backup-already-had"])
def test_restore_accepts_config_db_without_residue(tables, backup_tables):
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK], config_db_tables=tables, backup_tables=backup_tables)
    assert FrrConfigModeMigrator(dut).to_traditional() is True


def test_capture_pristine_backup_saves_then_backs_up():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE])
    FrrConfigModeMigrator(dut).capture_pristine_backup()
    save_idx = next(i for i, c in enumerate(dut.commands) if "config save" in c)
    cp_idx = next(i for i, c in enumerate(dut.commands)
                  if c.startswith("sudo cp {}".format(CONFIG_DB_FILE)))
    assert save_idx < cp_idx, dut.commands
    assert CONFIG_BAK in dut.files


def test_capture_pristine_backup_is_idempotent():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, GOLDEN_CFG_FILE])
    migrator = FrrConfigModeMigrator(dut)
    migrator.capture_pristine_backup()
    first = len([c for c in dut.commands if c.startswith("sudo cp")])
    migrator.capture_pristine_backup()
    assert len([c for c in dut.commands if c.startswith("sudo cp")]) == first


@pytest.mark.parametrize("has_origin", [True, False])
def test_backup_takes_the_golden_origin_backup_when_present(has_origin):
    files = [CONFIG_DB_FILE, GOLDEN_CFG_FILE] + ([GOLDEN_CFG_ORIGIN_FILE] if has_origin else [])
    dut = FakeDutHost(files=files)
    FrrConfigModeMigrator(dut)._backup()
    assert dut.ran("cp {0} {1}".format(GOLDEN_CFG_ORIGIN_FILE, ORIGIN_BAK)) is has_origin
    assert dut.ran(GOLDEN_CFG_ORIGIN_FILE) is has_origin


def test_to_traditional_restores_the_golden_origin_backup():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_BAK,
                             GOLDEN_CFG_ORIGIN_FILE, ORIGIN_BAK])
    assert FrrConfigModeMigrator(dut).to_traditional() is True
    assert dut.ran("cp {0} {1}".format(ORIGIN_BAK, GOLDEN_CFG_ORIGIN_FILE))


@pytest.mark.parametrize("files", [[CONFIG_BAK, GOLDEN_BAK, ORIGIN_BAK],
                                   [CONFIG_BAK, GOLDEN_BAK, SWITCHED_MARKER_FILE]])
def test_cleanup_removes_backups_and_marker(files):
    dut = FakeDutHost(files=files)
    FrrConfigModeMigrator(dut).cleanup()
    for path in files:
        assert path not in dut.files


def test_failed_restore_keeps_backups_for_manual_recovery():
    """A failed restore must keep the backups and the switch marker so recovery can retry."""
    dut = FakeDutHost(
        files=[CONFIG_DB_FILE, CONFIG_BAK, SWITCHED_MARKER_FILE],
        config_db_tables=["BGP_GLOBALS"],
    )
    migrator = FrrConfigModeMigrator(dut)
    with pytest.raises(FrrTranslationError):
        migrator.recover_interrupted_run()
    assert CONFIG_BAK in dut.files
    assert not dut.ran("rm -f")
    assert SWITCHED_MARKER_FILE in dut.files


def test_to_traditional_clears_the_switch_marker():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, SWITCHED_MARKER_FILE])
    assert FrrConfigModeMigrator(dut).to_traditional() is True
    assert dut.ran("rm -f {}".format(SWITCHED_MARKER_FILE))


class _SwitchingDut(FakeDutHost):
    """FakeDutHost that can run a forward switch, recording file writes alongside shell."""

    def shell(self, cmd, module_ignore_errors=False):
        if cmd.startswith("sudo cat "):
            self.commands.append(cmd)
            return {"rc": 0, "stdout": "{}"}
        if cmd.startswith("sudo vtysh"):
            self.commands.append(cmd)
            return {"rc": 0, "stdout": "{}"}
        if cmd.startswith("sudo config reload"):
            self.commands.append(cmd)
            raise RuntimeError("config reload failed")
        return super(_SwitchingDut, self).shell(cmd, module_ignore_errors)

    def copy(self, content, dest):
        self.commands.append("write {}".format(dest))


def test_switch_marker_is_written_before_any_persistent_file(monkeypatch):
    from tests.common.helpers.frr import frr_config_mode_migrator as mig
    monkeypatch.setattr(mig, "translate_config_db", lambda cfg, *a: cfg)
    monkeypatch.setattr(mig, "strip_unsupported_by_image", lambda dut, cfg: cfg)
    dut = _SwitchingDut(files=[CONFIG_DB_FILE, GOLDEN_CFG_FILE])
    with pytest.raises(RuntimeError):
        FrrConfigModeMigrator(dut).to_frr_mgmt_framework()
    touch = dut.commands.index("sudo touch {}".format(SWITCHED_MARKER_FILE))
    first_write = next(i for i, c in enumerate(dut.commands) if c.startswith("write "))
    assert touch < first_write
    assert SWITCHED_MARKER_FILE in dut.files


class _YangProbeDut(object):
    """duthost stand-in that answers only the shim's YANG-model grep."""

    hostname = "fake-dut"

    def __init__(self, supported=()):
        self.supported = list(supported)

    def shell(self, cmd, module_ignore_errors=False):
        return {"rc": 0 if self.supported else 1, "stdout": "\n".join(self.supported)}


def test_gated_globals_reported_missing_on_a_pre_28543_image():
    missing = gated_globals_missing_from_image(_YangProbeDut())
    assert "no bgp ebgp-requires-policy" in missing
    assert "bgp ebgp-requires-policy" in missing


def test_gated_globals_empty_once_the_image_carries_28543():
    supported = sorted(set(GATED_GLOBAL_LINES.values()))
    assert gated_globals_missing_from_image(_YangProbeDut(supported)) == set()


def test_device_knob_lines_gated_until_the_image_renders_them():
    missing = gated_globals_missing_from_image(_YangProbeDut(["ebgp_requires_policy"]))
    assert {"zebra nexthop-group keep 1", "zebra nexthop kernel enable",
            "bgp suppress-fib-pending"} <= missing
    config = {"DEVICE_METADATA": {"localhost": {"nexthop_group_keep_time": "1", "zebra_nexthop": "enabled"}}}
    assert strip_unsupported_by_image(_YangProbeDut(["zebra_nexthop"]), config) == {
        "DEVICE_METADATA": {"localhost": {"zebra_nexthop": "enabled"}}}
