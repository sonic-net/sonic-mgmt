"""Offline unit tests for FrrConfigModeMigrator's backup/restore bookkeeping.

These run without a DUT: duthost is a fake that records shell commands and answers
``is_file_existed`` from an in-memory set of paths.

They cover the crash-recovery path specifically, because that path is the one that cannot be
exercised by a normal test run -- it only fires when a *previous* run died between
``to_frr_mgmt_framework()`` and ``cleanup()``.
"""
import pytest

from tests.common.helpers.frr.frr_config_mode_migrator import (
    FrrConfigModeMigrator,
    FrrTranslationError,
    CONFIG_DB_FILE,
    GOLDEN_CFG_FILE,
    GOLDEN_CFG_ORIGIN_FILE,
    SWITCHED_MARKER_FILE,
    _BAK_SUFFIX,
)

# Pure offline unit tests (no DUT). The topology marker is required by the CI
# markers check; 'any' lets them run in any collection without a testbed.
pytestmark = [
    pytest.mark.topology('any')
]

CONFIG_BAK = CONFIG_DB_FILE + _BAK_SUFFIX
GOLDEN_BAK = GOLDEN_CFG_FILE + _BAK_SUFFIX
ORIGIN_BAK = GOLDEN_CFG_ORIGIN_FILE + _BAK_SUFFIX


class FakeDutHost(object):
    """Minimal duthost stand-in: tracks which files exist and what shell ran."""

    hostname = "fake-dut"

    def __init__(self, files=(), config_db_tables=()):
        self.files = set(files)
        self.config_db_tables = list(config_db_tables)
        self.commands = []

    def is_file_existed(self, path):
        return path in self.files

    def shell(self, cmd, module_ignore_errors=False):
        self.commands.append(cmd)
        # Emulate the table listing used by assert_no_frr_schema_residue().
        if "CONFIG_DB KEYS" in cmd:
            return {"rc": 0, "stdout": "\n".join(self.config_db_tables)}
        # Emulate `cp src dst` so a restore is visible to later is_file_existed calls.
        parts = cmd.split()
        if "cp" in parts:
            self.files.add(parts[-1])
        if "rm" in parts:
            for path in parts:
                self.files.discard(path)
        return {"rc": 0, "stdout": ""}

    def ran(self, needle):
        return any(needle in c for c in self.commands)


def test_to_traditional_restores_from_backup_file_without_local_flag():
    """A fresh migrator must restore from a backup file it did not create itself.

    Regression test: gating on the in-process ``_backed_up`` flag made this a silent no-op,
    which is the whole of the crash-recovery path.
    """
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
    # The switch marker is what says a switch actually happened; the backups alone do not.
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_BAK,
                             SWITCHED_MARKER_FILE])
    migrator = FrrConfigModeMigrator(dut)

    assert migrator.recover_interrupted_run() is True
    assert dut.ran("cp {0} {1}".format(CONFIG_BAK, CONFIG_DB_FILE))
    assert dut.ran("rm -f")
    assert CONFIG_BAK not in dut.files


def test_recover_interrupted_run_is_noop_without_backups():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, GOLDEN_CFG_FILE])
    assert FrrConfigModeMigrator(dut).recover_interrupted_run() is False
    assert dut.commands == []


def test_recover_is_noop_when_backups_exist_but_no_switch_happened():
    """capture_pristine_backup() writes the backups at session start, before any switch is
    attempted. On a DUT that natively boots frrcfgd no switch ever happens, so treating the
    backups as evidence of one made a killed run "recover" by reloading the DUT's own native
    frr config -- which assert_no_frr_schema_residue() then rejected. Only the marker counts."""
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_BAK])
    assert FrrConfigModeMigrator(dut).recover_interrupted_run() is False
    assert dut.commands == []


def test_backup_never_overwrites_a_previous_runs_backup():
    """The existing backup is the only pristine pre-switch config; adopt it, never clobber it."""
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE])
    migrator = FrrConfigModeMigrator(dut)

    migrator._backup()
    assert migrator._backed_up is True
    assert not dut.ran("cp {0} {1}".format(CONFIG_DB_FILE, CONFIG_BAK))


def test_restore_raises_when_frr_tables_survive():
    """A restore that leaves frr-only tables behind must fail loudly, not poison later GCU."""
    dut = FakeDutHost(
        files=[CONFIG_DB_FILE, CONFIG_BAK],
        config_db_tables=["BGP_NEIGHBOR", "BGP_GLOBALS", "BGP_NEIGHBOR_AF", "PORT"],
    )
    with pytest.raises(FrrTranslationError) as excinfo:
        FrrConfigModeMigrator(dut).to_traditional()
    assert "BGP_GLOBALS" in str(excinfo.value)
    assert "BGP_NEIGHBOR_AF" in str(excinfo.value)


def test_restore_accepts_a_clean_traditional_config_db():
    dut = FakeDutHost(
        files=[CONFIG_DB_FILE, CONFIG_BAK],
        config_db_tables=["BGP_NEIGHBOR", "BGP_PEER_GROUP", "BGP_DEVICE_GLOBAL", "PORT"],
    )
    assert FrrConfigModeMigrator(dut).to_traditional() is True


def test_capture_pristine_backup_saves_then_backs_up():
    """The session-start capture must persist the running config first, else the backup is a
    stale on-disk copy rather than what is actually running."""
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


def test_backup_includes_the_golden_origin_backup():
    """restore_golden_config_db copies .origin.backup over golden at every module setup, so the
    origin file is part of the state a mode switch has to save and restore."""
    dut = FakeDutHost(files=[CONFIG_DB_FILE, GOLDEN_CFG_FILE, GOLDEN_CFG_ORIGIN_FILE])
    FrrConfigModeMigrator(dut)._backup()
    assert dut.ran("cp {0} {1}".format(GOLDEN_CFG_ORIGIN_FILE, ORIGIN_BAK))


def test_backup_skips_origin_when_the_dut_has_none():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, GOLDEN_CFG_FILE])
    FrrConfigModeMigrator(dut)._backup()
    assert not dut.ran(GOLDEN_CFG_ORIGIN_FILE)


def test_to_traditional_restores_the_golden_origin_backup():
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, GOLDEN_CFG_FILE, GOLDEN_BAK,
                             GOLDEN_CFG_ORIGIN_FILE, ORIGIN_BAK])
    assert FrrConfigModeMigrator(dut).to_traditional() is True
    assert dut.ran("cp {0} {1}".format(ORIGIN_BAK, GOLDEN_CFG_ORIGIN_FILE))


def test_cleanup_removes_the_golden_origin_backup():
    dut = FakeDutHost(files=[CONFIG_BAK, GOLDEN_BAK, ORIGIN_BAK])
    FrrConfigModeMigrator(dut).cleanup()
    assert ORIGIN_BAK not in dut.files
    assert CONFIG_BAK not in dut.files
    assert GOLDEN_BAK not in dut.files


def test_failed_restore_keeps_backups_for_manual_recovery():
    """If the restore cannot complete, the backups must survive -- deleting them is what turns
    a recoverable interruption into a permanently mis-configured DUT."""
    dut = FakeDutHost(
        files=[CONFIG_DB_FILE, CONFIG_BAK, SWITCHED_MARKER_FILE],
        config_db_tables=["BGP_GLOBALS"],
    )
    migrator = FrrConfigModeMigrator(dut)
    with pytest.raises(FrrTranslationError):
        migrator.recover_interrupted_run()
    assert CONFIG_BAK in dut.files
    assert not dut.ran("rm -f")
    # The switch marker must survive too: clearing it on a failed restore would make the
    # next run's interrupted_run_pending() read False, so recovery would never retry and
    # the DUT would stay stranded in translated frr config.
    assert SWITCHED_MARKER_FILE in dut.files


def test_to_traditional_clears_the_switch_marker():
    """Leaving the marker behind would make every later run think a switch is still pending."""
    dut = FakeDutHost(files=[CONFIG_DB_FILE, CONFIG_BAK, SWITCHED_MARKER_FILE])
    assert FrrConfigModeMigrator(dut).to_traditional() is True
    assert dut.ran("rm -f {}".format(SWITCHED_MARKER_FILE))


def test_cleanup_removes_the_switch_marker():
    dut = FakeDutHost(files=[CONFIG_BAK, GOLDEN_BAK, SWITCHED_MARKER_FILE])
    FrrConfigModeMigrator(dut).cleanup()
    assert SWITCHED_MARKER_FILE not in dut.files
