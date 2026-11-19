"""
Unit tests for ``tests/common/helpers/logger_row.py`` against a fake DUT that
behaves like an older image (every daemon has a CONFIG_DB LOGGER row) or a
newer one (no row until configured, effective level in STATE_DB LOGGER_TABLE).

Run with --noconftest.
"""

import shlex
from importlib import util
from pathlib import Path

import pytest

# Loaded by path: importing the tests.common package pulls in the whole framework.
_SPEC = util.spec_from_file_location(
    "logger_row", Path(__file__).resolve().parents[2] / "helpers" / "logger_row.py")
logger_row = util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(logger_row)


class CommandFailed(Exception):
    pass


class FakeDut(object):
    """Answers the sonic-db-cli and swssloglevel commands the helper runs,
    behind any prefix such as "docker exec swss" or "-n asic0"."""

    def __init__(self, config=None, state=None, broken=False):
        self.db = {"CONFIG_DB": dict(config or {}), "STATE_DB": dict(state or {})}
        self.broken = broken
        self.commands = []

    def shell(self, cmd, module_ignore_errors=False):
        self.commands.append(cmd)
        args = shlex.split(cmd)
        if self.broken:
            if not module_ignore_errors:
                raise CommandFailed(cmd)
            return {"stdout": "", "stdout_lines": []}
        out = ""
        if "swssloglevel" in args and "-p" in args:
            names = set(k.split("|", 1)[1] for k in self.db["CONFIG_DB"]) | \
                set(k.split("|", 1)[1] for k in self.db["STATE_DB"])
            lines = []
            for name in sorted(names):
                row = self.db["CONFIG_DB"].get("LOGGER|" + name) or self.db["STATE_DB"].get("LOGGER_TABLE|" + name)
                lines.append("{:<30}{}".format(name, row["LOGLEVEL"]))
            out = "\n".join(lines)
        elif "sonic-db-cli" in args:
            args = args[args.index("sonic-db-cli") + 1:]
            if args[0] == "-n":
                args = args[2:]
            db, op, key = args[0], args[1], args[2]
            table = self.db[db]
            if op == "EXISTS":
                out = "1" if key in table else "0"
            elif op == "HGET":
                out = table.get(key, {}).get(args[3], "")
            elif op == "HSET":
                table.setdefault(key, {})[args[3]] = args[4]
            elif op == "HDEL":
                table.get(key, {}).pop(args[3], None)
            elif op == "DEL":
                table.pop(key, None)
        return {"stdout": out, "stdout_lines": out.splitlines()}


ROW = {"LOGLEVEL": "NOTICE", "LOGOUTPUT": "SYSLOG"}
OLD_IMAGE = {"config": {"LOGGER|orchagent": dict(ROW)}}
NEW_IMAGE = {"state": {"LOGGER_TABLE|orchagent": dict(ROW)}}


@pytest.mark.parametrize("image", [OLD_IMAGE, NEW_IMAGE], ids=["old_image", "new_image"])
@pytest.mark.parametrize("db_cli", ["sonic-db-cli", "sonic-db-cli -n asic0", "docker exec swss sonic-db-cli"])
def test_restore_leaves_config_db_as_found(image, db_cli):
    dut = FakeDut(**image)
    before = {k: dict(v) for k, v in dut.db["CONFIG_DB"].items()}

    saved = logger_row.save_logger_row(dut, "orchagent", db_cli=db_cli)
    assert saved["level"] == "NOTICE"
    logger_row.set_log_level(dut, "orchagent", "DEBUG", db_cli=db_cli)
    assert dut.db["CONFIG_DB"]["LOGGER|orchagent"]["LOGLEVEL"] == "DEBUG"

    logger_row.restore_logger_row(dut, saved)
    assert dut.db["CONFIG_DB"] == before
    assert all(c.startswith(db_cli) for c in dut.commands if "sonic-db-cli" in c)


def test_old_image_without_row_keeps_restored_level():
    """An older daemon ignores a deleted row, so the row keeps the saved level."""
    dut = FakeDut()
    saved = logger_row.save_logger_row(dut, "orchagent", default="NOTICE")
    logger_row.set_log_level(dut, "orchagent", "DEBUG")
    logger_row.restore_logger_row(dut, saved)
    assert dut.db["CONFIG_DB"] == {"LOGGER|orchagent": {"LOGLEVEL": "NOTICE"}}


def test_configured_row_is_kept_with_its_level():
    dut = FakeDut(config={"LOGGER|orchagent": {"LOGLEVEL": "INFO"}},
                  state={"LOGGER_TABLE|orchagent": {"LOGLEVEL": "INFO", "LOGOUTPUT": "SYSLOG"}})
    saved = logger_row.save_logger_row(dut, "orchagent")
    logger_row.set_log_level(dut, "orchagent", "DEBUG")
    logger_row.restore_logger_row(dut, saved)
    assert dut.db["CONFIG_DB"] == {"LOGGER|orchagent": {"LOGLEVEL": "INFO"}}


def test_row_without_loglevel_is_restored_without_it():
    dut = FakeDut(config={"LOGGER|orchagent": {"LOGOUTPUT": "STDERR"}},
                  state={"LOGGER_TABLE|orchagent": {"LOGLEVEL": "NOTICE", "LOGOUTPUT": "STDERR"}})
    saved = logger_row.save_logger_row(dut, "orchagent")
    logger_row.set_log_level(dut, "orchagent", "DEBUG")
    logger_row.restore_logger_row(dut, saved)
    assert dut.db["CONFIG_DB"] == {"LOGGER|orchagent": {"LOGOUTPUT": "STDERR"}}


def test_configured_level_wins_over_effective_level():
    # A process that applies a change only on SIGHUP still runs NOTICE while
    # its row says INFO; restore puts back the configured INFO.
    dut = FakeDut(config={"LOGGER|xcvrd": {"LOGLEVEL": "INFO"}},
                  state={"LOGGER_TABLE|xcvrd": {"LOGLEVEL": "NOTICE", "LOGOUTPUT": "SYSLOG"}})
    saved = logger_row.save_logger_row(dut, "xcvrd")
    logger_row.set_log_level(dut, "xcvrd", "DEBUG")
    logger_row.restore_logger_row(dut, saved)
    assert dut.db["CONFIG_DB"] == {"LOGGER|xcvrd": {"LOGLEVEL": "INFO"}}


def test_failed_lookup_raises_rather_than_guessing():
    """A failed EXISTS must not read as "absent", or restore would delete a real row."""
    with pytest.raises(CommandFailed):
        logger_row.save_logger_row(FakeDut(broken=True), "orchagent")


def test_level_falls_back_to_swssloglevel_then_default():
    dut = FakeDut()
    assert logger_row.get_log_level(dut, "orchagent", default="NOTICE") == "NOTICE"
    assert logger_row.get_log_level(dut, "orchagent", loglevel_cli=None) is None
    dut = FakeDut(config={"LOGGER|orchagent": {"LOGLEVEL": "WARN"}})
    assert logger_row.get_log_level(dut, "orchagent") == "WARN"
