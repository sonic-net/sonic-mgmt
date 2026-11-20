"""Save and restore a component's CONFIG_DB LOGGER row around a test.

save_logger_row reads, before the test changes a level:
- whether CONFIG_DB LOGGER|<component> exists, and its LOGLEVEL;
- the current level: STATE_DB LOGGER_TABLE|<component> LOGLEVEL, else the
  CONFIG_DB LOGLEVEL, else ``swssloglevel -p``;
- whether STATE_DB holds any LOGGER_TABLE|* key.

restore_logger_row deletes a row the test created when STATE_DB held
LOGGER_TABLE keys, taking that to mean a deleted row returns the daemon to
its default. Otherwise it writes the saved level back to the row, so a row
that was absent is left holding that level: CONFIG_DB ends as found only when
the row existed or STATE_DB held LOGGER_TABLE keys.
"""

import logging

logger = logging.getLogger(__name__)


def _db(duthost, db_cli, args, strict=False):
    """Run a sonic-db-cli command; a read that may fail softly passes strict=False."""
    return duthost.shell("{} {}".format(db_cli, args), module_ignore_errors=not strict)["stdout"].strip()


def _restore_write(duthost, db_cli, args):
    """A teardown write: a failure is logged rather than raised, so the rest
    of the caller's cleanup still runs."""
    res = duthost.shell("{} {}".format(db_cli, args), module_ignore_errors=True)
    if res.get("failed") or res.get("rc"):
        logger.warning("Restoring the LOGGER row failed: %s %s: %s", db_cli, args, res.get("stderr", ""))


def logger_row_exists(duthost, component, db_cli="sonic-db-cli"):
    return _db(duthost, db_cli, "CONFIG_DB EXISTS 'LOGGER|{}'".format(component), strict=True) == "1"


def _state_has_logger_table(duthost, db_cli):
    """Whether STATE_DB holds any LOGGER_TABLE key. Asked of the whole table,
    not one component, so a component without a row of its own (a SAI API
    category, a daemon mid-restart) does not decide it; a failed read raises."""
    return bool(_db(duthost, db_cli, "STATE_DB KEYS 'LOGGER_TABLE|*'", strict=True))


def get_log_level(duthost, component, db_cli="sonic-db-cli", loglevel_cli="swssloglevel", default=None):
    """The component's current level: STATE_DB, then CONFIG_DB, then swssloglevel -p."""
    for db, key in (("STATE_DB", "LOGGER_TABLE"), ("CONFIG_DB", "LOGGER")):
        level = _db(duthost, db_cli, "{} HGET '{}|{}' LOGLEVEL".format(db, key, component))
        if level:
            return level
    if loglevel_cli:
        for line in duthost.shell("{} -p".format(loglevel_cli), module_ignore_errors=True)["stdout_lines"]:
            fields = line.split()
            if len(fields) == 2 and fields[0] == component:
                return fields[1]
    return default


def save_logger_row(duthost, component, db_cli="sonic-db-cli", loglevel_cli="swssloglevel", default=None):
    """Record what restore_logger_row needs; the reads it branches on raise on failure."""
    existed = logger_row_exists(duthost, component, db_cli)
    configured = _db(duthost, db_cli, "CONFIG_DB HGET 'LOGGER|{}' LOGLEVEL".format(component),
                     strict=True) if existed else ""
    return {
        "component": component,
        "db_cli": db_cli,
        "existed": existed,
        "configured": configured,
        "level": get_log_level(duthost, component, db_cli, loglevel_cli, default),
        "state_has_logger_table": _state_has_logger_table(duthost, db_cli),
    }


def set_log_level(duthost, component, level, db_cli="sonic-db-cli"):
    _db(duthost, db_cli, "CONFIG_DB HSET 'LOGGER|{}' LOGLEVEL {}".format(component, level), strict=True)


def restore_logger_row(duthost, saved):
    """Delete the row if the test created it and STATE_DB held LOGGER_TABLE
    keys at save time; otherwise put the saved level back, preferring the
    row's own configured LOGLEVEL.

    Without LOGGER_TABLE keys a row that was absent keeps the saved level. A
    row that existed without LOGLEVEL gets the field removed again once the
    daemon has been set back to the saved level. A Python daemon applies any
    of this only on SIGHUP. Writes are best-effort: a failure is logged.
    """
    component, db_cli = saved["component"], saved["db_cli"]
    key = "'LOGGER|{}'".format(component)
    if not saved["existed"] and saved["state_has_logger_table"]:
        _restore_write(duthost, db_cli, "CONFIG_DB DEL {}".format(key))
        return
    level = saved["configured"] or saved["level"]
    if level:
        _restore_write(duthost, db_cli, "CONFIG_DB HSET {} LOGLEVEL {}".format(key, level))
    if saved["existed"] and not saved["configured"] and saved["state_has_logger_table"]:
        _restore_write(duthost, db_cli, "CONFIG_DB HDEL {} LOGLEVEL".format(key))
