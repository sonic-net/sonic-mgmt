"""Save and restore a component's CONFIG_DB LOGGER row around a test.

A test that changes a log level must leave CONFIG_DB as it found it. On older
images every daemon writes its own LOGGER row at start; on newer ones an absent
row means the daemon's default, the effective level is in STATE_DB
LOGGER_TABLE, and deleting the row returns the daemon to its default. These
helpers work on both.
"""


def _db(duthost, db_cli, args, strict=False):
    """Run a sonic-db-cli command; a read that may fail softly passes strict=False."""
    return duthost.shell("{} {}".format(db_cli, args), module_ignore_errors=not strict)["stdout"].strip()


def logger_row_exists(duthost, component, db_cli="sonic-db-cli"):
    return _db(duthost, db_cli, "CONFIG_DB EXISTS 'LOGGER|{}'".format(component), strict=True) == "1"


def _publishes_state(duthost, component, db_cli):
    """Whether the image publishes LOGGER_TABLE, and so reverts a deleted row to the default."""
    return _db(duthost, db_cli, "STATE_DB EXISTS 'LOGGER_TABLE|{}'".format(component)) == "1"


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
    """Record whether the row exists, its configured LOGLEVEL and the current
    level, for restore_logger_row."""
    existed = logger_row_exists(duthost, component, db_cli)
    return {
        "component": component,
        "db_cli": db_cli,
        "existed": existed,
        "configured": _db(duthost, db_cli, "CONFIG_DB HGET 'LOGGER|{}' LOGLEVEL".format(component)) if existed else "",
        "level": get_log_level(duthost, component, db_cli, loglevel_cli, default),
    }


def set_log_level(duthost, component, level, db_cli="sonic-db-cli"):
    _db(duthost, db_cli, "CONFIG_DB HSET 'LOGGER|{}' LOGLEVEL {}".format(component, level), strict=True)


def restore_logger_row(duthost, saved):
    """Delete the row if the test created it and the image reverts a deleted
    row to the default; otherwise put the saved level back, preferring the
    row's own configured LOGLEVEL.

    A daemon on an older image ignores a deleted row, so there the row keeps
    the saved level. A row that existed without LOGLEVEL gets the field
    removed again once the daemon has been set back to the saved level.
    A Python daemon applies any of this only on SIGHUP.
    """
    component, db_cli = saved["component"], saved["db_cli"]
    if not saved["existed"] and _publishes_state(duthost, component, db_cli):
        _db(duthost, db_cli, "CONFIG_DB DEL 'LOGGER|{}'".format(component), strict=True)
        return
    if saved.get("configured") or saved["level"]:
        set_log_level(duthost, component, saved.get("configured") or saved["level"], db_cli)
    if saved["existed"] and not saved.get("configured") and _publishes_state(duthost, component, db_cli):
        _db(duthost, db_cli, "CONFIG_DB HDEL 'LOGGER|{}' LOGLEVEL".format(component), strict=True)
