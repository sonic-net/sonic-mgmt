import shlex


CONFIG_DB_LOCK_FILE = "/tmp/sonic_mgmt_config_db.lock"
CONFIG_DB_LOCK_TIMEOUT = 600


def run_config_db_command(duthost, command, **kwargs):
    """
    Run a CONFIG_DB command under a DUT-local cross-process lock.

    The lock coordinates independent pytest and MARS processes that share a
    DUT, preventing CONFIG_DB writes from overlapping consistency checks.
    """
    payload = shlex.quote(command)
    locked_command = (
        f"sudo flock -x -w {CONFIG_DB_LOCK_TIMEOUT} "
        f"{CONFIG_DB_LOCK_FILE} sh -c {payload}"
    )
    return duthost.shell(locked_command, **kwargs)
