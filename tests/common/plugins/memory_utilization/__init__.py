import logging
import pytest
from tests.common.plugins.memory_utilization.memory_utilization import MemoryMonitor

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add this to store memory errors per test
_memory_errors_by_test = {}


def pytest_addoption(parser):
    parser.addoption(
        "--disable_memory_utilization",
        action="store_true",
        default=False,
        help="Disable memory utilization analysis for the 'memory_utilization' fixture"
    )
    parser.addoption(
        "--monit_polling_interval",
        type=int,
        default=None,
        help="Override the monit daemon polling interval (seconds) on the DUT "
             "for the duration of the pytest session. When set, the fixture "
             "reads the current `set daemon N` value from /etc/monit/monitrc on "
             "each DUT, replaces it with the provided value, reloads monit, and "
             "restores the original value at session teardown. A smaller value "
             "(e.g. 10) shrinks the stale-cache window and reduces the chance "
             "of false memory alarms. When not set (default), monit's polling "
             "interval is left unchanged."
    )


@pytest.fixture(scope="function", autouse=True)
def store_fixture_values(request, duthosts, memory_utilization):
    if request.config.getoption("--disable_memory_utilization") or "disable_memory_utilization" in request.keywords:
        return

    logger.debug("store memory_utilization {}".format(request.node.name))
    request.config.store_duthosts = duthosts
    request.config.store_memory_utilization = memory_utilization



# ---------------------------------------------------------------------------
# --monit_polling_interval support
#
# Optionally override monit's daemon polling interval at session scope by
# rewriting `set daemon N` in /etc/monit/monitrc and reloading monit, with a
# full-file backup so the original config can be restored even if the session
# crashes mid-run.
# ---------------------------------------------------------------------------

MONIT_RC_PATH = "/etc/monit/monitrc"
MONIT_RC_BACKUP_PATH = "/etc/monit/monitrc.copilot_memory_utilization.bak"


def _monit_rc_backup_exists(duthost):
    """Return True iff the monit_rc backup file already exists on the DUT."""
    res = duthost.shell("test -f {}".format(MONIT_RC_BACKUP_PATH), module_ignore_errors=True)
    return res.get("rc", 1) == 0


def _backup_monit_rc(duthost):
    """Copy /etc/monit/monitrc to the well-known backup path (preserving perms)."""
    duthost.shell("sudo cp -p {} {}".format(MONIT_RC_PATH, MONIT_RC_BACKUP_PATH))


def _restore_monit_rc(duthost):
    """Restore /etc/monit/monitrc from backup (if present) and reload monit."""
    if not _monit_rc_backup_exists(duthost):
        logger.warning(
            "No monit_rc backup found on %s at %s; skipping restore",
            duthost.hostname, MONIT_RC_BACKUP_PATH)
        return
    duthost.shell("sudo cp -p {} {}".format(MONIT_RC_BACKUP_PATH, MONIT_RC_PATH))
    duthost.shell("sudo rm -f {}".format(MONIT_RC_BACKUP_PATH))
    duthost.shell("sudo monit reload", module_ignore_errors=True)


def _read_monit_daemon_interval(duthost):
    """
    Read the current `set daemon N` value from /etc/monit/monitrc.

    Tolerates leading whitespace (sonic-buildimage indents the directive by two
    spaces) and any trailing inline comment. Returns the integer N on success
    or None if the directive cannot be located.
    """
    cmd = r"grep -m1 -oP '^\s*set daemon \K[0-9]+' " + MONIT_RC_PATH
    res = duthost.shell(cmd, module_ignore_errors=True)
    out = (res.get("stdout") or "").strip()
    if not out.isdigit():
        return None
    return int(out)


def _write_monit_daemon_interval(duthost, value):
    """
    Rewrite the integer in the `set daemon N` directive to `value` and reload monit.

    The sed regex captures the leading whitespace + literal text via group \1 so
    any indentation and any trailing inline comment on the line are preserved.
    """
    sed_expr = r"s/(^[[:space:]]*set daemon )[0-9]+/\1{}/".format(int(value))
    duthost.shell("sudo sed -i -E '{}' {}".format(sed_expr, MONIT_RC_PATH))
    duthost.shell("sudo monit reload", module_ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def override_monit_polling_interval(request, duthosts):
    """
    Temporarily override monit's daemon polling interval on each non-t2 DUT for
    the lifetime of the pytest session, restoring the original value at session
    teardown. No-op when --monit_polling_interval is not provided.
    """
    new_interval = request.config.getoption("--monit_polling_interval")
    if new_interval is None:
        yield
        return

    original_intervals = {}
    for duthost in duthosts:
        if duthost.topo_type == "t2":
            continue

        # Recover from a previous crashed session that left a backup behind.
        if _monit_rc_backup_exists(duthost):
            logger.warning(
                "Found leftover %s on %s from a previous session; restoring "
                "from backup before modifying monitrc",
                MONIT_RC_BACKUP_PATH, duthost.hostname)
            _restore_monit_rc(duthost)

        current = _read_monit_daemon_interval(duthost)
        if current is None:
            logger.warning(
                "Could not locate `set daemon N` in %s on %s; skipping override",
                MONIT_RC_PATH, duthost.hostname)
            continue

        # Create a fresh backup of the (original) live config, then verify it
        # exists before modifying. If the backup did not get created, skip the
        # modification on this DUT rather than leaving it in an inconsistent state.
        _backup_monit_rc(duthost)
        if not _monit_rc_backup_exists(duthost):
            logger.error(
                "Failed to create monit_rc backup at %s on %s; skipping override",
                MONIT_RC_BACKUP_PATH, duthost.hostname)
            continue

        logger.info(
            "[MemoryUtilization] overriding monit daemon polling interval on %s: %ss -> %ss",
            duthost.hostname, current, new_interval)
        _write_monit_daemon_interval(duthost, new_interval)
        original_intervals[duthost.hostname] = current

    yield

    for duthost in duthosts:
        if duthost.hostname not in original_intervals:
            continue
        logger.info(
            "[MemoryUtilization] restoring monit daemon polling interval on %s from backup",
            duthost.hostname)
        _restore_monit_rc(duthost)


def _compute_monit_retry_wait(config):
    """
    Pair the freshness-retry sleep with the monit daemon polling interval.

    - If --monit_polling_interval is NOT set: return None and let the freshness
      retry use the module-level MONIT_STATUS_FRESHNESS_WAIT_SECONDS default (60s).
    - If --monit_polling_interval is set: return polling_interval exactly.
      `sudo monit validate` is invoked immediately before reading status, so we
      are phase-aligned with the daemon and the next cycle is at most one
      polling_interval away.

    The fixture itself is session-scoped, so monit is reconfigured once at
    session start and restored once at session end, not per test.
    """
    polling = config.getoption("--monit_polling_interval")
    if polling is None:
        return None
    return polling


@pytest.hookimpl(trylast=True)
def pytest_runtest_setup(item):
    if "request" in item.fixturenames:
        request = item.funcargs.get("request", None)
        if request:
            if request.config.getoption("--disable_memory_utilization") or \
                    "disable_memory_utilization" in request.keywords:
                return

    logger.debug("collect memory before test {}".format(item.name))

    duthosts = getattr(item.config, 'store_duthosts', None)
    memory_utilization = getattr(item.config, 'store_memory_utilization', None)
    if duthosts is None and memory_utilization is None:
        return

    memory_monitors, memory_values = memory_utilization
    logger.debug("Memory monitors ready: {}".format(list(memory_monitors.keys()) if memory_monitors else "None"))
    logger.debug("memory_values {} ".format(memory_values))

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue

        # Trigger monit to refresh its cache so subsequent collection reads fresh data
        logger.info("Triggering monit refresh on {} before collecting memory data".format(duthost.hostname))
        validate_output = memory_monitors[duthost.hostname].execute_command("sudo monit validate")
        memory_monitors[duthost.hostname].record_monit_baseline_from_validate_output(validate_output)

        # Compute polling-aligned retry_wait (None falls back to module default)
        retry_wait = _compute_monit_retry_wait(item.config)
        if retry_wait is not None:
            logger.info(
                "[MemoryUtilization] [setup] DUT={} polling-aligned freshness-retry wait={}s "
                "(polling_interval={})".format(
                    duthost.hostname, retry_wait,
                    item.config.getoption('--monit_polling_interval')))

        # Initial memory check for all registered commands
        for name, cmd, memory_params, memory_check in memory_monitors[duthost.hostname].commands:
            try:
                if name == "monit":
                    output = memory_monitors[duthost.hostname].read_monit_status_with_freshness_retry(
                        cmd, retry_wait=retry_wait)
                else:
                    output = memory_monitors[duthost.hostname].execute_command(cmd)
                memory_values["before_test"][duthost.hostname][name] = memory_check(output, memory_params)
            except Exception as e:
                logger.warning("Error collecting initial memory data for {}: {}".format(name, str(e)))
                memory_values["before_test"][duthost.hostname][name] = {}

    logger.info("Before test: collected memory_values {}".format(memory_values))


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    if not hasattr(item, "rep_setup") or item.rep_setup.skipped or \
            not hasattr(item, "rep_call") or item.rep_call.skipped:
        return
    logger.debug("pytest_runtest_teardown early for test {}".format(item.name))
    if "request" in item.fixturenames:
        request = item.funcargs.get("request", None)
        if request:
            if request.config.getoption("--disable_memory_utilization") or \
                    "disable_memory_utilization" in request.keywords:
                return

    logger.debug("collect memory after test {}".format(item.name))

    duthosts = getattr(item.config, 'store_duthosts', None)
    memory_utilization = getattr(item.config, 'store_memory_utilization', None)
    if duthosts is None and memory_utilization is None:
        return

    memory_monitors, memory_values = memory_utilization
    memory_errors = []

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue

        # Trigger monit to refresh its cache so subsequent collection reads fresh data
        logger.info("Triggering monit refresh on {} before collecting memory data".format(duthost.hostname))
        validate_output = memory_monitors[duthost.hostname].execute_command("sudo monit validate")
        memory_monitors[duthost.hostname].record_monit_baseline_from_validate_output(validate_output)

        # Compute polling-aligned retry_wait (None falls back to module default)
        retry_wait = _compute_monit_retry_wait(item.config)
        if retry_wait is not None:
            logger.info(
                "[MemoryUtilization] [teardown] DUT={} polling-aligned freshness-retry wait={}s "
                "(polling_interval={})".format(
                    duthost.hostname, retry_wait,
                    item.config.getoption('--monit_polling_interval')))

        # memory check for all registered commands
        for name, cmd, memory_params, memory_check in memory_monitors[duthost.hostname].commands:
            try:
                if name == "monit":
                    output = memory_monitors[duthost.hostname].read_monit_status_with_freshness_retry(
                        cmd, retry_wait=retry_wait)
                else:
                    output = memory_monitors[duthost.hostname].execute_command(cmd)
                memory_values["after_test"][duthost.hostname][name] = memory_check(output, memory_params)
            except Exception as e:
                logger.warning("Error collecting final memory data for {}: {}".format(name, str(e)))
                memory_values["after_test"][duthost.hostname][name] = {}

        # Only check thresholds if we have data to compare
        if any(memory_values["before_test"][duthost.hostname]) and any(memory_values["after_test"][duthost.hostname]):
            try:
                memory_monitors[duthost.hostname].check_memory_thresholds(
                    memory_values["after_test"][duthost.hostname], memory_values["before_test"][duthost.hostname])

                # Check if any memory errors were detected
                if memory_monitors[duthost.hostname].has_memory_errors():
                    memory_errors.extend(memory_monitors[duthost.hostname].get_memory_errors())
                    memory_monitors[duthost.hostname].clear_memory_errors()

            except Exception as e:
                logger.error("Error checking memory thresholds: {}".format(str(e)))
        else:
            logger.warning("Skipping memory threshold check for {} due to missing data".format(duthost.hostname))

        # Store any detected errors for this test
        if memory_errors:
            _memory_errors_by_test[item.nodeid] = memory_errors
            logger.error("Memory errors detected: {}".format("\n".join(memory_errors)))

    logger.info("After test: collected memory_values {}".format(memory_values))


@pytest.fixture(autouse=True)
def memory_utilization(duthosts, request):
    if request.config.getoption("--disable_memory_utilization") or "disable_memory_utilization" in request.keywords:
        logger.info("Memory utilization monitoring is disabled")
        yield None, None
        return

    memory_monitors = {}
    memory_values = {"before_test": {}, "after_test": {}}

    for duthost in duthosts:
        if duthost.topo_type == 't2':
            continue
        memory_monitor = MemoryMonitor(ansible_host=duthost)
        memory_values["before_test"][duthost.hostname] = {}
        memory_values["after_test"][duthost.hostname] = {}
        logger.info("Hostname: {}, Hwsku: {}, Platform: {}".format(
            duthost.hostname, duthost.sonichost._facts["hwsku"], duthost.sonichost._facts["platform"]))
        memory_monitor.parse_and_register_commands(hwsku=duthost.sonichost._facts["hwsku"])
        memory_monitors[duthost.hostname] = memory_monitor

    yield memory_monitors, memory_values

    # Check if we stored any memory errors for this test
    if request.node.nodeid in _memory_errors_by_test:
        errors = _memory_errors_by_test.pop(request.node.nodeid)
        if errors:
            failure_message = "\n".join(errors)
            logger.error(f"Memory errors detected in fixture teardown: {failure_message}")
            pytest.fail(failure_message)

    logger.debug("Memory utilization fixture cleanup")
