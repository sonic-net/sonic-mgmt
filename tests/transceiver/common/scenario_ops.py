"""Reusable, feature-agnostic scenario helpers for transceiver tests.

Shared half of the scenario-coverage model
(``docs/testplan/transceiver/scenario_test_template.md``): a scenario pairs a
``perform_<op>`` from here with a feature-owned ``verify_<feature>_*`` verifier,
so EEPROM/DOM/VDM/PM reuse the same disruptive operations. Each ``perform_<op>``
wraps the canonical repo helper (``reboot`` / ``config_reload`` /
``restart_service`` / ...) — never an inlined reboot/reload/restart.

Two operation shapes:
* Whole-DUT operations (reboot, config reload, daemon restart) raise (via the
    wrapped repo helper) on failure — there is no per-port outcome to aggregate;
    the feature verifier owns pass/fail. Daemon restart returns its unused settle
    budget so the operation and verifier share one deadline.
* Port-scoped operations (bulk shut/startup, sfputil reset) act on a list of
    ports and return per-port failure strings for the caller to aggregate into one
    ``pytest.fail``.

Alongside the operations this module holds the feature-agnostic wait/poll
utilities both halves compose with: ``scale_bulk_wait`` (operation settle
budgets) and ``poll_ports_recovered`` (the verifier recovery-poll loop).
"""

import logging
import time

import pytest

from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import get_program_info
from tests.common.platform.interface_utils import wait_ports_oper_status
from tests.common.platform.processes_utils import get_docker_started_at
from tests.common.reboot import reboot
from tests.transceiver.common import cli_helpers
from tests.transceiver.common.health_checks import DEFAULT_MONITORED_PROCESSES

logger = logging.getLogger(__name__)

# Processes that must be RUNNING after each supported daemon operation.
DAEMON_READY_PROCESSES = {
    "xcvrd": ("xcvrd",),
    "pmon": ("xcvrd",),
    "swss": ("syncd", "orchagent"),
    "syncd": ("syncd", "orchagent"),
}
DAEMON_RESTART_CONTAINERS = {
    "xcvrd": (),
    "pmon": ("pmon",),
    "swss": ("swss", "syncd"),
    "syncd": ("syncd",),
}
DAEMON_RESTART_POLL_INTERVAL_SEC = 5


def _parse_supervisor_uptime_seconds(uptime):
    """Convert supervisor's ``[N days, ]H:MM:SS`` uptime to seconds."""
    days = 0
    if "day" in uptime:
        day_part, uptime = uptime.split(", ", 1)
        days = int(day_part.split()[0])
    hours, minutes, seconds = (int(part) for part in uptime.split(":"))
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def _get_process_start_time_range(duthost, container, process):
    """Estimate process start-time bounds from whole-second supervisor uptime."""
    query_started_at = time.monotonic()
    status, _pid, uptime = get_program_info(
        duthost, container, process, include_uptime=True
    )
    query_finished_at = time.monotonic()
    if status != "RUNNING" or not uptime:
        return status, uptime, None
    uptime_seconds = _parse_supervisor_uptime_seconds(uptime)
    return status, uptime, (
        query_started_at - uptime_seconds - 1,
        query_finished_at - uptime_seconds,
    )


def _get_service_containers(duthost, service):
    """Return the host-level or per-ASIC container names for ``service``."""
    if service in duthost.get_default_critical_services_list():
        return (service,)
    return tuple(asic.get_docker_name(service) for asic in duthost.asics)


def _wait_until_deadline(deadline, interval, condition):
    """Poll ``condition`` without sleeping past a monotonic deadline."""
    while time.monotonic() < deadline:
        try:
            if condition():
                return time.monotonic() <= deadline
        except (Exception, pytest.fail.Exception):
            logger.exception(
                "Error while polling %s",
                getattr(condition, "__name__", type(condition).__name__),
            )
        remaining_sec = deadline - time.monotonic()
        if remaining_sec > 0:
            time.sleep(min(interval, remaining_sec))
    return False


# Base port count for scaling a *per-port* settle wait up to a *bulk*
# (all-at-once) operation, matching ``tests/common/port_toggle.BASE_PORT_COUNT``
# (the default t0 topology's ~28 toggled ports).
BASE_PORT_COUNT = 28.0


def scale_bulk_wait(per_port_wait_sec, num_ports):
    """Scale a per-port settle wait to a bulk (all-at-once) operation budget.

    A bulk shut/startup of ``num_ports`` ports settles slower than a single port,
    so the per-port attribute (``port_startup_wait_sec`` /
    ``port_shutdown_wait_sec``) is multiplied by
    ``max(1, num_ports / BASE_PORT_COUNT)`` — the same port-count scaling
    ``tests/common/port_toggle.default_port_toggle_wait_time`` uses. Because
    ``wait_until`` polls and returns the instant every port settles, this only
    raises the give-up ceiling; it never lengthens a fast run, so over-estimating
    on a large fabric (e.g. 512 ports) is free.
    """
    factor = max(1.0, num_ports / BASE_PORT_COUNT)
    return int(per_port_wait_sec * factor)


def poll_ports_recovered(check_fn, wait_sec, interval_sec, label):
    """Poll ``check_fn`` until it reports no per-port failures or ``wait_sec``
    elapses; log the still-failing count each time it changes.

    Shared verifier-side recovery loop: a ``verify_<feature>_recovered`` verifier
    supplies a ``check_fn`` and gets back the aggregated failures.

    Args:
        check_fn: zero-arg callable returning a list of per-port failure strings
            (empty once every port under test has recovered).
        wait_sec: max poll time; ``<= 0`` does a single snapshot (no polling).
        interval_sec: seconds between polls.
        label: prefix for the progress log line (e.g. ``"DataPath"``).

    Returns:
        list[str]: the final per-port failures, or ``[]`` once all recover.
    """
    deadline = time.monotonic() + wait_sec
    failures = check_fn()
    if not failures or wait_sec <= 0:
        return failures

    state = {"latest": failures, "last_count": None}

    def _recovered():
        state["latest"] = check_fn()
        count = len(state["latest"])
        if count and count != state["last_count"]:
            logger.info("%s recovery poll: %d item(s) still not recovered", label, count)
        state["last_count"] = count
        return not state["latest"]

    if not _wait_until_deadline(deadline, interval_sec, _recovered):
        return state["latest"]
    return []


def _perform_reboot(duthost, localhost, reboot_type):
    """Reboot the DUT via the repo helper, returning once SSH reconnects.

    Args:
        localhost: controller fixture used to observe SSH loss/recovery.
        reboot_type: one of ``cold`` / ``warm`` / ``fast``.
    """
    logger.info("Performing %s reboot for transceiver scenario", reboot_type)
    reboot(
        duthost,
        localhost,
        reboot_type=reboot_type,
        return_after_reconnect=True,
    )


def perform_cold_reboot(duthost, localhost):
    """Perform a cold reboot and return when DUT SSH connectivity is restored."""
    _perform_reboot(duthost, localhost, "cold")


def perform_warm_reboot(duthost, localhost):
    """Perform a warm reboot and return when DUT SSH connectivity is restored."""
    _perform_reboot(duthost, localhost, "warm")


def perform_fast_reboot(duthost, localhost):
    """Perform a fast reboot and return when DUT SSH connectivity is restored."""
    _perform_reboot(duthost, localhost, "fast")


def perform_config_reload(duthost):
    """Reload CONFIG_DB through the canonical repository helper.

    ``yang_validate=False`` because transceiver tests do not own CONFIG_DB YANG
    validity; the strict gate trips on framework/config quirks (e.g.
    ``zebra_nexthop``) unrelated to transceivers. Matches the widespread repo
    idiom for disruptive config-reload tests.
    """
    logger.info("Performing config reload for transceiver scenario")
    config_reload(duthost, wait=0, yang_validate=False)


def perform_daemon_restart(duthost, daemon, settle_sec, affected_processes=None):
    """Restart a transceiver-related process/container and return the unused
    portion of its post-command settle budget.

    Args:
        daemon: ``xcvrd`` (supervisor process in ``pmon``) or a container
            (``pmon`` / ``swss`` / ``syncd``).
        settle_sec: maximum time for affected processes to complete their
            restart transitions.
        affected_processes: monitored processes that must return to ``RUNNING``.
            Defaults to the processes directly affected by ``daemon``.

    Returns:
        float: seconds remaining in ``settle_sec`` after process restart
            polling.
    """
    if affected_processes is None:
        affected_processes = DAEMON_READY_PROCESSES[daemon]
    affected_process_containers = tuple(
        (process, container)
        for process in affected_processes
        for container in _get_service_containers(
            duthost, DEFAULT_MONITORED_PROCESSES[process]
        )
    )
    directly_restarted_containers = tuple(
        container
        for service in DAEMON_RESTART_CONTAINERS[daemon]
        for container in _get_service_containers(duthost, service)
    )
    indirectly_restarted_processes = (
        set(affected_processes) - set(DAEMON_READY_PROCESSES[daemon])
    )
    baseline_container_start_times = {
        container: get_docker_started_at(duthost, container)
        for container in directly_restarted_containers
    }
    pytest_assert(
        all(baseline_container_start_times.values()),
        "Could not capture container start times before {} restart: {}"
        .format(daemon, baseline_container_start_times),
    )
    baseline_process_latest_started_at = {}
    for process in indirectly_restarted_processes:
        container = DEFAULT_MONITORED_PROCESSES[process]
        status, uptime, start_time_range = _get_process_start_time_range(
            duthost, container, process
        )
        pytest_assert(
            start_time_range is not None,
            "Could not capture {} uptime before {} restart: status={}, uptime={}"
            .format(process, daemon, status, uptime),
        )
        baseline_process_latest_started_at[process] = start_time_range[1]
    if daemon == "xcvrd":
        logger.info("Restarting xcvrd inside pmon for transceiver scenario")
        duthost.command("docker exec pmon supervisorctl restart xcvrd")
    else:
        logger.info("Restarting %s container for transceiver scenario", daemon)
        duthost.restart_service(daemon)

    settle_deadline = time.monotonic() + settle_sec
    last_process_states = {}
    last_container_start_times = {}
    last_process_uptimes = {}

    def _processes_restarted():
        last_process_states.clear()
        for process, container in affected_process_containers:
            last_process_states["{}@{}".format(process, container)] = get_program_info(
                duthost, container, process
            )
        if not all(status == "RUNNING" for status, _pid in last_process_states.values()):
            return False
        last_process_uptimes.clear()
        for process in indirectly_restarted_processes:
            container = DEFAULT_MONITORED_PROCESSES[process]
            _status, uptime, start_time_range = _get_process_start_time_range(
                duthost, container, process
            )
            last_process_uptimes[process] = uptime
            if (start_time_range is None
                    or start_time_range[0]
                    <= baseline_process_latest_started_at[process]):
                return False
        if daemon == "xcvrd":
            return True
        last_container_start_times.clear()
        for container in directly_restarted_containers:
            last_container_start_times[container] = get_docker_started_at(duthost, container)
        return all(
            last_container_start_times[container]
            and last_container_start_times[container] != baseline_container_start_times[container]
            for container in directly_restarted_containers
        )

    pytest_assert(
        _wait_until_deadline(
            settle_deadline, DAEMON_RESTART_POLL_INTERVAL_SEC, _processes_restarted
        ),
        "Processes did not complete restart after {} restart: processes={}, "
        "process_uptimes={}, containers={}"
        .format(daemon, last_process_states, last_process_uptimes,
                last_container_start_times),
    )
    return max(0, settle_deadline - time.monotonic())


def perform_sfputil_reset(duthost, reset_ports, toggle_ports, shutdown_wait_sec, startup_wait_sec,
                          recover_wait_sec=0):
    """Shut every toggle port, sfputil-reset each module, start them back up.

    ``sfputil reset <port>`` resets a whole physical module, dropping every
    subport's datapath, so recovery toggles all of ``toggle_ports`` (every
    subport of every reset module). All modules are reset within one bulk
    shut/startup cycle (not one cycle per module), matching the other whole-DUT
    scenario operations. EEPROM re-readability (the real I2C-recovery signal) is
    owned by the feature verifier's poll, so this operation does not gate on
    presence.

    Args:
        reset_ports: ports to issue ``sfputil reset`` on (one per module).
        toggle_ports: every subport to shut before / start after the resets.
        recover_wait_sec: settle time between the resets and the startup.

    Returns:
        list[str]: operation failures for the caller to aggregate.
    """
    logger.info("sfputil reset of %d module(s), toggling %d port(s)",
                len(reset_ports), len(toggle_ports))
    failures = perform_ports_shutdown(duthost, toggle_ports, shutdown_wait_sec)

    try:
        for port in reset_ports:
            elapsed, err = cli_helpers.sfputil_reset(duthost, port)
            logger.info("sfputil reset of %s took %ss", port, elapsed)
            if err:
                logger.warning("%s", err)
                failures.append(err)
        if recover_wait_sec:
            time.sleep(recover_wait_sec)
    finally:
        failures += perform_ports_startup(duthost, toggle_ports, startup_wait_sec)

    return failures


def perform_ports_shutdown(duthost, ports, wait_sec):
    """Admin-down all ``ports`` (one bulk config) then wait until each is oper-down.

    Uses the canonical ``SonicHost.shutdown_multiple`` (single ``config interface
    shutdown <p1>,<p2>,...``). Returns a list of per-port failure strings, one per
    port that did not reach oper-down within ``wait_sec``; empty when all did.
    """
    if not ports:
        logger.debug("perform_ports_shutdown called with no ports; nothing to do")
        return []
    duthost.shutdown_multiple(ports)
    logger.info("Admin-down issued for %d port(s); waiting up to %ss for oper-down",
                len(ports), wait_sec)
    failures = wait_ports_oper_status(duthost, ports, "down", wait_sec)
    if failures:
        for failure in failures:
            logger.warning("%s", failure)
    else:
        logger.info("All %d port(s) reached oper-down", len(ports))
    return failures


def perform_ports_startup(duthost, ports, wait_sec):
    """Admin-up all ``ports`` (one bulk config) then wait until each is oper-up.

    Uses the canonical ``SonicHost.no_shutdown_multiple`` (single ``config
    interface startup <p1>,<p2>,...``). Returns a list of per-port failure
    strings, one per port that did not reach oper-up within ``wait_sec``; empty
    when all did.
    """
    if not ports:
        logger.debug("perform_ports_startup called with no ports; nothing to do")
        return []
    duthost.no_shutdown_multiple(ports)
    logger.info("Admin-up issued for %d port(s); waiting up to %ss for oper-up",
                len(ports), wait_sec)
    failures = wait_ports_oper_status(duthost, ports, "up", wait_sec)
    if failures:
        for failure in failures:
            logger.warning("%s", failure)
    else:
        logger.info("All %d port(s) reached oper-up", len(ports))
    return failures


def verify_lpmode(duthost, port, low_power):
    """Return failures if ``port``'s module is not in the expected power mode."""
    expected = "On" if low_power else "Off"
    lpmode, err = cli_helpers.sfputil_show_lpmode(duthost, port)
    if err:
        return [err]
    actual = lpmode.get(port)
    logger.info("Port %s: low-power mode is %s (expected %s)", port, actual, expected)
    if actual != expected:
        return [f"port {port} low-power mode is {actual or 'unknown'}, expected {expected}"]
    return []


def perform_lpmode_set(duthost, port, low_power=True):
    """Move ``port``'s module into (``low_power=True``) or out of low-power mode.

    Returns a list of per-port failure strings.
    """
    elapsed, err = cli_helpers.sfputil_set_lpmode(duthost, port, low_power)
    logger.info("Port %s: lpmode %s took %ss", port, "on" if low_power else "off", elapsed)
    if err:
        return [err]
    return verify_lpmode(duthost, port, low_power)
