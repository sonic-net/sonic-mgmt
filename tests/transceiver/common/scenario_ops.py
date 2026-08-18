"""Reusable, feature-agnostic scenario helpers for transceiver tests.

Shared half of the scenario-coverage model
(``docs/testplan/transceiver/scenario_test_template.md``): a scenario pairs a
``perform_<op>`` from here with a feature-owned ``verify_<feature>_*`` verifier,
so EEPROM/DOM/VDM/PM reuse the same disruptive operations. Each ``perform_<op>``
wraps the canonical repo helper (``reboot`` / ``config_reload`` /
``restart_service`` / ...) — never an inlined reboot/reload/restart.

Two operation shapes:
  * Whole-DUT operations (reboot, config reload, daemon restart) return ``None``
    and raise (via the wrapped repo helper) on failure — there is no per-port
    outcome to aggregate; the feature verifier owns pass/fail.
  * Port-scoped operations (bulk shut/startup, sfputil reset) act on a list of
    ports and return per-port failure strings for the caller to aggregate into
    one ``pytest.fail``.

Alongside the operations this module holds the feature-agnostic wait/poll
utilities both halves compose with: ``scale_bulk_wait`` (operation settle
budgets) and ``poll_ports_recovered`` (the verifier recovery-poll loop).
"""

import logging
import time

from tests.common.config_reload import config_reload
from tests.common.platform.interface_utils import wait_ports_oper_status
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from tests.transceiver.common import cli_helpers

logger = logging.getLogger(__name__)

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

    if not wait_until(wait_sec, interval_sec, 0, _recovered):
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


def perform_daemon_restart(duthost, daemon):
    """Restart a transceiver-related process/container.

    Args:
        daemon: ``xcvrd`` (supervisor process in ``pmon``) or a container
            (``pmon`` / ``swss`` / ``syncd``).
    """
    if daemon == "xcvrd":
        logger.info("Restarting xcvrd inside pmon for transceiver scenario")
        duthost.command("docker exec pmon supervisorctl restart xcvrd")
        return
    logger.info("Restarting %s container for transceiver scenario", daemon)
    duthost.restart_service(daemon)


def perform_sfputil_reset(duthost, reset_ports, toggle_ports, shutdown_wait_sec, startup_wait_sec):
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
                failures.append(err)
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


def perform_lpm_toggle(duthost, port, low_power=True, settle_sec=5):
    """Move ``port``'s module into (``low_power=True``) or out of low-power mode.

    Returns a list of per-port failure strings.
    """
    elapsed, err = cli_helpers.sfputil_set_lpmode(duthost, port, low_power)
    logger.info("Port %s: lpmode %s took %ss", port, "on" if low_power else "off", elapsed)
    if err:
        return [err]
    time.sleep(settle_sec)
    return verify_lpmode(duthost, port, low_power)
