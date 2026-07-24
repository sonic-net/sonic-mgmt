"""Reusable, feature-agnostic scenario *operation* helpers for transceiver tests.

Shared half of the scenario-coverage model
(``docs/testplan/transceiver/scenario_test_template.md``): a scenario pairs a
``perform_<op>`` from here with a feature-owned ``verify_<feature>_*`` verifier,
so EEPROM/DOM/VDM/PM reuse the same disruptive operations. The operations act on
a *list* of ports (one bulk config + a single settle wait) and return the
suite-wide list of per-port failure strings for aggregation into one
``pytest.fail``.
"""

import logging

from tests.common.platform.interface_utils import wait_ports_oper_status

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
