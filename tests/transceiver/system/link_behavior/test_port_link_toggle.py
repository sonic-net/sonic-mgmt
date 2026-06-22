"""System / Link Behavior - Combined per-port shutdown + startup validation.

Implements TC1 (Port Shutdown Validation) and TC2 (Port Startup Validation)
from ``docs/testplan/transceiver/system_test_plan.md`` as a single
test that toggles one port at a time:

    for each port P in port_attributes_dict:
        config interface shutdown P
        wait for oper-down
        config interface startup  P
        run Standard Port Recovery and Verification Procedure on P

Why one combined test instead of "shutdown ALL ports, then startup ALL
ports":
  * Only one port is admin-down at any moment. Every other port in the
    bundle stays operationally up on our side, so the remote partner's
    LLDP table never loses sight of the bundle as a whole.
  * When port P comes back up, its LLDP entry can re-converge against a
    remote that already has the link bundle's other members alive. This
    keeps the LLDP step of Standard Port Recovery and Verification
    meaningful instead of racing every remote LLDP teardown at once.

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every System test)
    `- test_system_port_sns_validation
         |- run_pre_check  (xcvrd RUNNING)    <- _per_test_health_check
         |- <body>: for each port -> shutdown -> verify oper-down ->
         |          startup -> Standard Port Recovery and Verification
         `- run_post_check (PIDs unchanged + no new cores)
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         |- STATE_DB consistency check
         `- final link + LLDP check

Failure handling: failures are collected across every (port, step) pair
and reported in a single ``pytest.fail`` at the end of the test, so a
single run surfaces every misbehaving port instead of fast-failing on
the first miss. ``config interface startup`` is always issued after
``config interface shutdown`` even if shutdown verify missed, so a port
never ends up stuck admin-down because of a verification failure mid-loop.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common.prerequisites import (
    standard_port_recovery_and_verification,
    wait_for_port_oper_state,
)

logger = logging.getLogger(__name__)


def _sys_attr(port_attrs, name, default):
    return port_attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get(name, default)


def _shutdown_port(duthost, port):
    duthost.shell(f"config interface shutdown {port}")


def _startup_port(duthost, port):
    duthost.shell(f"config interface startup {port}")


# ──────────────────────────────────────────────────────────────────────
# Module-scoped safety net.
# Even with always-issue-startup inside the test body, a hard test
# abort (e.g. fixture error, infrastructure exception) could leave a
# port admin-down. This teardown re-issues startup for every port in
# scope regardless of whether the test passed.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True, scope="module")
def _restore_ports_after_module(duthost, port_attributes_dict):
    yield
    ports = sorted(port_attributes_dict.keys())
    if not ports:
        return
    logger.info("Link-behavior teardown: ensuring %d port(s) are admin-up", len(ports))
    for port in ports:
        _startup_port(duthost, port)


# ──────────────────────────────────────────────────────────────────────
# TC1 + TC2 combined - per-port shutdown + startup validation
# ──────────────────────────────────────────────────────────────────────


def test_system_port_sns_validation(duthost, port_attributes_dict):
    """For each transceiver port individually: shutdown, verify oper-down,
    startup, then run the Standard Port Recovery and Verification Procedure.

    A single ``shared_state`` dict is threaded through every recovery
    call so the logical->physical port map and the per-parent
    ``TRANSCEIVER_STATUS|<parent>`` query happen at most once per test.
    For an 8x100G breakout that means one query reused across all 8
    sibling ports.

    Failures from both the shutdown and startup phases are accumulated
    in a single list; the test reports every bad (port, step) in one
    ``pytest.fail`` at the end so a single run surfaces every issue.
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"

    shared_state = {}
    failures = []  # collected across every (port, step) tuple

    for port in ports:
        port_attrs = port_attributes_dict[port]

        # ── Phase 1: shutdown ─────────────────────────────────────
        shutdown_wait = _sys_attr(port_attrs, "port_shutdown_wait_sec", 5)
        logger.info("Shutting down %s; polling for oper=down up to %ds", port, shutdown_wait)
        _shutdown_port(duthost, port)
        result = wait_for_port_oper_state(duthost, port, "down", shutdown_wait)
        if not result["passed"]:
            failures.append(f"[shutdown] {result['details']}")
            logger.warning("Shutdown validation FAILED: %s", result["details"])
        else:
            logger.info("Shutdown validation PASSED: %s", result["details"])

        # ── Phase 2: startup + Standard Port Recovery ─────────────
        # Startup is issued unconditionally so the port is never left
        # admin-down because shutdown verify happened to fail.
        startup_wait = _sys_attr(port_attrs, "port_startup_wait_sec", 60)
        logger.info("Starting up %s; will run Standard Recovery procedure", port)
        _startup_port(duthost, port)
        result = standard_port_recovery_and_verification(
            duthost, port, port_attrs,
            link_up_timeout_sec=startup_wait,
            shared_state=shared_state,
        )
        if not result["passed"]:
            failures.append(f"[startup] {result['details']}")
            logger.warning("Startup validation FAILED: %s", result["details"])
        else:
            logger.info("Startup validation PASSED: %s", result["details"])

    if failures:
        pytest.fail(
            f"Port shutdown+startup validation FAILED on {len(failures)} "
            f"step(s) across {len(ports)} port(s):\n  - "
            + "\n  - ".join(failures)
        )
