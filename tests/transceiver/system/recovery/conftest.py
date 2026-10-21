"""System Recovery category conftest.
The session-level ``presence_verified, gold_fw_verified, links_verified`` gates are already
pulled in for every System test by ``_system_session_prerequisites`` in ``system/conftest.py``.
Per ``docs/testplan/transceiver/system_test_plan.md`` (System Recovery), a config reload / reboot /
power cycle invalidates the per-test PID baseline, so this conftest overrides the per-test health
check to verify against a baseline that is re-established after the operation.
"""

import logging

import pytest

from tests.common.platform.processes_utils import wait_critical_processes
from tests.transceiver.common.health_checks import (
    DEFAULT_MONITORED_PROCESSES,
    capture_baseline,
    run_post_check,
    run_pre_check,
    verify_health,
)
from tests.transceiver.conftest import health_check_events

logger = logging.getLogger(__name__)


# Per-test health baseline, shared by the override below and reestablish_health_baseline.
@pytest.fixture
def health_baseline(request, duthost):
    """Capture the pre-test health baseline; mutated in place once re-established."""
    baseline = capture_baseline(duthost)
    logger.debug("Health baseline captured for %s", request.node.name)
    return baseline


# Overrides tests/transceiver/conftest.py::_per_test_health_check for System Recovery tests.
@pytest.fixture(autouse=True)
def _per_test_health_check(request, duthost, health_baseline, expected_pid_changes):
    """Verify health before and after each test against ``health_baseline``.

    Same checks as the parent fixture, but the post-test check reads ``health_baseline``
    at teardown, so it sees the post-reboot baseline set by ``reestablish_health_baseline``.
    """
    pre_checks = [
        (f"process_{process}_running", status == "RUNNING",
         f"Process {process} is {status}, expected RUNNING")
        for process, (status, _pid) in health_baseline["pid_baselines"].items()
    ]
    run_pre_check(request, pre_checks, health_check_events)

    yield

    result = verify_health(duthost, health_baseline, expect_pid_change=expected_pid_changes)
    post_checks = [
        ("system_health", result["passed"], "; ".join(result["failures"])),
    ]
    run_post_check(request, post_checks, health_check_events)


# Re-establish the per-test health baseline after a reboot.
@pytest.fixture
def reestablish_health_baseline(duthost, health_baseline, expected_pid_changes):
    """Return ``_reestablish(timeout_sec)``, to call once the disruptive operation has completed.

    Until then every monitored process is expected to change PID, so a test that fails
    mid-reboot doesn't abort the session on stale PIDs. ``_reestablish`` waits for critical
    processes, replaces the PID baseline in place with the post-operation PIDs and drops that
    expectation, so a restart *after* recovery is flagged. Core files keep the pre-test baseline.
    """
    expected_pid_changes.update(DEFAULT_MONITORED_PROCESSES)

    def _reestablish(timeout_sec):
        logger.info("Re-establishing health baseline on %s (timeout=%ss)",
                    duthost.hostname, timeout_sec)
        wait_critical_processes(duthost, timeout=timeout_sec)
        health_baseline["pid_baselines"] = capture_baseline(duthost)["pid_baselines"]
        expected_pid_changes.difference_update(DEFAULT_MONITORED_PROCESSES)
        return health_baseline

    return _reestablish
