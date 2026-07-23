"""System / System Recovery - cold reboot link recovery validation.

Implements the "Cold reboot link recovery" test case from
    ``docs/testplan/transceiver/system_test_plan.md`` 
    (System Recovery Test Cases).

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every System test)
    `- test_system_cold_reboot_link_recovery
         |- run_pre_check  (health OK)         <- _per_test_health_check
         |- <body>: verify links up -> cold reboot -> verify all ports recovery
         `- run_post_check
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         |- STATE_DB consistency check
         `- final link + LLDP check

Note: per system_test_plan.md, a reboot invalidates the PID / log baselines
established at test start ("PID and log baselines are invalidated by a
reboot; re-establish them after each reboot before proceeding to the next
test case"), since every monitored process restarts along with the DUT. This
test therefore declares every ``DEFAULT_MONITORED_PROCESSES`` entry as an
expected PID change up front (so the autouse pre/post-test health check does
not flag the reboot itself as a regression) and captures a fresh baseline
after the DUT comes back up for the Standard Port Recovery and Verification
Procedure's own health step.

Failure handling: failures are accumulated per test case and reported in a single
pytest.fail at the end, so a single run surfaces all issues across all ports.
"""
import logging

import pytest

from tests.common.reboot import reboot
from tests.transceiver.common.health_checks import (
    DEFAULT_MONITORED_PROCESSES,
    capture_baseline,
)
from tests.transceiver.common.prerequisites import check_links_up
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)
import tests.transceiver.common.process_restart_helpers as prh

logger = logging.getLogger(__name__)


@pytest.mark.disable_loganalyzer
def test_system_cold_reboot_link_recovery(duthost, localhost, port_attributes_dict, expected_pid_changes):
    """Cold reboot the DUT and verify all transceiver ports recover cleanly.

    See the module docstring for the full execution tree.  Steps:

      * verify all ports are oper-up before the reboot,
      * cold reboot the DUT via ``tests.common.reboot.reboot``, waiting
        ``cold_reboot_settle_sec`` for the DUT to come back up,
      * run Standard Port Recovery and Verification for every port against a
        fresh post-reboot health baseline.

    All (port, step) failures are accumulated and reported in a single
    ``pytest.fail`` so one run surfaces every issue.
    """
    # A cold reboot restarts every monitored process; tell the autouse
    # per-test health check to expect it rather than flag it as a regression.
    expected_pid_changes.update(DEFAULT_MONITORED_PROCESSES)

    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    cold_reboot_wait = prh.sys_attr(port_attributes_dict[ports[0]], "cold_reboot_settle_sec", 400)

    logger.info("Verifying link states for %d port(s) before reboot", len(ports))
    if not check_links_up(duthost, port_attributes_dict)["passed"]:
        logger.warning("Validation on Start FAILED: some ports are down")

    logger.info("Cold rebooting %s, waiting up to %ss for the DUT to come back up",
                duthost.hostname, cold_reboot_wait)
    reboot(duthost, localhost, reboot_type='cold', wait=cold_reboot_wait, safe_reboot=True)

    # PID/log baselines are invalidated by the reboot (system_test_plan.md);
    # capture a fresh post-reboot baseline for the health step below.
    health_baseline = capture_baseline(duthost)

    logger.info("Running Standard Port Recovery and Verification for %d port(s)", len(ports))
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=cold_reboot_wait,
        health_baseline=health_baseline,
        shared_state=None,
        expected_pid_changes=None
    )

    failures = []  # collected across every (port, step) tuple
    if not result["passed"]:
        failures.append(f"[post-reboot] {result['details']}")
        logger.warning("Post-reboot validation FAILED: %s", result["details"])
    else:
        logger.info("Post-reboot validation PASSED: %s", result["details"])

    if failures:
        pytest.fail(
            f"Cold reboot link recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )
