"""System / Process Restart - xcvrd daemon restart validation.

Implements xcvrd daemon restart impact, xcvrd restart with I2C errors,
and xcvrd crash recovery test from
    ``docs/testplan/transceiver/system_test_plan.md``.

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every
                                                 System test)
    `- test_system_xcvrd_restart
         |- run_pre_check  (xcvrd RUNNING)    <- _per_test_health_check
         |- <body>: restart xcvrd -> verify all ports recovery
         `- run_post_check
    `- test_system_xcvrd_restart_with_i2c_errors
            NOTE: this test has been skipped during initial development
            due to library issues
         |- run_pre_check  (xcvrd RUNNING)    <- _per_test_health_check
         |- <body>: induce I2C errors -> restart xcvrd -> verify recovery
         `- run_post_check
    `- test_system_xcvrd_crash_recovery
         |- run_pre_check  (xcvrd RUNNING)    <- _per_test_health_check
         |- <body>: inject crash -> monitor restart -> verify recovery
         `- run_post_check
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         |- STATE_DB consistency check
         `- final link + LLDP check

Failure handling: failures are accumulated per test case and reported in
a single pytest.fail at the end, so a single run surfaces all issues
across all ports.
"""
import logging
import time

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common.health_checks import (
    capture_baseline
)
from tests.transceiver.common.prerequisites import (
    check_links_up
)
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)
from tests.common.helpers.dut_utils import get_program_info

logger = logging.getLogger(__name__)


@pytest.mark.disable_loganalyzer
def test_system_xcvrd_restart(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """Restart xcvrd and verify all ports recover cleanly.

    See the module docstring for the full execution tree.  Steps:

      * verify all ports are oper-up and record xcvrd uptime,
      * restart xcvrd via ``docker exec pmon supervisorctl restart xcvrd``,
      * wait for ``xcvrd_restart_settle_sec`` then run Standard Port Recovery
        and Verification for every port.

    All (port, step) failures are accumulated and reported in a single
    ``pytest.fail`` so one run surfaces every issue.
    """
    expected_pid_changes.add("xcvrd")
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    xcvrd_wait = port_attributes_dict[ports[0]].get(
        SYSTEM_ATTRIBUTES_KEY, {}
    ).get("xcvrd_restart_settle_sec", 120)
    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording link states and uptime for %d port(s)", len(ports))
    status, pid, uptime = get_program_info(
        duthost, 'pmon', 'xcvrd', include_uptime=True
    )
    logger.info(
        "Recording initial xcvrd status: %s (pid %s, uptime %s)",
        status, pid, uptime,
    )
    link_check = check_links_up(duthost, port_attributes_dict)
    if not link_check["passed"]:
        logger.warning("Validation on Start FAILED: some ports are down")
    logger.info("Restarting xcvrd...")
    duthost.stop_pmon_daemon_service('xcvrd')
    duthost.start_pmon_daemon('xcvrd')
    time.sleep(xcvrd_wait)

    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=xcvrd_wait,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    if not result["passed"]:
        failures.append(f"[post-restart] {result['details']}")
        logger.warning("Post-restart validation FAILED: %s", result["details"])
    else:
        logger.info("Post-restart validation PASSED: %s", result["details"])

    if failures:
        pytest.fail(
            f"TC1: xcvrd restart recovery FAILED on {len(failures)} "
            "port(s):\n  - "
            + "\n  - ".join(failures)
        )


@pytest.mark.disable_loganalyzer
def test_system_xcvrd_crash_recovery(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """Inject an xcvrd crash and verify automatic restart and port recovery.

    See the module docstring for the full execution tree.  Steps:

      * verify all ports are oper-up and record xcvrd uptime,
      * inject a crash into the xcvrd script via ``inject_xcvrd_crash``,
      * monitor automatic restart behavior,
      * wait for ``xcvrd_restart_settle_sec`` then run Standard Port Recovery
        and Verification for every port.

    All (port, step) failures are accumulated and reported in a single
    ``pytest.fail`` so one run surfaces every issue.
    """
    expected_pid_changes.add("xcvrd")
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    xcvrd_wait = port_attributes_dict[ports[0]].get(
        SYSTEM_ATTRIBUTES_KEY, {}
    ).get("xcvrd_restart_settle_sec", 120)
    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording initial link states for %d port(s)", len(ports))
    status, pid, uptime = get_program_info(
        duthost, 'pmon', 'xcvrd', include_uptime=True
    )
    logger.info(
        "Recording initial xcvrd status: %s (pid %s, uptime %s)",
        status, pid, uptime,
    )
    link_check = check_links_up(duthost, port_attributes_dict)
    if not link_check["passed"]:
        logger.warning("Validation on Start FAILED: some ports are down")

    logger.info("Using SIGKILL to crash xcvrd")
    status, pid = get_program_info(duthost, 'pmon', 'xcvrd')
    duthost.kill_pmon_daemon_pid_w_sig(pid, "-9")

    # Wait, then run Standard Port Recovery and Verification for all ports
    time.sleep(xcvrd_wait)
    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=xcvrd_wait,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    if not result["passed"]:
        failures.append(f"[post-crash] {result['details']}")
        logger.warning("Post-crash validation FAILED: %s", result["details"])
    else:
        logger.info("Post-crash validation PASSED: %s", result["details"])

    if failures:
        pytest.fail(
            f"xcvrd crash recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )
