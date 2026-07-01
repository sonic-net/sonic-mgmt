"""System / Process Restart - swss daemon restart validation.

Implements the swss restart test from
    ``docs/testplan/transceiver/system_test_plan.md``.

Execution order::

  session start
    `- check_links_up()             <- session-scoped via
                                        ``links_verified`` in
                                        tests/transceiver/conftest.py
                                        (failure skips every System test)
    `- test_system_swss_restart
         |- <body>: restart swss -> verify pmon restart (if expected)
         `-                      -> verify all ports recovery
  session end
    `- _system_post_session_checks (system/conftest.py)
         |- post_state_restoration()
         `- final link + LLDP check

Failure handling: failures are accumulated per test case and reported in a
single ``pytest.fail`` at the end, so a single run surfaces all issues across
all ports.
"""
import logging
import time
import pytest

from tests.transceiver.common.prerequisites import (
    check_links_up
)
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification,
    list_core_files
)
import tests.transceiver.common.process_restart_helpers as prh
from tests.common.platform.processes_utils import check_process_up

logger = logging.getLogger(__name__)


@pytest.mark.disable_loganalyzer
def test_system_swss_restart(
    duthost, port_attributes_dict, expected_pid_changes
):
    """Restart swss and verify all ports recover cleanly.

    See the module docstring for the full execution tree.  Steps:

      * verify all ports are oper-up and record link-up timestamps,
      * restart swss via ``sudo systemctl restart swss``,
      * if ``expect_pmon_restart_with_swss_or_syncd`` is set, verify pmon
        restarted as expected,
      * wait for ``swss_restart_settle_sec`` then run Standard Port Recovery
        and Verification for every port.

    All (port, step) failures are accumulated and reported in a single
    ``pytest.fail`` so one run surfaces every issue.
    """
    expected_pid_changes.add("xcvrd")
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    shared_state = {"core_baseline": list_core_files(duthost)}
    failures = []

    logger.info("Recording link states and uptime for %d port(s)", len(ports))
    if not check_links_up(duthost, port_attributes_dict):
        logger.warning("Validation on Start FAILED: some ports are down")
    else:
        for port in ports:
            logger.info(
                "Recording initial link uptime: %s",
                prh.get_db_port_table(
                    duthost, port, attr_filter='last_up_time'
                ),
            )

    logger.info("Restarting swss...")
    prh.restart_process(duthost, 'swss')
    swss_wait = prh.sys_attr(
        port_attributes_dict[ports[0]],
        "swss_restart_settle_sec",
        prh.DEFAULT_SWSS_SETTLE_SEC,
    )
    time.sleep(swss_wait)

    # Check whether pmon restarted alongside swss
    if prh.sys_attr(
        port_attributes_dict[ports[0]],
        "expect_pmon_restart_with_swss_or_syncd",
        False,
    ):
        time.sleep(15)
        logger.info("Verifying pmon restart after swss restart...")
        if check_process_up(duthost, 'pmon'):
            failures.append("[pmon] pmon did not restart as expected")
            logger.warning(
                "pmon FAILED to Restart when"
                " expect_pmon_restart_with_swss_or_syncd is True"
            )

    # Wait for settle time and verify
    for port in ports:
        port_attrs = port_attributes_dict[port]
        result = standard_port_recovery_and_verification(
            duthost, port, port_attrs,
            link_up_timeout_sec=swss_wait,
            shared_state=shared_state,
        )
        if not result["passed"]:
            failures.append(f"[startup] {result['details']}")
            logger.warning("Startup validation FAILED: %s", result["details"])
        else:
            logger.info("Startup validation PASSED: %s", result["details"])

    if failures:
        pytest.fail(
            f"swss restart recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )
