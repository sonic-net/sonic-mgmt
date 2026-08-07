"""System / Process Restart - syncd daemon restart validation.

Implements the syncd restart test from
    ``docs/testplan/transceiver/system_test_plan.md``.

Execution order::

  session start
    `- check_links_up()             <- session-scoped via
                                        ``links_verified`` in
                                        tests/transceiver/conftest.py
                                        (failure skips every System test)
    `- test_system_syncd_restart
         |- <body>: restart syncd -> verify pmon restart (if expected)
         `-                       -> verify all ports recover
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

from tests.transceiver.attribute_parser.attribute_keys import (
    SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.prerequisites import (
    check_links_up
)
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)
from tests.common.helpers.sonic_db import AppDbCli as sdbHelp
from tests.common.platform.processes_utils import check_pmon_uptime_minutes

logger = logging.getLogger(__name__)


@pytest.mark.disable_loganalyzer
def test_system_syncd_restart(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """Restart syncd and verify all ports recover cleanly.

    See the module docstring for the full execution tree.  Steps:

      * verify all ports are oper-up and record link-up timestamps,
      * restart syncd via ``sudo systemctl restart syncd``,
      * if ``expect_pmon_restart_with_swss_or_syncd`` is set, verify pmon
        restarted as expected,
      * wait for ``syncd_restart_settle_sec`` then run Standard Port Recovery
        and Verification for every port.

    All (port, step) failures are accumulated and reported in a single
    ``pytest.fail`` so one run surfaces every issue.
    """
    expected_pid_changes.add("xcvrd")
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    failures = []
    health_baseline = capture_baseline(duthost)

    logger.info("Recording link states and uptime for %d port(s)", len(ports))
    link_check = check_links_up(duthost, port_attributes_dict)
    if not link_check["passed"]:
        logger.warning("Validation on Start FAILED: some ports are down")
    else:
        appl_db = sdbHelp(duthost)
        for port in ports:
            logger.info(
                "Recording initial link uptime: %s",
                appl_db.hget_key_value(
                    "PORT_TABLE:{}".format(port), "last_up_time"
                ),
            )

    logger.info("Restarting syncd...")
    duthost.restart_service("syncd", "syncd")
    syncd_wait = port_attributes_dict[ports[0]].get(
        SYSTEM_ATTRIBUTES_KEY, {}
    ).get("syncd_restart_settle_sec", 240)
    time.sleep(syncd_wait)

    # Check whether pmon restarted alongside syncd
    if port_attributes_dict[ports[0]].get(
        SYSTEM_ATTRIBUTES_KEY, {}
    ).get("expect_pmon_restart_with_swss_or_syncd", False):
        time.sleep(15)
        logger.info("Verifying pmon restart after syncd restart...")
        if check_pmon_uptime_minutes(duthost, minimal_runtime=3):
            failures.append("[pmon] pmon did not restart as expected")
            logger.warning(
                "pmon FAILED to restart when"
                " expect_pmon_restart_with_swss_or_syncd is True"
            )

    # Wait for settle time and verify
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=syncd_wait,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    if not result["passed"]:
        failures.append(f"[startup] {result['details']}")
        logger.warning(
            "Post-restart validation FAILED: %s", result["details"]
        )
    else:
        logger.info(
            "Post-restart validation PASSED: %s", result["details"]
        )

    if failures:
        pytest.fail(
            f"syncd restart recovery FAILED on {len(failures)} port(s):\n  - "
            + "\n  - ".join(failures)
        )
