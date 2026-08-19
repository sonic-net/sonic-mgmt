"""System / Process Restart - process restart and crash validation.

Implements the xcvrd, pmon, swss, and syncd restart tests, and the xcvrd
crash recovery test, from
    ``docs/testplan/transceiver/system_test_plan.md``.

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every
                                                 System test)
    `- test_system_xcvrd_restart
         |- <body>: restart xcvrd -> verify all ports recovery
    `- test_system_pmon_restart
         |- <body>: restart pmon -> verify all ports recovery
    `- test_system_swss_restart
         |- <body>: restart swss -> verify syncd/pmon restart (if expected)
         `-                      -> verify all ports recovery
    `- test_system_syncd_restart
         |- <body>: restart syncd -> verify pmon restart (if expected)
         `-                       -> verify all ports recover
    `- test_system_xcvrd_crash_recovery
         |- <body>: inject crash -> monitor restart -> verify recovery
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
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.prerequisites import (
    check_links_up
)
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)
from tests.common.helpers.dut_utils import get_program_info
from tests.common.helpers.sonic_db import AppDbCli as sdbHelp
from tests.common.platform.processes_utils import (
    check_docker_uptime_minutes,
    check_pmon_uptime_minutes
)

logger = logging.getLogger(__name__)

# Fallback values for settle time to wait after restarting a process
_DEFAULT_RESTART_SETTLE_SEC = {
    "xcvrd": 120,
    "pmon": 120,
    "swss": 180,
    "syncd": 240,
}


def _process_restart_tester(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping, process_name):
    """
        Generic process restart tester, used for:
        xcvrd, pmon, swss, and syncd

    Restarts ``process_name`` and runs Standard Port Recovery and
    Verification across all ports. The processes differ in a few ways
    that are branched on below:

      * xcvrd is restarted as a pmon-supervised daemon (supervisorctl
        stop/start); pmon, swss, and syncd are restarted as system
        services (``duthost.restart_service``).
      * swss and syncd restarts are also expected to cycle syncd/swss and
        orchagent, are checked against docker uptime, and optionally
        checked for a coupled pmon restart, and share the longer of the
        two processes' settle times.
    """
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    system_attributes = port_attributes_dict[ports[0]].get(
        SYSTEM_ATTRIBUTES_KEY, {}
    )

    if process_name == "xcvrd" or process_name == "pmon":
        expected_pid_changes.add("xcvrd")
    if process_name == "swss" or process_name == "syncd":
        expected_pid_changes.add("syncd")
        expected_pid_changes.add("orchagent")
        if system_attributes.get(
            "expect_pmon_restart_with_swss_or_syncd", False
        ):
            expected_pid_changes.add("xcvrd")

    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording link states and uptime for %d port(s)", len(ports))
    link_check = check_links_up(duthost, port_attributes_dict)
    if not link_check["passed"]:
        logger.warning("Validation on Start FAILED: some ports are down")
    else:
        appl_db = sdbHelp(duthost)
        port_table = appl_db.dump("PORT_TABLE")
        for port in ports:
            last_up_time = port_table.get(
                "PORT_TABLE:{}".format(port), {}
            ).get("value", {}).get("last_up_time")
            logger.info(
                "Recording initial link uptime: %s: %s", port, last_up_time
            )

    logger.info("Restarting %s...", process_name)
    if process_name == "xcvrd":
        duthost.stop_pmon_daemon_service('xcvrd')
        duthost.start_pmon_daemon('xcvrd')
    else:
        duthost.restart_service(process_name)

    if process_name == "swss" or process_name == "syncd":
        if check_docker_uptime_minutes(
            duthost, process_name, minimal_runtime=3
        ):
            failures.append(f"{process_name} did not restart as expected")
            logger.warning("%s FAILED to restart", process_name)

        if system_attributes.get(
            "expect_pmon_restart_with_swss_or_syncd", False
        ):
            time.sleep(15)
            logger.info(
                "Verifying pmon restart after %s restart...", process_name
            )
            if check_pmon_uptime_minutes(duthost, minimal_runtime=3):
                failures.append("pmon did not restart as expected")
                logger.warning(
                    "pmon FAILED to restart when"
                    " expect_pmon_restart_with_swss_or_syncd is True"
                )

    if process_name == "swss" or process_name == "syncd":
        syncd_wait = system_attributes.get("syncd_restart_settle_sec", 240)
        swss_wait = system_attributes.get("swss_restart_settle_sec", 180)
        settle_wait = max(syncd_wait, swss_wait)
    else:
        settle_wait = system_attributes.get(
            f"{process_name}_restart_settle_sec",
            _DEFAULT_RESTART_SETTLE_SEC[process_name],
        )

    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=settle_wait,
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
        time.sleep(90)  # wait for the system to settle before the next test
        pytest.fail(
            f"{process_name} restart recovery FAILED on {len(failures)} "
            "port(s):\n  - "
            + "\n  - ".join(failures)
        )


def _process_crash_tester(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping, container_name, program_name,
        kill_signal="-9"):
    """
        Generic process crash tester.

        Only used for the xcvrd crash-recovery test case today, but takes
        the supervised container/program and kill signal as parameters so
        it can be extended to other programs later.
    """
    expected_pid_changes.add(program_name)
    ports = sorted(port_attributes_dict.keys())
    assert ports, "port_attributes_dict is empty - nothing to validate"
    settle_wait = port_attributes_dict[ports[0]].get(
        SYSTEM_ATTRIBUTES_KEY, {}
    ).get(f"{program_name}_restart_settle_sec", 120)
    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    logger.info("Recording initial link states for %d port(s)", len(ports))
    status, pid, uptime = get_program_info(
        duthost, container_name, program_name, include_uptime=True
    )
    logger.info(
        "Recording initial %s status: %s (pid %s, uptime %s)",
        program_name, status, pid, uptime,
    )
    link_check = check_links_up(duthost, port_attributes_dict)
    if not link_check["passed"]:
        logger.warning("Validation on Start FAILED: some ports are down")

    logger.info("Using kill %s to crash %s", kill_signal, program_name)
    status, pid = get_program_info(duthost, container_name, program_name)
    duthost.kill_pmon_daemon_pid_w_sig(pid, kill_signal)

    # Wait, then run Standard Port Recovery and Verification for all ports
    time.sleep(settle_wait)
    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=settle_wait,
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
            f"{program_name} crash recovery FAILED on {len(failures)} "
            "port(s):\n  - "
            + "\n  - ".join(failures)
        )


@pytest.mark.disable_loganalyzer
def test_system_xcvrd_restart(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Restart xcvrd and verify all ports recover cleanly
    """
    _process_restart_tester(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping, "xcvrd",
    )


@pytest.mark.disable_loganalyzer
def test_system_pmon_restart(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Restart pmon and verify all ports recover cleanly
    """
    _process_restart_tester(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping, "pmon",
    )


@pytest.mark.disable_loganalyzer
def test_system_swss_restart(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Restart swss and verify all ports recover cleanly
    """
    _process_restart_tester(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping, "swss",
    )


@pytest.mark.disable_loganalyzer
def test_system_syncd_restart(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Restart syncd and verify all ports recover cleanly
    """
    _process_restart_tester(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping, "syncd",
    )


@pytest.mark.disable_loganalyzer
def test_system_xcvrd_crash_recovery(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Inject an xcvrd crash and verify automatic restart and port recovery
    """
    _process_crash_tester(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping, "pmon", "xcvrd",
    )
