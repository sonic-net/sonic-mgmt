"""System / Event Handling - low power mode validation.

Implements the low power mode tests from
    ``docs/testplan/transceiver/system_test_plan.md`` (Transceiver Event
    Handling Test Cases, TC 2-3):

  * TC 2 - Transceiver low power mode validation: toggle a port into and
    out of low power mode via CLI and verify link/DataPath state.
  * TC 3 - CMIS transceiver boot-up low power mode test: disable xcvrd at
    boot (via ``pmon_daemon_control.json``), cold-reboot, and verify CMIS
    transceivers come up in low power mode by default.

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
    `- test_system_low_power_mode
         |- <body>: skip unless low_power_mode_supported is True for at
                    least one port
         `-         every port: force high power -> enter LPMode -> one
                    shared I2C-recover wait -> one batched link-down poll
                    -> per port verify DPDeactivated -> every port: exit
                    LPMode -> one shared I2C-recover wait -> Standard Port
                    Recovery for all ports
    `- test_system_cmis_bootup_low_power_mode
         |- <body>: skip unless cmis_bootup_low_power_test_supported is
                    True for at least one port
         `-         disable xcvrd at boot -> cold reboot -> verify LPMode
                    On -> revert + restart pmon -> Standard Port Recovery
  session end
    `- _system_post_session_checks (system/conftest.py)

Each step is applied to every port before the shared wait for that step,
so the test waits once per step rather than once per port.

Failure handling: failures are accumulated per port and reported in a
single pytest.fail at the end, so a single run surfaces all issues across
all ports.
"""
import logging
import time

import pytest

from tests.common.platform.interface_utils import wait_ports_oper_status
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY, SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common import cli_helpers, cmis_helper, scenario_ops, state_management
from tests.transceiver.common.health_checks import (
    capture_baseline,
    DEFAULT_MONITORED_PROCESSES,
)
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)

logger = logging.getLogger(__name__)

_DEFAULT_PORT_STARTUP_WAIT_SEC = 60
_DEFAULT_RESET_I2C_RECOVER_SEC = 5
_DEFAULT_COLD_REBOOT_SETTLE_SEC = 400
_DEFAULT_PMON_RESTART_SETTLE_SEC = 120


def _max_system_attr(port_attributes_dict, ports, key, default):
    """Largest ``key`` across ``ports``' SYSTEM_ATTRIBUTES - the one shared
    wait that covers every port in a batched step."""
    return max(
        port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(key, default)
        for port in ports
    )


def test_system_low_power_mode(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Toggle each transceiver that supports it into low power mode and back,
    verifying link/DataPath state at each transition.
    """
    ports = sorted(
        port for port, attrs in port_attributes_dict.items()
        if attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get("low_power_mode_supported", True)
    )
    if not ports:
        pytest.skip("low_power_mode_supported is False for every port")

    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    recover_sec = _max_system_attr(
        port_attributes_dict, ports,
        "transceiver_reset_i2c_recover_sec", _DEFAULT_RESET_I2C_RECOVER_SEC,
    )
    settle_wait = scenario_ops.scale_bulk_wait(_max_system_attr(
        port_attributes_dict, ports, "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC,
    ), len(ports))

    # Step 3: ensure high power mode initially (idempotent safety net).
    failures.extend(scenario_ops.perform_ports_lpmode_set(duthost, ports, low_power=False))

    # Step 4-5, 7: enter low power mode on every port (verifies LPMode via
    # CLI), then share one I2C-recovery wait.
    logger.info("Setting %d port(s) to low power mode", len(ports))
    failures.extend(scenario_ops.perform_ports_lpmode_set(duthost, ports, low_power=True))
    time.sleep(recover_sec)

    # Step 6: verify link down (one batched poll) and DataPath deactivated.
    failures.extend(wait_ports_oper_status(
        duthost, ports, "down", scenario_ops.scale_bulk_wait(recover_sec, len(ports))
    ))
    for port in ports:
        num_lanes = int(
            port_attributes_dict[port].get(BASE_ATTRIBUTES_KEY, {}).get("host_lane_count", 0)
        )
        page_11_data, dp_err = cmis_helper.read_dp_state_bytes(duthost, port, num_lanes)
        if dp_err:
            failures.append(f"{port}: {dp_err}")
        else:
            dp_failures = cmis_helper.check_dp_state(
                page_11_data, num_lanes, cmis_helper.CMIS_DP_STATE_DEACTIVATED,
                state_label="DPDeactivated",
            )
            failures.extend(f"{port}: {failure}" for failure in dp_failures)

    # Step 8-9: disable low power mode (restore high power) on every port,
    # then share one I2C-recovery wait.
    logger.info("Restoring %d port(s) to high power mode", len(ports))
    failures.extend(scenario_ops.perform_ports_lpmode_set(duthost, ports, low_power=False))
    time.sleep(recover_sec)

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
        failures.append(f"[post-lpmode] {result['details']}")
        logger.warning("Post-lpmode validation FAILED: %s", result["details"])
    else:
        logger.info("Post-lpmode validation PASSED for %d port(s)", len(ports))

    if failures:
        pytest.fail(
            f"Low power mode validation FAILED on {len(failures)} "
            "item(s):\n  - " + "\n  - ".join(failures)
        )


@pytest.mark.disable_loganalyzer
def test_system_cmis_bootup_low_power_mode(
    duthost, localhost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Disable xcvrd at boot, cold-reboot, and verify every CMIS transceiver
    that supports the check comes up in low power mode by default.
    """
    ports = sorted(
        port for port, attrs in port_attributes_dict.items()
        if attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get(
            "cmis_bootup_low_power_test_supported", False
        )
    )
    if not ports:
        pytest.skip("cmis_bootup_low_power_test_supported is False for every port")

    cold_reboot_settle_sec = _max_system_attr(
        port_attributes_dict, ports, "cold_reboot_settle_sec", _DEFAULT_COLD_REBOOT_SETTLE_SEC,
    )
    pmon_restart_settle_sec = _max_system_attr(
        port_attributes_dict, ports, "pmon_restart_settle_sec", _DEFAULT_PMON_RESTART_SETTLE_SEC,
    )

    failures = []  # collected across every (port, step) tuple

    # A cold reboot restarts every framework-monitored process, so the
    # autouse per-test health check (tests/transceiver/conftest.py) must be
    # told all of them are expected to change PID, not just xcvrd.
    expected_pid_changes.update(DEFAULT_MONITORED_PROCESSES)

    setup_err = state_management.enable_pmon_skip_xcvrd(duthost)
    if setup_err:
        pytest.fail(f"Could not disable xcvrd at boot: {setup_err}")

    try:
        logger.info("Cold rebooting DUT with xcvrd disabled at boot")
        scenario_ops.perform_cold_reboot(duthost, localhost)
        time.sleep(cold_reboot_settle_sec)

        logger.info("Verifying CMIS transceivers are in low power mode after boot-up")
        lpmode_by_port, lpmode_err = cli_helpers.sfputil_show_lpmode(duthost)
        if lpmode_err:
            failures.append(lpmode_err)
        else:
            for port in ports:
                actual = (lpmode_by_port.get(port) or "").strip()
                if actual.lower() != "on":
                    failures.append(
                        f"{port}: expected LPMode On after boot with xcvrd "
                        f"disabled, got '{actual or 'unknown'}'"
                    )
    finally:
        logger.info("Reverting pmon_daemon_control.json and restarting pmon")
        restore_err = state_management.restore_pmon_daemon_control(duthost)
        if restore_err:
            failures.append(restore_err)
        duthost.restart_service("pmon")
        time.sleep(pmon_restart_settle_sec)

    health_baseline = capture_baseline(duthost)
    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=pmon_restart_settle_sec,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    if not result["passed"]:
        failures.append(f"[post-recovery] {result['details']}")
        logger.warning("Post-recovery validation FAILED: %s", result["details"])
    else:
        logger.info("Post-recovery validation PASSED for %d port(s)", len(ports))

    if failures:
        pytest.fail(
            f"CMIS boot-up low power mode test FAILED on {len(failures)} "
            "item(s):\n  - " + "\n  - ".join(failures)
        )
