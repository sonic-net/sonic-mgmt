"""System / Event Handling - transceiver reset validation.

Implements the transceiver reset test from
    ``docs/testplan/transceiver/system_test_plan.md`` (Transceiver Event
    Handling Test Cases, TC 1).

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
                                                 (failure skips every
                                                 System test)
    `- test_system_transceiver_reset
         |- <body>: skip unless transceiver_reset_supported is True for at
                    least one module (judged on its first sub-port)
         |-         scenario_ops.perform_sfputil_reset: sfputil reset of
                    each module with its sub-ports still admin-up -> one
                    shared I2C-recover wait -> post-reset check (every
                    sub-port oper-down -> one syslog scan asserting no OIR
                    log line -> one batched LPMode read -> per port, if
                    low_pwr_request_hw_asserted, verify DPDeactivated +
                    LowPwrAllowRequestHW) -> bulk shutdown -> bulk startup
         `-         Standard Port Recovery and Verification for all
                    toggled ports
  session end
    `- _system_post_session_checks (system/conftest.py)

Each step is applied to every port before the shared wait for that step,
so the test waits once per step rather than once per port.

Failure handling: failures are accumulated per port and reported in a
single pytest.fail at the end, so a single run surfaces all issues across
all ports.
"""
import logging

import pytest

from tests.common.platform.interface_utils import is_first_subport, wait_ports_oper_status
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY, SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common import cmis_helper, scenario_ops
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.syslog_helpers import (
    capture_syslog_line_watermark,
    scan_new_syslog_lines,
)
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)

logger = logging.getLogger(__name__)

_DEFAULT_PORT_SHUTDOWN_WAIT_SEC = 5
_DEFAULT_PORT_STARTUP_WAIT_SEC = 60
_DEFAULT_RESET_I2C_RECOVER_SEC = 5

# xcvrd log_notice lines an in-place reset must NOT generate - a reset is a
# re-init, not an OIR.
_OIR_EVENT_PATTERN = r": Got SFP (removed|inserted) event"


def _max_system_attr(port_attributes_dict, ports, key, default):
    """Largest ``key`` across ``ports``' SYSTEM_ATTRIBUTES - the one shared
    wait that covers every port in a batched step."""
    return max(
        port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(key, default)
        for port in ports
    )


def test_system_transceiver_reset(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    Reset each transceiver that supports it (with its sub-ports still
    admin-up) and verify: every sub-port is linked down, no OIR event is
    logged, the module is in low power mode, and (where
    ``low_pwr_request_hw_asserted`` is True) the DataPath and
    LowPwrAllowRequestHW registers reflect a deactivated/low-power state.
    The ports are then shut down, started back up and re-verified.
    """
    # ``sfputil reset`` resets a whole physical module, so issue it once per
    # module (its first sub-port, gated on that port's own attribute) and
    # toggle every sub-port of the reset modules.
    reset_ports = sorted(
        port for port, attrs in port_attributes_dict.items()
        if is_first_subport(port, lport_to_first_subport_mapping)
        and attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get("transceiver_reset_supported", True)
    )
    if not reset_ports:
        pytest.skip("transceiver_reset_supported is False for every port")
    reset_modules = set(reset_ports)
    ports = sorted(
        port for port in port_attributes_dict
        if lport_to_first_subport_mapping.get(port) in reset_modules
    )

    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    recover_sec = _max_system_attr(
        port_attributes_dict, ports,
        "transceiver_reset_i2c_recover_sec", _DEFAULT_RESET_I2C_RECOVER_SEC,
    )
    shutdown_wait = scenario_ops.scale_bulk_wait(_max_system_attr(
        port_attributes_dict, ports, "port_shutdown_wait_sec", _DEFAULT_PORT_SHUTDOWN_WAIT_SEC,
    ), len(ports))
    startup_wait = scenario_ops.scale_bulk_wait(_max_system_attr(
        port_attributes_dict, ports, "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC,
    ), len(ports))

    watermark, watermark_err = capture_syslog_line_watermark(duthost)
    if watermark_err:
        failures.append(watermark_err)

    def _verify_post_reset_state():
        """Run while the modules are still reset, before the ports are toggled."""
        # The reset alone - not an admin shutdown - must take the links down.
        check_failures = wait_ports_oper_status(duthost, ports, "down", shutdown_wait)

        # One scan covers the whole reset window; xcvrd's OIR lines don't
        # reliably name the port, so they are reported in aggregate.
        oir_lines, scan_err = scan_new_syslog_lines(duthost, watermark, _OIR_EVENT_PATTERN)
        if scan_err:
            check_failures.append(scan_err)
        elif oir_lines:
            check_failures.append(
                f"reset of {len(reset_ports)} module(s) generated {len(oir_lines)} "
                "unexpected OIR event log line(s): " + "; ".join(oir_lines[:3])
            )

        check_failures.extend(scenario_ops.verify_ports_lpmode(
            duthost,
            [
                port for port in ports
                if port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(
                    "low_power_mode_supported", True
                )
            ],
            low_power=True,
        ))

        for port in ports:
            attrs = port_attributes_dict[port]
            if not attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get("low_pwr_request_hw_asserted", True):
                continue
            num_lanes = int(attrs.get(BASE_ATTRIBUTES_KEY, {}).get("host_lane_count", 0))
            page_11_data, dp_err = cmis_helper.read_dp_state_bytes(duthost, port, num_lanes)
            if dp_err:
                check_failures.append(f"{port}: {dp_err}")
            else:
                dp_failures = cmis_helper.check_dp_state(
                    page_11_data, num_lanes, cmis_helper.CMIS_DP_STATE_DEACTIVATED,
                    state_label="DPDeactivated",
                )
                check_failures.extend(f"{port}: {failure}" for failure in dp_failures)

            byte_val, lpreq_err = cmis_helper.read_low_pwr_allow_request_hw(duthost, port)
            if lpreq_err:
                check_failures.append(f"{port}: {lpreq_err}")
            else:
                bit_failures = cmis_helper.check_bit_set(
                    byte_val, cmis_helper.CMIS_PAGE_00_LOW_PWR_ALLOW_REQUEST_HW_BIT,
                    1, "LowPwrAllowRequestHW",
                )
                check_failures.extend(f"{port}: {failure}" for failure in bit_failures)
        return check_failures

    failures.extend(scenario_ops.perform_sfputil_reset(
        duthost, reset_ports, ports, shutdown_wait, startup_wait,
        recover_wait_sec=recover_sec, post_reset_check=_verify_post_reset_state,
        skip_pre_reset_shutdown=True,
    ))

    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, port_attributes_dict,
        link_up_timeout_sec=startup_wait,
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    if not result["passed"]:
        failures.append(f"[post-reset] {result['details']}")
        logger.warning("Post-reset validation FAILED: %s", result["details"])
    else:
        logger.info("Post-reset validation PASSED for %d port(s)", len(ports))

    if failures:
        pytest.fail(
            f"Transceiver reset validation FAILED on {len(failures)} "
            "item(s):\n  - " + "\n  - ".join(failures)
        )
