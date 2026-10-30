"""System / Event Handling - Tx disable DataPath validation.

Implements the Tx disable test from
    ``docs/testplan/transceiver/system_test_plan.md`` (Transceiver Event
    Handling Test Cases, TC 4).

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
    `- test_system_tx_disable
         |- <body>: skip unless tx_disable_test_supported is True for at
                    least one port
         |-         one batched DataPathActivated pre-check -> per port
                    read MaxDurationDPTxTurnOff -> disable Tx on every
                    port back-to-back -> one round-robin poll until each
                    port's DataPath leaves DataPathActivated within its own
                    budget -> one bulk shutdown/startup to recover
         `-         Standard Port Recovery and Verification for all ports
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

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY, SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common import cli_helpers, cmis_helper, scenario_ops
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.verification import (
    check_cmis_state,
    standard_port_recovery_and_verification,
)

logger = logging.getLogger(__name__)

_DEFAULT_PORT_SHUTDOWN_WAIT_SEC = 5
_DEFAULT_PORT_STARTUP_WAIT_SEC = 60
_DP_TURNOFF_POLL_INTERVAL_SEC = 1
# Fallback when MaxDurationDPTxTurnOff reads as "not advertised" (code 0/14/15
# decode to 0 us) - a module that doesn't advertise the field still needs a
# bounded poll budget.
_DEFAULT_TX_TURNOFF_TIMEOUT_SEC = 5.0


def _max_system_attr(port_attributes_dict, ports, key, default):
    """Largest ``key`` across ``ports``' SYSTEM_ATTRIBUTES - the one shared
    wait that covers every port in a batched step."""
    return max(
        port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(key, default)
        for port in ports
    )


def _poll_dp_state_left_activated(duthost, pending):
    """Round-robin poll CMIS page 11h across every Tx-disabled port until each
    has at least one lane out of DataPathActivated, or its own deadline passes.

    Args:
        pending: ``{port: (num_lanes, deadline, timeout_sec)}`` where
            ``deadline`` is ``time.monotonic()`` at Tx disable plus that
            port's budget, so a port's budget still starts at its own
            disable rather than at the start of the poll.

    Returns a list with one failure string per port that timed out.
    """
    failures = []
    pending = dict(pending)
    while pending:
        for port, (num_lanes, deadline, timeout_sec) in list(pending.items()):
            page_11_data, err = cmis_helper.read_dp_state_bytes(duthost, port, num_lanes)
            if err is None:
                not_activated = cmis_helper.check_dp_state(
                    page_11_data, num_lanes, cmis_helper.CMIS_DP_STATE_ACTIVATED,
                    state_label="DPActivated",
                )
                if not_activated:
                    # At least one lane left DataPathActivated - transitioned.
                    del pending[port]
                    continue
            else:
                logger.warning("%s: %s", port, err)
            if time.monotonic() >= deadline:
                failures.append(
                    f"{port}: DataPath did not leave DataPathActivated within "
                    f"{timeout_sec:.3f}s of Tx disable"
                )
                del pending[port]
        if pending:
            time.sleep(_DP_TURNOFF_POLL_INTERVAL_SEC)
    return failures


def test_system_tx_disable(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping, get_lport_to_pport_mapping,
):
    """
    Disable Tx on each transceiver that supports the check and verify its
    DataPath leaves DataPathActivated within the module-advertised
    ``MaxDurationDPTxTurnOff`` budget, then recover via shutdown/startup.
    """
    ports = sorted(
        port for port, attrs in port_attributes_dict.items()
        if attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get("tx_disable_test_supported", False)
    )
    if not ports:
        pytest.skip("tx_disable_test_supported is False for every port")

    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, step) tuple

    shutdown_wait = scenario_ops.scale_bulk_wait(_max_system_attr(
        port_attributes_dict, ports, "port_shutdown_wait_sec", _DEFAULT_PORT_SHUTDOWN_WAIT_SEC,
    ), len(ports))
    startup_wait = scenario_ops.scale_bulk_wait(_max_system_attr(
        port_attributes_dict, ports, "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC,
    ), len(ports))

    # Step 3: verify every port operational with DataPath activated - all
    # before any Tx is disabled, so a breakout sibling sharing a module is
    # never pre-checked after its module's Tx went off.
    precheck_results = check_cmis_state(
        duthost, ports, lport_to_first_subport_mapping
    )
    candidates = []
    for port in ports:
        if get_lport_to_pport_mapping.get(port) is None:
            failures.append(f"{port}: no physical port index resolved - cannot disable Tx")
        elif not precheck_results[port]["passed"]:
            failures.append(f"{port}: pre-check failed: {precheck_results[port]['details']}")
        else:
            candidates.append(port)

    # Step 4: read MaxDurationDPTxTurnOff for every port.
    timeouts = {}
    for port in candidates:
        turnoff_us, duration_err = cmis_helper.read_max_duration_dp_tx_turnoff_us(duthost, port)
        if duration_err:
            failures.append(f"{port}: {duration_err}")
            continue
        timeouts[port] = (turnoff_us / 1_000_000) or _DEFAULT_TX_TURNOFF_TIMEOUT_SEC
        logger.info(
            "%s: MaxDurationDPTxTurnOff=%dus (poll budget %.3fs)",
            port, turnoff_us, timeouts[port],
        )

    # Step 5: disable Tx on every port back-to-back, stamping each port's
    # own deadline at the moment its Tx went off.
    pending = {}
    for port, timeout_sec in timeouts.items():
        physical_index = get_lport_to_pport_mapping[port]
        logger.info("Disabling Tx on %s (physical index %s)", port, physical_index)
        tx_disable_err = cli_helpers.set_tx_disable(duthost, physical_index, True)
        if tx_disable_err:
            failures.append(f"{port}: {tx_disable_err}")
            continue
        num_lanes = int(
            port_attributes_dict[port].get(BASE_ATTRIBUTES_KEY, {}).get("host_lane_count", 0)
        )
        deadline = time.monotonic() + max(timeout_sec, _DP_TURNOFF_POLL_INTERVAL_SEC)
        pending[port] = (num_lanes, deadline, timeout_sec)

    # Step 6-7: monitor + verify DataPath transitions within budget.
    failures.extend(_poll_dp_state_left_activated(duthost, pending))

    # Step 8-9: recover every port in one bulk shutdown/startup cycle (also
    # clears Tx disable).
    logger.info("Recovering %d port(s) via bulk shutdown/startup", len(ports))
    failures.extend(scenario_ops.perform_ports_shutdown(duthost, ports, shutdown_wait))
    failures.extend(scenario_ops.perform_ports_startup(duthost, ports, startup_wait))

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
        failures.append(f"[post-tx-disable] {result['details']}")
        logger.warning("Post-Tx-disable validation FAILED: %s", result["details"])
    else:
        logger.info("Post-Tx-disable validation PASSED for %d port(s)", len(ports))

    if failures:
        pytest.fail(
            f"Tx disable DataPath validation FAILED on {len(failures)} "
            "item(s):\n  - " + "\n  - ".join(failures)
        )
