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
         |-         one batched DataPathActivated pre-check -> per
                    module read MaxDurationDPTxTurnOff -> per module, one
                    on-DUT snippet disables Tx and times how long its
                    DataPath takes to leave DataPathActivated -> (in
                    finally) re-enable Tx on every module touched -> one
                    bulk shutdown/startup to recover
         `-         Standard Port Recovery and Verification for all ports
  session end
    `- _system_post_session_checks (system/conftest.py)

The DataPath transition is timed on the DUT, one module at a time, so each
module's measurement starts at its own Tx-disable write; timing it from the
test host would add the per-call round trip (seconds) to a budget that is
often a few milliseconds. ``tx_disable`` writes every lane of a module, so
breakout sub-ports sharing a module are covered by a single call.

Failure handling: failures are accumulated per port and reported in a
single pytest.fail at the end, so a single run surfaces all issues across
all ports.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    SYSTEM_ATTRIBUTES_KEY
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
# Used when MaxDurationDPTxTurnOff isn't advertised (decodes to 0).
_DEFAULT_TX_TURNOFF_TIMEOUT_SEC = 5.0
# Extra polling past the budget so a slow module reports its actual time;
# the pass/fail budget is unchanged.
_TX_TURNOFF_OVERRUN_REPORT_SEC = 1.0


def _max_system_attr(port_attributes_dict, ports, key, default):
    """Largest ``key`` across ``ports``' SYSTEM_ATTRIBUTES - the one shared
    wait that covers every port in a batched step."""
    return max(
        port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(key, default)
        for port in ports
    )


def test_system_tx_disable(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping, get_lport_to_pport_mapping,
):
    """Disabling Tx takes the DataPath out of DataPathActivated within the
    module-advertised MaxDurationDPTxTurnOff; the ports recover after shutdown/startup.
    """
    ports = sorted(
        port for port, attrs in port_attributes_dict.items()
        if attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get("tx_disable_test_supported", False)
    )
    if not ports:
        pytest.skip("tx_disable_test_supported is False for every port")

    health_baseline = capture_baseline(duthost)
    failures = []

    shutdown_wait = scenario_ops.scale_bulk_wait(_max_system_attr(
        port_attributes_dict, ports, "port_shutdown_wait_sec", _DEFAULT_PORT_SHUTDOWN_WAIT_SEC,
    ), len(ports))
    startup_wait = scenario_ops.scale_bulk_wait(_max_system_attr(
        port_attributes_dict, ports, "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC,
    ), len(ports))

    # Pre-check every port before disabling any Tx, so no breakout sibling is
    # checked after its module's Tx went off.
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

    modules = {}
    for port in candidates:
        modules.setdefault(get_lport_to_pport_mapping[port], []).append(port)

    tx_disabled_modules = set()
    try:
        for physical_index, module_ports in sorted(modules.items()):
            label = "{} (module {})".format("/".join(module_ports), physical_index)

            # Same byte for every sub-port.
            turnoff_ms, duration_err = cmis_helper.read_max_duration_dp_tx_turnoff_ms(
                duthost, module_ports[0],
            )
            if duration_err:
                failures.append(f"{label}: {duration_err}")
                continue
            budget_sec = (turnoff_ms / 1000) or _DEFAULT_TX_TURNOFF_TIMEOUT_SEC
            # tx_disable writes every lane.
            num_lanes, lane_err = cmis_helper.module_host_lane_count(
                lport_to_first_subport_mapping.get(module_ports[0], module_ports[0]),
                port_attributes_dict, lport_to_first_subport_mapping,
            )
            if lane_err:
                failures.append(f"{label}: {lane_err}")
                continue

            logger.info(
                "%s: MaxDurationDPTxTurnOff=%dms (budget %.3fs); disabling Tx",
                label, turnoff_ms, budget_sec,
            )
            # Recorded first: if the call raises after the write, Tx is already off.
            tx_disabled_modules.add(physical_index)
            timing, timing_err = cli_helpers.time_tx_disable_dp_transition(
                duthost, physical_index, num_lanes, budget_sec + _TX_TURNOFF_OVERRUN_REPORT_SEC,
            )
            if timing_err:
                failures.append(f"{label}: {timing_err}")
                continue
            elapsed_ms = timing["elapsed_ms"]
            if elapsed_ms is None:
                failures.append(
                    f"{label}: DataPath did not leave DataPathActivated within "
                    f"{budget_sec + _TX_TURNOFF_OVERRUN_REPORT_SEC:.3f}s of Tx disable "
                    f"(budget {budget_sec:.3f}s); last states {timing.get('states')}"
                )
                continue
            logger.info(
                "%s: DataPath left DataPathActivated %.1fms after Tx disable "
                "(poll read %.1fms, tx_disable call %.1fms); states %s",
                label, elapsed_ms, timing.get("read_ms", 0.0),
                timing.get("disable_call_ms", 0.0), timing.get("states"),
            )
            if elapsed_ms > budget_sec * 1000:
                failures.append(
                    f"{label}: DataPath left DataPathActivated {elapsed_ms:.1f}ms after "
                    f"Tx disable, budget {budget_sec * 1000:.0f}ms"
                )
    finally:
        # tx_disable() turned off every media lane, but xcvrd's re-init after the
        # toggle below only re-enables lanes of the ports it re-inits.
        if tx_disabled_modules:
            logger.info("Re-enabling Tx on %d module(s)", len(tx_disabled_modules))
            enable_errs = cli_helpers.set_modules_tx_disable(duthost, tx_disabled_modules, False)
            if enable_errs:
                pytest.exit(
                    "Could not re-enable Tx after Tx disable test: "
                    + "; ".join(enable_errs[idx] for idx in sorted(enable_errs))
                )

    logger.info("Recovering %d port(s) via bulk shutdown/startup", len(ports))
    failures.extend(scenario_ops.perform_ports_shutdown(duthost, ports, shutdown_wait))
    failures.extend(scenario_ops.perform_ports_startup(duthost, ports, startup_wait))

    logger.info(
        "Running Standard Port Recovery and Verification for %d port(s)",
        len(ports),
    )
    result = standard_port_recovery_and_verification(
        duthost, ports, {port: port_attributes_dict[port] for port in ports},
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
