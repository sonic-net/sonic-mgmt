"""System / Event Handling - C-CMIS frequency / Tx power tuning validation.

Implements the C-CMIS tuning tests from
    ``docs/testplan/transceiver/system_test_plan.md`` (Configuration
    Validation Test Cases, TC 1-2 there; TC 5-6 in this folder's
    numbering per ``docs/testplan/transceiver/diagrams/file_organization.md``):

  * Frequency adjustment: ``config interface transceiver frequency``.
  * Tx power adjustment: ``config interface transceiver tx_power``.

Both share the same shape (apply each non-default inventory value, verify
CONFIG_DB + Standard Port Recovery, restore the default), so
``_run_ccmis_tuning_test`` implements it once and each public test supplies
the attribute/CLI/field specifics.

Values are applied in rounds by list index: round N applies every port's
Nth value back-to-back, then shares one ``port_startup_wait_sec`` wait, one
CONFIG_DB read and one batched Standard Port Recovery, so the test waits
once per round rather than once per (port, value).

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
    `- test_system_ccmis_frequency_adjustment
         |- <body>: skip unless frequency_values is non-empty for at least
                    one port
         `-         per non-default value index, every port: apply ->
                    one shared wait -> verify CONFIG_DB -> one batched
                    Standard Port Recovery; then restore every default
    `- test_system_ccmis_tx_power_adjustment
         `- <body>: same shape, driven by tx_power_values
  session end
    `- _system_post_session_checks (system/conftest.py)

Failure handling: failures are accumulated per (port, value) and reported
in a single pytest.fail at the end, so a single run surfaces all issues
across all ports.
"""
import logging
import time

import pytest

from tests.transceiver.attribute_parser.attribute_keys import SYSTEM_ATTRIBUTES_KEY
from tests.transceiver.common import cli_helpers, db_helpers, scenario_ops
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)

logger = logging.getLogger(__name__)

_DEFAULT_PORT_STARTUP_WAIT_SEC = 60


def _apply_frequency(duthost, port, value):
    namespace = db_helpers.resolve_port_namespace(duthost, port)
    return cli_helpers.config_interface_transceiver_frequency(
        duthost, port, value, namespace=namespace
    )


def _apply_tx_power(duthost, port, value):
    namespace = db_helpers.resolve_port_namespace(duthost, port)
    return cli_helpers.config_interface_transceiver_tx_power(
        duthost, port, value, namespace=namespace
    )


def _verify_config_db_field(port_table, port, field, expected_value):
    """Verify CONFIG_DB PORT ``field`` reflects ``expected_value``."""
    actual = (port_table.get(port) or {}).get(field)
    if actual is None:
        return [f"{port}: CONFIG_DB PORT field '{field}' not set (expected {expected_value})"]
    try:
        matches = float(actual) == float(expected_value)
    except (TypeError, ValueError):
        matches = str(actual) == str(expected_value)
    if not matches:
        return [f"{port}: CONFIG_DB PORT '{field}'={actual}, expected {expected_value}"]
    return []


def _log_state_db_field(duthost, port, field, expected_value):
    """Best-effort STATE_DB cross-check - informational only.

    No STATE_DB schema in this codebase confirms which field (if any)
    publishes the *applied* laser_freq/tx_power value back from xcvrd, so
    this logs a comparison instead of asserting on it; callers must not
    treat a mismatch here as a failure.
    """
    namespace = db_helpers.resolve_port_namespace(duthost, port)
    entry_by_port, err = db_helpers.get_state_db_table(
        duthost, "TRANSCEIVER_INFO", namespace=namespace
    )
    if err:
        logger.info("%s: STATE_DB TRANSCEIVER_INFO read failed (informational): %s", port, err)
        return
    value = (entry_by_port.get(port) or {}).get(field)
    if value is None:
        logger.info(
            "%s: STATE_DB TRANSCEIVER_INFO has no '%s' field (informational)", port, field
        )
    elif str(value) != str(expected_value):
        logger.info(
            "%s: STATE_DB TRANSCEIVER_INFO '%s'=%s differs from applied %s (informational)",
            port, field, value, expected_value,
        )
    else:
        logger.info("%s: STATE_DB TRANSCEIVER_INFO '%s' matches applied value", port, field)


def _apply_and_verify_round(
    duthost, port_values, apply_fn, config_field,
    port_attributes_dict, health_baseline, lport_to_first_subport_mapping,
    expected_pid_changes, label,
):
    """Apply one value per port (``{port: value}``) back-to-back, share one
    startup wait, verify CONFIG_DB (+ best-effort STATE_DB) from one read,
    and run one batched Standard Port Recovery. Returns a list of failure
    strings."""
    failures = []
    applied = {}
    for port, value in port_values.items():
        logger.info("%s: applying %s=%s", port, label, value)
        err = apply_fn(duthost, port, value)
        if err:
            failures.append(f"{port}: [{label}={value}] {err}")
            continue
        applied[port] = value
    if not applied:
        return failures

    startup_wait = max(
        port_attributes_dict[port].get(SYSTEM_ATTRIBUTES_KEY, {}).get(
            "port_startup_wait_sec", _DEFAULT_PORT_STARTUP_WAIT_SEC
        )
        for port in applied
    )
    time.sleep(startup_wait)

    port_table = db_helpers.get_config_db_port_table(duthost)
    for port, value in applied.items():
        failures.extend(_verify_config_db_field(port_table, port, config_field, value))
        _log_state_db_field(duthost, port, config_field, value)

    result = standard_port_recovery_and_verification(
        duthost, list(applied), port_attributes_dict,
        link_up_timeout_sec=scenario_ops.scale_bulk_wait(startup_wait, len(applied)),
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    failures.extend(
        f"[{label}={applied[port]}] {port_result['details']}"
        for port, port_result in result["per_port"].items()
        if not port_result["passed"]
    )
    return failures


def _run_ccmis_tuning_test(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping, attribute_key, config_field, apply_fn, label,
):
    ports = sorted(
        port for port, attrs in port_attributes_dict.items()
        if attrs.get(SYSTEM_ATTRIBUTES_KEY, {}).get(attribute_key)
    )
    if not ports:
        pytest.skip(f"{attribute_key} is empty for every port")

    values_by_port = {}
    for port in ports:
        values = port_attributes_dict[port][SYSTEM_ATTRIBUTES_KEY][attribute_key]
        if len(values) < 2:
            logger.info(
                "%s: only a default value in %s - nothing to tune", port, attribute_key
            )
            continue
        values_by_port[port] = values
    if not values_by_port:
        return

    health_baseline = capture_baseline(duthost)
    failures = []  # collected across every (port, value) tuple
    round_kwargs = dict(
        apply_fn=apply_fn, config_field=config_field,
        port_attributes_dict=port_attributes_dict, health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes, label=label,
    )

    # Round N applies every port's Nth non-default value; ports with shorter
    # lists simply drop out of the later rounds.
    max_len = max(len(values) for values in values_by_port.values())
    for index in range(1, max_len):
        port_values = {
            port: values[index]
            for port, values in values_by_port.items() if len(values) > index
        }
        logger.info("Round %d: applying %s to %d port(s)", index, label, len(port_values))
        failures.extend(_apply_and_verify_round(duthost, port_values, **round_kwargs))

    logger.info("Restoring default %s on %d port(s)", label, len(values_by_port))
    failures.extend(_apply_and_verify_round(
        duthost, {port: values[0] for port, values in values_by_port.items()},
        **round_kwargs,
    ))

    if failures:
        pytest.fail(
            f"C-CMIS {label} adjustment validation FAILED on {len(failures)} "
            "item(s):\n  - " + "\n  - ".join(failures)
        )


def test_system_ccmis_frequency_adjustment(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    C-CMIS frequency adjustment validation: apply each non-default
    ``frequency_values`` entry, verify CONFIG_DB, then restore the default
    frequency.
    """
    _run_ccmis_tuning_test(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping,
        attribute_key="frequency_values", config_field="laser_freq",
        apply_fn=_apply_frequency, label="frequency",
    )


def test_system_ccmis_tx_power_adjustment(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """
    C-CMIS tx power adjustment validation: apply each non-default
    ``tx_power_values`` entry, verify CONFIG_DB, then restore the default
    tx power.
    """
    _run_ccmis_tuning_test(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping,
        attribute_key="tx_power_values", config_field="tx_power",
        apply_fn=_apply_tx_power, label="tx power",
    )
