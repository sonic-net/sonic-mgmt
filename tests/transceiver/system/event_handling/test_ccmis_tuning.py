"""System / Event Handling - C-CMIS frequency / Tx power tuning validation.

Implements the C-CMIS tuning tests from
    ``docs/testplan/transceiver/system_test_plan.md`` (Configuration
    Validation Test Cases, TC 1-2 there; TC 5-6 in this folder's
    numbering per ``docs/testplan/transceiver/diagrams/file_organization.md``):

  * Frequency adjustment: ``config interface transceiver frequency``.
  * Tx power adjustment: ``config interface transceiver tx_power``.

Both share the same shape (apply each non-default inventory value, verify
CONFIG_DB and the value the module reports back in STATE_DB, run Standard
Port Recovery, restore the default), so
``_run_ccmis_tuning_test`` implements it once and each public test supplies
the attribute/CLI/field specifics.

Values are applied in rounds by list index: round N applies every port's
Nth value back-to-back, then shares one ``port_startup_wait_sec`` wait, one
CONFIG_DB read, one STATE_DB poll and one batched Standard Port Recovery, so
the test waits once per round rather than once per (port, value).

CONFIG_DB alone does not show the value took effect: xcvrd rejects an
off-grid or out-of-range frequency (logging an error and leaving the laser on
its old channel) while CONFIG_DB keeps the requested value. So each round
also polls ``TRANSCEIVER_DOM_SENSOR``, where C-CMIS publishes the applied
values (``laser_config_freq`` / ``laser_curr_freq`` / ``tx_config_power``,
from ``CCmisApi.get_transceiver_dom_real_value()``) on xcvrd's DOM update
cycle.

Inventory requirements:

* ``values[0]`` must be each port's current setting. The test checks this
  before changing anything (plan step 3: capture CONFIG_DB / STATE_DB) and
  fails early on a mismatch, because the restore applies ``values[0]`` and
  would otherwise leave the port on a different setting than it started on.
* Frequency only: a coherent link comes up only when both ends use the same
  channel, and the test does not resolve or tune link peers. So both ends of
  every link under test must be DUT ports in this inventory with identical
  ``frequency_values`` - they are then tuned in the same round. A port whose
  peer is not tuned identically (a non-DUT peer, or a different list) will
  fail Standard Port Recovery on every non-default round. Tx power has no
  such constraint as long as every value stays within the peer's receive
  range.

Execution order::

  session start
    `- check_links_up()                       <- session-scoped via
                                                 ``links_verified`` in
                                                 tests/transceiver/conftest.py
    `- test_system_ccmis_frequency_adjustment
         |- <body>: skip unless frequency_values is non-empty for at least
                    one port
         |-         capture CONFIG_DB + TRANSCEIVER_DOM_SENSOR; fail early
                    unless every port is on its values[0]
         `-         per non-default value index, every port: apply ->
                    one shared wait -> verify CONFIG_DB -> poll
                    TRANSCEIVER_DOM_SENSOR until applied -> one batched
                    Standard Port Recovery; then (in finally) restore
                    every default
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

from tests.transceiver.attribute_parser.attribute_keys import (
    DOM_ATTRIBUTES_KEY, SYSTEM_ATTRIBUTES_KEY
)
from tests.transceiver.common import cli_helpers, db_helpers, scenario_ops
from tests.transceiver.common.health_checks import capture_baseline
from tests.transceiver.common.verification import (
    standard_port_recovery_and_verification
)

logger = logging.getLogger(__name__)

_DEFAULT_PORT_STARTUP_WAIT_SEC = 60
# The DOM test plan's default for max_update_time_sec.
_DEFAULT_DOM_UPDATE_INTERVAL_SEC = 60
_STATE_DB_POLL_INTERVAL_SEC = 5
_DOM_SENSOR_TABLE = "TRANSCEIVER_DOM_SENSOR"

# (field, tolerance). GHz: the configured frequency is grid-derived, so exact;
# the measured one within 1 GHz, under half the narrowest grid spacing
# (3.125 GHz), so a laser left on the old channel still fails. Tx power (dBm)
# is published at 0.01 resolution.
_FREQUENCY_STATE_FIELDS = (("laser_config_freq", 0.001), ("laser_curr_freq", 1.0))
_TX_POWER_STATE_FIELDS = (("tx_config_power", 0.01),)


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


def _check_pre_test_values(
    duthost, values_by_port, config_field, state_fields, lport_to_first_subport_mapping,
):
    """Check each port is currently on its ``values[0]``, so restoring that value
    returns it to its pre-test state.

    Args:
        duthost: DUT host object.
        values_by_port: ``{port: [default, test values...]}``.
        config_field: CONFIG_DB PORT field; if unset, STATE_DB alone decides.
        state_fields: ``((field, tolerance), ...)`` in TRANSCEIVER_DOM_SENSOR.
        lport_to_first_subport_mapping: ``{port: first_subport}``.

    Returns:
        list[str]: one entry per (port, field) not on ``values[0]``.
    """
    defaults = {port: values[0] for port, values in values_by_port.items()}
    port_table = db_helpers.get_config_db_port_table(duthost)
    failures = []
    for port, default in defaults.items():
        configured = (port_table.get(port) or {}).get(config_field)
        logger.info("%s: pre-test CONFIG_DB %s=%s (inventory default %s)",
                    port, config_field, configured, default)
        if configured is not None:
            failures.extend(_verify_config_db_field(port_table, port, config_field, default))
    failures.extend(_check_state_db_applied(
        duthost, defaults, state_fields, lport_to_first_subport_mapping,
    ))
    return failures


def _check_state_db_applied(duthost, applied, state_fields, lport_to_first_subport_mapping):
    """Check one TRANSCEIVER_DOM_SENSOR snapshot against every applied value.

    Reads the table once per namespace; DOM is looked up under each port's first
    sub-port.

    Args:
        duthost: DUT host object.
        applied: ``{port: value}``.
        state_fields: ``((field, tolerance), ...)``.
        lport_to_first_subport_mapping: ``{port: first_subport}``.

    Returns:
        list[str]: one entry per (port, field) that doesn't match yet.
    """
    ports_by_namespace = {}
    for port in applied:
        ports_by_namespace.setdefault(db_helpers.resolve_port_namespace(duthost, port), []).append(port)

    failures = []
    for namespace, ns_ports in ports_by_namespace.items():
        entry_by_port, err = db_helpers.get_state_db_table(duthost, _DOM_SENSOR_TABLE, namespace=namespace)
        if err:
            failures.extend(f"{port}: STATE_DB {_DOM_SENSOR_TABLE} read failed: {err}" for port in ns_ports)
            continue
        for port in ns_ports:
            key = lport_to_first_subport_mapping.get(port, port)
            entry = entry_by_port.get(key) or {}
            expected = db_helpers.parse_numeric(applied[port])
            for field, tolerance in state_fields:
                raw = entry.get(field)
                actual = db_helpers.parse_numeric(raw)
                if expected is None or actual is None or abs(actual - expected) > tolerance:
                    failures.append(
                        f"{port}: STATE_DB {_DOM_SENSOR_TABLE}|{key} '{field}'="
                        f"{raw if raw is not None else 'missing'}, expected {applied[port]}"
                        f" (+/-{tolerance})"
                    )
    return failures


def _wait_state_db_applied(
    duthost, applied, state_fields, port_attributes_dict, lport_to_first_subport_mapping,
):
    """Poll :func:`_check_state_db_applied` for up to one DOM update interval.

    Args:
        duthost: DUT host object.
        applied: ``{port: value}``.
        state_fields: ``((field, tolerance), ...)``.
        port_attributes_dict: per-port attributes; the window is the largest
            ``DOM_ATTRIBUTES.max_update_time_sec``.
        lport_to_first_subport_mapping: ``{port: first_subport}``.

    Returns:
        list[str]: mismatches left at the end of the window.
    """
    wait_sec = max(
        port_attributes_dict[port].get(DOM_ATTRIBUTES_KEY, {}).get(
            "max_update_time_sec", _DEFAULT_DOM_UPDATE_INTERVAL_SEC
        )
        for port in applied
    )
    return scenario_ops.poll_ports_recovered(
        lambda: _check_state_db_applied(duthost, applied, state_fields, lport_to_first_subport_mapping),
        wait_sec, interval_sec=_STATE_DB_POLL_INTERVAL_SEC, label=f"STATE_DB {_DOM_SENSOR_TABLE}",
    )


def _apply_and_verify_round(
    duthost, port_values, apply_fn, config_field, state_fields,
    port_attributes_dict, health_baseline, lport_to_first_subport_mapping,
    expected_pid_changes, label,
):
    """Apply ``{port: value}``, wait once, then verify CONFIG_DB, STATE_DB and
    Standard Port Recovery.

    Returns:
        tuple: ``(setting_failures, recovery_failures)``: values not applied or not
        reflected in CONFIG_DB/STATE_DB, and ports that failed recovery.
    """
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
        return failures, []

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
    # Mismatch text already includes the port and expected value.
    failures.extend(
        f"[{label}] {failure}"
        for failure in _wait_state_db_applied(
            duthost, applied, state_fields, port_attributes_dict, lport_to_first_subport_mapping,
        )
    )

    result = standard_port_recovery_and_verification(
        duthost, list(applied), {port: port_attributes_dict[port] for port in applied},
        link_up_timeout_sec=scenario_ops.scale_bulk_wait(startup_wait, len(applied)),
        health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes,
    )
    recovery_failures = [
        f"[{label}={applied[port]}] {port_result['details']}"
        for port, port_result in result["per_port"].items()
        if not port_result["passed"]
    ]
    return failures, recovery_failures


def _run_ccmis_tuning_test(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping, attribute_key, config_field, state_fields, apply_fn, label,
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
        pytest.skip(f"{attribute_key} has only a default value for every port - nothing to tune")

    pre_test_failures = _check_pre_test_values(
        duthost, values_by_port, config_field, state_fields, lport_to_first_subport_mapping,
    )
    if pre_test_failures:
        pytest.fail(
            f"Pre-test C-CMIS {label} does not match the inventory default ({attribute_key}[0]), "
            "so restoring it would not return the DUT to its pre-test state:\n  - "
            + "\n  - ".join(pre_test_failures)
        )

    health_baseline = capture_baseline(duthost)
    failures = []
    round_kwargs = dict(
        apply_fn=apply_fn, config_field=config_field, state_fields=state_fields,
        port_attributes_dict=port_attributes_dict, health_baseline=health_baseline,
        lport_to_first_subport_mapping=lport_to_first_subport_mapping,
        expected_pid_changes=expected_pid_changes, label=label,
    )

    max_len = max(len(values) for values in values_by_port.values())
    try:
        for index in range(1, max_len):
            port_values = {
                port: values[index]
                for port, values in values_by_port.items() if len(values) > index
            }
            logger.info("Round %d: applying %s to %d port(s)", index, label, len(port_values))
            setting_failures, recovery_failures = _apply_and_verify_round(
                duthost, port_values, **round_kwargs,
            )
            failures.extend(setting_failures + recovery_failures)
    finally:
        # A default that doesn't take ends the session; a port that doesn't
        # recover on it is an ordinary failure.
        logger.info("Restoring default %s on %d port(s)", label, len(values_by_port))
        restore_failures, recovery_failures = _apply_and_verify_round(
            duthost, {port: values[0] for port, values in values_by_port.items()},
            **round_kwargs,
        )
        if restore_failures:
            pytest.exit(
                f"Could not restore default C-CMIS {label}: " + "; ".join(restore_failures)
            )
        failures.extend(recovery_failures)

    if failures:
        pytest.fail(
            f"C-CMIS {label} adjustment validation FAILED on {len(failures)} "
            "item(s):\n  - " + "\n  - ".join(failures)
        )


def test_system_ccmis_frequency_adjustment(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """Each non-default frequency is applied and reported back in CONFIG_DB and as the
    configured and current laser frequency in STATE_DB; the default is then restored.
    """
    _run_ccmis_tuning_test(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping,
        attribute_key="frequency_values", config_field="laser_freq",
        state_fields=_FREQUENCY_STATE_FIELDS,
        apply_fn=_apply_frequency, label="frequency",
    )


def test_system_ccmis_tx_power_adjustment(
    duthost, port_attributes_dict, expected_pid_changes,
    lport_to_first_subport_mapping,
):
    """Each non-default tx power is applied and reported back in CONFIG_DB and as the
    configured tx power in STATE_DB; the default is then restored.
    """
    _run_ccmis_tuning_test(
        duthost, port_attributes_dict, expected_pid_changes,
        lport_to_first_subport_mapping,
        attribute_key="tx_power_values", config_field="tx_power",
        state_fields=_TX_POWER_STATE_FIELDS,
        apply_fn=_apply_tx_power, label="tx power",
    )
