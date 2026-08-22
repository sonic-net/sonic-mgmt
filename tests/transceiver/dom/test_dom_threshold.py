import logging
import math

import pytest

from tests.transceiver.common.db_helpers import parse_numeric
from tests.transceiver.dom.dom_helpers import (
    STATE_DB_THRESHOLD_TABLE,
    THRESHOLD_FIELD_SUFFIXES,
    THRESHOLD_VALUE_TOLERANCE,
    build_dom_threshold_plan,
    format_dom_port_failure,
    parse_min_max_range,
    read_dom_threshold_data,
)

logger = logging.getLogger(__name__)


def _parse_threshold_range(attr_name, attr_value):
    """Return ``(thresholds, errors)`` for one configured threshold attribute."""
    if not isinstance(attr_value, dict):
        return {}, [
            "{} must be a dict with {} in DOM_ATTRIBUTES".format(
                attr_name,
                THRESHOLD_FIELD_SUFFIXES,
            )
        ]

    thresholds = {}
    errors = []
    for threshold_key in THRESHOLD_FIELD_SUFFIXES:
        value = parse_numeric(attr_value.get(threshold_key))
        if value is None or not math.isfinite(value):
            errors.append(
                "{} missing/non-finite numeric {} in DOM_ATTRIBUTES".format(
                    attr_name,
                    threshold_key,
                )
            )
            continue
        thresholds[threshold_key] = value

    if errors:
        return {}, errors

    hierarchy_error = _threshold_hierarchy_error(attr_name, thresholds, "configured")
    if hierarchy_error:
        return {}, [hierarchy_error]

    return thresholds, []


def _threshold_hierarchy_error(attr_name, thresholds, source):
    if (
        thresholds["lowalarm"]
        < thresholds["lowwarning"]
        < thresholds["highwarning"]
        < thresholds["highalarm"]
    ):
        return None
    return (
        "{} {} hierarchy lowalarm < lowwarning < highwarning < highalarm "
        "is violated".format(attr_name, source)
    )


def _validate_operational_range_within_warning(threshold_attr, thresholds, operational_mapped_field):
    """Validate a paired operational range sits inside threshold warning bounds."""
    op_min, op_max, range_error = parse_min_max_range(operational_mapped_field)
    if range_error:
        return [range_error]

    if thresholds["lowwarning"] < op_min and op_max < thresholds["highwarning"]:
        return []

    return [
        "{} operational range [{}, {}] is not within {} warning bounds ({}, {})".format(
            operational_mapped_field.source_attr,
            op_min,
            op_max,
            threshold_attr,
            thresholds["lowwarning"],
            thresholds["highwarning"],
        )
    ]


def _has_threshold_range_attributes(threshold_plan_by_port):
    """Return True when any primary port has configured threshold-range checks."""
    return any(
        plan.get("configured_by_attr") or plan.get("errors")
        for plan in threshold_plan_by_port.values()
    )


def _db_values_for_attr(attr_name, threshold_table_data, db_fields_by_name):
    """Return ``(db_values, errors)`` for one configured threshold attribute."""
    db_values = {}
    errors = []
    for field, mapped_field in db_fields_by_name.items():
        raw_value = threshold_table_data.get(field)
        actual_value = parse_numeric(raw_value)
        if actual_value is None or not math.isfinite(actual_value):
            errors.append(
                "{} threshold field {} missing/non-finite in STATE_DB (raw={!r})".format(
                    attr_name,
                    field,
                    raw_value,
                )
            )
            continue
        db_values[mapped_field.threshold_key] = actual_value
    return db_values, errors


def _compare_thresholds(attr_name, configured_values, db_values):
    """Return threshold value mismatch errors between configured and STATE_DB values."""
    errors = []
    for threshold_key in THRESHOLD_FIELD_SUFFIXES:
        expected_value = configured_values[threshold_key]
        actual_value = db_values[threshold_key]
        if abs(actual_value - expected_value) > THRESHOLD_VALUE_TOLERANCE:
            errors.append(
                "{} expected {}={}, got {} from STATE_DB".format(
                    attr_name,
                    threshold_key,
                    expected_value,
                    actual_value,
                )
            )
    return errors


def _validate_threshold_attr(attr_name, attr_value, threshold_table_data, db_fields_by_name, operational_mapped_field):
    """Return ``(errors, checked_fields, skipped_checks)`` for one threshold attribute."""
    attr_errors = []
    skipped_checks = 0

    configured_values, threshold_errors = _parse_threshold_range(attr_name, attr_value)
    attr_errors.extend(threshold_errors)
    if threshold_errors:
        return attr_errors, 0, skipped_checks

    if not db_fields_by_name:
        return ["{} has no expected STATE_DB threshold fields".format(attr_name)], 0, skipped_checks

    db_values, db_value_errors = _db_values_for_attr(attr_name, threshold_table_data, db_fields_by_name)
    attr_errors.extend(db_value_errors)
    if len(db_values) != len(THRESHOLD_FIELD_SUFFIXES):
        skipped_checks += 1
        if operational_mapped_field:
            skipped_checks += 1
        attr_errors.append(
            "{} skipped STATE_DB hierarchy{} check(s) because STATE_DB threshold data is incomplete".format(
                attr_name,
                " and operational-range-within-warning" if operational_mapped_field else "",
            )
        )
        return attr_errors, 0, skipped_checks

    attr_errors.extend(_compare_thresholds(attr_name, configured_values, db_values))

    hierarchy_error = _threshold_hierarchy_error(attr_name, db_values, "STATE_DB")
    if hierarchy_error:
        attr_errors.append(hierarchy_error)

    if operational_mapped_field:
        attr_errors.extend(
            _validate_operational_range_within_warning(
                attr_name,
                db_values,
                operational_mapped_field,
            )
        )
    else:
        skipped_checks += 1

    return attr_errors, len(db_fields_by_name) if not attr_errors else 0, skipped_checks


def _validate_dom_threshold_ranges(dom_primary_ports, threshold_table_by_port, threshold_plan_by_port):
    """Validate configured DOM threshold fields against STATE_DB threshold data."""
    failures = []
    checked_attr_count = 0
    checked_field_count = 0
    checked_port_count = 0
    skipped_check_count = 0

    for port in dom_primary_ports:
        threshold_table_data = threshold_table_by_port.get(port, {})
        threshold_plan = threshold_plan_by_port.get(port, {})
        expected_fields = threshold_plan.get("expected_fields", {})
        configured_by_attr = threshold_plan.get("configured_by_attr", {})
        db_fields_by_threshold_attr = threshold_plan.get("db_fields_by_threshold_attr", {})
        operational_range_by_threshold_attr = threshold_plan.get("operational_range_by_threshold_attr", {})
        field_failures = list(threshold_plan.get("errors", []))
        has_threshold_checks = bool(expected_fields or configured_by_attr or field_failures)

        if has_threshold_checks:
            checked_port_count += 1

        if has_threshold_checks and threshold_table_data is None:
            field_failures.append(
                "could not read {} for port (namespace read failed)".format(STATE_DB_THRESHOLD_TABLE)
            )
            failures.append(
                format_dom_port_failure(
                    port,
                    [],
                    expected_fields,
                    field_failures,
                    field_label="expected threshold field(s)",
                    include_lanes=False,
                )
            )
            continue

        if has_threshold_checks and not threshold_table_data:
            field_failures.append(
                "no {} entry published for port".format(STATE_DB_THRESHOLD_TABLE)
            )
            failures.append(
                format_dom_port_failure(
                    port,
                    [],
                    expected_fields,
                    field_failures,
                    field_label="expected threshold field(s)",
                    include_lanes=False,
                )
            )
            continue

        for attr_name, attr_value in sorted(configured_by_attr.items()):
            db_fields_by_name = db_fields_by_threshold_attr.get(attr_name, {})
            operational_mapped_field = operational_range_by_threshold_attr.get(attr_name)
            attr_errors, checked_fields, skipped_checks = _validate_threshold_attr(
                attr_name,
                attr_value,
                threshold_table_data,
                db_fields_by_name,
                operational_mapped_field,
            )
            skipped_check_count += skipped_checks
            if skipped_checks:
                logger.warning(
                    "DOM threshold reduced coverage %s %s: %d check(s) skipped",
                    port,
                    attr_name,
                    skipped_checks,
                )
            if not operational_mapped_field:
                logger.warning(
                    "DOM threshold reduced coverage %s %s: no paired operational range configured",
                    port,
                    attr_name,
                )

            if attr_errors:
                field_failures.extend(attr_errors)
            else:
                checked_attr_count += 1
                checked_field_count += checked_fields
                logger.debug(
                    "DOM threshold PASS %s %s fields=%s operational_attr=%s",
                    port,
                    attr_name,
                    sorted(db_fields_by_name),
                    operational_mapped_field.source_attr if operational_mapped_field else "not-configured",
                )

        if field_failures:
            failures.append(
                format_dom_port_failure(
                    port,
                    [],
                    expected_fields,
                    field_failures,
                    field_label="expected threshold field(s)",
                    include_lanes=False,
                )
            )

    return failures, checked_attr_count, checked_field_count, checked_port_count, skipped_check_count


def test_dom_threshold_validation(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
):
    """Verify configured DOM threshold ranges against STATE_DB threshold data."""
    threshold_plan_by_port = build_dom_threshold_plan(port_attributes_dict, dom_primary_ports)
    if not _has_threshold_range_attributes(threshold_plan_by_port):
        pytest.skip("No *_threshold_range attributes configured for DOM threshold validation")

    threshold_table_by_port, threshold_read_errors = read_dom_threshold_data(duthost, dom_primary_ports)
    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in threshold_read_errors]
    threshold_failures, checked_attr_count, checked_field_count, checked_port_count, skipped_check_count = (
        _validate_dom_threshold_ranges(
            dom_primary_ports,
            threshold_table_by_port,
            threshold_plan_by_port,
        )
    )
    all_failures.extend(threshold_failures)

    if all_failures:
        pytest.fail("DOM threshold validation failures:\n" + "\n".join(all_failures))

    if skipped_check_count:
        logger.warning("DOM threshold validation completed with %d skipped check(s)", skipped_check_count)
    logger.info(
        "DOM threshold validation passed: %d threshold attribute(s), %d field(s) across %d port(s), "
        "%d skipped check(s)",
        checked_attr_count,
        checked_field_count,
        checked_port_count,
        skipped_check_count,
    )
