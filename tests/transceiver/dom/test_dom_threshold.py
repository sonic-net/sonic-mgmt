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
        plan.get("threshold_attrs") or plan.get("errors")
        for plan in threshold_plan_by_port.values()
    )


def _validate_dom_threshold_ranges(dom_primary_ports, threshold_by_port, threshold_plan_by_port):
    """Validate configured DOM threshold fields against STATE_DB threshold data."""
    failures = []
    checked_attr_count = 0
    checked_field_count = 0
    checked_port_count = 0

    for port in dom_primary_ports:
        threshold_data = threshold_by_port.get(port, {})
        threshold_plan = threshold_plan_by_port.get(port, {})
        expected_fields = threshold_plan.get("expected_fields", {})
        threshold_attrs = threshold_plan.get("threshold_attrs", {})
        operational_ranges = threshold_plan.get("operational_ranges", {})
        field_failures = list(threshold_plan.get("errors", []))
        has_threshold_checks = bool(expected_fields or threshold_attrs or field_failures)

        if has_threshold_checks:
            checked_port_count += 1

        if has_threshold_checks and not threshold_data:
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

        for attr_name, attr_value in sorted(threshold_attrs.items()):
            attr_failure_count = len(field_failures)
            attr_expected_fields = {
                field: mapped_field
                for field, mapped_field in expected_fields.items()
                if mapped_field.source_attr == attr_name
            }

            expected_thresholds, threshold_errors = _parse_threshold_range(attr_name, attr_value)
            field_failures.extend(threshold_errors)
            if threshold_errors:
                continue

            if not attr_expected_fields:
                field_failures.append("{} has no expected STATE_DB threshold fields".format(attr_name))
                continue

            actual_thresholds = {}
            for field, mapped_field in attr_expected_fields.items():
                raw_value = threshold_data.get(field)
                actual_value = parse_numeric(raw_value)
                if actual_value is None or not math.isfinite(actual_value):
                    field_failures.append(
                        "{} threshold field {} missing/non-finite in STATE_DB (raw={!r})".format(
                            attr_name,
                            field,
                            raw_value,
                        )
                    )
                    continue
                actual_thresholds[mapped_field.threshold_key] = actual_value

            if len(actual_thresholds) != len(THRESHOLD_FIELD_SUFFIXES):
                continue

            for threshold_key in THRESHOLD_FIELD_SUFFIXES:
                expected_value = expected_thresholds[threshold_key]
                actual_value = actual_thresholds[threshold_key]
                if abs(actual_value - expected_value) > THRESHOLD_VALUE_TOLERANCE:
                    field_failures.append(
                        "{} expected {}={}, got {} from STATE_DB".format(
                            attr_name,
                            threshold_key,
                            expected_value,
                            actual_value,
                        )
                    )

            hierarchy_error = _threshold_hierarchy_error(attr_name, actual_thresholds, "STATE_DB")
            if hierarchy_error:
                field_failures.append(hierarchy_error)

            operational_mapped_field = operational_ranges.get(attr_name)
            if operational_mapped_field:
                field_failures.extend(
                    _validate_operational_range_within_warning(
                        attr_name,
                        actual_thresholds,
                        operational_mapped_field,
                    )
                )

            if len(field_failures) == attr_failure_count:
                checked_attr_count += 1
                checked_field_count += len(attr_expected_fields)
                logger.debug(
                    "DOM threshold PASS %s %s fields=%s operational_attr=%s",
                    port,
                    attr_name,
                    sorted(attr_expected_fields),
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

    return failures, checked_attr_count, checked_field_count, checked_port_count


def test_dom_threshold_validation(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
):
    """Verify configured DOM threshold ranges against STATE_DB threshold data."""
    threshold_plan_by_port = build_dom_threshold_plan(port_attributes_dict, dom_primary_ports)
    if not _has_threshold_range_attributes(threshold_plan_by_port):
        pytest.skip("No *_threshold_range attributes configured for DOM threshold validation")

    threshold_by_port, threshold_read_errors = read_dom_threshold_data(duthost, dom_primary_ports)
    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in threshold_read_errors]
    threshold_failures, checked_attr_count, checked_field_count, checked_port_count = (
        _validate_dom_threshold_ranges(
            dom_primary_ports,
            threshold_by_port,
            threshold_plan_by_port,
        )
    )
    all_failures.extend(threshold_failures)

    if all_failures:
        pytest.fail("DOM threshold validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM threshold validation passed: %d threshold attribute(s), %d field(s) across %d port(s)",
        checked_attr_count,
        checked_field_count,
        checked_port_count,
    )
