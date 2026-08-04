import logging
import math

import pytest

from tests.transceiver.common.db_helpers import parse_numeric
from tests.transceiver.dom.dom_helpers import (
    build_dom_availability_plan,
    check_dom_sensor_freshness,
    read_dom_sensor_data,
)

logger = logging.getLogger(__name__)


def _format_optional_float(value):
    return "{:.2f}".format(value) if value is not None else "not-available"


def _format_port_failure(port, active_lanes, expected_fields, field_failures):
    """Prefix a port's failure block with its expected shape."""
    return "{} [{} expected field(s), media lanes {}]:\n  {}".format(
        port,
        len(expected_fields),
        active_lanes or "none",
        "\n  ".join(field_failures),
    )


def _parse_operational_range(mapped_field):
    """Return ``(min_value, max_value, error)`` for one mapped DOM field."""
    attr_name = mapped_field.source_attr
    attr_value = mapped_field.attr_value

    if not isinstance(attr_value, dict):
        return None, None, "{} must be a dict with min/max in DOM_ATTRIBUTES".format(attr_name)

    min_value = parse_numeric(attr_value.get("min"))
    max_value = parse_numeric(attr_value.get("max"))
    if min_value is None or max_value is None:
        return None, None, "{} missing numeric min/max in DOM_ATTRIBUTES".format(attr_name)
    if not math.isfinite(min_value) or not math.isfinite(max_value):
        return None, None, "{} has non-finite min/max in DOM_ATTRIBUTES".format(attr_name)
    if min_value > max_value:
        return None, None, "{} has invalid range [{}, {}]".format(
            attr_name,
            attr_value.get("min"),
            attr_value.get("max"),
        )

    return min_value, max_value, None


def _validate_dom_operational_ranges(
    duthost,
    dom_primary_ports,
    sensor_by_port,
    availability_plan_by_port,
):
    """Validate configured DOM sensor fields are fresh and within range."""
    failures = []
    checked_field_count = 0
    checked_port_count = 0
    now_utc = None

    for port in dom_primary_ports:
        sensor_data = sensor_by_port.get(port, {})
        availability_plan = availability_plan_by_port.get(port, {})
        expected_fields = availability_plan.get("expected_fields", {})
        active_lanes = availability_plan.get("active_media_lanes", [])
        field_failures = list(availability_plan.get("errors", []))
        max_age_min = availability_plan.get("max_age_min")
        has_operational_checks = bool(expected_fields or field_failures)

        if has_operational_checks:
            checked_port_count += 1

        freshness_age_min = None
        if max_age_min is not None and has_operational_checks:
            if now_utc is None:
                now_utc = duthost.get_now_time(utc_timezone=True)
            result = check_dom_sensor_freshness(sensor_data, max_age_min, now_utc)
            field_failures.extend(result["failures"])
            freshness_age_min = result["age_minutes"]

        if not sensor_data:
            for field in expected_fields:
                field_failures.append("{} DOM sensor table missing".format(field))
            if field_failures:
                failures.append(_format_port_failure(port, active_lanes, expected_fields, field_failures))
            continue

        checked_fields = 0
        for field, mapped_field in expected_fields.items():
            min_value, max_value, range_error = _parse_operational_range(mapped_field)
            if range_error:
                field_failures.append(range_error)
                continue

            if field not in sensor_data:
                field_failures.append(
                    "expected DOM field missing in STATE_DB sensor data: {}".format(field)
                )
                continue

            raw_value = sensor_data[field]
            numeric_value = parse_numeric(raw_value)
            if numeric_value is None or not math.isfinite(numeric_value):
                field_failures.append(
                    "{} missing/non-finite operational value in STATE_DB (raw={!r})".format(
                        field,
                        raw_value,
                    )
                )
                continue

            if not min_value <= numeric_value <= max_value:
                field_failures.append(
                    "{} value {} out of range [{}, {}]".format(
                        field,
                        numeric_value,
                        min_value,
                        max_value,
                    )
                )
                continue

            checked_fields += 1
            logger.debug(
                "DOM operational range PASS %s %s=%s within [%s, %s] "
                "(source_attr=%s media_lanes=%s freshness_age_min=%s freshness_limit_min=%s)",
                port,
                field,
                numeric_value,
                min_value,
                max_value,
                mapped_field.source_attr,
                active_lanes or "none",
                _format_optional_float(freshness_age_min),
                max_age_min if max_age_min is not None else "not-configured",
            )

        checked_field_count += checked_fields

        if field_failures:
            failures.append(_format_port_failure(port, active_lanes, expected_fields, field_failures))

    return failures, checked_field_count, checked_port_count


def test_dom_sensor_operational_range_validation(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify configured DOM sensor values are fresh and within operational ranges."""
    sensor_by_port, sensor_read_errors = read_dom_sensor_data(duthost, dom_primary_ports)
    availability_plan_by_port = build_dom_availability_plan(
        port_attributes_dict,
        dom_primary_ports,
        lport_to_first_subport_mapping,
    )

    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in sensor_read_errors]
    range_failures, checked_field_count, checked_port_count = _validate_dom_operational_ranges(
        duthost,
        dom_primary_ports,
        sensor_by_port,
        availability_plan_by_port,
    )
    all_failures.extend(range_failures)

    if not (all_failures or checked_port_count):
        pytest.skip("No *_operational_range attributes configured for DOM operational range validation")

    if all_failures:
        pytest.fail("DOM operational range validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM operational range validation passed: %d field(s) across %d port(s)",
        checked_field_count,
        checked_port_count,
    )
