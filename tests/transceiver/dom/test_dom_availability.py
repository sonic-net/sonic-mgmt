import logging
import math

import pytest

from natsort import natsorted

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
    """Prefix a port's failure block with its expected shape (lanes + field count)."""
    return "{} [{} expected field(s), media lanes {}]:\n  {}".format(
        port,
        len(expected_fields),
        active_lanes or "none",
        "\n  ".join(field_failures),
    )


def _validate_dom_primary_ports(duthost, dom_primary_ports, sensor_by_port, availability_plan_by_port):
    """Validate configured DOM fields and freshness for primary breakout subports."""
    failures = []
    checked_field_count = 0
    checked_port_count = 0
    now_utc = None

    for port in dom_primary_ports:
        sensor_data = sensor_by_port.get(port, {})
        availability_plan = availability_plan_by_port.get(port, {})
        expected_fields = availability_plan.get("expected_fields", [])
        active_lanes = availability_plan.get("active_media_lanes", [])
        field_failures = list(availability_plan.get("errors", []))
        max_age_min = availability_plan.get("max_age_min")

        if max_age_min is not None or expected_fields or field_failures:
            checked_port_count += 1

        freshness_age_min = None
        if max_age_min is not None:
            if now_utc is None:
                now_utc = duthost.get_now_time(utc_timezone=True)
            result = check_dom_sensor_freshness(sensor_data, max_age_min, now_utc)
            field_failures.extend(result["failures"])
            freshness_age_min = result["age_minutes"]

        if not sensor_data:
            for field in expected_fields:
                field_failures.append(
                    "missing TRANSCEIVER_DOM_SENSOR data for expected field {}".format(field)
                )
            if field_failures:
                failures.append(_format_port_failure(port, active_lanes, expected_fields, field_failures))
            continue

        checked_fields = 0
        for field in expected_fields:
            if field not in sensor_data:
                field_failures.append(
                    "expected DOM field missing in STATE_DB sensor data: {}".format(field)
                )
                continue
            value = parse_numeric(sensor_data[field])
            if value is None or not math.isfinite(value):
                field_failures.append(
                    "expected DOM field {} has no valid finite value (got {!r})".format(
                        field, sensor_data[field]
                    )
                )
                continue
            checked_fields += 1

        checked_field_count += checked_fields

        if field_failures:
            failures.append(_format_port_failure(port, active_lanes, expected_fields, field_failures))
            continue

        logger.debug(
            "DOM availability PASS %s: media_lanes=%s expected_fields=%s freshness_age_min=%s freshness_limit_min=%s",
            port,
            active_lanes or "none",
            ", ".join(expected_fields) or "none",
            _format_optional_float(freshness_age_min),
            max_age_min if max_age_min is not None else "not-configured",
        )

    return failures, checked_field_count, checked_port_count


def _validate_dom_non_primary_ports(dom_non_primary_ports, sensor_by_port):
    """Validate non-primary breakout subports do not publish DOM sensor data."""
    failures = []
    checked_port_count = 0

    for port in dom_non_primary_ports:
        checked_port_count += 1
        sensor_data = sensor_by_port.get(port, {})
        if sensor_data:
            failures.append(
                "{}:\n  non-primary breakout subport unexpectedly has "
                "TRANSCEIVER_DOM_SENSOR data (fields: {})".format(
                    port, ", ".join(natsorted(sensor_data)) or "none"
                )
            )
            continue
        logger.debug(
            "DOM availability PASS %s: non-primary breakout subport has no TRANSCEIVER_DOM_SENSOR data",
            port,
        )

    return failures, checked_port_count


def test_dom_data_availability_verification(
    duthost,
    dom_primary_ports,
    dom_non_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify configured DOM sensor data is present and fresh in STATE_DB."""
    sensor_ports = natsorted(set(dom_primary_ports) | set(dom_non_primary_ports))
    sensor_by_port, sensor_read_errors = read_dom_sensor_data(duthost, sensor_ports)
    availability_plan_by_port = build_dom_availability_plan(
        port_attributes_dict,
        dom_primary_ports,
        lport_to_first_subport_mapping,
    )

    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in sensor_read_errors]
    primary_failures, checked_field_count, checked_primary_port_count = _validate_dom_primary_ports(
        duthost,
        dom_primary_ports,
        sensor_by_port,
        availability_plan_by_port,
    )
    non_primary_failures, checked_non_primary_port_count = _validate_dom_non_primary_ports(
        dom_non_primary_ports,
        sensor_by_port,
    )
    all_failures.extend(primary_failures)
    all_failures.extend(non_primary_failures)

    if not (all_failures or checked_primary_port_count or checked_non_primary_port_count):
        pytest.skip("No DOM availability checks configured from DOM_ATTRIBUTES")

    if all_failures:
        pytest.fail("DOM availability validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM availability validation passed: %d expected field(s) across %d port(s)",
        checked_field_count,
        checked_primary_port_count,
    )

    if checked_non_primary_port_count:
        logger.info(
            "DOM availability validation passed: %d non-primary breakout subport(s) had no sensor data",
            checked_non_primary_port_count,
        )
