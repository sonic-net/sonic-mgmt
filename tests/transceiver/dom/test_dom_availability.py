import logging

import pytest

from natsort import natsorted

logger = logging.getLogger(__name__)


def test_dom_data_availability_verification(
    dom_ports,
    dom_port_context,
    dom_sensor_by_port,
    dom_availability_plan_by_port,
    dom_freshness_failures,
    dom_freshness_age_minutes,
    dom_now_utc,
):
    """Verify configured DOM sensor data is present and fresh in STATE_DB."""
    all_failures = []
    has_configured_checks = False
    now_utc = dom_now_utc()
    checked_fields_by_port = {}
    freshness_age_by_port = {}

    for port in dom_ports:
        dom_attrs = dom_port_context[port]["dom"]
        sensor_data = dom_sensor_by_port.get(port, {})
        availability_plan = dom_availability_plan_by_port.get(port, {})
        expected_fields = availability_plan.get("expected_fields", [])
        field_failures = list(availability_plan.get("errors", []))
        max_age_min = dom_attrs.get("data_max_age_min")

        if max_age_min is not None or expected_fields or field_failures:
            has_configured_checks = True

        field_failures.extend(dom_freshness_failures(sensor_data, max_age_min, now_utc))
        freshness_age_min = dom_freshness_age_minutes(sensor_data, now_utc)
        freshness_age_by_port[port] = freshness_age_min

        if not sensor_data:
            for field in expected_fields:
                field_failures.append(
                    "missing TRANSCEIVER_DOM_SENSOR data for expected field {}".format(field)
                )
            if field_failures:
                all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
            continue

        checked_fields = 0
        for field in expected_fields:
            if field not in sensor_data:
                field_failures.append(
                    "expected DOM field missing in STATE_DB sensor data: {}".format(field)
                )
                continue
            checked_fields += 1

        checked_fields_by_port[port] = checked_fields

        if field_failures:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
            continue

        logger.debug(
            "DOM availability PASS %s: expected_fields=%s freshness_age_min=%s freshness_limit_min=%s",
            port,
            ", ".join(expected_fields) or "none",
            "{:.2f}".format(freshness_age_min) if freshness_age_min is not None else "not-available",
            max_age_min if max_age_min is not None else "not-configured",
        )

    if not has_configured_checks:
        pytest.skip("No DOM availability checks configured from DOM_ATTRIBUTES")

    if all_failures:
        pytest.fail("DOM availability validation failures:\n" + "\n".join(all_failures))

    total_checked_fields = sum(checked_fields_by_port.values())
    logger.info(
        "DOM availability validation passed: %d expected field(s) across %d port(s)",
        total_checked_fields,
        len(checked_fields_by_port),
    )
    for port in natsorted(checked_fields_by_port):
        freshness_age_min = freshness_age_by_port.get(port)
        logger.info(
            "DOM availability validation %s: checked %d field(s), freshness age_min=%s limit_min=%s",
            port,
            checked_fields_by_port[port],
            "{:.2f}".format(freshness_age_min) if freshness_age_min is not None else "not-available",
            dom_port_context[port]["dom"].get("data_max_age_min", "not-configured"),
        )
