import pytest


def test_dom_data_availability_verification(
    duthost,
    dom_ports,
    dom_port_context,
    dom_sensor_by_port,
    dom_availability_plan_by_port,
    dom_freshness_failures,
    dom_now_utc,
):
    """Verify configured DOM sensor data is present and fresh in STATE_DB."""
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping DOM verification on virtual switch testbed")

    all_failures = []
    has_configured_checks = False
    now_utc = dom_now_utc()

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

        if not sensor_data:
            for field in expected_fields:
                field_failures.append(
                    "missing TRANSCEIVER_DOM_SENSOR data for expected field {}".format(field)
                )
            if field_failures:
                all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
            continue

        for field in expected_fields:
            if field not in sensor_data:
                field_failures.append(
                    "expected DOM field missing in STATE_DB sensor data: {}".format(field)
                )

        if field_failures:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))

    if not has_configured_checks:
        pytest.skip("No DOM availability checks configured from DOM_ATTRIBUTES")

    if all_failures:
        pytest.fail("DOM availability validation failures:\n" + "\n".join(all_failures))
