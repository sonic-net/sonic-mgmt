import pytest


def test_dom_data_availability_verification(
    duthost,
    dom_ports,
    dom_port_context,
    dom_sensor_by_port,
    dom_availability_plan_by_port,
    parse_dom_update_time,
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

        if not sensor_data:
            if max_age_min is not None:
                field_failures.append(
                    "missing TRANSCEIVER_DOM_SENSOR data for last_update_time freshness check"
                )
            for field in expected_fields:
                field_failures.append(
                    "missing TRANSCEIVER_DOM_SENSOR data for expected field {}".format(field)
                )
            if field_failures:
                all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
            continue

        if max_age_min is not None:
            try:
                max_age = float(max_age_min)
            except (TypeError, ValueError):
                field_failures.append(
                    "invalid data_max_age_min={!r} in DOM_ATTRIBUTES".format(max_age_min)
                )
            else:
                parsed_time = parse_dom_update_time(sensor_data.get("last_update_time"))
                if parsed_time is None:
                    field_failures.append(
                        "last_update_time missing or unparsable while data_max_age_min is configured"
                    )
                else:
                    age_minutes = (now_utc - parsed_time).total_seconds() / 60.0
                    if age_minutes > max_age:
                        field_failures.append(
                            "last_update_time too old (age_min={:.2f}, limit={})".format(
                                age_minutes,
                                max_age_min,
                            )
                        )

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
