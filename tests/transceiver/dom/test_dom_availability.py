import pytest


def test_dom_data_availability_verification(
    duthost,
    dom_health_guard,
    dom_ports,
    dom_port_context,
    dom_sensor_by_port,
    dom_operational_fields_by_port,
    parse_dom_update_time,
    dom_now_utc,
):
    """Verify DOM readability and freshness via STATE_DB in a configuration-driven manner.

    Args:
        duthost: DUT host fixture.
        dom_health_guard: Explicit pre-test and post-test DOM health guard.
        dom_ports: DOM-enabled ports selected for validation.
        dom_port_context: Per-port DOM context with configured DOM attributes.
        dom_sensor_by_port: Initial ``TRANSCEIVER_DOM_SENSOR`` data keyed by port.
        dom_operational_fields_by_port: Expected DOM sensor fields keyed by port.
        parse_dom_update_time: Parser for DOM ``last_update_time`` values.
        dom_now_utc: Callable that returns the current UTC time.

    Returns:
        None.
    """
    # Step 0: Skip unsupported virtual-switch environment.
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping DOM verification on virtual switch testbed")

    all_failures = []
    has_configured_checks = False
    now_utc = dom_now_utc()

    for port in dom_ports:
        # Step 1: Build expected checks for this port from resolved DOM attributes.
        sensor_data = dom_sensor_by_port.get(port, {})
        dom_attrs = dom_port_context[port]["dom"]
        expected_fields = dom_operational_fields_by_port.get(port, [])
        field_failures = []

        # last_update_time freshness is config-driven and optional.
        max_age_min = dom_attrs.get("data_max_age_min")
        if max_age_min is not None:
            has_configured_checks = True
        if expected_fields:
            has_configured_checks = True

        # Step 2: Validate STATE_DB table existence when checks are configured.
        if not sensor_data:
            if max_age_min is not None:
                field_failures.append("missing TRANSCEIVER_DOM_SENSOR data for freshness check")
            for field in expected_fields:
                field_failures.append("missing TRANSCEIVER_DOM_SENSOR data for expected field {}".format(field))
            if field_failures:
                all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
            continue

        # Step 3: Validate timestamp freshness when data_max_age_min is configured.
        if max_age_min is not None:
            parsed_time = parse_dom_update_time(sensor_data.get("last_update_time"))
            if parsed_time is None:
                field_failures.append("last_update_time missing or unparsable while data_max_age_min is configured")
            else:
                age_minutes = (now_utc - parsed_time).total_seconds() / 60.0
                if age_minutes > float(max_age_min):
                    field_failures.append(
                        "last_update_time too old (age_min={:.2f}, limit={})".format(age_minutes, max_age_min)
                    )

        # Step 4: Validate presence of all dynamically expected DOM sensor fields.
        for field in expected_fields:
            if field not in sensor_data:
                field_failures.append("expected DOM field missing in STATE_DB sensor data: {}".format(field))

        if field_failures:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))

    # Step 5: Final decision for skip/fail.
    if not has_configured_checks:
        pytest.skip("No DOM availability checks configured from DOM_ATTRIBUTES")

    if all_failures:
        pytest.fail("DOM availability validation failures:\n" + "\n".join(all_failures))
