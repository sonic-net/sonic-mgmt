import pytest

from tests.transceiver.dom.utils.dom_constants import (
    LANE_NUM_PLACEHOLDER,
    OPERATIONAL_SUFFIX,
)
from tests.transceiver.dom.utils.dom_field_mapper import (
    expand_operational_fields,
    get_lane_count,
)


def test_dom_sensor_operational_range_validation(
    dom_health_guard,
    dom_ports,
    dom_port_context,
    dom_sensor_by_port,
    parse_dom_numeric,
    parse_dom_update_time,
    dom_now_utc,
):
    """TC2: Validate configured operational ranges against DOM sensor readings.

    Args:
        dom_health_guard: Explicit pre-test and post-test DOM health guard.
        dom_ports: DOM-enabled ports selected for validation.
        dom_port_context: Per-port DOM context with configured DOM attributes.
        dom_sensor_by_port: Initial ``TRANSCEIVER_DOM_SENSOR`` data keyed by port.
        parse_dom_numeric: Parser for numeric DOM values.
        parse_dom_update_time: Parser for DOM ``last_update_time`` values.
        dom_now_utc: Callable that returns the current UTC time.

    Returns:
        None.
    """
    # Step 0: Initialize per-test aggregation and current DUT time source.
    all_failures = []
    has_configured_checks = False
    now_utc = dom_now_utc()

    for port in dom_ports:
        # Step 1: Resolve per-port context and DOM sensor data.
        context = dom_port_context[port]
        dom_attrs = context["dom"]
        base_attrs = context["base"]
        sensor_data = dom_sensor_by_port.get(port, {})
        field_failures = []

        # Step 2: Validate timestamp freshness when data_max_age_min is configured.
        max_age_min = dom_attrs.get("data_max_age_min")
        if max_age_min is not None:
            has_configured_checks = True

        if max_age_min is not None:
            if not sensor_data:
                field_failures.append("missing TRANSCEIVER_DOM_SENSOR data for freshness check")
            else:
                parsed_time = parse_dom_update_time(sensor_data.get("last_update_time"))
                if parsed_time is None:
                    field_failures.append(
                        "last_update_time missing or unparsable while data_max_age_min is configured"
                    )
                else:
                    age_minutes = (now_utc - parsed_time).total_seconds() / 60.0
                    if age_minutes > float(max_age_min):
                        field_failures.append(
                            "last_update_time too old (age_min={:.2f}, limit={})".format(age_minutes, max_age_min)
                        )

        # Step 3: Dynamically derive expected sensor fields from *_operational_range attributes.
        lane_count = get_lane_count(base_attrs)

        for attr_name, attr_value in dom_attrs.items():
            if not attr_name.endswith(OPERATIONAL_SUFFIX) or not isinstance(attr_value, dict):
                continue

            has_configured_checks = True

            min_value = attr_value.get("min")
            max_value = attr_value.get("max")
            if min_value is None or max_value is None:
                field_failures.append("{} missing required min/max in DOM_ATTRIBUTES".format(attr_name))
                continue

            fields = expand_operational_fields(attr_name, lane_count)
            if not fields and LANE_NUM_PLACEHOLDER in attr_name:
                field_failures.append("{} requires lane count but lane_count <= 0".format(attr_name))
                continue

            # Step 4: Validate each derived field is numeric and inside configured operational range.
            for field in fields:
                if not sensor_data:
                    field_failures.append("{} DOM sensor table missing".format(field))
                    continue
                raw_value = sensor_data.get(field)
                numeric_value = parse_dom_numeric(raw_value)
                if numeric_value is None:
                    field_failures.append(
                        "{} missing/non-numeric operational value in STATE_DB (raw={!r})".format(field, raw_value)
                    )
                    continue

                if not float(min_value) <= numeric_value <= float(max_value):
                    field_failures.append(
                        "{} value {} out of range [{}, {}]".format(field, numeric_value, min_value, max_value)
                    )

        if field_failures:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))

    # Step 5: Final decision for skip/fail.
    if not has_configured_checks:
        pytest.skip("No *_operational_range attributes configured for DOM operational range validation")

    if all_failures:
        pytest.fail("DOM operational range validation failures:\n" + "\n".join(all_failures))
