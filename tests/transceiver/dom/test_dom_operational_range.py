import logging

import pytest

logger = logging.getLogger(__name__)


def test_dom_sensor_operational_range_validation(
    duthost,
    dom_ports,
    dom_port_context,
    dom_sensor_by_port,
    parse_dom_numeric,
    parse_dom_update_time,
    dom_now_utc,
    dom_operational_suffix,
    dom_lane_num_placeholder,
    dom_expand_operational_fields,
    dom_get_lane_count,
):
    """Verify configured DOM sensor values are within operational ranges."""
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping DOM verification on virtual switch testbed")

    all_failures = []
    has_configured_checks = False
    now_utc = dom_now_utc()
    checked_fields_by_port = {}

    for port in dom_ports:
        context = dom_port_context[port]
        dom_attrs = context["dom"]
        sensor_data = dom_sensor_by_port.get(port, {})
        field_failures = []
        checked_fields = 0

        max_age_min = dom_attrs.get("data_max_age_min")
        if max_age_min is not None:
            has_configured_checks = True
            if not sensor_data:
                field_failures.append("missing TRANSCEIVER_DOM_SENSOR data for freshness check")
            else:
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

        lane_count = dom_get_lane_count(context["base"])
        for attr_name, attr_value in sorted(dom_attrs.items()):
            if not attr_name.endswith(dom_operational_suffix):
                continue

            has_configured_checks = True
            if not isinstance(attr_value, dict):
                field_failures.append(
                    "{} must be a dict with min/max in DOM_ATTRIBUTES".format(attr_name)
                )
                continue

            min_value = parse_dom_numeric(attr_value.get("min"))
            max_value = parse_dom_numeric(attr_value.get("max"))
            if min_value is None or max_value is None:
                field_failures.append("{} missing numeric min/max in DOM_ATTRIBUTES".format(attr_name))
                continue
            if min_value > max_value:
                field_failures.append(
                    "{} has invalid range [{}, {}]".format(attr_name, attr_value.get("min"), attr_value.get("max"))
                )
                continue

            fields = dom_expand_operational_fields(attr_name, lane_count)
            if not fields and dom_lane_num_placeholder in attr_name:
                field_failures.append(
                    "{} uses {} but {} has no valid lane count".format(
                        attr_name,
                        dom_lane_num_placeholder,
                        port,
                    )
                )
                continue

            for field in fields:
                if not sensor_data:
                    field_failures.append("{} DOM sensor table missing".format(field))
                    continue

                raw_value = sensor_data.get(field)
                numeric_value = parse_dom_numeric(raw_value)
                if numeric_value is None:
                    field_failures.append(
                        "{} missing/non-numeric operational value in STATE_DB (raw={!r})".format(
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
                    "DOM operational range PASS %s %s=%s within [%s, %s]",
                    port,
                    field,
                    numeric_value,
                    min_value,
                    max_value,
                )

        if field_failures:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
        checked_fields_by_port[port] = checked_fields

    if not has_configured_checks:
        pytest.skip("No *_operational_range attributes configured for DOM operational range validation")

    if all_failures:
        pytest.fail("DOM operational range validation failures:\n" + "\n".join(all_failures))

    total_checked_fields = sum(checked_fields_by_port.values())
    logger.info(
        "DOM operational range validation passed: %d field(s) across %d port(s)",
        total_checked_fields,
        len(checked_fields_by_port),
    )
