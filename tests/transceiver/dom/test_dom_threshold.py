import logging

import pytest

logger = logging.getLogger(__name__)


def test_dom_threshold_validation(
    duthost,
    dom_ports,
    dom_port_context,
    dom_threshold_fields_by_port,
    dom_threshold_by_port,
    parse_dom_numeric,
    dom_threshold_field_suffixes,
    dom_threshold_suffix,
    dom_threshold_value_tolerance,
    dom_operational_attr_candidates,
):
    """Verify configured DOM threshold ranges against STATE_DB threshold data."""
    if duthost.facts.get("asic_type") == "vs":
        pytest.skip("Skipping DOM verification on virtual switch testbed")

    all_failures = []
    has_configured_checks = False
    checked_attrs_by_port = {}
    checked_fields_by_port = {}

    for port in dom_ports:
        dom_attrs = dom_port_context[port]["dom"]
        threshold_fields = dom_threshold_fields_by_port.get(port, {})
        threshold_data = dom_threshold_by_port.get(port, {})
        field_failures = []
        checked_attrs = 0
        checked_fields = 0

        for attr_name, attr_value in sorted(dom_attrs.items()):
            if not attr_name.endswith(dom_threshold_suffix):
                continue

            has_configured_checks = True
            attr_failure_count = len(field_failures)

            if not isinstance(attr_value, dict):
                field_failures.append(
                    "{} must be a dict with {} in DOM_ATTRIBUTES".format(
                        attr_name,
                        dom_threshold_field_suffixes,
                    )
                )
                continue

            expected_thresholds = {}
            for logical_key in dom_threshold_field_suffixes:
                expected = parse_dom_numeric(attr_value.get(logical_key))
                if expected is None:
                    field_failures.append(
                        "{} missing numeric {} in DOM_ATTRIBUTES".format(attr_name, logical_key)
                    )
                    continue
                expected_thresholds[logical_key] = expected

            if len(expected_thresholds) != len(dom_threshold_field_suffixes):
                continue

            if not (
                expected_thresholds["lowalarm"]
                < expected_thresholds["lowwarning"]
                < expected_thresholds["highwarning"]
                < expected_thresholds["highalarm"]
            ):
                field_failures.append(
                    "{} configured hierarchy lowalarm < lowwarning < highwarning < highalarm "
                    "is violated".format(attr_name)
                )
                continue

            if not threshold_data:
                field_failures.append("{} threshold table missing in STATE_DB".format(attr_name))
                continue

            field_map = threshold_fields.get(attr_name, {})
            if not field_map:
                field_failures.append("{} has no STATE_DB threshold field mapping".format(attr_name))
                continue

            actual_thresholds = {}
            for logical_key in dom_threshold_field_suffixes:
                db_field = field_map.get(logical_key)
                actual = parse_dom_numeric(threshold_data.get(db_field))
                if actual is None:
                    field_failures.append(
                        "{} threshold field {} missing/non-numeric in STATE_DB".format(
                            attr_name,
                            db_field,
                        )
                    )
                    continue
                actual_thresholds[logical_key] = actual

            if len(actual_thresholds) != len(dom_threshold_field_suffixes):
                continue

            for logical_key in dom_threshold_field_suffixes:
                expected = expected_thresholds[logical_key]
                actual = actual_thresholds[logical_key]
                if abs(actual - expected) > dom_threshold_value_tolerance:
                    field_failures.append(
                        "{} expected {}={}, got {}".format(
                            attr_name,
                            logical_key,
                            expected,
                            actual,
                        )
                    )

            if not (
                actual_thresholds["lowalarm"]
                < actual_thresholds["lowwarning"]
                < actual_thresholds["highwarning"]
                < actual_thresholds["highalarm"]
            ):
                field_failures.append(
                    "{} STATE_DB hierarchy lowalarm < lowwarning < highwarning < highalarm "
                    "is violated".format(attr_name)
                )

            base_name = attr_name[:-len(dom_threshold_suffix)]
            for operational_attr in dom_operational_attr_candidates(base_name):
                if operational_attr not in dom_attrs:
                    continue

                operational_range = dom_attrs.get(operational_attr)
                if not isinstance(operational_range, dict):
                    field_failures.append(
                        "{} must be a dict with min/max in DOM_ATTRIBUTES".format(operational_attr)
                    )
                    continue

                op_min = parse_dom_numeric(operational_range.get("min"))
                op_max = parse_dom_numeric(operational_range.get("max"))
                if op_min is None or op_max is None:
                    field_failures.append(
                        "{} missing numeric min/max in DOM_ATTRIBUTES".format(operational_attr)
                    )
                    continue

                if not actual_thresholds["lowwarning"] < op_min <= op_max < actual_thresholds["highwarning"]:
                    field_failures.append(
                        "{} operational range [{}, {}] is not within warning bounds ({}, {})".format(
                            operational_attr,
                            op_min,
                            op_max,
                            actual_thresholds["lowwarning"],
                            actual_thresholds["highwarning"],
                        )
                    )

            if len(field_failures) == attr_failure_count:
                checked_attrs += 1
                checked_fields += len(field_map)
                logger.debug(
                    "DOM threshold PASS %s %s fields=%s",
                    port,
                    attr_name,
                    sorted(field_map.values()),
                )

        if field_failures:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
        checked_attrs_by_port[port] = checked_attrs
        checked_fields_by_port[port] = checked_fields

    if not has_configured_checks:
        pytest.skip("No *_threshold_range attributes configured for DOM threshold validation")

    if all_failures:
        pytest.fail("DOM threshold validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM threshold validation passed: %d threshold attribute(s), %d threshold field(s) across %d port(s)",
        sum(checked_attrs_by_port.values()),
        sum(checked_fields_by_port.values()),
        len(checked_attrs_by_port),
    )
