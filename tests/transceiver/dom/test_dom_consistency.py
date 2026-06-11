import time

import logging
import pytest

logger = logging.getLogger(__name__)


def test_dom_data_consistency_verification(
    dom_ports,
    dom_consistency_validation_plan_by_port,
    dom_consistency_variation_rules,
    dom_db_reader,
    parse_dom_numeric,
    parse_dom_update_time,
):
    """TC4: Validate DOM data consistency across polling cycles.

    Args:
        dom_ports: DOM-enabled ports selected for validation.
        dom_consistency_validation_plan_by_port: Static consistency validation plan keyed by port.
        dom_consistency_variation_rules: Mapping from operational attributes to variation threshold rules.
        dom_db_reader: Callable DOM STATE_DB readers for repeated polling.
        parse_dom_numeric: Parser for numeric DOM values.
        parse_dom_update_time: Parser for DOM ``last_update_time`` values.

    Returns:
        None.
    """
    all_failures = []
    has_configured_checks = bool(dom_ports)
    logger.info("DOM consistency validation starting for %d port(s)", len(dom_ports))

    read_sensor = dom_db_reader["sensor"]
    poll_groups = {}
    port_states = {}

    for port in dom_ports:
        # Step 1: Resolve per-port polling configuration and expected DOM fields.
        plan = dom_consistency_validation_plan_by_port.get(port)
        if plan is None:
            all_failures.append("{}:\n  missing consistency validation plan".format(port))
            continue

        dom_attrs = plan["dom_attrs"]
        expected_fields = plan["expected_fields"]
        field_ranges = plan["field_ranges"]
        variation_thresholds = plan["variation_thresholds"]
        poll_count = plan["poll_count"]
        poll_interval_sec = plan["poll_interval_sec"]
        field_failures = []
        invalid_range_attrs = set()
        invalid_variation_rule_attrs = set()

        for error in plan["errors"]:
            field_failures.append(error)

        if field_failures:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
            continue

        logger.info(
            "DOM consistency validation %s: poll_count=%d poll_interval_sec=%d field(s)=%d",
            port,
            poll_count,
            poll_interval_sec,
            len(expected_fields),
        )

        # Step 2: Capture baseline DOM sensor snapshot.
        previous = read_sensor(port)
        if not previous:
            field_failures.append("initial DOM sensor read missing")
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(field_failures)))
            continue

        previous_ts = parse_dom_update_time(previous.get("last_update_time"))
        if previous_ts is None:
            field_failures.append("baseline last_update_time missing or unparsable")

        port_states[port] = {
            "expected_fields": expected_fields,
            "field_ranges": field_ranges,
            "variation_thresholds": variation_thresholds,
            "poll_count": poll_count,
            "poll_interval_sec": poll_interval_sec,
            "field_failures": field_failures,
            "invalid_range_attrs": invalid_range_attrs,
            "invalid_variation_rule_attrs": invalid_variation_rule_attrs,
            "previous": previous,
            "previous_ts": previous_ts,
            "polling_active": True,
            "checked_fields": 0,
        }
        poll_groups.setdefault((poll_count, poll_interval_sec), []).append(port)

    # Step 3/4: Poll grouped ports repeatedly so the sleep cost scales by poll group, not by port.
    for (poll_count, poll_interval_sec), grouped_ports in poll_groups.items():
        grouped_ports_label = ", ".join(grouped_ports)
        logger.debug(
            "DOM consistency polling group ports=%s poll_count=%d poll_interval_sec=%d",
            grouped_ports_label,
            poll_count,
            poll_interval_sec,
        )
        for poll_idx in range(1, poll_count):
            logger.info(
                "DOM consistency polling group %s: waiting %ds before poll %d/%d",
                grouped_ports_label,
                poll_interval_sec,
                poll_idx + 1,
                poll_count,
            )
            poll_start = time.monotonic()
            time.sleep(poll_interval_sec)

            for port in grouped_ports:
                state = port_states[port]
                if not state["polling_active"]:
                    continue

                current = read_sensor(port)
                if not current:
                    state["field_failures"].append("DOM sensor read failed during consistency polling")
                    state["polling_active"] = False
                    continue

                previous = state["previous"]
                previous_ts = state["previous_ts"]
                curr_ts = parse_dom_update_time(current.get("last_update_time"))
                if curr_ts is None:
                    state["field_failures"].append("last_update_time missing or unparsable during consistency polling")
                elif previous_ts is not None and curr_ts <= previous_ts:
                    state["field_failures"].append(
                        "last_update_time did not advance (prev={}, curr={})".format(
                            previous_ts.isoformat(), curr_ts.isoformat()
                        )
                    )

                for field in state["expected_fields"]:
                    prev_val = parse_dom_numeric(previous.get(field))
                    curr_val = parse_dom_numeric(current.get(field))
                    if prev_val is None or curr_val is None:
                        state["field_failures"].append(
                            "{} missing/non-numeric value during consistency polling".format(field)
                        )
                        continue

                    range_info = state["field_ranges"].get(field)
                    if range_info is None:
                        continue

                    attr_name = range_info["attr_name"]
                    min_cfg = parse_dom_numeric(range_info.get("min"))
                    max_cfg = parse_dom_numeric(range_info.get("max"))
                    if min_cfg is None or max_cfg is None:
                        if attr_name not in state["invalid_range_attrs"]:
                            state["field_failures"].append(
                                "{} missing/non-numeric min or max in DOM_ATTRIBUTES".format(attr_name)
                            )
                            state["invalid_range_attrs"].add(attr_name)
                        continue

                    if min_cfg > max_cfg:
                        if attr_name not in state["invalid_range_attrs"]:
                            state["field_failures"].append(
                                "{} has invalid range with min={} > max={}".format(attr_name, min_cfg, max_cfg)
                            )
                            state["invalid_range_attrs"].add(attr_name)
                        continue

                    if not min_cfg <= curr_val <= max_cfg:
                        state["field_failures"].append(
                            "{} value {} out of configured operational range [{}, {}] during poll {}".format(
                                field, curr_val, min_cfg, max_cfg, poll_idx + 1
                            )
                        )

                    variation_rule = dom_consistency_variation_rules.get(attr_name)
                    if variation_rule is None:
                        continue

                    threshold_attr, mode = variation_rule
                    threshold_value = state["variation_thresholds"].get(threshold_attr)
                    if threshold_value is None:
                        continue

                    if mode == "abs":
                        allowed_delta = threshold_value
                    elif mode == "pct":
                        allowed_delta = abs(prev_val) * threshold_value / 100.0
                    else:
                        if attr_name not in state["invalid_variation_rule_attrs"]:
                            state["field_failures"].append(
                                "{} has invalid consistency variation mode {}".format(attr_name, mode)
                            )
                            state["invalid_variation_rule_attrs"].add(attr_name)
                        continue

                    delta = abs(curr_val - prev_val)
                    if delta > allowed_delta:
                        state["field_failures"].append(
                            "{} unreasonable change between polls (prev={}, curr={}, delta={}, "
                            "allowed_delta={}, threshold_attr={})".format(
                                field, prev_val, curr_val, delta, allowed_delta, threshold_attr
                            )
                        )
                        continue

                    state["checked_fields"] += 1

                state["previous"] = current
                if curr_ts is not None:
                    state["previous_ts"] = curr_ts

            logger.debug(
                "DOM consistency poll %d/%d for ports=%s took %.2fs",
                poll_idx + 1,
                poll_count,
                grouped_ports_label,
                time.monotonic() - poll_start,
            )
            logger.info(
                "DOM consistency polling group %s: completed poll %d/%d after %.2fs",
                grouped_ports_label,
                poll_idx + 1,
                poll_count,
                time.monotonic() - poll_start,
            )

    for port in dom_ports:
        state = port_states.get(port)
        if state and state["field_failures"]:
            all_failures.append("{}:\n  {}".format(port, "\n  ".join(state["field_failures"])))

    # Step 5: Final decision for skip/fail.
    if not has_configured_checks:
        pytest.skip("No DOM ports configured for consistency validation")

    if all_failures:
        pytest.fail("DOM consistency validation failures:\n" + "\n".join(all_failures))

    total_checked_fields = sum(state["checked_fields"] for state in port_states.values())
    logger.info(
        "DOM consistency validation passed: %d field(s) across %d port(s)",
        total_checked_fields,
        len(port_states),
    )
    for port in sorted(port_states):
        state = port_states[port]
        logger.info(
            "DOM consistency validation %s: checked %d field(s) over %d poll(s)",
            port,
            state["checked_fields"],
            state["poll_count"],
        )
