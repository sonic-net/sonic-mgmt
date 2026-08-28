import logging
import math
import time
from collections import defaultdict

import pytest

from tests.transceiver.attribute_parser.attribute_keys import DOM_ATTRIBUTES_KEY
from tests.transceiver.common.db_helpers import (
    STATE_DB_UPDATE_TIME_FIELD,
    parse_numeric,
    parse_update_time,
)
from tests.transceiver.dom.dom_helpers import (
    STATE_DB_SENSOR_TABLE,
    build_dom_sensor_plan,
    consistency_field_template_for_attr,
    field_template_is_lane_expanded,
    format_dom_port_failure,
    format_optional_float,
    read_dom_sensor_data,
)

logger = logging.getLogger(__name__)

UPDATE_ADVANCE_MARGIN_SEC = 5
TX_BIAS_THRESHOLD_ATTR = "tx_bias_threshold_range"
TX_BIAS_CONSISTENCY_ATTR = "tx_bias_consistency_variation_threshold"
MODE_ABSOLUTE = "absolute"
MODE_PERCENT = "percent"

CONSISTENCY_CHECK_DEFINITIONS = (
    ("temperature_consistency_variation_threshold", "C", MODE_ABSOLUTE),
    ("voltage_consistency_variation_threshold", "V", MODE_ABSOLUTE),
    ("laser_temperature_consistency_variation_threshold", "C", MODE_ABSOLUTE),
    ("tx_power_consistency_variation_threshold", "dB", MODE_ABSOLUTE),
    ("rx_power_consistency_variation_threshold", "dB", MODE_ABSOLUTE),
    (TX_BIAS_CONSISTENCY_ATTR, "percent", MODE_PERCENT),
)


def _parse_positive_int(attr_name, raw_value, minimum):
    """Return ``(value, error)`` for configured positive integer DOM attributes."""
    if raw_value is None:
        return None, "{} missing in DOM_ATTRIBUTES".format(attr_name)

    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value) or int(value) != value or value < minimum:
        return None, "{} must be an integer >= {} in DOM_ATTRIBUTES (got {!r})".format(
            attr_name, minimum, raw_value
        )
    return int(value), None


def _parse_non_negative_threshold(attr_name, raw_value):
    """Return ``(threshold, error)`` for configured consistency thresholds."""
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value) or value < 0:
        return None, "{} must be a finite non-negative number in DOM_ATTRIBUTES (got {!r})".format(
            attr_name, raw_value
        )
    return value, None


def _parse_tx_bias_warning_range(dom_attrs):
    """Return ``{"low": value, "high": value, "error": reason}`` for Tx-bias gating."""
    attr_value = dom_attrs.get(TX_BIAS_THRESHOLD_ATTR)
    if not isinstance(attr_value, dict):
        return {"low": None, "high": None, "error": "{} not configured as a dict".format(TX_BIAS_THRESHOLD_ATTR)}

    lowwarning = parse_numeric(attr_value.get("lowwarning"))
    highwarning = parse_numeric(attr_value.get("highwarning"))
    if (
        lowwarning is None
        or highwarning is None
        or not math.isfinite(lowwarning)
        or not math.isfinite(highwarning)
        or lowwarning > highwarning
    ):
        return {
            "low": None,
            "high": None,
            "error": "{} has no valid lowwarning/highwarning range".format(TX_BIAS_THRESHOLD_ATTR),
        }
    return {"low": lowwarning, "high": highwarning, "error": None}


def _build_dom_consistency_plan(port_attributes_dict, dom_primary_ports, sensor_plan_by_port):
    """Build per-port update-count and variation checks from DOM attributes."""
    plan_by_port = {}
    for port in dom_primary_ports:
        dom_attrs = port_attributes_dict.get(port, {}).get(DOM_ATTRIBUTES_KEY, {})
        sensor_plan = sensor_plan_by_port.get(port, {})
        active_lanes = sensor_plan.get("active_media_lanes", [])
        errors = []
        field_checks = {}

        poll_count, poll_error = _parse_positive_int(
            "consistency_check_poll_count",
            dom_attrs.get("consistency_check_poll_count"),
            minimum=2,
        )
        if poll_error:
            errors.append(poll_error)

        has_lane_check = any(
            attr_name in dom_attrs
            and consistency_field_template_for_attr(attr_name)
            and field_template_is_lane_expanded(consistency_field_template_for_attr(attr_name))
            for attr_name, _unit, _mode in CONSISTENCY_CHECK_DEFINITIONS
        )
        if has_lane_check and sensor_plan.get("errors"):
            errors.extend(sensor_plan["errors"])

        for attr_name, unit, mode in CONSISTENCY_CHECK_DEFINITIONS:
            if attr_name not in dom_attrs:
                continue

            field_template = consistency_field_template_for_attr(attr_name)
            if field_template is None:
                errors.append("{} has no DOM consistency field mapping".format(attr_name))
                continue
            lane_expanded = field_template_is_lane_expanded(field_template)

            threshold, threshold_error = _parse_non_negative_threshold(attr_name, dom_attrs[attr_name])
            if threshold_error:
                errors.append(threshold_error)
                continue

            if lane_expanded and not active_lanes:
                errors.append("{} configured but no active media lanes resolved".format(attr_name))
                continue

            lanes = active_lanes if lane_expanded else [None]
            for lane in lanes:
                field = field_template.format(lane) if lane is not None else field_template
                field_checks[field] = {
                    "source_attr": attr_name,
                    "threshold": threshold,
                    "mode": mode,
                    "unit": unit,
                }

        plan_by_port[port] = {
            "active_media_lanes": active_lanes,
            "errors": errors,
            "field_checks": {field: field_checks[field] for field in sorted(field_checks)},
            "poll_count": poll_count,
            "tx_bias_warning_range": (
                _parse_tx_bias_warning_range(dom_attrs)
                if TX_BIAS_CONSISTENCY_ATTR in dom_attrs
                else {"low": None, "high": None, "error": None}
            ),
        }
    return plan_by_port


def _collect_dom_samples(duthost, dom_primary_ports, sample_count, interval_sec):
    """Return ``(samples_by_port, read_failures)`` for interval-based DOM samples."""
    samples_by_port = {port: [] for port in dom_primary_ports}
    read_failures = []
    sleep_sec = interval_sec + UPDATE_ADVANCE_MARGIN_SEC

    for sample_index in range(1, sample_count + 1):
        sensor_by_port, sensor_errors = read_dom_sensor_data(duthost, dom_primary_ports)

        read_failures.extend(
            "STATE_DB sample {} sensor read:\n  {}".format(sample_index, error)
            for error in sensor_errors
        )
        for port in dom_primary_ports:
            samples_by_port[port].append({
                "sensor": sensor_by_port.get(port, {}),
            })

        logger.debug("Collected DOM consistency sample %d/%d", sample_index, sample_count)
        if sample_index < sample_count:
            time.sleep(sleep_sec)

    return samples_by_port, read_failures


def _numeric_sensor_value(sensor_data, field):
    """Return a finite numeric sensor value, or ``None`` when absent/unparseable."""
    if not isinstance(sensor_data, dict):
        return None
    value = parse_numeric(sensor_data.get(field))
    return value if value is not None and math.isfinite(value) else None


def _format_delta_failure(field, sample_index, delta, threshold, unit, previous_value, current_value):
    """Return a formatted sensor-delta threshold failure message."""
    return "{} sample {}->{} delta {}{} exceeds {}{} (prev={}, curr={})".format(
        field,
        sample_index,
        sample_index + 1,
        format_optional_float(delta),
        unit,
        format_optional_float(threshold),
        unit,
        format_optional_float(previous_value),
        format_optional_float(current_value),
    )


def _validate_absolute_pair(port, field, check, previous_sensor, current_sensor,
                            previous_value, current_value, sample_index):
    """Return ``(error, checked, skip_reason)`` for one absolute-delta check."""
    if previous_value is None or current_value is None:
        return "{} sample {}->{}: missing/non-finite value (prev={!r}, curr={!r})".format(
            field, sample_index, sample_index + 1, previous_sensor.get(field), current_sensor.get(field)
        ), False, None
    delta = abs(current_value - previous_value)
    if delta > check["threshold"]:
        return _format_delta_failure(
            field, sample_index, delta, check["threshold"], check["unit"], previous_value, current_value
        ), True, None
    logger.debug("DOM consistency PASS %s %s sample %d->%d: delta=%s%s limit=%s%s",
                 port, field, sample_index, sample_index + 1, format_optional_float(delta),
                 check["unit"], format_optional_float(check["threshold"]), check["unit"])
    return None, True, None


def _tx_bias_percent_skip_reason(field, warning_range, previous_value, current_value,
                                 previous_sensor, current_sensor):
    """Return the Tx-bias percent-check skip reason, or ``None`` when checkable."""
    if warning_range["error"]:
        return warning_range["error"]
    if previous_value is None or current_value is None:
        return "missing/non-finite value (prev={!r}, curr={!r})".format(
            previous_sensor.get(field), current_sensor.get(field)
        )
    if not (warning_range["low"] <= previous_value <= warning_range["high"]
            and warning_range["low"] <= current_value <= warning_range["high"]):
        # Tx-bias percent stability is meaningful only in the normal warning range;
        # threshold/alarm tests own values that are already outside this envelope.
        return "value outside tx_bias warning range [{}, {}] (prev={}, curr={})".format(
            format_optional_float(warning_range["low"]),
            format_optional_float(warning_range["high"]),
            format_optional_float(previous_value),
            format_optional_float(current_value),
        )
    if previous_value == 0:
        return "previous value is zero; percent change is undefined"
    return None


def _validate_tx_bias_percent_pair(port, field, check, previous_sample, current_sample,
                                   previous_value, current_value, sample_index, plan):
    """Return ``(error, checked, skip_reason)`` for one Tx-bias percent check."""
    skip_reason = _tx_bias_percent_skip_reason(
        field,
        plan["tx_bias_warning_range"],
        previous_value,
        current_value,
        previous_sample["sensor"],
        current_sample["sensor"],
    )
    if skip_reason:
        logger.info("DOM consistency SKIP %s %s sample %d->%d: %s",
                    port, field, sample_index, sample_index + 1, skip_reason)
        return None, False, skip_reason

    delta_percent = abs(current_value - previous_value) / abs(previous_value) * 100
    if delta_percent > check["threshold"]:
        return _format_delta_failure(
            field, sample_index, delta_percent, check["threshold"], "%", previous_value, current_value
        ), True, None
    logger.debug("DOM consistency PASS %s %s sample %d->%d: delta=%.2f%% limit=%s%%",
                 port, field, sample_index, sample_index + 1, delta_percent,
                 format_optional_float(check["threshold"]))
    return None, True, None


def _validate_pair(port, field, check, previous_sample, current_sample, sample_index, plan):
    """Return ``(error, checked, skip_reason)`` for one sample pair and field."""
    previous_sensor = previous_sample["sensor"]
    current_sensor = current_sample["sensor"]
    if previous_sensor is None or current_sensor is None:
        return None, False, "{} namespace read failed".format(STATE_DB_SENSOR_TABLE)
    if not previous_sensor or not current_sensor:
        return None, False, "{} entry missing for one or both samples".format(STATE_DB_SENSOR_TABLE)

    previous_value = _numeric_sensor_value(previous_sensor, field)
    current_value = _numeric_sensor_value(current_sensor, field)
    if check["mode"] == MODE_ABSOLUTE:
        return _validate_absolute_pair(
            port, field, check, previous_sensor, current_sensor, previous_value, current_value, sample_index
        )
    return _validate_tx_bias_percent_pair(
        port, field, check, previous_sample, current_sample, previous_value, current_value, sample_index, plan
    )


def _validate_port_samples(port, port_samples, plan):
    """Return ``(failures, checked_pair_count)`` for one port's collected samples."""
    failures = []
    checked_pair_count = 0
    checked_by_attr = defaultdict(int)
    skipped_by_attr = defaultdict(list)

    parsed_times = []
    for sample_index in range(plan["poll_count"]):
        sensor_data = port_samples[sample_index]["sensor"]
        if sensor_data is None:
            failures.append("sample {}: could not read {} for port (namespace read failed)".format(
                sample_index + 1, STATE_DB_SENSOR_TABLE
            ))
            parsed_times.append(None)
            continue
        if not sensor_data:
            failures.append("sample {}: no {} entry published for port".format(
                sample_index + 1, STATE_DB_SENSOR_TABLE
            ))
            parsed_times.append(None)
            continue
        raw_update_time = sensor_data.get(STATE_DB_UPDATE_TIME_FIELD)
        parsed_time = parse_update_time(raw_update_time)
        if parsed_time is None:
            failures.append("sample {}: {} missing or unparsable (raw={!r})".format(
                sample_index + 1, STATE_DB_UPDATE_TIME_FIELD, raw_update_time
            ))
        parsed_times.append(parsed_time)

    for sample_index in range(1, plan["poll_count"]):
        previous_time = parsed_times[sample_index - 1]
        current_time = parsed_times[sample_index]
        if previous_time is not None and current_time is not None and current_time <= previous_time:
            failures.append("{} did not advance between sample {} and {} (prev={!r}, curr={!r})".format(
                STATE_DB_UPDATE_TIME_FIELD, sample_index, sample_index + 1,
                port_samples[sample_index - 1]["sensor"].get(STATE_DB_UPDATE_TIME_FIELD),
                port_samples[sample_index]["sensor"].get(STATE_DB_UPDATE_TIME_FIELD),
            ))

    for sample_index in range(1, plan["poll_count"]):
        previous_sample = port_samples[sample_index - 1]
        current_sample = port_samples[sample_index]
        for field, check in plan["field_checks"].items():
            error, checked, skip_reason = _validate_pair(
                port, field, check, previous_sample, current_sample, sample_index, plan
            )
            if checked:
                checked_pair_count += 1
                checked_by_attr[check["source_attr"]] += 1
            if skip_reason:
                skipped_by_attr[check["source_attr"]].append(
                    "{} sample {}->{}: {}".format(field, sample_index, sample_index + 1, skip_reason)
                )
            if error:
                failures.append(error)

    percent_attrs = {
        check["source_attr"] for check in plan["field_checks"].values() if check["mode"] == MODE_PERCENT
    }
    for attr_name in sorted(percent_attrs):
        if checked_by_attr[attr_name]:
            continue
        skip_details = "; ".join(sorted(set(skipped_by_attr[attr_name]))) or "no eligible sample pairs"
        logger.warning(
            "DOM consistency SKIP %s %s: no Tx-bias sample pair was checked (%s)",
            port,
            attr_name,
            skip_details,
        )

    return failures, checked_pair_count


def test_dom_data_consistency_verification(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify DOM sensor update cadence and any configured variation thresholds."""
    sensor_plan_by_port = build_dom_sensor_plan(
        port_attributes_dict, dom_primary_ports, lport_to_first_subport_mapping
    )
    consistency_plan_by_port = _build_dom_consistency_plan(
        port_attributes_dict, dom_primary_ports, sensor_plan_by_port
    )

    raw_update_interval = next(
        (
            port_attributes_dict.get(port, {}).get(DOM_ATTRIBUTES_KEY, {}).get("max_update_time_sec")
            for port in dom_primary_ports
            if "max_update_time_sec" in port_attributes_dict.get(port, {}).get(DOM_ATTRIBUTES_KEY, {})
        ),
        None,
    )
    update_interval_sec, update_interval_error = _parse_positive_int(
        "max_update_time_sec", raw_update_interval, minimum=1
    )

    config_failures = [update_interval_error] if update_interval_error else []
    for port in dom_primary_ports:
        plan = consistency_plan_by_port[port]
        if plan["errors"]:
            config_failures.append(format_dom_port_failure(
                port,
                plan["active_media_lanes"],
                plan["field_checks"],
                plan["errors"],
                field_label="configured consistency field(s)",
            ))
    if config_failures:
        pytest.fail("DOM consistency configuration failures:\n" + "\n".join(config_failures))

    sample_count = max(plan["poll_count"] for plan in consistency_plan_by_port.values())
    if not any(plan["field_checks"] for plan in consistency_plan_by_port.values()):
        logger.info("No DOM consistency variation thresholds configured; validating last_update_time cadence only")
    logger.info(
        "DOM consistency sampling: %d sample(s), %d second interval, %d second margin",
        sample_count,
        update_interval_sec,
        UPDATE_ADVANCE_MARGIN_SEC,
    )

    samples_by_port, all_failures = _collect_dom_samples(
        duthost, dom_primary_ports, sample_count, update_interval_sec
    )
    checked_pair_count = 0
    checked_port_count = 0
    for port in dom_primary_ports:
        plan = consistency_plan_by_port[port]
        port_samples = samples_by_port.get(port, [])
        if len(port_samples) < plan["poll_count"]:
            port_failures = ["only {} sample(s) collected, expected {}".format(
                len(port_samples), plan["poll_count"]
            )]
            port_checked_pair_count = 0
        else:
            port_failures, port_checked_pair_count = _validate_port_samples(port, port_samples, plan)

        checked_port_count += 1
        checked_pair_count += port_checked_pair_count
        if port_failures:
            all_failures.append(format_dom_port_failure(
                port,
                plan["active_media_lanes"],
                plan["field_checks"],
                port_failures,
                field_label="configured consistency field(s)",
            ))

    if all_failures:
        pytest.fail("DOM consistency validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM consistency validation passed: %d variation pair(s), %d port(s), %d sample(s)",
        checked_pair_count,
        checked_port_count,
        sample_count,
    )
