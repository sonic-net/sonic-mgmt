import logging
import math
import time

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
    format_dom_port_failure,
    read_dom_sensor_data,
    read_dom_status_data,
)

logger = logging.getLogger(__name__)

DEFAULT_CONSISTENCY_CHECK_POLL_COUNT = 3
DEFAULT_MAX_UPDATE_TIME_SEC = 60
TX_BIAS_THRESHOLD_ATTR = "tx_bias_threshold_range"
DP_ACTIVATED_VALUES = ("DPActivated", "DataPathActivated")

ABSOLUTE_CONSISTENCY_FIELDS = {
    "temperature_consistency_variation_threshold": ("temperature", "C"),
    "voltage_consistency_variation_threshold": ("voltage", "V"),
    "laser_temperature_consistency_variation_threshold": ("laser_temperature", "C"),
}
LANE_CONSISTENCY_FIELDS = {
    "tx_power_consistency_variation_threshold": ("tx{}power", "dB", "absolute"),
    "rx_power_consistency_variation_threshold": ("rx{}power", "dB", "absolute"),
    "tx_bias_consistency_variation_threshold": ("tx{}bias", "percent", "percent"),
}


def _parse_positive_int(attr_name, raw_value, default_value, minimum):
    """Return ``(value, error)`` for positive integer DOM timing attributes."""
    if raw_value is None:
        return default_value, None

    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value) or int(value) != value or value < minimum:
        return None, "{} must be an integer >= {} in DOM_ATTRIBUTES (got {!r})".format(
            attr_name,
            minimum,
            raw_value,
        )
    return int(value), None


def _parse_non_negative_threshold(attr_name, raw_value):
    """Return ``(threshold, error)`` for configured consistency thresholds."""
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value) or value < 0:
        return None, "{} must be a finite non-negative number in DOM_ATTRIBUTES (got {!r})".format(
            attr_name,
            raw_value,
        )
    return value, None


def _parse_tx_bias_warning_range(dom_attrs):
    """Return ``(lowwarning, highwarning, reason)`` for Tx-bias percentage gating."""
    attr_value = dom_attrs.get(TX_BIAS_THRESHOLD_ATTR)
    if not isinstance(attr_value, dict):
        return None, None, "{} not configured as a dict".format(TX_BIAS_THRESHOLD_ATTR)

    lowwarning = parse_numeric(attr_value.get("lowwarning"))
    highwarning = parse_numeric(attr_value.get("highwarning"))
    if (
        lowwarning is None
        or highwarning is None
        or not math.isfinite(lowwarning)
        or not math.isfinite(highwarning)
        or lowwarning > highwarning
    ):
        return None, None, "{} has no valid lowwarning/highwarning range".format(TX_BIAS_THRESHOLD_ATTR)

    return lowwarning, highwarning, None


def _build_dom_consistency_plan(port_attributes_dict, dom_primary_ports, sensor_plan_by_port):
    """Build per-port TC4 timing and field-variation checks from DOM attributes."""
    plan_by_port = {}
    for port in dom_primary_ports:
        dom_attrs = port_attributes_dict.get(port, {}).get(DOM_ATTRIBUTES_KEY, {})
        sensor_plan = sensor_plan_by_port.get(port, {})
        active_lanes = sensor_plan.get("active_media_lanes", [])
        errors = []
        field_checks = {}

        poll_count, poll_count_error = _parse_positive_int(
            "consistency_check_poll_count",
            dom_attrs.get("consistency_check_poll_count"),
            DEFAULT_CONSISTENCY_CHECK_POLL_COUNT,
            minimum=2,
        )
        if poll_count_error:
            errors.append(poll_count_error)
            poll_count = DEFAULT_CONSISTENCY_CHECK_POLL_COUNT

        update_interval_sec, update_interval_error = _parse_positive_int(
            "max_update_time_sec",
            dom_attrs.get("max_update_time_sec"),
            DEFAULT_MAX_UPDATE_TIME_SEC,
            minimum=1,
        )
        if update_interval_error:
            errors.append(update_interval_error)
            update_interval_sec = DEFAULT_MAX_UPDATE_TIME_SEC

        for attr_name, (field, unit) in sorted(ABSOLUTE_CONSISTENCY_FIELDS.items()):
            if attr_name not in dom_attrs:
                continue
            threshold, threshold_error = _parse_non_negative_threshold(attr_name, dom_attrs[attr_name])
            if threshold_error:
                errors.append(threshold_error)
                continue
            field_checks[field] = {
                "source_attr": attr_name,
                "threshold": threshold,
                "mode": "absolute",
                "unit": unit,
            }

        has_lane_checks = any(attr_name in dom_attrs for attr_name in LANE_CONSISTENCY_FIELDS)
        if has_lane_checks and sensor_plan.get("errors"):
            errors.extend(sensor_plan.get("errors", []))

        for attr_name, (field_template, unit, mode) in sorted(LANE_CONSISTENCY_FIELDS.items()):
            if attr_name not in dom_attrs:
                continue
            threshold, threshold_error = _parse_non_negative_threshold(attr_name, dom_attrs[attr_name])
            if threshold_error:
                errors.append(threshold_error)
                continue
            if not active_lanes:
                errors.append("{} configured but no active media lanes resolved".format(attr_name))
                continue

            lowwarning = highwarning = warning_range_error = None
            if mode == "percent":
                lowwarning, highwarning, warning_range_error = _parse_tx_bias_warning_range(dom_attrs)

            for lane in active_lanes:
                field_checks[field_template.format(lane)] = {
                    "source_attr": attr_name,
                    "threshold": threshold,
                    "mode": mode,
                    "unit": unit,
                    "lane": lane,
                    "warning_low": lowwarning,
                    "warning_high": highwarning,
                    "warning_range_error": warning_range_error,
                }

        plan_by_port[port] = {
            "active_media_lanes": active_lanes,
            "errors": errors,
            "field_checks": {field: field_checks[field] for field in sorted(field_checks)},
            "poll_count": poll_count,
            "update_interval_sec": update_interval_sec,
        }
        logger.debug(
            "%s DOM consistency plan: poll_count=%s update_interval_sec=%s "
            "field_checks=%s active_media_lanes=%s",
            port,
            poll_count,
            update_interval_sec,
            sorted(field_checks),
            active_lanes or "none",
        )

    return plan_by_port


def _collect_dom_samples(duthost, dom_primary_ports, sample_count, interval_sec, read_status):
    """Read DOM sensor/status samples with a fixed interval between samples."""
    samples = []
    for sample_index in range(sample_count):
        sensor_by_port, sensor_errors = read_dom_sensor_data(duthost, dom_primary_ports)
        status_by_port = {}
        status_errors = []
        if read_status:
            status_by_port, status_errors = read_dom_status_data(duthost, dom_primary_ports)
        samples.append(
            {
                "sensor_by_port": sensor_by_port,
                "status_by_port": status_by_port,
                "sensor_errors": sensor_errors,
                "status_errors": status_errors,
            }
        )
        logger.debug("Collected DOM consistency sample %d/%d", sample_index + 1, sample_count)
        if sample_index + 1 < sample_count:
            time.sleep(interval_sec)
    return samples


def _sensor_sample_for_port(samples, sample_index, port):
    return samples[sample_index]["sensor_by_port"].get(port, {}) or {}


def _status_sample_for_port(samples, sample_index, port):
    return samples[sample_index]["status_by_port"].get(port, {}) or {}


def _validate_last_update_time(port, samples, poll_count):
    """Validate last_update_time exists and advances between TC4 samples."""
    failures = []
    parsed_times = []

    for sample_index in range(poll_count):
        sensor_data = _sensor_sample_for_port(samples, sample_index, port)
        if not sensor_data:
            failures.append(
                "sample {}: no {} entry published for port".format(
                    sample_index + 1,
                    STATE_DB_SENSOR_TABLE,
                )
            )
            parsed_times.append(None)
            continue

        raw_update_time = sensor_data.get(STATE_DB_UPDATE_TIME_FIELD)
        parsed_time = parse_update_time(raw_update_time)
        if parsed_time is None:
            failures.append(
                "sample {}: {} missing or unparsable (raw={!r})".format(
                    sample_index + 1,
                    STATE_DB_UPDATE_TIME_FIELD,
                    raw_update_time,
                )
            )
        parsed_times.append(parsed_time)

    for sample_index in range(1, poll_count):
        previous_time = parsed_times[sample_index - 1]
        current_time = parsed_times[sample_index]
        if previous_time is None or current_time is None:
            continue
        if current_time <= previous_time:
            failures.append(
                "{} did not advance between sample {} and {} (prev={!r}, curr={!r})".format(
                    STATE_DB_UPDATE_TIME_FIELD,
                    sample_index,
                    sample_index + 1,
                    _sensor_sample_for_port(samples, sample_index - 1, port).get(STATE_DB_UPDATE_TIME_FIELD),
                    _sensor_sample_for_port(samples, sample_index, port).get(STATE_DB_UPDATE_TIME_FIELD),
                )
            )

    return failures


def _numeric_sensor_value(sensor_data, field):
    value = parse_numeric(sensor_data.get(field))
    if value is None or not math.isfinite(value):
        return None
    return value


def _dp_state_activated(status_data, lane):
    return status_data.get("DP{}State".format(lane)) in DP_ACTIVATED_VALUES


def _validate_absolute_delta(port, field, check, previous_sensor, current_sensor, sample_index):
    previous_value = _numeric_sensor_value(previous_sensor, field)
    current_value = _numeric_sensor_value(current_sensor, field)
    if previous_value is None or current_value is None:
        return (
            "{} sample {}->{}: missing/non-finite value (prev={!r}, curr={!r})".format(
                field,
                sample_index,
                sample_index + 1,
                previous_sensor.get(field),
                current_sensor.get(field),
            )
        )

    delta = abs(current_value - previous_value)
    if delta > check["threshold"]:
        return (
            "{} sample {}->{} delta {}{} exceeds {}{} "
            "(prev={}, curr={})".format(
                field,
                sample_index,
                sample_index + 1,
                delta,
                check["unit"],
                check["threshold"],
                check["unit"],
                previous_value,
                current_value,
            )
        )

    logger.debug(
        "DOM consistency PASS %s %s sample %d->%d: delta=%s%s limit=%s%s",
        port,
        field,
        sample_index,
        sample_index + 1,
        delta,
        check["unit"],
        check["threshold"],
        check["unit"],
    )
    return None


def _tx_bias_skip_reason(field, check, previous_sensor, current_sensor, previous_status, current_status):
    if check.get("warning_range_error"):
        return check["warning_range_error"]

    lane = check["lane"]
    previous_state = previous_status.get("DP{}State".format(lane))
    current_state = current_status.get("DP{}State".format(lane))
    if not (_dp_state_activated(previous_status, lane) and _dp_state_activated(current_status, lane)):
        return "DP{}State not activated (prev={!r}, curr={!r})".format(
            lane,
            previous_state,
            current_state,
        )

    previous_value = _numeric_sensor_value(previous_sensor, field)
    current_value = _numeric_sensor_value(current_sensor, field)
    if previous_value is None or current_value is None:
        return "missing/non-finite value (prev={!r}, curr={!r})".format(
            previous_sensor.get(field),
            current_sensor.get(field),
        )

    lowwarning = check["warning_low"]
    highwarning = check["warning_high"]
    if not (lowwarning <= previous_value <= highwarning and lowwarning <= current_value <= highwarning):
        return "value outside tx_bias warning range [{}, {}] (prev={}, curr={})".format(
            lowwarning,
            highwarning,
            previous_value,
            current_value,
        )

    if previous_value == 0:
        return "previous value is zero; percent change is undefined"

    return None


def _validate_tx_bias_percent_delta(
    port,
    field,
    check,
    previous_sensor,
    current_sensor,
    previous_status,
    current_status,
    sample_index,
):
    skip_reason = _tx_bias_skip_reason(field, check, previous_sensor, current_sensor, previous_status, current_status)
    if skip_reason:
        logger.info(
            "DOM consistency SKIP %s %s sample %d->%d: %s",
            port,
            field,
            sample_index,
            sample_index + 1,
            skip_reason,
        )
        return None, False

    previous_value = _numeric_sensor_value(previous_sensor, field)
    current_value = _numeric_sensor_value(current_sensor, field)
    delta_percent = abs(current_value - previous_value) / abs(previous_value) * 100
    if delta_percent > check["threshold"]:
        return (
            "{} sample {}->{} delta {:.2f}% exceeds {}% "
            "(prev={}, curr={})".format(
                field,
                sample_index,
                sample_index + 1,
                delta_percent,
                check["threshold"],
                previous_value,
                current_value,
            ),
            True,
        )

    logger.debug(
        "DOM consistency PASS %s %s sample %d->%d: delta=%.2f%% limit=%s%%",
        port,
        field,
        sample_index,
        sample_index + 1,
        delta_percent,
        check["threshold"],
    )
    return None, True


def _validate_variation_checks(port, samples, plan):
    """Validate configured variation checks for one port across samples."""
    failures = []
    checked_pair_count = 0
    field_checks = plan.get("field_checks", {})
    poll_count = plan["poll_count"]

    for sample_index in range(1, poll_count):
        previous_sensor = _sensor_sample_for_port(samples, sample_index - 1, port)
        current_sensor = _sensor_sample_for_port(samples, sample_index, port)
        previous_status = _status_sample_for_port(samples, sample_index - 1, port)
        current_status = _status_sample_for_port(samples, sample_index, port)

        for field, check in field_checks.items():
            if check["mode"] == "percent":
                error, checked = _validate_tx_bias_percent_delta(
                    port,
                    field,
                    check,
                    previous_sensor,
                    current_sensor,
                    previous_status,
                    current_status,
                    sample_index,
                )
                if checked:
                    checked_pair_count += 1
            else:
                error = _validate_absolute_delta(
                    port,
                    field,
                    check,
                    previous_sensor,
                    current_sensor,
                    sample_index,
                )
                checked_pair_count += 1

            if error:
                failures.append(error)

    return failures, checked_pair_count


def _validate_dom_consistency(dom_primary_ports, samples, consistency_plan_by_port):
    failures = []
    checked_pair_count = 0
    checked_port_count = 0

    for port in dom_primary_ports:
        plan = consistency_plan_by_port.get(port, {})
        expected_fields = plan.get("field_checks", {})
        field_failures = list(plan.get("errors", []))
        active_lanes = plan.get("active_media_lanes", [])

        last_update_failures = _validate_last_update_time(port, samples, plan["poll_count"])
        variation_failures, port_checked_pair_count = _validate_variation_checks(port, samples, plan)
        field_failures.extend(last_update_failures)
        field_failures.extend(variation_failures)

        checked_port_count += 1
        checked_pair_count += port_checked_pair_count

        if field_failures:
            failures.append(
                format_dom_port_failure(
                    port,
                    active_lanes,
                    expected_fields,
                    field_failures,
                    field_label="configured consistency field(s)",
                )
            )

    return failures, checked_pair_count, checked_port_count


def _format_consistency_plan_failures(dom_primary_ports, consistency_plan_by_port):
    failures = []
    for port in dom_primary_ports:
        plan = consistency_plan_by_port.get(port, {})
        field_failures = list(plan.get("errors", []))
        if not field_failures:
            continue
        failures.append(
            format_dom_port_failure(
                port,
                plan.get("active_media_lanes", []),
                plan.get("field_checks", {}),
                field_failures,
                field_label="configured consistency field(s)",
            )
        )
    return failures


def test_dom_data_consistency_verification(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify DOM sensor update cadence and configured variation thresholds."""
    sensor_plan_by_port = build_dom_sensor_plan(
        port_attributes_dict,
        dom_primary_ports,
        lport_to_first_subport_mapping,
    )
    consistency_plan_by_port = _build_dom_consistency_plan(
        port_attributes_dict,
        dom_primary_ports,
        sensor_plan_by_port,
    )
    plan_failures = _format_consistency_plan_failures(dom_primary_ports, consistency_plan_by_port)
    if plan_failures:
        pytest.fail("DOM consistency validation failures:\n" + "\n".join(plan_failures))

    sample_count = max(plan["poll_count"] for plan in consistency_plan_by_port.values())
    interval_sec = max(plan["update_interval_sec"] for plan in consistency_plan_by_port.values())
    read_status = any(
        check["mode"] == "percent"
        for plan in consistency_plan_by_port.values()
        for check in plan.get("field_checks", {}).values()
    )
    logger.info(
        "DOM consistency sampling: %d sample(s), %d second interval, status_table=%s",
        sample_count,
        interval_sec,
        read_status,
    )

    samples = _collect_dom_samples(
        duthost,
        dom_primary_ports,
        sample_count,
        interval_sec,
        read_status,
    )
    all_failures = []
    for sample_index, sample in enumerate(samples, start=1):
        all_failures.extend(
            "STATE_DB sample {} sensor read:\n  {}".format(sample_index, error)
            for error in sample["sensor_errors"]
        )
        all_failures.extend(
            "STATE_DB sample {} status read:\n  {}".format(sample_index, error)
            for error in sample["status_errors"]
        )

    consistency_failures, checked_pair_count, checked_port_count = _validate_dom_consistency(
        dom_primary_ports,
        samples,
        consistency_plan_by_port,
    )
    all_failures.extend(consistency_failures)

    if all_failures:
        pytest.fail("DOM consistency validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM consistency validation passed: %d variation pair(s), %d port(s), %d sample(s)",
        checked_pair_count,
        checked_port_count,
        sample_count,
    )
