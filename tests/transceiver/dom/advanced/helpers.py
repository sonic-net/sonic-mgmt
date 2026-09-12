"""Advanced DOM TC1-specific STATE_DB and APPL_DB helpers."""
import logging
import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from tests.common.utilities import wait_until
from tests.transceiver.common.db_helpers import (
    STATE_DB_UPDATE_TIME_FIELD,
    check_entry_freshness,
    get_db_table,
    get_state_db_table,
    parse_numeric,
    parse_state_db_bool,
    parse_update_time,
    resolve_port_namespace,
)
from tests.transceiver.dom.dom_helpers import (
    DEVIATION_SUFFIX,
    DomMappedField,
    field_template_is_lane_expanded,
    dom_field_in_operational_range,
    format_optional_float,
    parse_min_max_range,
    read_dom_sensor_data,
    spec_for_attr,
)

logger = logging.getLogger(__name__)

STATE_DB_SENSOR_TABLE = "TRANSCEIVER_DOM_SENSOR"
STATE_DB_STATUS_TABLE = "TRANSCEIVER_STATUS"
STATE_DB_DOM_FLAG_TABLE = "TRANSCEIVER_DOM_FLAG"
STATE_DB_DOM_FLAG_CHANGE_COUNT_TABLE = "TRANSCEIVER_DOM_FLAG_CHANGE_COUNT"
STATE_DB_DOM_FLAG_SET_TIME_TABLE = "TRANSCEIVER_DOM_FLAG_SET_TIME"
STATE_DB_DOM_FLAG_CLEAR_TIME_TABLE = "TRANSCEIVER_DOM_FLAG_CLEAR_TIME"
STATE_DB_STATUS_FLAG_TABLE = "TRANSCEIVER_STATUS_FLAG"
STATE_DB_STATUS_FLAG_CHANGE_COUNT_TABLE = "TRANSCEIVER_STATUS_FLAG_CHANGE_COUNT"
STATE_DB_STATUS_FLAG_SET_TIME_TABLE = "TRANSCEIVER_STATUS_FLAG_SET_TIME"
STATE_DB_STATUS_FLAG_CLEAR_TIME_TABLE = "TRANSCEIVER_STATUS_FLAG_CLEAR_TIME"
APPL_DB_PORT_TABLE = "PORT_TABLE"

DOM_EVENT_TIME_TOLERANCE_SEC = 5
DOM_RECOVERY_POLL_INTERVAL_SEC = 20

INTERFACE_STATE_TABLES = (
    ("sensor", STATE_DB_SENSOR_TABLE),
    ("dom_flag", STATE_DB_DOM_FLAG_TABLE),
    ("dom_flag_count", STATE_DB_DOM_FLAG_CHANGE_COUNT_TABLE),
    ("dom_flag_set_time", STATE_DB_DOM_FLAG_SET_TIME_TABLE),
    ("dom_flag_clear_time", STATE_DB_DOM_FLAG_CLEAR_TIME_TABLE),
    ("status", STATE_DB_STATUS_TABLE),
    ("status_flag", STATE_DB_STATUS_FLAG_TABLE),
    ("status_flag_count", STATE_DB_STATUS_FLAG_CHANGE_COUNT_TABLE),
    ("status_flag_set_time", STATE_DB_STATUS_FLAG_SET_TIME_TABLE),
    ("status_flag_clear_time", STATE_DB_STATUS_FLAG_CLEAR_TIME_TABLE),
)


def normalize_datetime(value):
    """Normalize an aware datetime to naive UTC for SONiC timestamp comparisons."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def parse_sonic_timestamp(value):
    """Return a parsed SONiC timestamp, or ``None`` when it is absent/unparseable."""
    parsed = parse_update_time(value)
    if parsed is not None:
        return parsed
    if value is None:
        return None

    raw = str(value).strip()
    if not raw or raw.lower() == "never":
        return None
    for time_format in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, time_format)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _read_dom_table_data(duthost, ports, table_name):
    """Read one STATE_DB table for ports, preserving namespace read failures."""
    ports = list(ports)
    table_data_by_port = {port: {} for port in ports}
    errors = []
    ports_by_namespace = defaultdict(list)
    for port in ports:
        ports_by_namespace[resolve_port_namespace(duthost, port)].append(port)

    for namespace, namespace_ports in ports_by_namespace.items():
        table_data, error = get_state_db_table(duthost, table_name, namespace=namespace)
        if error:
            errors.append(
                "{} namespace {} ({} port(s) under test): {}".format(
                    table_name, namespace or "default", len(namespace_ports), error
                )
            )
            for port in namespace_ports:
                table_data_by_port[port] = None
            continue
        for port in namespace_ports:
            table_data_by_port[port] = table_data.get(port, {}) or {}
    return table_data_by_port, errors


def _read_appl_port_table_data(duthost, ports):
    """Read APPL_DB PORT_TABLE rows for ports, preserving namespace read failures."""
    ports = list(ports)
    table_by_port = {port: {} for port in ports}
    errors = []
    ports_by_namespace = defaultdict(list)
    for port in ports:
        ports_by_namespace[resolve_port_namespace(duthost, port)].append(port)

    for namespace, namespace_ports in ports_by_namespace.items():
        port_table, error = get_db_table(
            duthost, "APPL_DB", APPL_DB_PORT_TABLE, namespace=namespace, sep=":"
        )
        if error:
            errors.append(
                "{} namespace {} ({} port(s) under test): {}".format(
                    APPL_DB_PORT_TABLE, namespace or "default", len(namespace_ports), error
                )
            )
            for port in namespace_ports:
                table_by_port[port] = None
            continue
        for port in namespace_ports:
            table_by_port[port] = port_table.get(port, {}) or {}
    return table_by_port, errors


def read_dom_interface_state_tables(duthost, ports, include_appl_port=False):
    """Return the Advanced TC1 STATE_DB and optional APPL_DB table snapshots."""
    tables = {}
    errors = []
    for table_key, table_name in INTERFACE_STATE_TABLES:
        data_by_port, read_errors = _read_dom_table_data(duthost, ports, table_name)
        tables[table_key] = data_by_port
        errors.extend("STATE_DB read:\n  {}".format(error) for error in read_errors)

    if include_appl_port:
        appl_port_by_port, read_errors = _read_appl_port_table_data(duthost, ports)
        tables["appl_port"] = appl_port_by_port
        errors.extend("APPL_DB read:\n  {}".format(error) for error in read_errors)
    return tables, errors


def dom_tx_los_hostlane_candidates(lane):
    """Return candidate STATE_DB names for a Tx LOS host-lane flag."""
    return (
        "tx{}los_hostlane".format(lane),
        "tx{}losHostlane".format(lane),
        "tx{}losHostLane".format(lane),
    )


def dom_rx_power_flag_candidates(lane, suffix):
    """Return candidate STATE_DB names for an Rx power low-alarm or warning flag."""
    return ("rx{}power{}".format(lane, suffix), "rx{}Power{}".format(lane, suffix))


def _lookup_case_insensitive(entry, candidate_fields):
    if not isinstance(entry, dict):
        return None, None
    for candidate in candidate_fields:
        if candidate in entry:
            return candidate, entry[candidate]
    lowered = {field.lower(): field for field in entry}
    for candidate in candidate_fields:
        actual_field = lowered.get(candidate.lower())
        if actual_field is not None:
            return actual_field, entry[actual_field]
    return None, None


def _flag_entry_failure(table_name, entry):
    if entry is None:
        return "could not read {} for port (namespace read failed)".format(table_name)
    if not entry:
        return "no {} entry published for port".format(table_name)
    return None


def _metadata_raw_value(table_name, entry, candidate_fields):
    failure = _flag_entry_failure(table_name, entry)
    if failure:
        return None, None, failure
    actual_field, raw_value = _lookup_case_insensitive(entry, candidate_fields)
    if actual_field is None:
        return None, None, "{} missing metadata field {}".format(table_name, "/".join(candidate_fields))
    return actual_field, raw_value, None


def _parse_count(value):
    parsed = parse_numeric(value)
    if parsed is None or not math.isfinite(parsed) or int(parsed) != parsed:
        return None
    return int(parsed)


def validate_dom_flag_state(port, table_name, entry, candidate_fields, expected_state):
    """Return failures for one expected boolean flag state."""
    failure = _flag_entry_failure(table_name, entry)
    if failure:
        return [failure]
    actual_field, raw_value = _lookup_case_insensitive(entry, candidate_fields)
    if actual_field is None:
        return ["{} missing flag field {}".format(table_name, "/".join(candidate_fields))]
    actual_state = parse_state_db_bool(str(raw_value))
    if actual_state is None:
        return ["{} {} has unrecognized boolean value {!r}".format(table_name, actual_field, raw_value)]
    if actual_state != expected_state:
        return ["{} {} expected {}, got {}".format(table_name, actual_field, expected_state, raw_value)]
    logger.debug("DOM flag PASS %s %s %s=%s", port, table_name, actual_field, raw_value)
    return []


def _validate_count_increment(port, candidate_fields, baseline_entry, current_entry, table_name):
    field, baseline_raw, error = _metadata_raw_value(table_name, baseline_entry, candidate_fields)
    if error:
        return [error]
    _field, current_raw, error = _metadata_raw_value(table_name, current_entry, candidate_fields)
    if error:
        return [error]
    baseline_count = _parse_count(baseline_raw)
    current_count = _parse_count(current_raw)
    if baseline_count is None or current_count is None:
        return ["{} {} count is non-integer (baseline={!r}, current={!r})".format(
            table_name, field, baseline_raw, current_raw
        )]
    if current_count <= baseline_count:
        return ["{} {} did not increment (baseline={}, current={})".format(
            table_name, field, baseline_count, current_count
        )]
    logger.debug("DOM flag metadata PASS %s %s %s count %s->%s",
                 port, table_name, field, baseline_count, current_count)
    return []


def _validate_event_timestamp(port, candidate_fields, baseline_entry, current_entry, table_name, event_time):
    field, baseline_raw, error = _metadata_raw_value(table_name, baseline_entry, candidate_fields)
    if error:
        return [error]
    _field, current_raw, error = _metadata_raw_value(table_name, current_entry, candidate_fields)
    if error:
        return [error]
    if current_raw == baseline_raw:
        return ["{} {} did not update from baseline {!r}".format(table_name, field, baseline_raw)]

    parsed_time = normalize_datetime(parse_sonic_timestamp(current_raw))
    if parsed_time is None:
        return ["{} {} timestamp is unparsable: {!r}".format(table_name, field, current_raw)]
    earliest = normalize_datetime(event_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
    if parsed_time < earliest:
        return ["{} {} timestamp {} is before operation window {}".format(
            table_name, field, current_raw, event_time
        )]
    logger.debug("DOM flag metadata PASS %s %s %s timestamp %s", port, table_name, field, current_raw)
    return []


def _validate_timestamp_unchanged(candidate_fields, baseline_entry, current_entry, table_name):
    field, baseline_raw, error = _metadata_raw_value(table_name, baseline_entry, candidate_fields)
    if error:
        return [error]
    _field, current_raw, error = _metadata_raw_value(table_name, current_entry, candidate_fields)
    if error:
        return [error]
    if current_raw != baseline_raw:
        return ["{} {} changed unexpectedly (baseline={!r}, current={!r})".format(
            table_name, field, baseline_raw, current_raw
        )]
    return []


def validate_dom_flag_lifecycle(port, candidate_fields, baseline_tables, current_tables,
                                family, expected_state, event, event_time,
                                require_clear_time_unchanged=False):
    """Return state/count/event-time failures for one expected DOM flag lifecycle event."""
    if family == "dom":
        flag_table = STATE_DB_DOM_FLAG_TABLE
        flag_entry = current_tables["dom_flag"].get(port)
        count_table = STATE_DB_DOM_FLAG_CHANGE_COUNT_TABLE
        set_time_table = STATE_DB_DOM_FLAG_SET_TIME_TABLE
        clear_time_table = STATE_DB_DOM_FLAG_CLEAR_TIME_TABLE
        baseline_count = baseline_tables["dom_flag_count"].get(port)
        current_count = current_tables["dom_flag_count"].get(port)
        baseline_set = baseline_tables["dom_flag_set_time"].get(port)
        current_set = current_tables["dom_flag_set_time"].get(port)
        baseline_clear = baseline_tables["dom_flag_clear_time"].get(port)
        current_clear = current_tables["dom_flag_clear_time"].get(port)
    else:
        flag_table = STATE_DB_STATUS_FLAG_TABLE
        flag_entry = current_tables["status_flag"].get(port)
        if not flag_entry:
            flag_table = STATE_DB_STATUS_TABLE
            flag_entry = current_tables["status"].get(port)
        count_table = STATE_DB_STATUS_FLAG_CHANGE_COUNT_TABLE
        set_time_table = STATE_DB_STATUS_FLAG_SET_TIME_TABLE
        clear_time_table = STATE_DB_STATUS_FLAG_CLEAR_TIME_TABLE
        baseline_count = baseline_tables["status_flag_count"].get(port)
        current_count = current_tables["status_flag_count"].get(port)
        baseline_set = baseline_tables["status_flag_set_time"].get(port)
        current_set = current_tables["status_flag_set_time"].get(port)
        baseline_clear = baseline_tables["status_flag_clear_time"].get(port)
        current_clear = current_tables["status_flag_clear_time"].get(port)

    failures = validate_dom_flag_state(port, flag_table, flag_entry, candidate_fields, expected_state)
    failures.extend(_validate_count_increment(port, candidate_fields, baseline_count, current_count, count_table))
    if event == "set":
        failures.extend(_validate_event_timestamp(
            port, candidate_fields, baseline_set, current_set, set_time_table, event_time
        ))
    else:
        failures.extend(_validate_event_timestamp(
            port, candidate_fields, baseline_clear, current_clear, clear_time_table, event_time
        ))
    if require_clear_time_unchanged:
        failures.extend(_validate_timestamp_unchanged(
            candidate_fields, baseline_clear, current_clear, clear_time_table
        ))
    return failures


def validate_dom_baseline_flags(port, tables, active_host_lanes, active_media_lanes):
    """Return failures if TC1 starts with its local or remote flags asserted."""
    failures = []
    for lane in active_host_lanes:
        table_name = STATE_DB_STATUS_FLAG_TABLE
        flag_entry = tables["status_flag"].get(port)
        if not flag_entry:
            table_name = STATE_DB_STATUS_TABLE
            flag_entry = tables["status"].get(port)
        failures.extend(validate_dom_flag_state(
            port, table_name, flag_entry, dom_tx_los_hostlane_candidates(lane), False
        ))
    for lane in active_media_lanes:
        for suffix in ("LAlarm", "LWarn"):
            failures.extend(validate_dom_flag_state(
                port, STATE_DB_DOM_FLAG_TABLE, tables["dom_flag"].get(port),
                dom_rx_power_flag_candidates(lane, suffix), False
            ))
    return failures


def validate_sensor_freshness_after(duthost, port, sensor_data, max_age_min, operation_time, label):
    """Return freshness and operation-window failures for one post-operation sensor snapshot."""
    if sensor_data is None:
        return ["{}: could not read {} for port (namespace read failed)".format(label, STATE_DB_SENSOR_TABLE)]
    if not sensor_data:
        return ["{}: no {} entry published for port".format(label, STATE_DB_SENSOR_TABLE)]

    freshness = check_entry_freshness(
        sensor_data, max_age_min, duthost.get_now_time(utc_timezone=True), table_name=STATE_DB_SENSOR_TABLE
    )
    failures = ["{}: {}".format(label, failure) for failure in freshness["failures"]]
    update_time = parse_update_time(sensor_data.get(STATE_DB_UPDATE_TIME_FIELD))
    if update_time is None:
        return failures + ["{}: {} missing or unparsable (raw={!r})".format(
            label, STATE_DB_UPDATE_TIME_FIELD, sensor_data.get(STATE_DB_UPDATE_TIME_FIELD)
        )]
    earliest = normalize_datetime(operation_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
    if update_time < earliest:
        failures.append("{}: {}={!r} did not advance into operation window starting {}".format(
            label, STATE_DB_UPDATE_TIME_FIELD, sensor_data.get(STATE_DB_UPDATE_TIME_FIELD), operation_time
        ))
    return failures


def wait_for_dom_sensor_update(duthost, ports, baseline_update_times, operation_time, timeout_sec, label):
    """Poll until every port has a distinct, post-operation DOM sensor timestamp."""
    state = {"sensor_by_port": {}, "failures": []}

    def _all_ports_updated():
        sensor_by_port, read_errors = read_dom_sensor_data(duthost, ports)
        failures = ["{} STATE_DB read:\n  {}".format(label, error) for error in read_errors]
        earliest = normalize_datetime(operation_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
        for port in ports:
            sensor_data = sensor_by_port.get(port)
            if sensor_data is None:
                failures.append("{} {}: namespace read failed".format(label, port))
                continue
            if not sensor_data:
                failures.append("{} {}: no {} entry published".format(label, port, STATE_DB_SENSOR_TABLE))
                continue
            current_raw = sensor_data.get(STATE_DB_UPDATE_TIME_FIELD)
            parsed_update_time = parse_update_time(current_raw)
            if parsed_update_time is None:
                failures.append("{} {}: {} missing or unparsable (raw={!r})".format(
                    label, port, STATE_DB_UPDATE_TIME_FIELD, current_raw
                ))
                continue
            baseline_raw = baseline_update_times.get(port)
            if baseline_raw is None:
                failures.append("{} {}: baseline {} is missing".format(
                    label, port, STATE_DB_UPDATE_TIME_FIELD
                ))
                continue
            baseline_update_time = parse_update_time(baseline_raw)
            if baseline_update_time is None:
                failures.append("{} {}: baseline {} is unparsable (raw={!r})".format(
                    label, port, STATE_DB_UPDATE_TIME_FIELD, baseline_raw
                ))
                continue
            if parsed_update_time == baseline_update_time:
                failures.append("{} {}: {} did not change from baseline {!r}".format(
                    label, port, STATE_DB_UPDATE_TIME_FIELD, baseline_raw
                ))
                continue
            if parsed_update_time < earliest:
                failures.append("{} {}: {}={!r} is still older than operation start {}".format(
                    label, port, STATE_DB_UPDATE_TIME_FIELD, current_raw, operation_time
                ))

        state["sensor_by_port"] = sensor_by_port
        state["failures"] = failures
        return not failures

    if wait_until(timeout_sec, DOM_RECOVERY_POLL_INTERVAL_SEC, 0, _all_ports_updated):
        return state["sensor_by_port"], []
    return state["sensor_by_port"], state["failures"]


def numeric_sensor_value(sensor_data, field):
    value = parse_numeric(sensor_data.get(field)) if isinstance(sensor_data, dict) else None
    return value if value is not None and math.isfinite(value) else None


def validate_sensor_below_threshold(port, sensor_data, field, threshold, label):
    value = numeric_sensor_value(sensor_data, field)
    if value is None:
        raw_value = sensor_data.get(field) if isinstance(sensor_data, dict) else None
        return ["{} {} missing/non-finite in {} state (raw={!r})".format(label, field, port, raw_value)]
    if value >= threshold:
        return ["{} {} value {} is not below shutdown threshold {}".format(
            label, field, format_optional_float(value), format_optional_float(threshold)
        )]
    return []


def validate_sensor_operational_fields(port, sensor_data, expected_fields, field_filter, label):
    """Validate selected configured sensor fields with the supplied operational predicate."""
    failures = []
    checked = 0
    for field, mapped_field in expected_fields.items():
        if not field_filter(field):
            continue
        raw_value = sensor_data.get(field) if isinstance(sensor_data, dict) else None
        if raw_value is None:
            failures.append("{} {} missing in {}".format(label, field, port))
            continue
        error = dom_field_in_operational_range(field, mapped_field, raw_value)
        if error:
            failures.append("{} {}".format(label, error))
            continue
        checked += 1
    return failures, checked


def build_dom_deviation_checks(dom_attrs, active_lanes, attr_names):
    """Return configured post-startup deviation checks expanded over active media lanes."""
    checks_by_field = {}
    errors = []
    for attr_name in attr_names:
        if attr_name not in dom_attrs:
            continue
        spec = spec_for_attr(attr_name, DEVIATION_SUFFIX)
        if spec is None:
            errors.append("{} has no DOM deviation field mapping".format(attr_name))
            continue
        min_value, max_value, range_error = parse_min_max_range(
            DomMappedField(attr_name, dom_attrs[attr_name])
        )
        if range_error:
            errors.append(range_error)
            continue
        field_template = spec.sensor_field_template
        lanes = active_lanes if field_template_is_lane_expanded(field_template) else [None]
        if field_template_is_lane_expanded(field_template) and not lanes:
            errors.append("{} configured but no active media lanes resolved".format(attr_name))
            continue
        for lane in lanes:
            field = field_template.format(lane) if lane is not None else field_template
            checks_by_field[field] = {
                "source_attr": attr_name,
                "min": min_value,
                "max": max_value,
                "unit": spec.deviation_unit,
            }
    return {field: checks_by_field[field] for field in sorted(checks_by_field)}, errors


def validate_dom_deviation_checks(port, baseline_sensor, post_sensor, checks_by_field, label):
    """Return failures and checked field count for configured post-startup deviations."""
    failures = []
    checked_count = 0
    for field, check in checks_by_field.items():
        baseline_value = numeric_sensor_value(baseline_sensor, field)
        post_value = numeric_sensor_value(post_sensor, field)
        if baseline_value is None or post_value is None:
            failures.append("{} {} deviation cannot be checked (baseline={!r}, post={!r})".format(
                label, field,
                baseline_sensor.get(field) if isinstance(baseline_sensor, dict) else None,
                post_sensor.get(field) if isinstance(post_sensor, dict) else None,
            ))
            continue
        deviation = post_value - baseline_value
        if not check["min"] <= deviation <= check["max"]:
            failures.append("{} {} deviation {}{} is outside [{}, {}]{} from {}".format(
                label, field, format_optional_float(deviation), check["unit"],
                format_optional_float(check["min"]), format_optional_float(check["max"]),
                check["unit"], check["source_attr"],
            ))
            continue
        checked_count += 1
        logger.debug("DOM deviation PASS %s %s: %s%s within [%s, %s]%s",
                     port, field, format_optional_float(deviation), check["unit"],
                     format_optional_float(check["min"]), format_optional_float(check["max"]), check["unit"])
    return failures, checked_count


def validate_appl_port_down_time(port, baseline_entry, shutdown_entry, shutdown_time):
    """Return failures for APPL_DB PORT_TABLE last_down_time correlation."""
    if shutdown_entry is None:
        return ["{} could not read APPL_DB PORT_TABLE (namespace read failed)".format(port)]
    if not shutdown_entry:
        return ["{} no APPL_DB PORT_TABLE entry published".format(port)]
    last_down_time = shutdown_entry.get("last_down_time")
    if not last_down_time:
        return ["{} APPL_DB PORT_TABLE missing last_down_time after shutdown".format(port)]

    failures = []
    baseline_down_time = (baseline_entry or {}).get("last_down_time")
    if last_down_time == baseline_down_time:
        failures.append("{} APPL_DB PORT_TABLE last_down_time did not change after shutdown".format(port))
    parsed_down = normalize_datetime(parse_sonic_timestamp(last_down_time))
    if parsed_down is None:
        return failures + ["{} APPL_DB PORT_TABLE last_down_time {!r} is unparsable".format(
            port, last_down_time
        )]
    earliest = normalize_datetime(shutdown_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
    if parsed_down < earliest:
        failures.append(
            "{} APPL_DB PORT_TABLE last_down_time {} did not advance into shutdown window starting {}".format(
                port, last_down_time, shutdown_time
            )
        )
    return failures
