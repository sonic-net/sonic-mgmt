"""Advanced DOM TC1: validate DOM state across interface shutdown/startup."""
import logging
import math
from collections import defaultdict, namedtuple
from datetime import datetime, timedelta

import pytest

from tests.common.utilities import wait_until
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    DOM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.db_helpers import (
    STATE_DB_UPDATE_TIME_FIELD,
    get_db_table,
    parse_numeric,
    parse_state_db_bool,
    parse_update_time,
    resolve_port_namespace,
)
from tests.transceiver.dom.dom_helpers import (
    DOM_RECOVERY_POLL_INTERVAL_SEC,
    DomMappedField,
    STATE_DB_DOM_FLAG_CHANGE_COUNT_TABLE,
    STATE_DB_DOM_FLAG_CLEAR_TIME_TABLE,
    STATE_DB_DOM_FLAG_SET_TIME_TABLE,
    STATE_DB_DOM_FLAG_TABLE,
    STATE_DB_SENSOR_TABLE,
    STATE_DB_STATUS_FLAG_CHANGE_COUNT_TABLE,
    STATE_DB_STATUS_FLAG_CLEAR_TIME_TABLE,
    STATE_DB_STATUS_FLAG_SET_TIME_TABLE,
    STATE_DB_STATUS_FLAG_TABLE,
    STATE_DB_STATUS_TABLE,
    build_dom_sensor_plan,
    check_dom_sensor_freshness,
    deviation_field_template_for_attr,
    deviation_unit_for_attr,
    dom_field_available,
    dom_field_in_operational_range,
    field_template_is_lane_expanded,
    format_dom_port_failure,
    format_optional_float,
    parse_min_max_range,
    read_dom_flag_change_count_data,
    read_dom_flag_clear_time_data,
    read_dom_flag_data,
    read_dom_flag_set_time_data,
    read_dom_sensor_data,
    read_transceiver_status_data,
    read_transceiver_status_flag_change_count_data,
    read_transceiver_status_flag_clear_time_data,
    read_transceiver_status_flag_data,
    read_transceiver_status_flag_set_time_data,
    validate_dom_plan_fields,
)

logger = logging.getLogger(__name__)

APPL_DB_PORT_TABLE = "PORT_TABLE"
HOST_LANE_MASK_KEY = "host_lane_mask"
SHUTDOWN_TX_BIAS_ATTR = "shutdown_tx_bias_threshold"
SHUTDOWN_TX_POWER_ATTR = "shutdown_tx_power_threshold"
SHUTDOWN_RX_POWER_ATTR = "shutdown_rx_power_threshold"
MAX_UPDATE_TIME_ATTR = "max_update_time_sec"
LOCAL_DEVIATION_ATTRS = (
    "voltage_deviation_range",
    "laser_temperature_deviation_range",
    "txLANE_NUMbias_deviation_range",
    "txLANE_NUMpower_deviation_range",
)
REMOTE_DEVIATION_ATTRS = ("rxLANE_NUMpower_deviation_range",)
LOCAL_SHUTDOWN_OPERATIONAL_FIELDS = ("temperature", "voltage")
DOM_UPDATE_MARGIN_SEC = 30
EVENT_TIME_TOLERANCE_SEC = 5
PORT_TABLE_TIME_TOLERANCE_SEC = 5

PeerInfo = namedtuple("PeerInfo", ("host", "device", "port", "primary_port"))


def _normalize_datetime(value):
    """Return a timezone-naive datetime for arithmetic with xcvrd timestamps."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value


def _parse_any_timestamp(value):
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


def _ports_for_primary(primary_port, port_attributes_dict, lport_to_first_subport_mapping):
    """Return logical subports that share ``primary_port`` as their first subport."""
    mapping = lport_to_first_subport_mapping or {}
    return sorted(
        port
        for port in port_attributes_dict
        if mapping.get(port, port) == primary_port
    ) or [primary_port]


def _active_lanes_from_group_mask(primary_port, port_attributes_dict, lport_to_first_subport_mapping, mask_key):
    """Return ``(lanes, errors)`` from the union of a breakout group's lane masks."""
    mask_union = 0
    errors = []
    for port in _ports_for_primary(primary_port, port_attributes_dict, lport_to_first_subport_mapping):
        base_attrs = port_attributes_dict.get(port, {}).get(BASE_ATTRIBUTES_KEY, {})
        raw_mask = base_attrs.get(mask_key)
        if raw_mask is None:
            errors.append("{} missing {} in {}".format(port, mask_key, BASE_ATTRIBUTES_KEY))
            continue
        try:
            mask_union |= int(str(raw_mask), 16)
        except (TypeError, ValueError):
            errors.append("{} has unparsable {}={!r}".format(port, mask_key, raw_mask))

    return [bit + 1 for bit in range(mask_union.bit_length()) if mask_union & (1 << bit)], errors


def _parse_required_number(dom_attrs, attr_name):
    """Return ``(value, error)`` for a required numeric DOM attribute."""
    raw_value = dom_attrs.get(attr_name)
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value):
        return None, "{} must be configured as a finite number in DOM_ATTRIBUTES (got {!r})".format(
            attr_name,
            raw_value,
        )
    return value, None


def _parse_required_positive_int(attrs, attr_name, minimum=1):
    """Return ``(value, error)`` for a required integer attribute."""
    raw_value = attrs.get(attr_name)
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value) or int(value) != value or value < minimum:
        return None, "{} must be an integer >= {} (got {!r})".format(attr_name, minimum, raw_value)
    return int(value), None


def _max_system_wait(port_attributes_dict, ports, attr_name):
    """Return ``(wait_sec, errors)`` for a system timing attribute across ports."""
    values = []
    errors = []
    for port in ports:
        system_attrs = port_attributes_dict.get(port, {}).get(SYSTEM_ATTRIBUTES_KEY, {})
        value, error = _parse_required_positive_int(system_attrs, attr_name, minimum=0)
        if error:
            errors.append("{} {}".format(port, error))
        else:
            values.append(value)
    return (max(values) if values else None), errors


def _read_appl_port_table_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for APPL_DB PORT_TABLE rows."""
    ports = list(ports)
    table_by_port = {port: {} for port in ports}
    errors = []
    ports_by_namespace = defaultdict(list)

    for port in ports:
        ports_by_namespace[resolve_port_namespace(duthost, port)].append(port)

    for namespace, namespace_ports in ports_by_namespace.items():
        port_table, err = get_db_table(
            duthost,
            "APPL_DB",
            APPL_DB_PORT_TABLE,
            namespace=namespace,
            sep=":",
        )
        if err:
            errors.append(
                "{} namespace {} ({} port(s) under test): {}".format(
                    APPL_DB_PORT_TABLE,
                    namespace or "default",
                    len(namespace_ports),
                    err,
                )
            )
            for port in namespace_ports:
                table_by_port[port] = None
            continue

        for port in namespace_ports:
            table_by_port[port] = port_table.get(port, {}) or {}

    return table_by_port, errors


def _read_dom_interface_state_tables(duthost, ports, include_appl_port=False):
    """Return ``(tables, errors)`` for the STATE_DB/APPL_DB tables TC1 consumes."""
    table_readers = (
        ("sensor", read_dom_sensor_data),
        ("dom_flag", read_dom_flag_data),
        ("dom_flag_count", read_dom_flag_change_count_data),
        ("dom_flag_set_time", read_dom_flag_set_time_data),
        ("dom_flag_clear_time", read_dom_flag_clear_time_data),
        ("status", read_transceiver_status_data),
        ("status_flag", read_transceiver_status_flag_data),
        ("status_flag_count", read_transceiver_status_flag_change_count_data),
        ("status_flag_set_time", read_transceiver_status_flag_set_time_data),
        ("status_flag_clear_time", read_transceiver_status_flag_clear_time_data),
    )
    tables = {}
    errors = []
    for table_key, reader in table_readers:
        data_by_port, read_errors = reader(duthost, ports)
        tables[table_key] = data_by_port
        errors.extend("STATE_DB read:\n  {}".format(error) for error in read_errors)

    if include_appl_port:
        appl_port_by_port, read_errors = _read_appl_port_table_data(duthost, ports)
        tables["appl_port"] = appl_port_by_port
        errors.extend("APPL_DB read:\n  {}".format(error) for error in read_errors)

    return tables, errors


def _resolve_remote_peer(duthost, duthosts, conn_graph_facts, local_port, lport_to_first_subport_mapping):
    """Return ``(PeerInfo, error)`` using the shared connection-graph contract."""
    dut_conn = conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {})
    peer_entry = dut_conn.get(local_port)
    if not peer_entry:
        return None, "{} has no remote peer in conn_graph_facts".format(local_port)

    peer_device = peer_entry.get("peerdevice")
    peer_port = peer_entry.get("peerport")
    if not peer_device or not peer_port:
        return None, "{} peer entry missing peerdevice/peerport: {}".format(local_port, peer_entry)

    if peer_device == duthost.hostname:
        peer_host = duthost
        peer_primary = lport_to_first_subport_mapping.get(peer_port, peer_port)
    else:
        try:
            peer_host = duthosts[peer_device]
        except (KeyError, TypeError):
            return None, "{} peer device {} is not available as a DUT host".format(local_port, peer_device)
        peer_primary = peer_port

    return PeerInfo(peer_host, peer_device, peer_port, peer_primary), None


def _lookup_case_insensitive(entry, candidate_fields):
    """Return ``(actual_field, raw_value)`` for the first matching field candidate."""
    if not isinstance(entry, dict):
        return None, None
    for candidate in candidate_fields:
        if candidate in entry:
            return candidate, entry[candidate]
    lowered = {field.lower(): field for field in entry}
    for candidate in candidate_fields:
        actual = lowered.get(candidate.lower())
        if actual is not None:
            return actual, entry[actual]
    return None, None


def _tx_los_hostlane_candidates(lane):
    """Return candidate STATE_DB names for the Tx LOS host-lane flag."""
    return (
        "tx{}los_hostlane".format(lane),
        "tx{}losHostlane".format(lane),
        "tx{}losHostLane".format(lane),
    )


def _rx_power_flag_candidates(lane, suffix):
    """Return candidate DOM flag names for one Rx power low-alarm/warning flag."""
    return (
        "rx{}power{}".format(lane, suffix),
        "rx{}Power{}".format(lane, suffix),
    )


def _flag_entry_failure(table_name, entry):
    """Return a table-presence failure for a flag/metadata entry, or ``None``."""
    if entry is None:
        return "could not read {} for port (namespace read failed)".format(table_name)
    if not entry:
        return "no {} entry published for port".format(table_name)
    return None


def _parse_count(value):
    """Return an integer metadata count, or ``None`` when absent/unparseable."""
    parsed = parse_numeric(value)
    if parsed is None or not math.isfinite(parsed) or int(parsed) != parsed:
        return None
    return int(parsed)


def _validate_flag_state(port, table_name, entry, candidate_fields, expected_state):
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
        return [
            "{} {} expected {}, got {}".format(
                table_name,
                actual_field,
                expected_state,
                raw_value,
            )
        ]
    logger.debug("DOM flag PASS %s %s %s=%s", port, table_name, actual_field, raw_value)
    return []


def _metadata_raw_value(table_name, entry, candidate_fields):
    """Return ``(field, raw_value, error)`` from one flag metadata table."""
    failure = _flag_entry_failure(table_name, entry)
    if failure:
        return None, None, failure
    actual_field, raw_value = _lookup_case_insensitive(entry, candidate_fields)
    if actual_field is None:
        return None, None, "{} missing metadata field {}".format(table_name, "/".join(candidate_fields))
    return actual_field, raw_value, None


def _validate_count_increment(port, candidate_fields, baseline_entry, current_entry, table_name):
    """Return failures if a flag metadata change count did not increment."""
    field, baseline_raw, error = _metadata_raw_value(table_name, baseline_entry, candidate_fields)
    if error:
        return [error]
    _field, current_raw, error = _metadata_raw_value(table_name, current_entry, candidate_fields)
    if error:
        return [error]

    baseline_count = _parse_count(baseline_raw)
    current_count = _parse_count(current_raw)
    if baseline_count is None or current_count is None:
        return [
            "{} {} count is non-integer (baseline={!r}, current={!r})".format(
                table_name,
                field,
                baseline_raw,
                current_raw,
            )
        ]
    if current_count <= baseline_count:
        return [
            "{} {} did not increment (baseline={}, current={})".format(
                table_name,
                field,
                baseline_count,
                current_count,
            )
        ]
    logger.debug("DOM flag metadata PASS %s %s %s count %s->%s",
                 port, table_name, field, baseline_count, current_count)
    return []


def _validate_event_timestamp(port, candidate_fields, baseline_entry, current_entry, table_name, event_time):
    """Return failures if an event timestamp did not update after the operation."""
    field, baseline_raw, error = _metadata_raw_value(table_name, baseline_entry, candidate_fields)
    if error:
        return [error]
    _field, current_raw, error = _metadata_raw_value(table_name, current_entry, candidate_fields)
    if error:
        return [error]

    if current_raw == baseline_raw:
        return ["{} {} did not update from baseline {!r}".format(table_name, field, baseline_raw)]

    parsed_time = _parse_any_timestamp(current_raw)
    if parsed_time is None:
        return ["{} {} timestamp is unparsable: {!r}".format(table_name, field, current_raw)]

    earliest = _normalize_datetime(event_time) - timedelta(seconds=EVENT_TIME_TOLERANCE_SEC)
    if parsed_time < earliest:
        return [
            "{} {} timestamp {} is before operation window {}".format(
                table_name,
                field,
                current_raw,
                event_time,
            )
        ]
    logger.debug("DOM flag metadata PASS %s %s %s timestamp %s",
                 port, table_name, field, current_raw)
    return []


def _validate_timestamp_unchanged(candidate_fields, baseline_entry, current_entry, table_name):
    """Return failures if an unchanged metadata timestamp changed."""
    field, baseline_raw, error = _metadata_raw_value(table_name, baseline_entry, candidate_fields)
    if error:
        return [error]
    _field, current_raw, error = _metadata_raw_value(table_name, current_entry, candidate_fields)
    if error:
        return [error]
    if current_raw != baseline_raw:
        return ["{} {} changed unexpectedly (baseline={!r}, current={!r})".format(
            table_name,
            field,
            baseline_raw,
            current_raw,
        )]
    return []


def _validate_flag_lifecycle(port, candidate_fields, baseline_tables, current_tables,
                             family, expected_state, event, event_time,
                             require_clear_time_unchanged=False):
    """Return flag state/count/timestamp failures for one expected flag event."""
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

    failures = []
    failures.extend(_validate_flag_state(port, flag_table, flag_entry, candidate_fields, expected_state))
    failures.extend(_validate_count_increment(port, candidate_fields, baseline_count, current_count, count_table))
    if event == "set":
        failures.extend(
            _validate_event_timestamp(
                port,
                candidate_fields,
                baseline_set,
                current_set,
                set_time_table,
                event_time,
            )
        )
    else:
        failures.extend(
            _validate_event_timestamp(
                port,
                candidate_fields,
                baseline_clear,
                current_clear,
                clear_time_table,
                event_time,
            )
        )

    if require_clear_time_unchanged:
        failures.extend(
            _validate_timestamp_unchanged(
                candidate_fields,
                baseline_clear,
                current_clear,
                clear_time_table,
            )
        )
    return failures


def _validate_sensor_freshness_after(duthost, port, sensor_data, max_age_min, operation_time, label):
    """Return freshness/update-timing failures for one DOM sensor snapshot."""
    if sensor_data is None:
        return ["{}: could not read {} for port (namespace read failed)".format(label, STATE_DB_SENSOR_TABLE)]
    if not sensor_data:
        return ["{}: no {} entry published for port".format(label, STATE_DB_SENSOR_TABLE)]

    now_utc = duthost.get_now_time(utc_timezone=True)
    freshness = check_dom_sensor_freshness(sensor_data, max_age_min, now_utc)
    failures = ["{}: {}".format(label, failure) for failure in freshness["failures"]]

    update_time = parse_update_time(sensor_data.get(STATE_DB_UPDATE_TIME_FIELD))
    if update_time is None:
        failures.append(
            "{}: {} missing or unparsable (raw={!r})".format(
                label,
                STATE_DB_UPDATE_TIME_FIELD,
                sensor_data.get(STATE_DB_UPDATE_TIME_FIELD),
            )
        )
        return failures

    earliest = _normalize_datetime(operation_time) - timedelta(seconds=EVENT_TIME_TOLERANCE_SEC)
    if update_time < earliest:
        failures.append(
            "{}: {}={!r} did not advance into operation window starting {}".format(
                label,
                STATE_DB_UPDATE_TIME_FIELD,
                sensor_data.get(STATE_DB_UPDATE_TIME_FIELD),
                operation_time,
            )
        )
    return failures


def _wait_for_dom_sensor_update(duthost, ports, operation_time, timeout_sec, label):
    """Return ``(sensor_by_port, failures)`` after polling for post-operation DOM data."""
    state = {"sensor_by_port": {}, "failures": []}

    def _all_ports_updated():
        sensor_by_port, read_errors = read_dom_sensor_data(duthost, ports)
        failures = ["{} STATE_DB read:\n  {}".format(label, error) for error in read_errors]
        for port in ports:
            sensor_data = sensor_by_port.get(port)
            if sensor_data is None:
                failures.append("{} {}: namespace read failed".format(label, port))
                continue
            if not sensor_data:
                failures.append("{} {}: no {} entry published".format(label, port, STATE_DB_SENSOR_TABLE))
                continue
            parsed_update_time = parse_update_time(sensor_data.get(STATE_DB_UPDATE_TIME_FIELD))
            if parsed_update_time is None:
                failures.append(
                    "{} {}: {} missing or unparsable (raw={!r})".format(
                        label,
                        port,
                        STATE_DB_UPDATE_TIME_FIELD,
                        sensor_data.get(STATE_DB_UPDATE_TIME_FIELD),
                    )
                )
                continue
            earliest = _normalize_datetime(operation_time) - timedelta(seconds=EVENT_TIME_TOLERANCE_SEC)
            if parsed_update_time < earliest:
                failures.append(
                    "{} {}: {}={!r} is still older than operation start {}".format(
                        label,
                        port,
                        STATE_DB_UPDATE_TIME_FIELD,
                        sensor_data.get(STATE_DB_UPDATE_TIME_FIELD),
                        operation_time,
                    )
                )

        state["sensor_by_port"] = sensor_by_port
        state["failures"] = failures
        return not failures

    if wait_until(timeout_sec, DOM_RECOVERY_POLL_INTERVAL_SEC, 0, _all_ports_updated):
        return state["sensor_by_port"], []
    return state["sensor_by_port"], state["failures"]


def _numeric_sensor_value(sensor_data, field):
    """Return a finite numeric sensor value, or ``None`` when absent/unparseable."""
    if not isinstance(sensor_data, dict):
        return None
    value = parse_numeric(sensor_data.get(field))
    return value if value is not None and math.isfinite(value) else None


def _validate_sensor_below(port, sensor_data, field, threshold, label):
    """Return failures if one sensor field is not below its shutdown threshold."""
    value = _numeric_sensor_value(sensor_data, field)
    if value is None:
        raw_value = sensor_data.get(field) if isinstance(sensor_data, dict) else None
        return ["{} {} missing/non-finite in {} state (raw={!r})".format(label, field, port, raw_value)]
    if value >= threshold:
        return [
            "{} {} value {} is not below shutdown threshold {}".format(
                label,
                field,
                format_optional_float(value),
                format_optional_float(threshold),
            )
        ]
    logger.debug("DOM interface-state PASS %s %s: %s < %s",
                 port, field, format_optional_float(value), format_optional_float(threshold))
    return []


def _validate_operational_fields(port, sensor_data, expected_fields, field_filter, label):
    """Return failures for configured operational-range fields selected by ``field_filter``."""
    failures = []
    checked = 0
    for field, mapped_field in expected_fields.items():
        if not field_filter(field):
            continue
        if field not in sensor_data:
            failures.append("{} expected DOM field missing in STATE_DB sensor data: {}".format(label, field))
            continue
        error = dom_field_in_operational_range(field, mapped_field, sensor_data[field])
        if error:
            failures.append("{} {}".format(label, error))
            continue
        checked += 1

    logger.debug("DOM interface-state checked %d operational field(s) for %s %s", checked, port, label)
    return failures, checked


def _build_deviation_checks(dom_attrs, active_lanes, attr_names):
    """Return ``(checks_by_field, errors)`` for configured deviation-range attributes."""
    checks_by_field = {}
    errors = []
    for attr_name in attr_names:
        if attr_name not in dom_attrs:
            continue

        field_template = deviation_field_template_for_attr(attr_name)
        if field_template is None:
            errors.append("{} has no DOM deviation field mapping".format(attr_name))
            continue

        min_value, max_value, range_error = parse_min_max_range(DomMappedField(attr_name, dom_attrs[attr_name]))
        if range_error:
            errors.append(range_error)
            continue

        if field_template_is_lane_expanded(field_template):
            if not active_lanes:
                errors.append("{} configured but no active media lanes resolved".format(attr_name))
                continue
            lanes = active_lanes
        else:
            lanes = [None]

        for lane in lanes:
            field = field_template.format(lane) if lane is not None else field_template
            checks_by_field[field] = {
                "source_attr": attr_name,
                "min": min_value,
                "max": max_value,
                "unit": deviation_unit_for_attr(attr_name) or "",
            }

    return {field: checks_by_field[field] for field in sorted(checks_by_field)}, errors


def _validate_deviation_checks(port, baseline_sensor, post_sensor, checks_by_field, label):
    """Return ``(failures, checked_count)`` for configured post-startup deviations."""
    failures = []
    checked_count = 0
    for field, check in checks_by_field.items():
        baseline_value = _numeric_sensor_value(baseline_sensor, field)
        post_value = _numeric_sensor_value(post_sensor, field)
        if baseline_value is None or post_value is None:
            failures.append(
                "{} {} deviation cannot be checked (baseline={!r}, post={!r})".format(
                    label,
                    field,
                    baseline_sensor.get(field) if isinstance(baseline_sensor, dict) else None,
                    post_sensor.get(field) if isinstance(post_sensor, dict) else None,
                )
            )
            continue

        deviation = post_value - baseline_value
        if not check["min"] <= deviation <= check["max"]:
            failures.append(
                "{} {} deviation {}{} is outside [{}, {}]{} from {}".format(
                    label,
                    field,
                    format_optional_float(deviation),
                    check["unit"],
                    format_optional_float(check["min"]),
                    format_optional_float(check["max"]),
                    check["unit"],
                    check["source_attr"],
                )
            )
            continue

        checked_count += 1
        logger.debug("DOM deviation PASS %s %s: %s%s within [%s, %s]%s",
                     port, field, format_optional_float(deviation), check["unit"],
                     format_optional_float(check["min"]), format_optional_float(check["max"]), check["unit"])
    return failures, checked_count


def _validate_appl_port_down_time(port, baseline_entry, shutdown_entry):
    """Return failures for APPL_DB PORT_TABLE last_update_time/last_down_time correlation."""
    if shutdown_entry is None:
        return ["{} could not read APPL_DB PORT_TABLE (namespace read failed)".format(port)]
    if not shutdown_entry:
        return ["{} no APPL_DB PORT_TABLE entry published".format(port)]

    failures = []
    last_down_time = shutdown_entry.get("last_down_time")
    last_update_time = shutdown_entry.get("last_update_time")
    if not last_down_time:
        failures.append("{} APPL_DB PORT_TABLE missing last_down_time after shutdown".format(port))
    if not last_update_time:
        failures.append("{} APPL_DB PORT_TABLE missing last_update_time after shutdown".format(port))

    baseline_down_time = (baseline_entry or {}).get("last_down_time")
    if last_down_time and last_down_time == baseline_down_time:
        failures.append("{} APPL_DB PORT_TABLE last_down_time did not change after shutdown".format(port))

    parsed_down = _parse_any_timestamp(last_down_time)
    parsed_update = _parse_any_timestamp(last_update_time)
    if last_down_time and last_update_time and parsed_down is not None and parsed_update is not None:
        delta_sec = abs((parsed_update - parsed_down).total_seconds())
        if delta_sec > PORT_TABLE_TIME_TOLERANCE_SEC:
            failures.append(
                "{} APPL_DB PORT_TABLE last_update_time {} is not within {}s of last_down_time {}".format(
                    port,
                    last_update_time,
                    PORT_TABLE_TIME_TOLERANCE_SEC,
                    last_down_time,
                )
            )
    elif last_down_time and last_update_time and last_down_time != last_update_time:
        failures.append(
            "{} APPL_DB PORT_TABLE last_update_time {!r} cannot be correlated with last_down_time {!r}".format(
                port,
                last_update_time,
                last_down_time,
            )
        )

    return failures


def _baseline_flag_failures(port, tables, active_host_lanes, active_media_lanes):
    """Return failures if TC1 starts with local/remote flags already asserted."""
    failures = []
    for lane in active_host_lanes:
        table_name = STATE_DB_STATUS_FLAG_TABLE
        flag_entry = tables["status_flag"].get(port)
        if not flag_entry:
            table_name = STATE_DB_STATUS_TABLE
            flag_entry = tables["status"].get(port)
        failures.extend(
            _validate_flag_state(
                port,
                table_name,
                flag_entry,
                _tx_los_hostlane_candidates(lane),
                False,
            )
        )
    for lane in active_media_lanes:
        for suffix in ("LAlarm", "LWarn"):
            failures.extend(
                _validate_flag_state(
                    port,
                    STATE_DB_DOM_FLAG_TABLE,
                    tables["dom_flag"].get(port),
                    _rx_power_flag_candidates(lane, suffix),
                    False,
                )
            )
    return failures


def _validate_local_shutdown(context, baseline_tables, shutdown_tables, shutdown_time):
    """Return failures for local DOM shutdown state."""
    local_port = context["local_port"]
    sensor_data = shutdown_tables["sensor"].get(local_port)
    plan = context["local_plan"]
    failures = []

    failures.extend(
        _validate_sensor_freshness_after(
            context["duthost"],
            local_port,
            sensor_data,
            plan.get("max_age_min"),
            shutdown_time,
            "local shutdown",
        )
    )
    if not isinstance(sensor_data, dict) or not sensor_data:
        return failures

    for lane in plan["active_media_lanes"]:
        failures.extend(
            _validate_sensor_below(
                local_port,
                sensor_data,
                "tx{}bias".format(lane),
                context["shutdown_tx_bias_threshold"],
                "local shutdown",
            )
        )
        failures.extend(
            _validate_sensor_below(
                local_port,
                sensor_data,
                "tx{}power".format(lane),
                context["shutdown_tx_power_threshold"],
                "local shutdown",
            )
        )

    op_failures, _checked = _validate_operational_fields(
        local_port,
        sensor_data,
        plan.get("expected_fields", {}),
        lambda field: field in LOCAL_SHUTDOWN_OPERATIONAL_FIELDS,
        "local shutdown",
    )
    failures.extend(op_failures)

    for lane in context["active_host_lanes"]:
        failures.extend(
            _validate_flag_lifecycle(
                local_port,
                _tx_los_hostlane_candidates(lane),
                baseline_tables,
                shutdown_tables,
                "status",
                True,
                "set",
                shutdown_time,
                require_clear_time_unchanged=True,
            )
        )

    baseline_appl = baseline_tables["appl_port"]
    shutdown_appl = shutdown_tables["appl_port"]
    for port in context["toggle_ports"]:
        failures.extend(
            _validate_appl_port_down_time(
                port,
                baseline_appl.get(port),
                shutdown_appl.get(port),
            )
        )

    return failures


def _validate_remote_shutdown(context, baseline_tables, shutdown_tables, shutdown_time):
    """Return failures for remote DOM link-down state."""
    remote_port = context["remote"].primary_port
    sensor_data = shutdown_tables["sensor"].get(remote_port)
    plan = context["remote_plan"]
    failures = []

    failures.extend(
        _validate_sensor_freshness_after(
            context["remote"].host,
            remote_port,
            sensor_data,
            plan.get("max_age_min"),
            shutdown_time,
            "remote shutdown",
        )
    )
    if not isinstance(sensor_data, dict) or not sensor_data:
        return failures

    for lane in plan["active_media_lanes"]:
        failures.extend(
            _validate_sensor_below(
                remote_port,
                sensor_data,
                "rx{}power".format(lane),
                context["shutdown_rx_power_threshold"],
                "remote shutdown",
            )
        )
        for suffix in ("LAlarm", "LWarn"):
            failures.extend(
                _validate_flag_lifecycle(
                    remote_port,
                    _rx_power_flag_candidates(lane, suffix),
                    baseline_tables,
                    shutdown_tables,
                    "dom",
                    True,
                    "set",
                    shutdown_time,
                )
            )

    return failures


def _validate_local_startup(context, baseline_tables, startup_tables, startup_time):
    """Return failures for local DOM recovery after startup."""
    local_port = context["local_port"]
    sensor_data = startup_tables["sensor"].get(local_port)
    plan = context["local_plan"]
    failures = []

    field_failures, _checked_fields, _checked_ports = validate_dom_plan_fields(
        context["duthost"],
        [local_port],
        startup_tables["sensor"],
        {local_port: plan},
        dom_field_in_operational_range,
    )
    failures.extend(field_failures)
    failures.extend(
        _validate_sensor_freshness_after(
            context["duthost"],
            local_port,
            sensor_data,
            plan.get("max_age_min"),
            startup_time,
            "local startup",
        )
    )

    for lane in context["active_host_lanes"]:
        failures.extend(
            _validate_flag_lifecycle(
                local_port,
                _tx_los_hostlane_candidates(lane),
                baseline_tables,
                startup_tables,
                "status",
                False,
                "clear",
                startup_time,
            )
        )

    deviation_failures, checked_count = _validate_deviation_checks(
        local_port,
        baseline_tables["sensor"].get(local_port, {}),
        sensor_data or {},
        context["local_deviation_checks"],
        "local startup",
    )
    failures.extend(deviation_failures)
    if checked_count:
        logger.info("DOM interface-state local deviation checks passed for %s: %d field(s)",
                    local_port, checked_count)
    return failures


def _validate_remote_startup(context, baseline_tables, startup_tables, startup_time):
    """Return failures for remote DOM recovery after startup."""
    remote_port = context["remote"].primary_port
    sensor_data = startup_tables["sensor"].get(remote_port)
    plan = context["remote_plan"]
    failures = []

    failures.extend(
        _validate_sensor_freshness_after(
            context["remote"].host,
            remote_port,
            sensor_data,
            plan.get("max_age_min"),
            startup_time,
            "remote startup",
        )
    )
    if isinstance(sensor_data, dict) and sensor_data:
        op_failures, checked = _validate_operational_fields(
            remote_port,
            sensor_data,
            plan.get("expected_fields", {}),
            lambda field: field.startswith("rx") and field.endswith("power"),
            "remote startup",
        )
        failures.extend(op_failures)
        if not checked:
            failures.append("remote startup no configured RX power operational field was checked")

    for lane in plan["active_media_lanes"]:
        for suffix in ("LAlarm", "LWarn"):
            failures.extend(
                _validate_flag_lifecycle(
                    remote_port,
                    _rx_power_flag_candidates(lane, suffix),
                    baseline_tables,
                    startup_tables,
                    "dom",
                    False,
                    "clear",
                    startup_time,
                )
            )

    deviation_failures, checked_count = _validate_deviation_checks(
        remote_port,
        baseline_tables["sensor"].get(remote_port, {}),
        sensor_data or {},
        context["remote_deviation_checks"],
        "remote startup",
    )
    failures.extend(deviation_failures)
    if checked_count:
        logger.info("DOM interface-state remote deviation checks passed for %s: %d field(s)",
                    remote_port, checked_count)
    return failures


def _validate_baseline(context, local_tables, remote_tables):
    """Return failures for pre-disruption local and remote baseline state."""
    local_port = context["local_port"]
    remote_port = context["remote"].primary_port
    failures = []

    local_failures, _checked_fields, _checked_ports = validate_dom_plan_fields(
        context["duthost"],
        [local_port],
        local_tables["sensor"],
        {local_port: context["local_plan"]},
        dom_field_available,
        include_freshness_only=True,
    )
    failures.extend(local_failures)

    remote_failures, _checked_fields, _checked_ports = validate_dom_plan_fields(
        context["remote"].host,
        [remote_port],
        remote_tables["sensor"],
        {remote_port: context["remote_plan"]},
        dom_field_available,
        include_freshness_only=True,
    )
    failures.extend(remote_failures)
    local_flag_failures = _baseline_flag_failures(
        local_port,
        local_tables,
        context["active_host_lanes"],
        [],
    )
    if local_flag_failures:
        failures.append(
            format_dom_port_failure(
                local_port,
                context["active_host_lanes"],
                {},
                local_flag_failures,
                field_label="baseline local flag(s)",
            )
        )

    remote_flag_failures = _baseline_flag_failures(
        remote_port,
        remote_tables,
        [],
        context["remote_plan"]["active_media_lanes"],
    )
    if remote_flag_failures:
        failures.append(
            format_dom_port_failure(
                remote_port,
                context["remote_plan"]["active_media_lanes"],
                {},
                remote_flag_failures,
                field_label="baseline remote flag(s)",
            )
        )
    return failures


def _operation_context(duthost, duthosts, conn_graph_facts, local_port,
                       port_attributes_dict, lport_to_first_subport_mapping):
    """Return ``(context, errors)`` for one local primary port under test."""
    errors = []
    remote, error = _resolve_remote_peer(
        duthost,
        duthosts,
        conn_graph_facts,
        local_port,
        lport_to_first_subport_mapping,
    )
    if error:
        return None, [error]

    if remote.primary_port not in port_attributes_dict:
        return None, [
            "{} peer port {} is not present in port_attributes_dict".format(local_port, remote.primary_port)
        ]

    toggle_ports = _ports_for_primary(local_port, port_attributes_dict, lport_to_first_subport_mapping)
    if remote.host == duthost and remote.primary_port in toggle_ports:
        return None, [
            "{} remote peer {} overlaps local shutdown group {}".format(
                local_port,
                remote.primary_port,
                toggle_ports,
            )
        ]

    local_plan = build_dom_sensor_plan(
        port_attributes_dict,
        [local_port],
        lport_to_first_subport_mapping,
    )[local_port]
    remote_plan = build_dom_sensor_plan(
        port_attributes_dict,
        [remote.primary_port],
        lport_to_first_subport_mapping,
    )[remote.primary_port]
    active_host_lanes, host_lane_errors = _active_lanes_from_group_mask(
        local_port,
        port_attributes_dict,
        lport_to_first_subport_mapping,
        HOST_LANE_MASK_KEY,
    )
    errors.extend(host_lane_errors)
    if not active_host_lanes:
        errors.append("{} no active host lanes resolved".format(local_port))

    local_dom_attrs = port_attributes_dict[local_port].get(DOM_ATTRIBUTES_KEY, {})
    remote_dom_attrs = port_attributes_dict[remote.primary_port].get(DOM_ATTRIBUTES_KEY, {})
    local_deviation_checks, deviation_errors = _build_deviation_checks(
        local_dom_attrs,
        local_plan["active_media_lanes"],
        LOCAL_DEVIATION_ATTRS,
    )
    errors.extend(deviation_errors)
    remote_deviation_checks, deviation_errors = _build_deviation_checks(
        remote_dom_attrs,
        remote_plan["active_media_lanes"],
        REMOTE_DEVIATION_ATTRS,
    )
    errors.extend(deviation_errors)

    parsed_attrs = {}
    for attr_name in (SHUTDOWN_TX_BIAS_ATTR, SHUTDOWN_TX_POWER_ATTR):
        parsed_attrs[attr_name], error = _parse_required_number(local_dom_attrs, attr_name)
        if error:
            errors.append("{} {}".format(local_port, error))
    parsed_attrs[SHUTDOWN_RX_POWER_ATTR], error = _parse_required_number(remote_dom_attrs, SHUTDOWN_RX_POWER_ATTR)
    if error:
        errors.append("{} {}".format(remote.primary_port, error))

    local_update_time, error = _parse_required_positive_int(
        local_dom_attrs,
        MAX_UPDATE_TIME_ATTR,
        minimum=1,
    )
    if error:
        errors.append("{} {}".format(local_port, error))
    remote_update_time, error = _parse_required_positive_int(
        remote_dom_attrs,
        MAX_UPDATE_TIME_ATTR,
        minimum=1,
    )
    if error:
        errors.append("{} {}".format(remote.primary_port, error))

    shutdown_wait, wait_errors = _max_system_wait(
        port_attributes_dict,
        toggle_ports,
        "port_shutdown_wait_sec",
    )
    errors.extend(wait_errors)
    startup_wait, wait_errors = _max_system_wait(
        port_attributes_dict,
        toggle_ports,
        "port_startup_wait_sec",
    )
    errors.extend(wait_errors)

    if errors:
        return None, errors

    shutdown_wait = scenario_ops.scale_bulk_wait(shutdown_wait, len(toggle_ports))
    startup_wait = scenario_ops.scale_bulk_wait(startup_wait, len(toggle_ports))
    dom_update_wait = max(local_update_time, remote_update_time) + DOM_UPDATE_MARGIN_SEC

    return {
        "duthost": duthost,
        "local_port": local_port,
        "remote": remote,
        "toggle_ports": toggle_ports,
        "local_plan": local_plan,
        "remote_plan": remote_plan,
        "active_host_lanes": active_host_lanes,
        "shutdown_tx_bias_threshold": parsed_attrs[SHUTDOWN_TX_BIAS_ATTR],
        "shutdown_tx_power_threshold": parsed_attrs[SHUTDOWN_TX_POWER_ATTR],
        "shutdown_rx_power_threshold": parsed_attrs[SHUTDOWN_RX_POWER_ATTR],
        "local_deviation_checks": local_deviation_checks,
        "remote_deviation_checks": remote_deviation_checks,
        "shutdown_wait": shutdown_wait,
        "startup_wait": startup_wait,
        "dom_update_wait": dom_update_wait,
    }, []


def _exercise_port(context, baseline_local_tables, baseline_remote_tables):
    """Run shutdown/startup for one port context and return aggregate failures."""
    local_port = context["local_port"]
    remote_port = context["remote"].primary_port
    failures = []
    touched_ports = list(context["toggle_ports"])

    logger.info(
        "DOM Advanced TC1: %s -> peer %s:%s, toggling %s "
        "(shutdown_wait=%ss startup_wait=%ss dom_update_wait=%ss)",
        local_port,
        context["remote"].device,
        context["remote"].port,
        touched_ports,
        context["shutdown_wait"],
        context["startup_wait"],
        context["dom_update_wait"],
    )

    try:
        shutdown_time = context["duthost"].get_now_time(utc_timezone=True)
        failures.extend(
            scenario_ops.perform_ports_shutdown(
                context["duthost"],
                touched_ports,
                context["shutdown_wait"],
            )
        )
        local_sensor, update_failures = _wait_for_dom_sensor_update(
            context["duthost"],
            [local_port],
            shutdown_time,
            context["dom_update_wait"],
            "local shutdown",
        )
        failures.extend(update_failures)
        remote_sensor, update_failures = _wait_for_dom_sensor_update(
            context["remote"].host,
            [remote_port],
            shutdown_time,
            context["dom_update_wait"],
            "remote shutdown",
        )
        failures.extend(update_failures)
        shutdown_local_tables, read_failures = _read_dom_interface_state_tables(
            context["duthost"],
            [local_port] + touched_ports,
            include_appl_port=True,
        )
        failures.extend(read_failures)
        shutdown_remote_tables, read_failures = _read_dom_interface_state_tables(
            context["remote"].host,
            [remote_port],
            include_appl_port=False,
        )
        failures.extend(read_failures)
        shutdown_local_tables["sensor"].update(local_sensor)
        shutdown_remote_tables["sensor"].update(remote_sensor)

        failures.extend(
            _validate_local_shutdown(
                context,
                baseline_local_tables,
                shutdown_local_tables,
                shutdown_time,
            )
        )
        failures.extend(
            _validate_remote_shutdown(
                context,
                baseline_remote_tables,
                shutdown_remote_tables,
                shutdown_time,
            )
        )

        startup_time = context["duthost"].get_now_time(utc_timezone=True)
        failures.extend(
            scenario_ops.perform_ports_startup(
                context["duthost"],
                touched_ports,
                context["startup_wait"],
            )
        )
        local_sensor, update_failures = _wait_for_dom_sensor_update(
            context["duthost"],
            [local_port],
            startup_time,
            context["dom_update_wait"],
            "local startup",
        )
        failures.extend(update_failures)
        remote_sensor, update_failures = _wait_for_dom_sensor_update(
            context["remote"].host,
            [remote_port],
            startup_time,
            context["dom_update_wait"],
            "remote startup",
        )
        failures.extend(update_failures)
        startup_local_tables, read_failures = _read_dom_interface_state_tables(
            context["duthost"],
            [local_port],
            include_appl_port=False,
        )
        failures.extend(read_failures)
        startup_remote_tables, read_failures = _read_dom_interface_state_tables(
            context["remote"].host,
            [remote_port],
            include_appl_port=False,
        )
        failures.extend(read_failures)
        startup_local_tables["sensor"].update(local_sensor)
        startup_remote_tables["sensor"].update(remote_sensor)

        failures.extend(
            _validate_local_startup(
                context,
                baseline_local_tables,
                startup_local_tables,
                startup_time,
            )
        )
        failures.extend(
            _validate_remote_startup(
                context,
                baseline_remote_tables,
                startup_remote_tables,
                startup_time,
            )
        )
    finally:
        restore_failures = scenario_ops.perform_ports_startup(
            context["duthost"],
            touched_ports,
            context["startup_wait"],
        )
        failures.extend("teardown: {}".format(failure) for failure in restore_failures)

    return failures


def test_dom_data_during_interface_state_changes(
    duthost,
    duthosts,
    conn_graph_facts,
    dom_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify local and remote DOM state transitions across shut/no-shut."""
    all_failures = []
    checked_port_count = 0

    for local_port in dom_primary_ports:
        context, config_errors = _operation_context(
            duthost,
            duthosts,
            conn_graph_facts,
            local_port,
            port_attributes_dict,
            lport_to_first_subport_mapping,
        )
        if config_errors:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    [],
                    {},
                    config_errors,
                    field_label="advanced interface-state configuration item(s)",
                    include_lanes=False,
                )
            )
            continue

        baseline_local_tables, read_failures = _read_dom_interface_state_tables(
            duthost,
            [local_port] + context["toggle_ports"],
            include_appl_port=True,
        )
        baseline_remote_tables, remote_read_failures = _read_dom_interface_state_tables(
            context["remote"].host,
            [context["remote"].primary_port],
            include_appl_port=False,
        )
        read_failures.extend(remote_read_failures)
        if read_failures:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    context["local_plan"]["active_media_lanes"],
                    context["local_plan"]["expected_fields"],
                    read_failures,
                    field_label="baseline read item(s)",
                )
            )
            continue

        baseline_failures = _validate_baseline(context, baseline_local_tables, baseline_remote_tables)
        if baseline_failures:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    context["local_plan"]["active_media_lanes"],
                    context["local_plan"]["expected_fields"],
                    baseline_failures,
                    field_label="baseline validation item(s)",
                )
            )
            continue

        port_failures = _exercise_port(context, baseline_local_tables, baseline_remote_tables)
        if port_failures:
            all_failures.append(
                format_dom_port_failure(
                    local_port,
                    context["local_plan"]["active_media_lanes"],
                    context["local_plan"]["expected_fields"],
                    port_failures,
                    field_label="advanced interface-state check(s)",
                )
            )
            continue

        checked_port_count += 1

    if all_failures:
        pytest.fail("DOM interface-state validation failures:\n" + "\n".join(all_failures))

    if not checked_port_count:
        pytest.skip("No DOM interface-state checks executed")

    logger.info("DOM interface-state validation passed for %d primary port(s)", checked_port_count)
