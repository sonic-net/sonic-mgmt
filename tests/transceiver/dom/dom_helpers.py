"""Pure DOM helper functions.

Read/derive helpers use a ``(payload, errors)`` convention where ``errors`` is
a list of self-describing strings.  Callers aggregate those strings into the
final per-test failure message instead of raising immediately.
"""
import logging
import math
from collections import defaultdict, namedtuple
from datetime import datetime, timedelta

from tests.common.utilities import wait_until
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    DOM_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.db_helpers import (
    STATE_DB_UPDATE_TIME_FIELD,
    check_entry_freshness,
    get_config_db_port_table,
    get_db_table,
    get_state_db_table,
    parse_numeric,
    parse_state_db_bool,
    parse_update_time,
    resolve_port_namespace,
)

logger = logging.getLogger(__name__)

STATE_DB_SENSOR_TABLE = "TRANSCEIVER_DOM_SENSOR"
STATE_DB_THRESHOLD_TABLE = "TRANSCEIVER_DOM_THRESHOLD"
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

OPERATIONAL_SUFFIX = "_operational_range"
THRESHOLD_SUFFIX = "_threshold_range"
CONSISTENCY_SUFFIX = "_consistency_variation_threshold"
DEVIATION_SUFFIX = "_deviation_range"
CONSISTENCY_MODE_ABSOLUTE = "absolute"
CONSISTENCY_MODE_PERCENT = "percent"
LANE_NUM_PLACEHOLDER = "LANE_NUM"
MEDIA_LANE_MASK_KEY = "media_lane_mask"
DomMappedField = namedtuple("DomMappedField", ("source_attr", "attr_value"))
DomThresholdMappedField = namedtuple("DomThresholdMappedField", ("source_attr", "attr_value", "threshold_key"))
DomQuantitySpec = namedtuple(
    "DomQuantitySpec",
    (
        "threshold_db_prefix",
        "sensor_field_template",
        "operational_attr",
        "consistency_unit",
        "consistency_mode",
        "deviation_unit",
    ),
)

THRESHOLD_FIELD_SUFFIXES = ("lowalarm", "lowwarning", "highwarning", "highalarm")
DOM_QUANTITY_REGISTRY = {
    "temperature": DomQuantitySpec(
        "temp",
        "temperature",
        "temperature_operational_range",
        "C",
        CONSISTENCY_MODE_ABSOLUTE,
        "C",
    ),
    "voltage": DomQuantitySpec(
        "vcc",
        "voltage",
        "voltage_operational_range",
        "V",
        CONSISTENCY_MODE_ABSOLUTE,
        "V",
    ),
    "laser_temperature": DomQuantitySpec(
        "lasertemp",
        "laser_temperature",
        "laser_temperature_operational_range",
        "C",
        CONSISTENCY_MODE_ABSOLUTE,
        "C",
    ),
    "tx_power": DomQuantitySpec(
        "txpower",
        "tx{}power",
        "txLANE_NUMpower_operational_range",
        "dB",
        CONSISTENCY_MODE_ABSOLUTE,
        "dBm",
    ),
    "rx_power": DomQuantitySpec(
        "rxpower",
        "rx{}power",
        "rxLANE_NUMpower_operational_range",
        "dB",
        CONSISTENCY_MODE_ABSOLUTE,
        "dBm",
    ),
    "tx_bias": DomQuantitySpec(
        "txbias",
        "tx{}bias",
        "txLANE_NUMbias_operational_range",
        "%",
        CONSISTENCY_MODE_PERCENT,
        "mA",
    ),
}
THRESHOLD_FIELD_PREFIXES = {
    base_name: spec.threshold_db_prefix
    for base_name, spec in DOM_QUANTITY_REGISTRY.items()
}
THRESHOLD_TO_OPERATIONAL_ATTR = {
    base_name: spec.operational_attr
    for base_name, spec in DOM_QUANTITY_REGISTRY.items()
}
THRESHOLD_VALUE_TOLERANCE = 0.01
CONSISTENCY_FIELD_TEMPLATES_BY_BASE = {
    base_name: spec.sensor_field_template
    for base_name, spec in DOM_QUANTITY_REGISTRY.items()
}
CONSISTENCY_UNITS_BY_BASE = {
    base_name: spec.consistency_unit
    for base_name, spec in DOM_QUANTITY_REGISTRY.items()
}
CONSISTENCY_MODES_BY_BASE = {
    base_name: spec.consistency_mode
    for base_name, spec in DOM_QUANTITY_REGISTRY.items()
}
DEVIATION_UNITS_BY_BASE = {
    base_name: spec.deviation_unit
    for base_name, spec in DOM_QUANTITY_REGISTRY.items()
}

DOM_POLLING_ENABLED_VALUES = ("", "enabled")
DOM_POLLING_DISABLED_VALUE = "disabled"

DOM_RECOVERY_POLL_INTERVAL_SEC = 20
DOM_EVENT_TIME_TOLERANCE_SEC = 5


def _active_media_lanes(primary_port, port_attributes_dict, lport_to_first_subport_mapping):
    """Return ``(active_lanes, errors)`` for a primary subport.

    DOM sensor data for a breakout module is published only on the first/primary
    subport, but that single entry carries all of the module's media lanes (one
    per subport). A subport's own ``media_lane_count`` is therefore too small
    (e.g. 1 on an 8x breakout), so LANE_NUM must expand over the whole module.
    The module's active media lanes are the union of the per-subport
    ``media_lane_mask`` across the breakout group; each set mask bit is an
    absolute, 1-indexed media lane. Padded/unconfigured lanes are excluded, so
    the caller only expects fields for lanes that actually carry a signal.
    """
    mapping = lport_to_first_subport_mapping or {}
    group = [sub for sub, first in mapping.items() if first == primary_port] or [primary_port]

    mask_union = 0
    errors = []
    for subport in group:
        base_attrs = port_attributes_dict.get(subport, {}).get(BASE_ATTRIBUTES_KEY, {})
        mask = base_attrs.get(MEDIA_LANE_MASK_KEY)
        if mask is None:
            errors.append(
                "{} missing {} in {}".format(
                    subport,
                    MEDIA_LANE_MASK_KEY,
                    BASE_ATTRIBUTES_KEY,
                )
            )
            continue
        try:
            mask_union |= int(str(mask), 16)
        except (TypeError, ValueError):
            errors.append(
                "{} has unparsable {} {!r} in {}".format(
                    subport,
                    MEDIA_LANE_MASK_KEY,
                    mask,
                    BASE_ATTRIBUTES_KEY,
                )
            )

    lanes = [bit + 1 for bit in range(mask_union.bit_length()) if mask_union & (1 << bit)]
    logger.debug(
        "%s active media lanes %s (breakout group %s, media_lane_mask union %#x)",
        primary_port,
        lanes,
        sorted(group),
        mask_union,
    )
    return lanes, errors


def _map_operational_attribute_to_fields(attr_name, attr_value, active_media_lanes):
    """Return ``({field: DomMappedField(source_attr, attr_value)}, errors)``."""
    base_name = attr_name[:-len(OPERATIONAL_SUFFIX)]
    if LANE_NUM_PLACEHOLDER not in base_name:
        return {base_name: DomMappedField(attr_name, attr_value)}, []

    if not active_media_lanes:
        return {}, [
            "{} uses {} but no active media lanes resolved from {} media_lane_mask".format(
                attr_name,
                LANE_NUM_PLACEHOLDER,
                BASE_ATTRIBUTES_KEY,
            )
        ]

    return {
        base_name.replace(LANE_NUM_PLACEHOLDER, str(lane)): DomMappedField(
            attr_name,
            attr_value,
        )
        for lane in active_media_lanes
    }, []


def _map_threshold_attribute_to_fields(attr_name, attr_value, _active_media_lanes=None):
    """Return ``({field: DomThresholdMappedField(...)}, errors)`` for one threshold range."""
    base_name = attr_name[:-len(THRESHOLD_SUFFIX)]
    prefix = THRESHOLD_FIELD_PREFIXES.get(base_name)
    if prefix is None:
        return {}, ["{} has no DOM threshold field mapping".format(attr_name)]

    return {
        "{}{}".format(prefix, suffix): DomThresholdMappedField(
            attr_name,
            attr_value,
            suffix,
        )
        for suffix in THRESHOLD_FIELD_SUFFIXES
    }, []


DOM_FIELD_MAPPERS = (
    (OPERATIONAL_SUFFIX, _map_operational_attribute_to_fields),
    (THRESHOLD_SUFFIX, _map_threshold_attribute_to_fields),
)


def map_dom_attribute_to_fields(attr_name, attr_value, active_media_lanes):
    """Map one DOM attribute to current STATE_DB field metadata.

    The suffix dispatch is DOM-local. Sensor-table operational ranges expand
    ``LANE_NUM`` across active media lanes. Threshold ranges are transceiver-
    level and return ``DomThresholdMappedField`` entries without lane expansion.
    Callers build table-specific plans from the mapped field type they need.
    """
    for suffix, mapper in DOM_FIELD_MAPPERS:
        if attr_name.endswith(suffix):
            return mapper(attr_name, attr_value, active_media_lanes)
    logger.debug("DOM attribute %s matched no field mapper; skipped", attr_name)
    return {}, []


def _operational_attr_for_threshold(attr_name):
    """Return the configured operational-range attribute paired with a threshold attribute."""
    base_name = attr_name[:-len(THRESHOLD_SUFFIX)]
    return THRESHOLD_TO_OPERATIONAL_ATTR.get(base_name)


def _quantity_base_name_for_attr(attr_name, suffix):
    """Return the DOM quantity registry key for an attribute name."""
    if not attr_name.endswith(suffix):
        return None

    attr_base_name = attr_name[:-len(suffix)]
    if attr_base_name in DOM_QUANTITY_REGISTRY:
        return attr_base_name

    for base_name, spec in DOM_QUANTITY_REGISTRY.items():
        operational_base_name = spec.operational_attr[:-len(OPERATIONAL_SUFFIX)]
        if attr_base_name == operational_base_name:
            return base_name

    return None


def consistency_field_template_for_attr(attr_name):
    """Return the STATE_DB sensor field template for a consistency attribute."""
    base_name = _quantity_base_name_for_attr(attr_name, CONSISTENCY_SUFFIX)
    return CONSISTENCY_FIELD_TEMPLATES_BY_BASE.get(base_name)


def consistency_unit_for_attr(attr_name):
    """Return the output unit for a configured consistency attribute."""
    base_name = _quantity_base_name_for_attr(attr_name, CONSISTENCY_SUFFIX)
    return CONSISTENCY_UNITS_BY_BASE.get(base_name)


def consistency_mode_for_attr(attr_name):
    """Return the validation mode for a configured consistency attribute."""
    base_name = _quantity_base_name_for_attr(attr_name, CONSISTENCY_SUFFIX)
    return CONSISTENCY_MODES_BY_BASE.get(base_name)


def deviation_field_template_for_attr(attr_name):
    """Return the STATE_DB sensor field template for a deviation-range attribute."""
    base_name = _quantity_base_name_for_attr(attr_name, DEVIATION_SUFFIX)
    return CONSISTENCY_FIELD_TEMPLATES_BY_BASE.get(base_name)


def deviation_unit_for_attr(attr_name):
    """Return the output unit for a configured deviation-range attribute."""
    base_name = _quantity_base_name_for_attr(attr_name, DEVIATION_SUFFIX)
    return DEVIATION_UNITS_BY_BASE.get(base_name)


def dom_consistency_attributes():
    """Return DOM consistency attribute names derived from the quantity registry."""
    return tuple(
        "{}{}".format(base_name, CONSISTENCY_SUFFIX)
        for base_name in DOM_QUANTITY_REGISTRY
    )


def field_template_is_lane_expanded(field_template):
    """Return True when a STATE_DB field template expects a lane number."""
    return "{}" in field_template


def build_dom_sensor_plan(port_attributes_dict, dom_primary_ports, lport_to_first_subport_mapping):
    """Return each port's expected DOM fields, active lanes, errors, and age limit.

    ``expected_fields`` is a ``{field: DomMappedField(source_attr, attr_value)}``
    map keyed in sorted field order: TC1 iterates the keys (presence/freshness),
    while range-based checks (TC2) read each field's ``attr_value`` (its
    ``{"min", "max"}`` operational range) without re-deriving the mapping.
    """
    plan_by_port = {}
    for port in dom_primary_ports:
        port_attrs = port_attributes_dict.get(port, {})
        dom_attrs = port_attrs.get(DOM_ATTRIBUTES_KEY, {})
        active_media_lanes, lane_errors = _active_media_lanes(
            port, port_attributes_dict, lport_to_first_subport_mapping
        )
        expected_fields = {}
        errors = list(lane_errors)

        for attr_name, attr_value in sorted(dom_attrs.items()):
            if not attr_name.endswith(OPERATIONAL_SUFFIX):
                continue
            mapped_fields, field_errors = map_dom_attribute_to_fields(
                attr_name,
                attr_value,
                active_media_lanes,
            )
            expected_fields.update(mapped_fields)
            errors.extend(field_errors)

        plan_by_port[port] = {
            "expected_fields": {field: expected_fields[field] for field in sorted(expected_fields)},
            "active_media_lanes": active_media_lanes,
            "errors": errors,
            "max_age_min": dom_attrs.get("data_max_age_min"),
        }
        logger.debug(
            "%s DOM plan: %d expected field(s), active media lanes %s, data_max_age_min=%s",
            port,
            len(expected_fields),
            active_media_lanes or "none",
            dom_attrs.get("data_max_age_min"),
        )

    return plan_by_port


def build_dom_threshold_plan(port_attributes_dict, dom_primary_ports):
    """Return each port's expected threshold fields and paired operational ranges.

    ``db_fields_by_threshold_attr`` groups ``TRANSCEIVER_DOM_THRESHOLD`` fields
    by source threshold attribute. Threshold validation is transceiver-level, so
    no LANE_NUM expansion is applied here.
    """
    plan_by_port = {}
    for port in dom_primary_ports:
        dom_attrs = port_attributes_dict.get(port, {}).get(DOM_ATTRIBUTES_KEY, {})
        configured_by_attr = {}
        db_fields_by_threshold_attr = defaultdict(dict)
        operational_range_by_threshold_attr = {}
        errors = []

        for attr_name, attr_value in sorted(dom_attrs.items()):
            if not attr_name.endswith(THRESHOLD_SUFFIX):
                continue

            configured_by_attr[attr_name] = attr_value
            mapped_fields, field_errors = map_dom_attribute_to_fields(attr_name, attr_value, active_media_lanes=None)
            for field, mapped_field in mapped_fields.items():
                db_fields_by_threshold_attr[attr_name][field] = mapped_field
            errors.extend(field_errors)

            operational_attr = _operational_attr_for_threshold(attr_name)
            if operational_attr in dom_attrs:
                operational_range_by_threshold_attr[attr_name] = DomMappedField(
                    operational_attr,
                    dom_attrs[operational_attr],
                )

        plan_by_port[port] = {
            "configured_by_attr": configured_by_attr,
            "db_fields_by_threshold_attr": {
                attr_name: {
                    field: db_fields_by_threshold_attr[attr_name][field]
                    for field in sorted(db_fields_by_threshold_attr[attr_name])
                }
                for attr_name in sorted(db_fields_by_threshold_attr)
            },
            "operational_range_by_threshold_attr": operational_range_by_threshold_attr,
            "errors": errors,
        }
        logger.debug(
            "%s DOM threshold plan: %d expected field(s), %d threshold attr(s), "
            "%d paired operational range attr(s)",
            port,
            sum(len(fields) for fields in db_fields_by_threshold_attr.values()),
            len(configured_by_attr),
            len(operational_range_by_threshold_attr),
        )

    return plan_by_port


def build_dom_polling_failures(duthost, dom_primary_ports):
    """Return DOM polling prerequisite failures for configured DOM ports."""
    failures = []
    port_table = get_config_db_port_table(duthost)

    for port in dom_primary_ports:
        port_config = port_table.get(port)
        if port_config is None:
            failures.append("{} missing from CONFIG_DB PORT table".format(port))
            continue
        if not isinstance(port_config, dict):
            failures.append(
                "{} CONFIG_DB PORT entry has unexpected type {}".format(
                    port,
                    type(port_config).__name__,
                )
            )
            continue

        raw_value = port_config.get("dom_polling")
        normalized = "" if raw_value is None else str(raw_value).strip().lower()

        if normalized in DOM_POLLING_ENABLED_VALUES:
            logger.debug(
                "%s DOM polling is enabled: %s",
                port,
                raw_value if raw_value is not None else "<default-enabled>",
            )
            continue

        if normalized == DOM_POLLING_DISABLED_VALUE:
            failures.append("{} dom_polling is disabled".format(port))
        else:
            failures.append("{} dom_polling has unexpected value {!r}".format(port, raw_value))

    return failures


def format_optional_float(value):
    return "{:.2f}".format(value) if value is not None else "not-available"


def normalize_datetime(value):
    """Return a timezone-naive datetime for arithmetic with xcvrd timestamps."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.replace(tzinfo=None)
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


def ports_for_primary(primary_port, port_attributes_dict, lport_to_first_subport_mapping):
    """Return logical subports that share ``primary_port`` as their first subport."""
    mapping = lport_to_first_subport_mapping or {}
    return sorted(
        port
        for port in port_attributes_dict
        if mapping.get(port, port) == primary_port
    ) or [primary_port]


def active_lanes_from_group_mask(primary_port, port_attributes_dict, lport_to_first_subport_mapping, mask_key):
    """Return ``(lanes, errors)`` from the union of a breakout group's lane masks."""
    mask_union = 0
    errors = []
    for port in ports_for_primary(primary_port, port_attributes_dict, lport_to_first_subport_mapping):
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


def parse_required_number(attrs, attr_name, category_name=DOM_ATTRIBUTES_KEY):
    """Return ``(value, error)`` for a required finite numeric attribute."""
    raw_value = attrs.get(attr_name)
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value):
        return None, "{} must be configured as a finite number in {} (got {!r})".format(
            attr_name,
            category_name,
            raw_value,
        )
    return value, None


def parse_required_positive_int(attrs, attr_name, minimum=1):
    """Return ``(value, error)`` for a required integer attribute."""
    raw_value = attrs.get(attr_name)
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value) or int(value) != value or value < minimum:
        return None, "{} must be an integer >= {} (got {!r})".format(attr_name, minimum, raw_value)
    return int(value), None


def max_system_wait(port_attributes_dict, ports, attr_name):
    """Return ``(wait_sec, errors)`` for a system timing attribute across ports."""
    values = []
    errors = []
    for port in ports:
        system_attrs = port_attributes_dict.get(port, {}).get(SYSTEM_ATTRIBUTES_KEY, {})
        value, error = parse_required_positive_int(system_attrs, attr_name, minimum=0)
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


def read_dom_interface_state_tables(duthost, ports, include_appl_port=False):
    """Return ``(tables, errors)`` for STATE_DB/APPL_DB tables Advanced TC1 consumes."""
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


def dom_tx_los_hostlane_candidates(lane):
    """Return candidate STATE_DB names for the Tx LOS host-lane flag."""
    return (
        "tx{}los_hostlane".format(lane),
        "tx{}losHostlane".format(lane),
        "tx{}losHostLane".format(lane),
    )


def dom_rx_power_flag_candidates(lane, suffix):
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

    parsed_time = parse_sonic_timestamp(current_raw)
    if parsed_time is None:
        return ["{} {} timestamp is unparsable: {!r}".format(table_name, field, current_raw)]

    earliest = normalize_datetime(event_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
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


def validate_dom_flag_lifecycle(port, candidate_fields, baseline_tables, current_tables,
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
    failures.extend(validate_dom_flag_state(port, flag_table, flag_entry, candidate_fields, expected_state))
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


def validate_dom_baseline_flags(port, tables, active_host_lanes, active_media_lanes):
    """Return failures if TC1 starts with local/remote flags already asserted."""
    failures = []
    for lane in active_host_lanes:
        table_name = STATE_DB_STATUS_FLAG_TABLE
        flag_entry = tables["status_flag"].get(port)
        if not flag_entry:
            table_name = STATE_DB_STATUS_TABLE
            flag_entry = tables["status"].get(port)
        failures.extend(
            validate_dom_flag_state(
                port,
                table_name,
                flag_entry,
                dom_tx_los_hostlane_candidates(lane),
                False,
            )
        )
    for lane in active_media_lanes:
        for suffix in ("LAlarm", "LWarn"):
            failures.extend(
                validate_dom_flag_state(
                    port,
                    STATE_DB_DOM_FLAG_TABLE,
                    tables["dom_flag"].get(port),
                    dom_rx_power_flag_candidates(lane, suffix),
                    False,
                )
            )
    return failures


def validate_sensor_freshness_after(duthost, port, sensor_data, max_age_min, operation_time, label):
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

    earliest = normalize_datetime(operation_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
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


def wait_for_dom_sensor_update(duthost, ports, operation_time, timeout_sec, label):
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
            earliest = normalize_datetime(operation_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
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


def numeric_sensor_value(sensor_data, field):
    """Return a finite numeric sensor value, or ``None`` when absent/unparseable."""
    if not isinstance(sensor_data, dict):
        return None
    value = parse_numeric(sensor_data.get(field))
    return value if value is not None and math.isfinite(value) else None


def validate_sensor_below_threshold(port, sensor_data, field, threshold, label):
    """Return failures if one sensor field is not below its shutdown threshold."""
    value = numeric_sensor_value(sensor_data, field)
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


def validate_sensor_operational_fields(port, sensor_data, expected_fields, field_filter, label):
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


def build_dom_deviation_checks(dom_attrs, active_lanes, attr_names):
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


def validate_dom_deviation_checks(port, baseline_sensor, post_sensor, checks_by_field, label):
    """Return ``(failures, checked_count)`` for configured post-startup deviations."""
    failures = []
    checked_count = 0
    for field, check in checks_by_field.items():
        baseline_value = numeric_sensor_value(baseline_sensor, field)
        post_value = numeric_sensor_value(post_sensor, field)
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


def validate_appl_port_down_time(port, baseline_entry, shutdown_entry, shutdown_time):
    """Return failures for APPL_DB PORT_TABLE last_down_time correlation."""
    if shutdown_entry is None:
        return ["{} could not read APPL_DB PORT_TABLE (namespace read failed)".format(port)]
    if not shutdown_entry:
        return ["{} no APPL_DB PORT_TABLE entry published".format(port)]

    failures = []
    last_down_time = shutdown_entry.get("last_down_time")
    if not last_down_time:
        failures.append("{} APPL_DB PORT_TABLE missing last_down_time after shutdown".format(port))
        return failures

    baseline_down_time = (baseline_entry or {}).get("last_down_time")
    if last_down_time == baseline_down_time:
        failures.append("{} APPL_DB PORT_TABLE last_down_time did not change after shutdown".format(port))

    parsed_down = parse_sonic_timestamp(last_down_time)
    if parsed_down is None:
        failures.append(
            "{} APPL_DB PORT_TABLE last_down_time {!r} is unparsable".format(
                port,
                last_down_time,
            )
        )
        return failures

    earliest = normalize_datetime(shutdown_time) - timedelta(seconds=DOM_EVENT_TIME_TOLERANCE_SEC)
    if parsed_down < earliest:
        failures.append(
            "{} APPL_DB PORT_TABLE last_down_time {} did not advance into shutdown window starting {}".format(
                port,
                last_down_time,
                shutdown_time,
            )
        )

    return failures


def format_dom_port_failure(
    port,
    active_lanes,
    expected_fields,
    field_failures,
    field_label="expected field(s)",
    include_lanes=True,
):
    """Prefix a port's failure block with its expected shape."""
    lane_context = ", lanes {}".format(active_lanes or "none") if include_lanes else ""
    return "{} [{} {}{}]:\n  {}".format(
        port,
        len(expected_fields),
        field_label,
        lane_context,
        "\n  ".join(field_failures),
    )


def parse_min_max_range(mapped_field):
    """Return ``(min_value, max_value, error)`` for a DOM ``{"min", "max"}`` range."""
    attr_name = mapped_field.source_attr
    attr_value = mapped_field.attr_value

    if not isinstance(attr_value, dict):
        return None, None, "{} must be a dict with min/max in DOM_ATTRIBUTES".format(attr_name)

    min_value = parse_numeric(attr_value.get("min"))
    max_value = parse_numeric(attr_value.get("max"))
    if min_value is None or max_value is None:
        return None, None, "{} missing numeric min/max in DOM_ATTRIBUTES".format(attr_name)
    if not math.isfinite(min_value) or not math.isfinite(max_value):
        return None, None, "{} has non-finite min/max in DOM_ATTRIBUTES".format(attr_name)
    if min_value > max_value:
        return None, None, "{} has invalid range [{}, {}]".format(
            attr_name,
            attr_value.get("min"),
            attr_value.get("max"),
        )

    return min_value, max_value, None


def dom_field_available(field, _mapped_field, raw_value):
    """``field_check`` callback: DOM field is present with a finite numeric value."""
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value):
        return "expected DOM field {} has no valid finite value (got {!r})".format(
            field,
            raw_value,
        )
    return None


def dom_field_in_operational_range(field, mapped_field, raw_value):
    """``field_check`` callback: DOM field is available and within its configured range."""
    min_value, max_value, range_error = parse_min_max_range(mapped_field)
    if range_error:
        return range_error

    error = dom_field_available(field, mapped_field, raw_value)
    if error:
        return error

    value = parse_numeric(raw_value)
    if not min_value <= value <= max_value:
        return "{} value {} out of range [{}, {}]".format(
            field,
            value,
            min_value,
            max_value,
        )
    return None


def validate_dom_plan_fields(
    duthost,
    dom_primary_ports,
    sensor_by_port,
    plan_by_port,
    field_check,
    include_freshness_only=False,
):
    """Drive primary-port DOM sensor validation and delegate per-field rules.

    ``field_check(field, mapped_field, raw_value)`` returns an error string or
    ``None``. The driver owns freshness, empty-sensor handling, missing-field
    handling, aggregation, and checked field/port counts.
    """
    failures = []
    checked_field_count = 0
    checked_port_count = 0
    now_utc = None

    for port in dom_primary_ports:
        sensor_data = sensor_by_port.get(port, {})
        plan = plan_by_port.get(port, {})
        expected_fields = plan.get("expected_fields", {})
        active_lanes = plan.get("active_media_lanes", [])
        field_failures = list(plan.get("errors", []))
        max_age_min = plan.get("max_age_min")
        has_field_checks = bool(expected_fields or field_failures)
        has_plan_checks = has_field_checks or (include_freshness_only and max_age_min is not None)

        if not has_plan_checks:
            continue
        checked_port_count += 1

        if sensor_data is None:
            field_failures.append(
                "could not read {} for port (namespace read failed)".format(STATE_DB_SENSOR_TABLE)
            )
            failures.append(format_dom_port_failure(port, active_lanes, expected_fields, field_failures))
            continue

        if not sensor_data:
            field_failures.append(
                "no {} entry published for port".format(STATE_DB_SENSOR_TABLE)
            )
            failures.append(format_dom_port_failure(port, active_lanes, expected_fields, field_failures))
            continue

        freshness_age_min = None
        if max_age_min is not None:
            if now_utc is None:
                now_utc = duthost.get_now_time(utc_timezone=True)
            freshness_result = check_dom_sensor_freshness(sensor_data, max_age_min, now_utc)
            field_failures.extend(freshness_result["failures"])
            freshness_age_min = freshness_result["age_minutes"]

        checked_fields = 0
        for field, mapped_field in expected_fields.items():
            if field not in sensor_data:
                field_failures.append(
                    "expected DOM field missing in STATE_DB sensor data: {}".format(field)
                )
                continue

            raw_value = sensor_data[field]
            error = field_check(field, mapped_field, raw_value)
            if error:
                field_failures.append(error)
                continue

            checked_fields += 1
            logger.debug(
                "DOM field PASS %s %s (source_attr=%s)",
                port,
                field,
                mapped_field.source_attr,
            )

        checked_field_count += checked_fields

        if field_failures:
            failures.append(format_dom_port_failure(port, active_lanes, expected_fields, field_failures))
            continue

        logger.debug(
            "DOM plan PASS %s: media_lanes=%s expected_fields=%s "
            "freshness_age_min=%s freshness_limit_min=%s",
            port,
            active_lanes or "none",
            ", ".join(expected_fields) or "none",
            format_optional_float(freshness_age_min),
            max_age_min if max_age_min is not None else "not-configured",
        )

    return failures, checked_field_count, checked_port_count


def _read_dom_table_data(duthost, ports, table_name):
    """Return ``({port: data_or_None}, errors)`` for a current DOM STATE_DB table.

    A value of ``None`` means the namespace-level table read failed, while an
    empty dict means the table read succeeded and the port entry was absent.
    """
    ports = list(ports)
    table_data_by_port = {port: {} for port in ports}
    errors = []
    ports_by_namespace = defaultdict(list)

    for port in ports:
        namespace = resolve_port_namespace(duthost, port)
        ports_by_namespace[namespace].append(port)

    for namespace, namespace_ports in ports_by_namespace.items():
        dom_table, err = get_state_db_table(
            duthost,
            table_name,
            namespace=namespace,
        )
        if err:
            errors.append(
                "{} namespace {} ({} port(s) under test): {}".format(
                    table_name,
                    namespace or "default",
                    len(namespace_ports),
                    err,
                )
            )
            logger.warning(
                "Failed to read %s namespace %s for %d port(s): %s",
                table_name,
                namespace or "default",
                len(namespace_ports),
                err,
            )
            for port in namespace_ports:
                table_data_by_port[port] = None
            continue

        for port in namespace_ports:
            table_data_by_port[port] = dom_table.get(port, {}) or {}

    logger.debug(
        "Read %s data for %d port(s) across %d namespace(s); "
        "%d port(s) returned data",
        table_name,
        len(ports),
        len(ports_by_namespace),
        sum(1 for port_data in table_data_by_port.values() if port_data),
    )

    return table_data_by_port, errors


def read_dom_sensor_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current DOM sensor data."""
    return _read_dom_table_data(duthost, ports, STATE_DB_SENSOR_TABLE)


def read_dom_threshold_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current DOM threshold data."""
    return _read_dom_table_data(duthost, ports, STATE_DB_THRESHOLD_TABLE)


def read_transceiver_status_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current transceiver status data."""
    return _read_dom_table_data(duthost, ports, STATE_DB_STATUS_TABLE)


def read_dom_flag_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current DOM flag data."""
    return _read_dom_table_data(duthost, ports, STATE_DB_DOM_FLAG_TABLE)


def read_dom_flag_change_count_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current DOM flag change counts."""
    return _read_dom_table_data(duthost, ports, STATE_DB_DOM_FLAG_CHANGE_COUNT_TABLE)


def read_dom_flag_set_time_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current DOM flag set timestamps."""
    return _read_dom_table_data(duthost, ports, STATE_DB_DOM_FLAG_SET_TIME_TABLE)


def read_dom_flag_clear_time_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current DOM flag clear timestamps."""
    return _read_dom_table_data(duthost, ports, STATE_DB_DOM_FLAG_CLEAR_TIME_TABLE)


def read_transceiver_status_flag_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for current transceiver status flags."""
    return _read_dom_table_data(duthost, ports, STATE_DB_STATUS_FLAG_TABLE)


def read_transceiver_status_flag_change_count_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for transceiver status flag change counts."""
    return _read_dom_table_data(duthost, ports, STATE_DB_STATUS_FLAG_CHANGE_COUNT_TABLE)


def read_transceiver_status_flag_set_time_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for transceiver status flag set timestamps."""
    return _read_dom_table_data(duthost, ports, STATE_DB_STATUS_FLAG_SET_TIME_TABLE)


def read_transceiver_status_flag_clear_time_data(duthost, ports):
    """Return ``({port: data_or_None}, errors)`` for transceiver status flag clear timestamps."""
    return _read_dom_table_data(duthost, ports, STATE_DB_STATUS_FLAG_CLEAR_TIME_TABLE)


def check_dom_sensor_freshness(sensor_data, max_age_min, now_utc):
    """Return DOM freshness failures plus the parsed age for one sensor read."""
    return check_entry_freshness(
        sensor_data,
        max_age_min,
        now_utc,
        table_name=STATE_DB_SENSOR_TABLE,
    )


def verify_dom_recovered(duthost, port_attributes_dict, ports,
                         lport_to_first_subport_mapping, baseline_sensor_data):
    """Confirm DOM data recovered after a disruptive operation. Polls until the sensor
    entry is republished and every configured field is readable, then asserts each field
    is within its operational range.

    Returns a list of failure strings (empty on success).
    """
    dom_attrs = port_attributes_dict[ports[0]].get(DOM_ATTRIBUTES_KEY, {})
    if dom_attrs.get("data_max_age_min") is None:
        return [f"{ports[0]}: {DOM_ATTRIBUTES_KEY} is missing data_max_age_min"]

    plan_by_port = build_dom_sensor_plan(
        port_attributes_dict, ports, lport_to_first_subport_mapping,
    )

    def _check_republished():
        sensor_by_port, read_errors = read_dom_sensor_data(duthost, ports)
        failures = [f"DOM sensor read error: {read_error}" for read_error in read_errors]
        for port in ports:
            updated = (sensor_by_port.get(port) or {}).get("last_update_time")
            baseline = (baseline_sensor_data.get(port) or {}).get("last_update_time")
            if updated is not None and updated == baseline:
                failures.append(f"{port}: DOM data not republished; last_update_time still {updated}")
        port_failures, _, _ = validate_dom_plan_fields(
            duthost, ports, sensor_by_port, plan_by_port,
            dom_field_available,
            include_freshness_only=True,
        )
        return failures + port_failures

    failures = scenario_ops.poll_ports_recovered(
        _check_republished, dom_attrs["dom_info_recover_sec"],
        DOM_RECOVERY_POLL_INTERVAL_SEC, "DOM recovery",
    )
    if failures:
        return failures

    sensor_by_port, read_errors = read_dom_sensor_data(duthost, ports)
    port_failures, _, _ = validate_dom_plan_fields(
        duthost, ports, sensor_by_port, plan_by_port,
        dom_field_in_operational_range,
        include_freshness_only=True,
    )
    return [f"DOM sensor read error: {read_error}" for read_error in read_errors] + port_failures
