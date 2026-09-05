"""Pure DOM helper functions.

Read/derive helpers use a ``(payload, errors)`` convention where ``errors`` is
a list of self-describing strings.  Callers aggregate those strings into the
final per-test failure message instead of raising immediately.
"""
import logging
import math
from collections import defaultdict, namedtuple

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    DOM_ATTRIBUTES_KEY,
)
from tests.transceiver.common import scenario_ops
from tests.transceiver.common.db_helpers import (
    check_entry_freshness,
    get_config_db_port_table,
    get_state_db_table,
    parse_numeric,
    resolve_port_namespace,
)

logger = logging.getLogger(__name__)

STATE_DB_SENSOR_TABLE = "TRANSCEIVER_DOM_SENSOR"
STATE_DB_THRESHOLD_TABLE = "TRANSCEIVER_DOM_THRESHOLD"

OPERATIONAL_SUFFIX = "_operational_range"
THRESHOLD_SUFFIX = "_threshold_range"
CONSISTENCY_SUFFIX = "_consistency_variation_threshold"
CONSISTENCY_MODE_ABSOLUTE = "absolute"
CONSISTENCY_MODE_PERCENT = "percent"
LANE_NUM_PLACEHOLDER = "LANE_NUM"
MEDIA_LANE_MASK_KEY = "media_lane_mask"
DomMappedField = namedtuple("DomMappedField", ("source_attr", "attr_value"))
DomThresholdMappedField = namedtuple("DomThresholdMappedField", ("source_attr", "attr_value", "threshold_key"))
DomQuantitySpec = namedtuple(
    "DomQuantitySpec",
    ("threshold_db_prefix", "sensor_field_template", "operational_attr", "consistency_unit", "consistency_mode"),
)

THRESHOLD_FIELD_SUFFIXES = ("lowalarm", "lowwarning", "highwarning", "highalarm")
DOM_QUANTITY_REGISTRY = {
    "temperature": DomQuantitySpec(
        "temp",
        "temperature",
        "temperature_operational_range",
        "C",
        CONSISTENCY_MODE_ABSOLUTE,
    ),
    "voltage": DomQuantitySpec("vcc", "voltage", "voltage_operational_range", "V", CONSISTENCY_MODE_ABSOLUTE),
    "laser_temperature": DomQuantitySpec(
        "lasertemp",
        "laser_temperature",
        "laser_temperature_operational_range",
        "C",
        CONSISTENCY_MODE_ABSOLUTE,
    ),
    "tx_power": DomQuantitySpec(
        "txpower",
        "tx{}power",
        "txLANE_NUMpower_operational_range",
        "dB",
        CONSISTENCY_MODE_ABSOLUTE,
    ),
    "rx_power": DomQuantitySpec(
        "rxpower",
        "rx{}power",
        "rxLANE_NUMpower_operational_range",
        "dB",
        CONSISTENCY_MODE_ABSOLUTE,
    ),
    "tx_bias": DomQuantitySpec(
        "txbias",
        "tx{}bias",
        "txLANE_NUMbias_operational_range",
        "%",
        CONSISTENCY_MODE_PERCENT,
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

DOM_POLLING_ENABLED_VALUES = ("", "enabled")
DOM_POLLING_DISABLED_VALUE = "disabled"

DOM_RECOVERY_POLL_INTERVAL_SEC = 20


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


def consistency_field_template_for_attr(attr_name):
    """Return the STATE_DB sensor field template for a consistency attribute."""
    if not attr_name.endswith(CONSISTENCY_SUFFIX):
        return None
    base_name = attr_name[:-len(CONSISTENCY_SUFFIX)]
    return CONSISTENCY_FIELD_TEMPLATES_BY_BASE.get(base_name)


def consistency_unit_for_attr(attr_name):
    """Return the output unit for a configured consistency attribute."""
    if not attr_name.endswith(CONSISTENCY_SUFFIX):
        return None
    base_name = attr_name[:-len(CONSISTENCY_SUFFIX)]
    return CONSISTENCY_UNITS_BY_BASE.get(base_name)


def consistency_mode_for_attr(attr_name):
    """Return the validation mode for a configured consistency attribute."""
    if not attr_name.endswith(CONSISTENCY_SUFFIX):
        return None
    base_name = attr_name[:-len(CONSISTENCY_SUFFIX)]
    return CONSISTENCY_MODES_BY_BASE.get(base_name)


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


def _parse_threshold_range(attr_name, attr_value):
    """Return ``(thresholds, errors)`` for one configured threshold attribute."""
    if not isinstance(attr_value, dict):
        return {}, [
            "{} must be a dict with {} in DOM_ATTRIBUTES".format(
                attr_name,
                THRESHOLD_FIELD_SUFFIXES,
            )
        ]

    thresholds = {}
    errors = []
    for threshold_key in THRESHOLD_FIELD_SUFFIXES:
        value = parse_numeric(attr_value.get(threshold_key))
        if value is None or not math.isfinite(value):
            errors.append(
                "{} missing/non-finite numeric {} in DOM_ATTRIBUTES".format(
                    attr_name,
                    threshold_key,
                )
            )
            continue
        thresholds[threshold_key] = value

    if errors:
        return {}, errors

    hierarchy_error = _threshold_hierarchy_error(attr_name, thresholds, "configured")
    if hierarchy_error:
        return {}, [hierarchy_error]

    return thresholds, []


def _threshold_hierarchy_error(attr_name, thresholds, source):
    if (
        thresholds["lowalarm"]
        < thresholds["lowwarning"]
        < thresholds["highwarning"]
        < thresholds["highalarm"]
    ):
        return None
    return (
        "{} {} hierarchy lowalarm < lowwarning < highwarning < highalarm "
        "is violated".format(attr_name, source)
    )


def _validate_operational_range_within_warning(threshold_attr, thresholds, operational_mapped_field):
    """Validate a paired operational range sits inside threshold warning bounds."""
    op_min, op_max, range_error = parse_min_max_range(operational_mapped_field)
    if range_error:
        return [range_error]

    if thresholds["lowwarning"] < op_min and op_max < thresholds["highwarning"]:
        return []

    return [
        "{} operational range [{}, {}] is not within {} warning bounds ({}, {})".format(
            operational_mapped_field.source_attr,
            op_min,
            op_max,
            threshold_attr,
            thresholds["lowwarning"],
            thresholds["highwarning"],
        )
    ]


def has_dom_threshold_range_attributes(threshold_plan_by_port):
    """Return True when any primary port has configured threshold-range checks."""
    return any(
        plan.get("configured_by_attr") or plan.get("errors")
        for plan in threshold_plan_by_port.values()
    )


def _db_values_for_threshold_attr(attr_name, threshold_table_data, db_fields_by_name):
    """Return ``(db_values, errors)`` for one configured threshold attribute."""
    db_values = {}
    errors = []
    for field, mapped_field in db_fields_by_name.items():
        raw_value = threshold_table_data.get(field)
        actual_value = parse_numeric(raw_value)
        if actual_value is None or not math.isfinite(actual_value):
            errors.append(
                "{} threshold field {} missing/non-finite in STATE_DB (raw={!r})".format(
                    attr_name,
                    field,
                    raw_value,
                )
            )
            continue
        db_values[mapped_field.threshold_key] = actual_value
    return db_values, errors


def _compare_thresholds(attr_name, configured_values, db_values):
    """Return threshold value mismatch errors between configured and STATE_DB values."""
    errors = []
    for threshold_key in THRESHOLD_FIELD_SUFFIXES:
        expected_value = configured_values[threshold_key]
        actual_value = db_values[threshold_key]
        if abs(actual_value - expected_value) > THRESHOLD_VALUE_TOLERANCE:
            errors.append(
                "{} expected {}={}, got {} from STATE_DB".format(
                    attr_name,
                    threshold_key,
                    expected_value,
                    actual_value,
                )
            )
    return errors


def _expected_fields_from_threshold_plan(db_fields_by_threshold_attr):
    """Return a flat ``{db_field: mapped_field}`` view for failure headers."""
    return {
        field: db_fields_by_threshold_attr[attr_name][field]
        for attr_name in sorted(db_fields_by_threshold_attr)
        for field in sorted(db_fields_by_threshold_attr[attr_name])
    }


def _validate_threshold_attr(attr_name, attr_value, threshold_table_data, db_fields_by_name,
                             operational_mapped_field):
    """Return ``(errors, checked_fields, skipped_checks, skip_reasons)`` for one threshold attribute."""
    attr_errors = []
    skipped_checks = 0
    skip_reasons = []

    configured_values, threshold_errors = _parse_threshold_range(attr_name, attr_value)
    attr_errors.extend(threshold_errors)
    if threshold_errors:
        return attr_errors, 0, skipped_checks, skip_reasons

    if not db_fields_by_name:
        return ["{} has no expected STATE_DB threshold fields".format(attr_name)], 0, skipped_checks, skip_reasons

    db_values, db_value_errors = _db_values_for_threshold_attr(
        attr_name,
        threshold_table_data,
        db_fields_by_name,
    )
    attr_errors.extend(db_value_errors)
    if len(db_values) != len(THRESHOLD_FIELD_SUFFIXES):
        skipped_checks += 1
        skip_reasons.append("STATE_DB hierarchy skipped because STATE_DB threshold data is incomplete")
        if operational_mapped_field:
            skipped_checks += 1
            skip_reasons.append(
                "operational-range-within-warning skipped because STATE_DB threshold data is incomplete"
            )
        return attr_errors, 0, skipped_checks, skip_reasons

    attr_errors.extend(_compare_thresholds(attr_name, configured_values, db_values))

    hierarchy_error = _threshold_hierarchy_error(attr_name, db_values, "STATE_DB")
    if hierarchy_error:
        attr_errors.append(hierarchy_error)

    if operational_mapped_field:
        attr_errors.extend(
            _validate_operational_range_within_warning(
                attr_name,
                db_values,
                operational_mapped_field,
            )
        )
    else:
        skipped_checks += 1
        skip_reasons.append("no paired operational range configured")

    return attr_errors, len(db_fields_by_name) if not attr_errors else 0, skipped_checks, skip_reasons


def validate_dom_threshold_ranges(dom_primary_ports, threshold_table_by_port, threshold_plan_by_port):
    """Validate configured DOM threshold fields against STATE_DB threshold data."""
    failures = []
    checked_attr_count = 0
    checked_field_count = 0
    checked_port_count = 0
    skipped_check_count = 0

    for port in dom_primary_ports:
        threshold_table_data = threshold_table_by_port.get(port)
        threshold_plan = threshold_plan_by_port.get(port, {})
        configured_by_attr = threshold_plan.get("configured_by_attr", {})
        db_fields_by_threshold_attr = threshold_plan.get("db_fields_by_threshold_attr", {})
        expected_fields = _expected_fields_from_threshold_plan(db_fields_by_threshold_attr)
        operational_range_by_threshold_attr = threshold_plan.get("operational_range_by_threshold_attr", {})
        field_failures = list(threshold_plan.get("errors", []))
        has_threshold_checks = bool(configured_by_attr or field_failures)

        if has_threshold_checks:
            checked_port_count += 1

        if has_threshold_checks and threshold_table_data is None:
            field_failures.append(
                "could not read {} for port (namespace read failed)".format(STATE_DB_THRESHOLD_TABLE)
            )
            failures.append(
                format_dom_port_failure(
                    port,
                    [],
                    expected_fields,
                    field_failures,
                    field_label="expected threshold field(s)",
                    include_lanes=False,
                )
            )
            continue

        if has_threshold_checks and not threshold_table_data:
            field_failures.append(
                "no {} entry published for port".format(STATE_DB_THRESHOLD_TABLE)
            )
            failures.append(
                format_dom_port_failure(
                    port,
                    [],
                    expected_fields,
                    field_failures,
                    field_label="expected threshold field(s)",
                    include_lanes=False,
                )
            )
            continue

        for attr_name, attr_value in sorted(configured_by_attr.items()):
            db_fields_by_name = db_fields_by_threshold_attr.get(attr_name, {})
            operational_mapped_field = operational_range_by_threshold_attr.get(attr_name)
            attr_errors, checked_fields, skipped_checks, skip_reasons = _validate_threshold_attr(
                attr_name,
                attr_value,
                threshold_table_data,
                db_fields_by_name,
                operational_mapped_field,
            )
            skipped_check_count += skipped_checks
            if skipped_checks:
                logger.debug(
                    "DOM threshold reduced coverage %s %s: %d check(s) skipped (%s)",
                    port,
                    attr_name,
                    skipped_checks,
                    "; ".join(skip_reasons),
                )

            if attr_errors:
                field_failures.extend(attr_errors)
            else:
                checked_attr_count += 1
                checked_field_count += checked_fields
                logger.debug(
                    "DOM threshold PASS %s %s fields=%s operational_attr=%s",
                    port,
                    attr_name,
                    sorted(db_fields_by_name),
                    operational_mapped_field.source_attr if operational_mapped_field else "not-configured",
                )

        if field_failures:
            failures.append(
                format_dom_port_failure(
                    port,
                    [],
                    expected_fields,
                    field_failures,
                    field_label="expected threshold field(s)",
                    include_lanes=False,
                )
            )

    return failures, checked_attr_count, checked_field_count, checked_port_count, skipped_check_count


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
    """Confirm DOM data recovered after a disruptive operation. Polls until sensor
    entries are republished and configured sensor and threshold fields are readable,
    then validates sensor operational ranges.

    Returns a list of failure strings (empty on success).
    """
    dom_attrs = port_attributes_dict[ports[0]].get(DOM_ATTRIBUTES_KEY, {})
    if dom_attrs.get("data_max_age_min") is None:
        return [f"{ports[0]}: {DOM_ATTRIBUTES_KEY} is missing data_max_age_min"]

    plan_by_port = build_dom_sensor_plan(
        port_attributes_dict, ports, lport_to_first_subport_mapping,
    )
    threshold_plan_by_port = build_dom_threshold_plan(port_attributes_dict, ports)
    threshold_ports = [
        port for port in ports
        if threshold_plan_by_port[port].get("configured_by_attr")
        or threshold_plan_by_port[port].get("errors")
    ]
    if not threshold_ports:
        logger.info("DOM threshold recovery skipped: no *_threshold_range attributes configured")

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
        failures += port_failures

        if threshold_ports:
            threshold_table_by_port, threshold_read_errors = read_dom_threshold_data(duthost, threshold_ports)
            threshold_failures, _, _, _, _ = validate_dom_threshold_ranges(
                threshold_ports,
                threshold_table_by_port,
                threshold_plan_by_port,
            )
            failures += [
                f"DOM threshold read error: {read_error}"
                for read_error in threshold_read_errors
            ] + threshold_failures

        return failures

    failures = scenario_ops.poll_ports_recovered(
        _check_republished, dom_attrs["dom_info_recover_sec"],
        DOM_RECOVERY_POLL_INTERVAL_SEC,
        "DOM and threshold recovery" if threshold_ports else "DOM recovery",
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
