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
from tests.transceiver.common.db_helpers import (
    check_entry_freshness,
    get_config_db_port_table,
    get_state_db_table,
    parse_numeric,
    resolve_port_namespace,
)

logger = logging.getLogger(__name__)

STATE_DB_SENSOR_TABLE = "TRANSCEIVER_DOM_SENSOR"

OPERATIONAL_SUFFIX = "_operational_range"
LANE_NUM_PLACEHOLDER = "LANE_NUM"
MEDIA_LANE_MASK_KEY = "media_lane_mask"
DomMappedField = namedtuple("DomMappedField", ("source_attr", "attr_value"))

DOM_POLLING_ENABLED_VALUES = ("", "enabled")
DOM_POLLING_DISABLED_VALUE = "disabled"


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


DOM_FIELD_MAPPERS = (
    (OPERATIONAL_SUFFIX, _map_operational_attribute_to_fields),
)


def map_dom_attribute_to_fields(attr_name, attr_value, active_media_lanes):
    """Map one DOM attribute to current STATE_DB field metadata.

    The suffix dispatch is DOM-local: TC1/TC2 use the operational mapper today,
    and future threshold/consistency families can add their own mapper here
    without duplicating the LANE_NUM expansion path.
    """
    for suffix, mapper in DOM_FIELD_MAPPERS:
        if attr_name.endswith(suffix):
            return mapper(attr_name, attr_value, active_media_lanes)
    logger.debug("DOM attribute %s matched no field mapper; skipped", attr_name)
    return {}, []


def build_dom_availability_plan(port_attributes_dict, dom_primary_ports, lport_to_first_subport_mapping):
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


def format_dom_port_failure(port, active_lanes, expected_fields, field_failures):
    """Prefix a port's failure block with its expected shape."""
    return "{} [{} expected field(s), lanes {}]:\n  {}".format(
        port,
        len(expected_fields),
        active_lanes or "none",
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

        if not sensor_data:
            field_failures.append(
                "no {} entry published for port".format(STATE_DB_SENSOR_TABLE)
            )
            failures.append(format_dom_port_failure(port, active_lanes, expected_fields, field_failures))
            continue

        freshness_age_min = None
        if max_age_min is not None and (has_field_checks or include_freshness_only):
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


def read_dom_sensor_data(duthost, ports):
    """Return ``({port: {field: value}}, errors)`` for current DOM sensor data."""
    ports = list(ports)
    sensor_data = {port: {} for port in ports}
    errors = []
    ports_by_namespace = defaultdict(list)

    for port in ports:
        namespace = resolve_port_namespace(duthost, port)
        ports_by_namespace[namespace].append(port)

    for namespace, namespace_ports in ports_by_namespace.items():
        sensor_table, err = get_state_db_table(
            duthost,
            STATE_DB_SENSOR_TABLE,
            namespace=namespace,
        )
        if err:
            errors.append(
                "{} namespace {}: {}".format(
                    STATE_DB_SENSOR_TABLE,
                    namespace or "default",
                    err,
                )
            )
            continue

        for port in namespace_ports:
            sensor_data[port] = sensor_table.get(port, {}) or {}

    logger.debug(
        "Read DOM sensor data for %d port(s) across %d namespace(s); "
        "%d port(s) returned data",
        len(ports),
        len(ports_by_namespace),
        sum(1 for port_data in sensor_data.values() if port_data),
    )

    return sensor_data, errors


def check_dom_sensor_freshness(sensor_data, max_age_min, now_utc):
    """Return DOM freshness failures plus the parsed age for one sensor read."""
    return check_entry_freshness(
        sensor_data,
        max_age_min,
        now_utc,
        table_name=STATE_DB_SENSOR_TABLE,
    )
