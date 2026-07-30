"""Pure DOM helper functions.

Read/derive helpers use a ``(payload, errors)`` convention where ``errors`` is
a list of self-describing strings.  Callers aggregate those strings into the
final per-test failure message instead of raising immediately.
"""
import logging
from collections import defaultdict, namedtuple

from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    DOM_ATTRIBUTES_KEY,
)
from tests.transceiver.common.db_helpers import (
    check_entry_freshness,
    get_config_db_port_table,
    get_state_db_table,
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
    """Return a module's active media-lane indices for a primary subport.

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
    for subport in group:
        base_attrs = port_attributes_dict.get(subport, {}).get(BASE_ATTRIBUTES_KEY, {})
        mask = base_attrs.get(MEDIA_LANE_MASK_KEY)
        if mask is None:
            continue
        try:
            mask_union |= int(str(mask), 16)
        except (TypeError, ValueError):
            logger.debug("%s has unparsable %s %r", subport, MEDIA_LANE_MASK_KEY, mask)

    lanes = [bit + 1 for bit in range(mask_union.bit_length()) if mask_union & (1 << bit)]
    logger.debug(
        "%s active media lanes %s (breakout group %s, media_lane_mask union %#x)",
        primary_port,
        lanes,
        sorted(group),
        mask_union,
    )
    return lanes


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
    """Return ``{port: {"expected_fields": {field: DomMappedField}, "active_media_lanes": [...], "errors": [...], "max_age_min": value}}``.

    ``expected_fields`` is a ``{field: DomMappedField(source_attr, attr_value)}``
    map keyed in sorted field order: TC1 iterates the keys (presence/freshness),
    while range-based checks (TC2) read each field's ``attr_value`` (its
    ``{"min", "max"}`` operational range) without re-deriving the mapping.
    """
    plan_by_port = {}
    for port in dom_primary_ports:
        port_attrs = port_attributes_dict.get(port, {})
        dom_attrs = port_attrs.get(DOM_ATTRIBUTES_KEY, {})
        active_media_lanes = _active_media_lanes(
            port, port_attributes_dict, lport_to_first_subport_mapping
        )
        expected_fields = {}
        errors = []

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
