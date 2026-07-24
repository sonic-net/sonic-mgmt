import logging
from collections import defaultdict

from natsort import natsorted

from tests.common.platform.interface_utils import is_first_subport
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    DOM_ATTRIBUTES_KEY,
)
from tests.transceiver.common.db_helpers import (
    build_state_db_freshness_result,
    get_state_db_table,
    hgetall_dict,
    resolve_port_namespace,
)

logger = logging.getLogger(__name__)

STATE_DB_SENSOR_TABLE = "TRANSCEIVER_DOM_SENSOR"
CONFIG_DB = "CONFIG_DB"
CONFIG_DB_PORT_KEY_TEMPLATE = "PORT|{}"

OPERATIONAL_SUFFIX = "_operational_range"
LANE_NUM_PLACEHOLDER = "LANE_NUM"

DOM_POLLING_ENABLED_VALUES = ("", "enabled")
DOM_POLLING_DISABLED_VALUE = "disabled"


def _has_dom_attributes(attrs):
    dom_attrs = attrs.get(DOM_ATTRIBUTES_KEY, {})
    return isinstance(dom_attrs, dict) and bool(dom_attrs)


def dom_enabled_ports_from_attrs(port_attributes_dict, lport_to_first_subport_mapping):
    """Return DOM-capable primary subports in deterministic interface order."""
    return natsorted(
        port
        for port, attrs in port_attributes_dict.items()
        if _has_dom_attributes(attrs) and is_first_subport(port, lport_to_first_subport_mapping)
    )


def dom_non_primary_ports_from_attrs(port_attributes_dict, lport_to_first_subport_mapping):
    """Return DOM-capable non-primary breakout subports."""
    return natsorted(
        port
        for port, attrs in port_attributes_dict.items()
        if _has_dom_attributes(attrs) and not is_first_subport(port, lport_to_first_subport_mapping)
    )


def expand_operational_fields(attr_name, media_lane_count):
    """Expand one DOM operational attribute into STATE_DB sensor fields."""
    base_name = attr_name[:-len(OPERATIONAL_SUFFIX)]
    if LANE_NUM_PLACEHOLDER not in base_name:
        return [base_name]

    if media_lane_count <= 0:
        return []

    return [
        base_name.replace(LANE_NUM_PLACEHOLDER, str(lane))
        for lane in range(1, media_lane_count + 1)
    ]


def build_dom_availability_plan(port_attributes_dict, dom_ports):
    """Return expected TC1 STATE_DB sensor fields and configuration errors."""
    plan_by_port = {}
    for port in dom_ports:
        port_attrs = port_attributes_dict.get(port, {})
        dom_attrs = port_attrs.get(DOM_ATTRIBUTES_KEY, {})
        base_attrs = port_attrs.get(BASE_ATTRIBUTES_KEY, {})
        media_lane_count = base_attrs.get("media_lane_count")
        expected_fields = set()
        errors = []

        for attr_name in sorted(dom_attrs):
            if not attr_name.endswith(OPERATIONAL_SUFFIX):
                continue
            if LANE_NUM_PLACEHOLDER in attr_name:
                if not isinstance(media_lane_count, int) or media_lane_count <= 0:
                    errors.append(
                        "{} uses {} but {} has no valid media_lane_count in {}".format(
                            attr_name,
                            LANE_NUM_PLACEHOLDER,
                            port,
                            BASE_ATTRIBUTES_KEY,
                        )
                    )
                    continue
                expected_fields.update(expand_operational_fields(attr_name, media_lane_count))
                continue
            expected_fields.update(expand_operational_fields(attr_name, 0))

        plan_by_port[port] = {
            "expected_fields": sorted(expected_fields),
            "errors": errors,
        }

    return plan_by_port


def build_dom_polling_failures(duthost, dom_ports):
    """Return DOM polling prerequisite failures for configured DOM ports."""
    failures = []
    for port in dom_ports:
        namespace = resolve_port_namespace(duthost, port)
        port_config = hgetall_dict(
            duthost,
            CONFIG_DB,
            CONFIG_DB_PORT_KEY_TEMPLATE.format(port),
            namespace=namespace,
        )
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


def read_dom_sensor_snapshots(duthost, ports):
    """Bulk-read current DOM sensor STATE_DB hashes for selected ports."""
    snapshots = {port: {} for port in ports}
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
            snapshots[port] = sensor_table.get(port, {}) or {}

    return snapshots, errors


def build_dom_freshness_result(sensor_data, max_age_min, now_utc):
    """Return DOM freshness failures plus the parsed age for one snapshot."""
    return build_state_db_freshness_result(
        sensor_data,
        max_age_min,
        now_utc,
        table_name=STATE_DB_SENSOR_TABLE,
    )
