import logging
import ast
import json
import re
from datetime import datetime, timezone

import pytest

from tests.common.platform.interface_utils import get_dut_interfaces_status
from tests.transceiver.conftest import health_check_events
from tests.transceiver.common.health_checks import run_post_check, run_pre_check

logger = logging.getLogger(__name__)

_FLOAT_PATTERN = re.compile(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")


def parse_hgetall_output(stdout_lines):
    """Parse Redis HGETALL output from list or serialized-dict formats.

    Args:
        stdout_lines: Command output lines returned by ``sonic-db-cli`` or ``redis-cli``.

    Returns:
        dict: Parsed hash field/value pairs, or an empty dict when output is unusable.
    """
    lines = [line.strip() for line in stdout_lines if str(line).strip()]
    if not lines:
        return {}

    if len(lines) == 1:
        raw = lines[0]
        if raw in ("{}", "[]"):
            return {}

        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(raw)
            except Exception:
                continue
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}

    if len(lines) % 2 != 0:
        logger.warning("Unexpected HGETALL output line count=%d lines=%s", len(lines), lines)
        return {}

    parsed = {}
    for idx in range(0, len(lines), 2):
        parsed[lines[idx]] = lines[idx + 1]
    return parsed


def read_db_hash(duthost, db_name, key, namespace=None, redis_db_index=None):
    """Read one DB hash with multi-ASIC namespace lookup support.

    Args:
        duthost: DUT host fixture used to execute database commands.
        db_name: SONiC logical DB name, such as ``STATE_DB`` or ``CONFIG_DB``.
        key: DB hash key to read.
        namespace: Optional ASIC namespace to query before generic lookup.
        redis_db_index: Optional raw Redis DB index fallback.

    Returns:
        dict: Parsed hash field/value pairs, or an empty dict if the key cannot be read.
    """
    commands = []

    if namespace:
        commands.append('sonic-db-cli -n {} {} HGETALL "{}"'.format(namespace, db_name, key))
    elif getattr(duthost, "is_multi_asic", False):
        for asic in getattr(duthost, "frontend_asics", []):
            commands.append('sonic-db-cli -n {} {} HGETALL "{}"'.format(asic.namespace, db_name, key))

    commands.append('sonic-db-cli {} HGETALL "{}"'.format(db_name, key))
    if redis_db_index is not None:
        commands.append('redis-cli --raw -n {} HGETALL "{}"'.format(redis_db_index, key))

    for cmd in commands:
        result = duthost.command(cmd, module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            continue
        parsed = parse_hgetall_output(result.get("stdout_lines", []))
        if parsed:
            return parsed

    return {}


def read_state_db_hash(duthost, key, namespace=None):
    """Read one STATE_DB hash.

    Args:
        duthost: DUT host fixture used to execute database commands.
        key: STATE_DB hash key to read.
        namespace: Optional ASIC namespace to query before generic lookup.

    Returns:
        dict: Parsed hash field/value pairs, or an empty dict if the key cannot be read.
    """
    return read_db_hash(duthost, "STATE_DB", key, namespace=namespace, redis_db_index=6)


def read_config_db_hash(duthost, key, namespace=None):
    """Read one CONFIG_DB hash.

    Args:
        duthost: DUT host fixture used to execute database commands.
        key: CONFIG_DB hash key to read.
        namespace: Optional ASIC namespace to query before generic lookup.

    Returns:
        dict: Parsed hash field/value pairs, or an empty dict if the key cannot be read.
    """
    return read_db_hash(duthost, "CONFIG_DB", key, namespace=namespace)


def parse_numeric(value):
    """Parse the first floating-point number from a DOM DB value.

    Args:
        value: Raw DB value, potentially containing units or non-numeric text.

    Returns:
        float | None: Parsed number, or ``None`` when no valid number is present.
    """
    if value is None:
        return None

    text = str(value).strip()
    if not text or text.upper() in ("N/A", "NA", "NONE"):
        return None

    match = _FLOAT_PATTERN.search(text)
    if not match:
        return None

    try:
        return float(match.group(0))
    except ValueError:
        return None


def parse_update_time(value):
    """Parse a DOM update timestamp into a timezone-aware UTC datetime.

    Args:
        value: Raw timestamp value.

    Returns:
        datetime | None: Parsed UTC timestamp, or ``None`` when parsing fails.
    """
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    numeric = parse_numeric(raw)
    if numeric is not None and raw.replace(".", "", 1).isdigit():
        epoch_sec = numeric / 1000.0 if numeric > 1e12 else numeric
        try:
            return datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            pass

    iso_text = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso_text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%a %b %d %H:%M:%S %Y",
    )
    for fmt in formats:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    normalized = " ".join(raw.split())
    if normalized != raw:
        for fmt in formats:
            try:
                return datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


DOM_CATEGORY_KEY = "DOM_ATTRIBUTES"

STATE_DB_SENSOR_KEY_TEMPLATE = "TRANSCEIVER_DOM_SENSOR|{}"
STATE_DB_THRESHOLD_KEY_TEMPLATE = "TRANSCEIVER_DOM_THRESHOLD|{}"
CONFIG_DB_PORT_KEY_TEMPLATE = "PORT|{}"

OPERATIONAL_SUFFIX = "_operational_range"
THRESHOLD_SUFFIX = "_threshold_range"
LANE_NUM_PLACEHOLDER = "LANE_NUM"

THRESHOLD_FIELD_SUFFIXES = ("lowalarm", "lowwarning", "highwarning", "highalarm")
THRESHOLD_PREFIX_OVERRIDES = {
    "temperature": "temp",
    "voltage": "vcc",
    "tx_power": "txpower",
    "rx_power": "rxpower",
    "tx_bias": "txbias",
    "laser_temperature": "lasertemp",
}
VALUE_TOLERANCE = 0.01

THRESHOLD_TO_OPERATIONAL_ATTR_CANDIDATES = {
    "tx_bias": ("txLANE_NUMbias_operational_range", "tx_bias_operational_range"),
    "tx_power": ("txLANE_NUMpower_operational_range", "tx_power_operational_range"),
    "rx_power": ("rxLANE_NUMpower_operational_range", "rx_power_operational_range"),
}

DEFAULT_MAX_UPDATE_TIME_SEC = 60
DEFAULT_CONSISTENCY_CHECK_POLL_COUNT = 3

CONSISTENCY_VARIATION_THRESHOLD_ATTRS = (
    "tx_power_consistency_variation_threshold",
    "rx_power_consistency_variation_threshold",
    "tx_bias_consistency_variation_threshold",
    "laser_temperature_consistency_variation_threshold",
    "temperature_consistency_variation_threshold",
    "voltage_consistency_variation_threshold",
)
DEFAULT_CONSISTENCY_VARIATION_THRESHOLDS = {
    "tx_power_consistency_variation_threshold": 3.0,
    "rx_power_consistency_variation_threshold": 3.0,
    "tx_bias_consistency_variation_threshold": 10.0,
    "laser_temperature_consistency_variation_threshold": 3.0,
    "temperature_consistency_variation_threshold": 3.0,
    "voltage_consistency_variation_threshold": 0.1,
}

# operational range attribute -> (threshold attribute, mode)
# mode:
# - abs: absolute delta check
# - pct: percentage-of-previous-value delta check
CONSISTENCY_VARIATION_RULES = {
    "txLANE_NUMpower_operational_range": ("tx_power_consistency_variation_threshold", "abs"),
    "rxLANE_NUMpower_operational_range": ("rx_power_consistency_variation_threshold", "abs"),
    "txLANE_NUMbias_operational_range": ("tx_bias_consistency_variation_threshold", "pct"),
    "laser_temperature_operational_range": ("laser_temperature_consistency_variation_threshold", "abs"),
    "temperature_operational_range": ("temperature_consistency_variation_threshold", "abs"),
    "voltage_operational_range": ("voltage_consistency_variation_threshold", "abs"),
}

DOM_POLLING_ENABLED_VALUES = ("enabled", "")
DOM_POLLING_DISABLED = "disabled"
DOM_FLAP_COUNTER_FIELDS = ("flap_count", "flaps", "link_flap_count")
DOM_STABILITY_FIELDS = ("last_change", "last changed", "last_change_time")

_PORT_SUFFIX_PATTERN = re.compile(r"^(.*?)(\d+)$")


def port_sort_key(port_name):
    """Return a natural sort key for SONiC interface names.

    Args:
        port_name: Interface name such as ``Ethernet0``.

    Returns:
        tuple: Sort key that orders matching interface prefixes by numeric suffix.
    """
    text = str(port_name)
    match = _PORT_SUFFIX_PATTERN.match(text)
    if not match:
        return (text, -1, text)
    return (match.group(1), int(match.group(2)), text)


def get_lane_count(base_attrs):
    """Return the configured media lane count, falling back to host lanes.

    Args:
        base_attrs: Base transceiver attributes for one port.

    Returns:
        int: Positive media or host lane count when configured, otherwise ``0``.
    """
    media_lane_count = base_attrs.get("media_lane_count")
    if isinstance(media_lane_count, int) and media_lane_count > 0:
        return media_lane_count

    host_lane_count = base_attrs.get("host_lane_count")
    if isinstance(host_lane_count, int) and host_lane_count > 0:
        return host_lane_count

    return 0


def expand_operational_fields(attr_name, lane_count):
    """Expand a DOM operational attribute into expected STATE_DB sensor fields.

    Args:
        attr_name: DOM attribute name ending in ``_operational_range``.
        lane_count: Number of lanes used to expand lane placeholders.

    Returns:
        list: Expected ``TRANSCEIVER_DOM_SENSOR`` field names for the attribute.
    """
    base_name = attr_name[: -len(OPERATIONAL_SUFFIX)]
    if LANE_NUM_PLACEHOLDER not in base_name:
        return [base_name]

    if lane_count <= 0:
        return []

    return [base_name.replace(LANE_NUM_PLACEHOLDER, str(lane)) for lane in range(1, lane_count + 1)]


def build_operational_field_range_map(dom_attrs, lane_count):
    """Build a sensor field to operational range map from resolved DOM attributes.

    Args:
        dom_attrs: Resolved ``DOM_ATTRIBUTES`` for one port.
        lane_count: Number of lanes used to expand lane-scoped attributes.

    Returns:
        dict: Mapping from sensor field name to source attribute, min, and max metadata.
    """
    field_map = {}
    for attr_name, attr_value in dom_attrs.items():
        if not attr_name.endswith(OPERATIONAL_SUFFIX) or not isinstance(attr_value, dict):
            continue
        for field in expand_operational_fields(attr_name, lane_count):
            field_map[field] = {
                "attr_name": attr_name,
                "min": attr_value.get("min"),
                "max": attr_value.get("max"),
            }
    return field_map


def build_threshold_field_map(attr_name):
    """Build logical threshold keys to STATE_DB threshold field names.

    Args:
        attr_name: DOM attribute name ending in ``_threshold_range``.

    Returns:
        dict: Mapping from logical threshold suffix to STATE_DB threshold field name.
    """
    base_name = attr_name[: -len(THRESHOLD_SUFFIX)]
    prefix = THRESHOLD_PREFIX_OVERRIDES.get(base_name, base_name.replace("_", ""))
    return {suffix: "{}{}".format(prefix, suffix) for suffix in THRESHOLD_FIELD_SUFFIXES}


def threshold_field_map(attr_name):
    """Return threshold STATE_DB field mappings for threshold attributes only.

    Args:
        attr_name: Candidate DOM attribute name.

    Returns:
        dict: Threshold field map for threshold attributes, or an empty dict otherwise.
    """
    if not attr_name.endswith(THRESHOLD_SUFFIX):
        return {}
    return build_threshold_field_map(attr_name)


def operational_attr_candidates(base_name):
    """Return operational range attribute names related to a threshold base name.

    Args:
        base_name: Threshold attribute base name without ``_threshold_range``.

    Returns:
        tuple: Candidate operational range attribute names for the threshold base.
    """
    default = ("{}_operational_range".format(base_name),)
    return THRESHOLD_TO_OPERATIONAL_ATTR_CANDIDATES.get(base_name, default)


def parse_consistency_variation_thresholds(dom_attrs):
    """Parse consistency variation thresholds from resolved DOM attributes.

    Args:
        dom_attrs: Resolved ``DOM_ATTRIBUTES`` for one port.

    Returns:
        dict: Parsed threshold values plus separate ``errors`` and defaulted attrs.
    """
    thresholds = {}
    errors = []
    defaulted = []
    for attr_name in CONSISTENCY_VARIATION_THRESHOLD_ATTRS:
        raw_value = dom_attrs.get(attr_name)
        if raw_value is None:
            thresholds[attr_name] = DEFAULT_CONSISTENCY_VARIATION_THRESHOLDS[attr_name]
            defaulted.append(attr_name)
            continue

        numeric = parse_numeric(raw_value)
        if numeric is None:
            errors.append("{} is non-numeric in DOM_ATTRIBUTES (raw={!r})".format(attr_name, raw_value))
            continue

        if numeric < 0:
            errors.append("{} must be >= 0, got {}".format(attr_name, numeric))
            continue

        thresholds[attr_name] = float(numeric)

    return {
        "thresholds": thresholds,
        "errors": errors,
        "defaulted": defaulted,
    }


def _dom_enabled_ports_from_attrs(port_attributes_dict):
    """Return ports with non-empty DOM attributes.

    Args:
        port_attributes_dict: Resolved transceiver attribute data keyed by port name.

    Returns:
        list: DOM-enabled port names sorted in interface order.
    """
    ports = []
    for port, attrs in port_attributes_dict.items():
        dom_attrs = attrs.get(DOM_CATEGORY_KEY, {})
        if isinstance(dom_attrs, dict) and dom_attrs:
            ports.append(port)
    return sorted(ports, key=port_sort_key)


def _build_dom_polling_checks(duthost, port_attributes_dict):
    """Build session prerequisite checks for CONFIG_DB DOM polling state.

    Args:
        duthost: DUT host fixture used to execute DB commands.
        port_attributes_dict: Resolved transceiver attribute data keyed by port name.

    Returns:
        list: ``(name, passed, detail)`` tuples for DOM polling state.
    """
    checks = []
    for port in _dom_enabled_ports_from_attrs(port_attributes_dict):
        port_config = read_config_db_hash(duthost, CONFIG_DB_PORT_KEY_TEMPLATE.format(port))
        raw_value = port_config.get("dom_polling")
        normalized = "" if raw_value is None else str(raw_value).strip().lower()
        check_name = "dom_polling_enabled_{}".format(port)

        if normalized in DOM_POLLING_ENABLED_VALUES:
            detail = "{} dom_polling={}".format(port, raw_value if raw_value is not None else "<default-enabled>")
            checks.append((check_name, True, detail))
        elif normalized == DOM_POLLING_DISABLED:
            checks.append((check_name, False, "{} dom_polling is disabled".format(port)))
        else:
            checks.append((check_name, False, "{} dom_polling has unexpected value {!r}".format(port, raw_value)))

    return checks


def _read_dom_interface_status(duthost, dom_ports):
    """Read current interface status for DOM ports.

    Args:
        duthost: DUT host fixture.
        dom_ports: DOM-enabled ports selected for validation.

    Returns:
        dict: Per-port interface status dictionaries.
    """
    try:
        status_by_port = duthost.get_interfaces_status()
    except Exception as exc:
        logger.debug("Failed to read 'show interfaces status': %s", exc)
        status_by_port = {}

    if not status_by_port:
        try:
            status_by_port = get_dut_interfaces_status(duthost)
        except Exception as exc:
            logger.warning("Failed to read interface description status: %s", exc)
            status_by_port = {}

    return {port: status_by_port.get(port, {}) for port in dom_ports}


def _build_dom_link_liveness_checks(status_by_port, phase):
    """Build per-test checks that DOM ports remain admin-up and oper-up.

    Args:
        status_by_port: Per-port interface status dictionaries.
        phase: Human-readable phase label for details.

    Returns:
        list: ``(name, passed, detail)`` tuples for interface liveness.
    """
    checks = []
    for port, status in status_by_port.items():
        admin = status.get("admin", status.get("admin_state", "missing"))
        oper = status.get("oper", status.get("oper_state", "missing"))
        passed = str(admin).lower() == "up" and str(oper).lower() == "up"
        checks.append((
            "dom_link_liveness_{}_{}".format(phase, port),
            passed,
            "{} {} interface status admin={} oper={}".format(phase, port, admin, oper),
        ))
    return checks


def _extract_dom_stability_marker(status):
    """Extract a comparable flap counter or last-change marker from status.

    Args:
        status: One interface status dictionary.

    Returns:
        tuple | None: ``("counter", name, value)`` or ``("stable", name, value)``.
    """
    for field in DOM_FLAP_COUNTER_FIELDS:
        if field not in status:
            continue
        numeric = parse_numeric(status.get(field))
        if numeric is not None:
            return ("counter", field, numeric)

    for field in DOM_STABILITY_FIELDS:
        if field in status:
            return ("stable", field, str(status.get(field)))

    return None


def _build_dom_link_stability_checks(baseline_status_by_port, post_status_by_port):
    """Build checks that compare optional link-flap markers across a test.

    Args:
        baseline_status_by_port: Pre-test interface status dictionaries.
        post_status_by_port: Post-test interface status dictionaries.

    Returns:
        list: ``(name, passed, detail)`` tuples for stability markers.
    """
    checks = []
    for port, baseline_status in baseline_status_by_port.items():
        baseline_marker = _extract_dom_stability_marker(baseline_status)
        post_marker = _extract_dom_stability_marker(post_status_by_port.get(port, {}))
        if baseline_marker is None or post_marker is None:
            continue

        baseline_kind, baseline_field, baseline_value = baseline_marker
        post_kind, post_field, post_value = post_marker
        if baseline_kind != post_kind or baseline_field != post_field:
            continue

        if baseline_kind == "counter":
            passed = post_value <= baseline_value
            detail = "{} {} baseline={} post={}".format(port, baseline_field, baseline_value, post_value)
        else:
            passed = post_value == baseline_value
            detail = "{} {} baseline={!r} post={!r}".format(port, baseline_field, baseline_value, post_value)

        checks.append(("dom_link_stability_{}".format(port), passed, detail))

    return checks


@pytest.fixture(autouse=True, scope="session")
def _dom_session_prerequisites(
    duthost,
    port_attributes_dict,
    presence_verified,
    gold_fw_verified,
    links_verified,
):
    """Opt DOM tests into shared and DOM-specific session prerequisite gates."""
    polling_checks = _build_dom_polling_checks(duthost, port_attributes_dict)
    if not polling_checks:
        pytest.skip("No ports with non-empty DOM_ATTRIBUTES found for DOM polling prerequisite")

    failures = [detail for _name, passed, detail in polling_checks if not passed]
    if failures:
        pytest.skip("dom polling prerequisite failed - " + "; ".join(failures))

    logger.info("DOM polling prerequisite PASSED for %d port(s)", len(polling_checks))
    return


@pytest.fixture(scope="module")
def dom_port_context(port_attributes_dict):
    """Return per-port base and DOM attributes for ports with configured DOM data.

    Args:
        port_attributes_dict: Resolved transceiver attribute data keyed by port name.

    Returns:
        dict: Per-port context containing ``BASE_ATTRIBUTES`` and ``DOM_ATTRIBUTES``.
    """
    context = {}
    for port, attrs in port_attributes_dict.items():
        dom_attrs = attrs.get(DOM_CATEGORY_KEY, {})
        if not isinstance(dom_attrs, dict) or not dom_attrs:
            continue
        context[port] = {
            "base": attrs.get("BASE_ATTRIBUTES", {}),
            "dom": dom_attrs,
        }

    if not context:
        pytest.skip("No ports with non-empty DOM_ATTRIBUTES found in port_attributes_dict")

    return context


@pytest.fixture(scope="module")
def dom_ports(dom_port_context):
    """Return DOM-enabled port names in deterministic interface order.

    Args:
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.

    Returns:
        list: DOM-enabled port names sorted with natural interface ordering.
    """
    return sorted(dom_port_context.keys(), key=port_sort_key)


@pytest.fixture(scope="module")
def dom_operational_suffix():
    """Return the DOM operational range attribute suffix."""
    return OPERATIONAL_SUFFIX


@pytest.fixture(scope="module")
def dom_lane_num_placeholder():
    """Return the lane placeholder used by lane-scoped DOM attributes."""
    return LANE_NUM_PLACEHOLDER


@pytest.fixture(scope="module")
def dom_expand_operational_fields():
    """Return the DOM operational field expansion helper."""
    return expand_operational_fields


@pytest.fixture(scope="module")
def dom_get_lane_count():
    """Return the DOM lane count resolver."""
    return get_lane_count


@pytest.fixture(scope="module")
def dom_threshold_suffix():
    """Return the DOM threshold range attribute suffix."""
    return THRESHOLD_SUFFIX


@pytest.fixture(scope="module")
def dom_threshold_field_suffixes():
    """Return logical threshold suffixes in hierarchy order."""
    return THRESHOLD_FIELD_SUFFIXES


@pytest.fixture(scope="module")
def dom_threshold_value_tolerance():
    """Return numeric tolerance used when comparing threshold values."""
    return VALUE_TOLERANCE


@pytest.fixture(scope="module")
def dom_operational_attr_candidates():
    """Return helper that maps a threshold base name to operational attributes."""
    return operational_attr_candidates


@pytest.fixture(scope="module")
def dom_operational_fields_by_port(dom_port_context):
    """Return expected operational STATE_DB sensor fields for each DOM port.

    Args:
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.

    Returns:
        dict: Mapping from port name to sorted expected ``TRANSCEIVER_DOM_SENSOR`` fields.
    """
    fields_by_port = {}
    for port, context in dom_port_context.items():
        dom_attrs = context["dom"]
        lane_count = get_lane_count(context["base"])
        field_range_map = build_operational_field_range_map(dom_attrs, lane_count)
        fields_by_port[port] = sorted(field_range_map.keys())
    return fields_by_port


@pytest.fixture(scope="module")
def dom_operational_ranges_by_port(dom_port_context):
    """Return per-port operational range metadata keyed by STATE_DB sensor field.

    Args:
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.

    Returns:
        dict: Mapping from port name to expected sensor fields and configured range metadata.
    """
    ranges_by_port = {}
    for port, context in dom_port_context.items():
        dom_attrs = context["dom"]
        lane_count = get_lane_count(context["base"])
        ranges_by_port[port] = build_operational_field_range_map(dom_attrs, lane_count)
    return ranges_by_port


@pytest.fixture(scope="module")
def dom_consistency_variation_rules():
    """Return the configured operational-attribute to variation-threshold mapping.

    Returns:
        dict: Mapping from operational range attribute names to variation threshold rules.
    """
    return dict(CONSISTENCY_VARIATION_RULES)


@pytest.fixture(scope="module")
def dom_consistency_variation_thresholds_by_port(dom_port_context):
    """Return parsed consistency variation threshold metadata for each DOM port.

    Args:
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.

    Returns:
        dict: Mapping from port name to parsed optional variation thresholds and parse errors.
    """
    thresholds_by_port = {}
    for port, context in dom_port_context.items():
        thresholds_by_port[port] = parse_consistency_variation_thresholds(context["dom"])
    return thresholds_by_port


@pytest.fixture(scope="module")
def dom_consistency_validation_plan_by_port(
    dom_port_context,
    dom_operational_fields_by_port,
    dom_operational_ranges_by_port,
    dom_consistency_variation_thresholds_by_port,
):
    """Return the static consistency validation plan for each DOM port.

    Args:
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.
        dom_operational_fields_by_port: Expected DOM sensor fields keyed by port.
        dom_operational_ranges_by_port: Operational range metadata keyed by port and sensor field.
        dom_consistency_variation_thresholds_by_port: Parsed optional variation thresholds keyed by port.

    Returns:
        dict: Per-port consistency validation plan containing resolved static configuration.
    """
    plan_by_port = {}
    for port, context in dom_port_context.items():
        dom_attrs = context["dom"]
        variation_config = dom_consistency_variation_thresholds_by_port.get(port, {})
        poll_count_raw = dom_attrs.get(
            "consistency_check_poll_count",
            DEFAULT_CONSISTENCY_CHECK_POLL_COUNT,
        )
        poll_interval_raw = dom_attrs.get(
            "max_update_time_sec",
            DEFAULT_MAX_UPDATE_TIME_SEC,
        )
        errors = list(variation_config.get("errors", []))

        poll_count = None
        try:
            poll_count = int(poll_count_raw)
        except (TypeError, ValueError):
            errors.append("invalid consistency_check_poll_count={} in DOM_ATTRIBUTES".format(poll_count_raw))
        if poll_count is not None and poll_count < 2:
            errors.append("invalid consistency_check_poll_count={} (must be >= 2)".format(poll_count))

        poll_interval_sec = None
        try:
            poll_interval_sec = int(poll_interval_raw)
        except (TypeError, ValueError):
            errors.append("invalid max_update_time_sec={} in DOM_ATTRIBUTES".format(poll_interval_raw))
        if poll_interval_sec is not None and poll_interval_sec < 1:
            errors.append("invalid max_update_time_sec={} (must be >= 1)".format(poll_interval_sec))

        plan_by_port[port] = {
            "dom_attrs": dom_attrs,
            "expected_fields": dom_operational_fields_by_port.get(port, []),
            "field_ranges": dom_operational_ranges_by_port.get(port, {}),
            "variation_thresholds": variation_config.get("thresholds", {}),
            "poll_count": poll_count,
            "poll_interval_sec": poll_interval_sec,
            "errors": errors,
        }

    return plan_by_port


@pytest.fixture(scope="module")
def dom_threshold_fields_by_port(dom_port_context):
    """Return threshold attribute to STATE_DB field mappings for each DOM port.

    Args:
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.

    Returns:
        dict: Mapping from port name to threshold attribute and STATE_DB field mappings.
    """
    fields_by_port = {}
    for port, context in dom_port_context.items():
        dom_attrs = context["dom"]
        attr_to_fields = {}
        for attr_name, attr_value in dom_attrs.items():
            if not isinstance(attr_value, dict):
                continue
            field_map = threshold_field_map(attr_name)
            if field_map:
                attr_to_fields[attr_name] = field_map
        fields_by_port[port] = attr_to_fields
    return fields_by_port


@pytest.fixture
def dom_sensor_by_port(dom_per_test_snapshots):
    """Return the per-test baseline TRANSCEIVER_DOM_SENSOR data.

    Args:
        dom_per_test_snapshots: DOM per-test baseline and post-test snapshots.

    Returns:
        dict: Mapping from port name to ``TRANSCEIVER_DOM_SENSOR`` hash contents.
    """
    return dom_per_test_snapshots["baseline"]["sensor_by_port"]


@pytest.fixture(scope="module")
def dom_threshold_by_port(duthost, dom_ports):
    """Read the TRANSCEIVER_DOM_THRESHOLD hash once for each DOM port.

    Args:
        duthost: DUT host fixture used to execute STATE_DB commands.
        dom_ports: DOM-enabled ports selected for the module.

    Returns:
        dict: Mapping from port name to ``TRANSCEIVER_DOM_THRESHOLD`` hash contents.
    """
    return {
        port: read_state_db_hash(duthost, STATE_DB_THRESHOLD_KEY_TEMPLATE.format(port))
        for port in dom_ports
    }


@pytest.fixture(scope="module")
def dom_db_reader(duthost):
    """Return callable STATE_DB readers for repeated DOM sensor and threshold reads.

    Args:
        duthost: DUT host fixture used to execute STATE_DB commands.

    Returns:
        dict: Callable readers keyed by ``sensor`` and ``threshold``.
    """
    def _read_sensor(port):
        """Read current TRANSCEIVER_DOM_SENSOR data for one port.

        Args:
            port: Interface name whose DOM sensor data should be read.

        Returns:
            dict: Current ``TRANSCEIVER_DOM_SENSOR`` hash contents for the port.
        """
        return read_state_db_hash(duthost, STATE_DB_SENSOR_KEY_TEMPLATE.format(port))

    def _read_threshold(port):
        """Read current TRANSCEIVER_DOM_THRESHOLD data for one port.

        Args:
            port: Interface name whose DOM threshold data should be read.

        Returns:
            dict: Current ``TRANSCEIVER_DOM_THRESHOLD`` hash contents for the port.
        """
        return read_state_db_hash(duthost, STATE_DB_THRESHOLD_KEY_TEMPLATE.format(port))

    return {
        "sensor": _read_sensor,
        "threshold": _read_threshold,
    }


def _read_dom_sensor_snapshots(dom_ports, dom_db_reader):
    """Read current DOM sensor STATE_DB hashes for all DOM ports.

    Args:
        dom_ports: DOM-enabled port names selected for validation.
        dom_db_reader: Callable STATE_DB readers from ``dom_db_reader`` fixture.

    Returns:
        dict: Mapping from port name to current ``TRANSCEIVER_DOM_SENSOR`` data.
    """
    read_sensor = dom_db_reader["sensor"]
    return {
        port: read_sensor(port)
        for port in dom_ports
    }


def _build_dom_freshness_checks(snapshot_by_port, dom_port_context, parse_dom_update_time, now_utc):
    """Build freshness check tuples for configured DOM ports.

    Only ports with ``DOM_ATTRIBUTES.data_max_age_min`` configured participate
    in freshness validation. Ports without that attribute still get baseline
    and post-test snapshots, but no freshness pass/fail decision is made here.

    Args:
        snapshot_by_port: Mapping from port name to DOM sensor data.
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.
        parse_dom_update_time: Parser for DOM ``last_update_time`` values.
        now_utc: UTC timestamp used as the freshness reference.

    Returns:
        list: ``(name, passed, detail)`` tuples for common health-check dispatch.
    """
    checks = []
    for port, context in dom_port_context.items():
        dom_attrs = context["dom"]
        max_age_min = dom_attrs.get("data_max_age_min")
        if max_age_min is None:
            continue

        check_name = "dom_data_freshness_{}".format(port)
        sensor_data = snapshot_by_port.get(port, {})
        if not sensor_data:
            checks.append((
                check_name,
                False,
                "{} missing TRANSCEIVER_DOM_SENSOR data".format(port),
            ))
            continue

        parsed_time = parse_dom_update_time(sensor_data.get("last_update_time"))
        if parsed_time is None:
            checks.append((
                check_name,
                False,
                "{} last_update_time missing or unparsable".format(port),
            ))
            continue

        try:
            max_age = float(max_age_min)
        except (TypeError, ValueError):
            checks.append((
                check_name,
                False,
                "{} invalid data_max_age_min={!r}".format(port, max_age_min),
            ))
            continue

        age_minutes = (now_utc - parsed_time).total_seconds() / 60.0
        checks.append((
            check_name,
            age_minutes <= max_age,
            "{} last_update_time age_min={:.2f}, limit={}".format(port, age_minutes, max_age_min),
        ))

    return checks


def _log_dom_snapshot(phase, snapshot_by_port):
    """Log a compact summary of captured DOM sensor snapshots.

    Args:
        phase: Human-readable phase name, such as ``"pre-test"``.
        snapshot_by_port: Mapping from port name to DOM sensor data.
    """
    ports = sorted(snapshot_by_port)
    logger.info(
        "DOM %s snapshot captured for %d port(s): %s",
        phase,
        len(ports),
        ", ".join(ports) if ports else "none",
    )
    for port in ports:
        logger.debug(
            "DOM %s snapshot %s fields: %s",
            phase,
            port,
            ", ".join(sorted(snapshot_by_port[port].keys())) if snapshot_by_port[port] else "none",
        )


def _log_dom_freshness_checks(phase, checks):
    """Log DOM freshness check results on the success path as well as failure path.

    Args:
        phase: Human-readable phase name, such as ``"pre-test"``.
        checks: ``(name, passed, detail)`` tuples built by
            ``_build_dom_freshness_checks``.
    """
    if not checks:
        logger.info("DOM %s freshness checks skipped: no ports configured data_max_age_min", phase)
        return

    passed_count = sum(1 for _name, passed, _detail in checks if passed)
    logger.info("DOM %s freshness checks passed: %d/%d", phase, passed_count, len(checks))
    for name, passed, detail in checks:
        log_fn = logger.info if passed else logger.warning
        log_fn("DOM %s freshness %s %s: %s", phase, "PASS" if passed else "FAIL", name, detail)


def _log_dom_link_checks(phase, checks, check_label="link"):
    """Log DOM interface liveness and stability check results.

    Args:
        phase: Human-readable phase name, such as ``"pre-test"``.
        checks: ``(name, passed, detail)`` tuples built by DOM link helpers.
        check_label: Human-readable check category, such as ``"link"`` or
            ``"link stability"``.
    """
    if not checks:
        logger.info("DOM %s %s checks skipped: no comparable interface status fields", phase, check_label)
        return

    passed_count = sum(1 for _name, passed, _detail in checks if passed)
    logger.info("DOM %s %s checks passed: %d/%d", phase, check_label, passed_count, len(checks))
    for name, passed, detail in checks:
        log_fn = logger.info if passed else logger.warning
        log_fn("DOM %s %s %s %s: %s", phase, check_label, "PASS" if passed else "FAIL", name, detail)


def _log_dom_interface_status(phase, status_by_port):
    """Log interface liveness snapshots captured around DOM tests.

    Args:
        phase: Human-readable phase name, such as ``"pre-test"``.
        status_by_port: Mapping from port name to interface status dictionaries.
    """
    logger.info("DOM %s interface status captured for %d port(s)", phase, len(status_by_port))
    for port in sorted(status_by_port):
        status = status_by_port[port]
        admin = status.get("admin", status.get("admin_state", "missing"))
        oper = status.get("oper", status.get("oper_state", "missing"))
        logger.debug("DOM %s interface %s admin=%s oper=%s fields=%s", phase, port, admin, oper, sorted(status))


@pytest.fixture(autouse=True)
def dom_per_test_snapshots(
    request,
    duthost,
    dom_ports,
    dom_port_context,
    dom_db_reader,
    parse_dom_update_time,
    dom_now_utc,
):
    """Capture DOM sensor snapshots and validate data freshness around each DOM test.

    The fixture is autouse for every test under ``tests/transceiver/dom`` and
    can also be requested directly by tests that need the pre-test baseline.
    It intentionally covers only DOM data readiness; process/core health is
    handled by the top-level transceiver health-check fixture.

    Yields:
        dict: ``{"baseline": ..., "post": ...}`` where each phase contains
        ``captured_at`` and ``sensor_by_port`` keys.
    """
    snapshots = {
        "baseline": {
            "captured_at": dom_now_utc(),
            "sensor_by_port": {},
            "interface_by_port": {},
        },
        "post": {
            "captured_at": None,
            "sensor_by_port": {},
            "interface_by_port": {},
        },
    }

    snapshots["baseline"]["interface_by_port"] = _read_dom_interface_status(duthost, dom_ports)
    _log_dom_interface_status("pre-test", snapshots["baseline"]["interface_by_port"])
    snapshots["baseline"]["sensor_by_port"] = _read_dom_sensor_snapshots(dom_ports, dom_db_reader)
    _log_dom_snapshot("pre-test", snapshots["baseline"]["sensor_by_port"])
    pre_link_checks = _build_dom_link_liveness_checks(snapshots["baseline"]["interface_by_port"], "pre-test")
    pre_freshness_checks = _build_dom_freshness_checks(
        snapshots["baseline"]["sensor_by_port"],
        dom_port_context,
        parse_dom_update_time,
        snapshots["baseline"]["captured_at"],
    )
    _log_dom_link_checks("pre-test", pre_link_checks)
    _log_dom_freshness_checks("pre-test", pre_freshness_checks)
    run_pre_check(request, pre_link_checks + pre_freshness_checks, health_check_events)

    yield snapshots

    snapshots["post"]["captured_at"] = dom_now_utc()
    snapshots["post"]["interface_by_port"] = _read_dom_interface_status(duthost, dom_ports)
    _log_dom_interface_status("post-test", snapshots["post"]["interface_by_port"])
    snapshots["post"]["sensor_by_port"] = _read_dom_sensor_snapshots(dom_ports, dom_db_reader)
    _log_dom_snapshot("post-test", snapshots["post"]["sensor_by_port"])
    post_link_checks = _build_dom_link_liveness_checks(snapshots["post"]["interface_by_port"], "post-test")
    post_stability_checks = _build_dom_link_stability_checks(
        snapshots["baseline"]["interface_by_port"],
        snapshots["post"]["interface_by_port"],
    )
    post_freshness_checks = _build_dom_freshness_checks(
        snapshots["post"]["sensor_by_port"],
        dom_port_context,
        parse_dom_update_time,
        snapshots["post"]["captured_at"],
    )
    _log_dom_link_checks("post-test", post_link_checks)
    _log_dom_link_checks("post-test", post_stability_checks, check_label="link stability")
    _log_dom_freshness_checks("post-test", post_freshness_checks)
    run_post_check(
        request,
        post_link_checks + post_stability_checks + post_freshness_checks,
        health_check_events,
    )


@pytest.fixture(scope="module")
def parse_dom_numeric():
    """Return the shared DOM numeric parser.

    Returns:
        callable: Parser that extracts a floating-point value from DOM text.
    """
    return parse_numeric


@pytest.fixture(scope="module")
def parse_dom_update_time():
    """Return the shared DOM last_update_time parser.

    Returns:
        callable: Parser that converts DOM update timestamps to UTC datetimes.
    """
    return parse_update_time


@pytest.fixture(scope="module")
def dom_now_utc(duthost):
    """Return a callable UTC clock based on DUT time with local fallback.

    Args:
        duthost: DUT host fixture used to read device time.

    Returns:
        callable: Function returning the current UTC datetime.
    """
    def _now():
        """Return the current UTC time, preferring the DUT clock.

        Returns:
            datetime: Current UTC timestamp from the DUT, or local UTC time as fallback.
        """
        result = duthost.command("date +%s", module_ignore_errors=True)
        if result.get("rc", 1) == 0:
            text = result.get("stdout", "").strip()
            if text.isdigit():
                return datetime.fromtimestamp(int(text), tz=timezone.utc)
        return datetime.now(tz=timezone.utc)
    return _now
