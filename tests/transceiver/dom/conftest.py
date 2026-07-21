import logging
import re
from datetime import datetime, timezone

import pytest

from tests.common.platform.interface_utils import get_dut_interfaces_status
from tests.transceiver.attribute_parser.attribute_keys import (
    BASE_ATTRIBUTES_KEY,
    DOM_ATTRIBUTES_KEY,
)
from tests.transceiver.common.db_helpers import hgetall_dict
from tests.transceiver.common.health_checks import run_post_check, run_pre_check
from tests.transceiver.conftest import health_check_events

logger = logging.getLogger(__name__)

STATE_DB = "STATE_DB"
CONFIG_DB = "CONFIG_DB"

STATE_DB_SENSOR_KEY_TEMPLATE = "TRANSCEIVER_DOM_SENSOR|{}"
CONFIG_DB_PORT_KEY_TEMPLATE = "PORT|{}"

OPERATIONAL_SUFFIX = "_operational_range"
LANE_NUM_PLACEHOLDER = "LANE_NUM"

DOM_POLLING_ENABLED_VALUES = ("", "enabled")
DOM_POLLING_DISABLED_VALUE = "disabled"
DOM_FLAP_COUNTER_FIELDS = ("flap_count", "flaps", "link_flap_count")
DOM_STABILITY_FIELDS = ("last_change", "last changed", "last_change_time")

_FLOAT_PATTERN = re.compile(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")
_PORT_SUFFIX_PATTERN = re.compile(r"^(.*?)(\d+)$")


def port_sort_key(port_name):
    """Return a natural sort key for SONiC interface names."""
    text = str(port_name)
    match = _PORT_SUFFIX_PATTERN.match(text)
    if not match:
        return (text, -1, text)
    return (match.group(1), int(match.group(2)), text)


def parse_numeric(value):
    """Parse the first floating-point number from a DOM DB value."""
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
    """Parse a DOM update timestamp into a timezone-aware UTC datetime."""
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
    normalized_values = (raw, " ".join(raw.split()))
    for text in normalized_values:
        for fmt in formats:
            try:
                return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def get_lane_count(base_attrs):
    """Return media lane count, falling back to host lane count."""
    media_lane_count = base_attrs.get("media_lane_count")
    if isinstance(media_lane_count, int) and media_lane_count > 0:
        return media_lane_count

    host_lane_count = base_attrs.get("host_lane_count")
    if isinstance(host_lane_count, int) and host_lane_count > 0:
        return host_lane_count

    return 0


def expand_operational_fields(attr_name, lane_count):
    """Expand one DOM operational attribute into STATE_DB sensor fields."""
    base_name = attr_name[:-len(OPERATIONAL_SUFFIX)]
    if LANE_NUM_PLACEHOLDER not in base_name:
        return [base_name]

    if lane_count <= 0:
        return []

    return [
        base_name.replace(LANE_NUM_PLACEHOLDER, str(lane))
        for lane in range(1, lane_count + 1)
    ]


def _port_namespace(duthost, port):
    """Return the ASIC namespace for a logical port, or None on single-ASIC."""
    try:
        asic = duthost.get_port_asic_instance(port)
        asic_index = getattr(asic, "asic_index", None)
        if asic_index is None:
            return None
        return duthost.get_namespace_from_asic_id(asic_index) or None
    except Exception as exc:
        logger.debug("Could not resolve ASIC namespace for %s: %s", port, exc)
        return None


def _dom_enabled_ports_from_attrs(port_attributes_dict):
    """Return ports with non-empty DOM attributes."""
    ports = []
    for port, attrs in port_attributes_dict.items():
        dom_attrs = attrs.get(DOM_ATTRIBUTES_KEY, {})
        if isinstance(dom_attrs, dict) and dom_attrs:
            ports.append(port)
    return sorted(ports, key=port_sort_key)


def _build_dom_polling_failures(duthost, port_attributes_dict):
    """Return DOM polling prerequisite failures for configured DOM ports."""
    failures = []
    for port in _dom_enabled_ports_from_attrs(port_attributes_dict):
        namespace = _port_namespace(duthost, port)
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


def _read_dom_interface_status(duthost, dom_ports):
    """Read current interface status for DOM ports."""
    try:
        status_by_port = duthost.get_interfaces_status()
    except Exception as exc:
        logger.debug("Failed to read 'show interfaces status': %s", exc)
        status_by_port = {}

    if not status_by_port:
        try:
            status_by_port = get_dut_interfaces_status(duthost)
        except Exception as exc:
            logger.warning("Failed to read interface status: %s", exc)
            status_by_port = {}

    return {
        port: status_by_port.get(port, {})
        for port in dom_ports
    }


def _build_dom_link_liveness_checks(status_by_port, phase):
    """Build checks that DOM ports are admin-up and oper-up."""
    checks = []
    for port, status in status_by_port.items():
        admin = status.get("admin", status.get("admin_state", status.get("admin_status", "missing")))
        oper = status.get("oper", status.get("oper_state", status.get("oper_status", "missing")))
        passed = str(admin).lower() == "up" and str(oper).lower() == "up"
        checks.append((
            "dom_link_liveness_{}_{}".format(phase, port),
            passed,
            "{} {} interface status admin={} oper={}".format(phase, port, admin, oper),
        ))
    return checks


def _extract_dom_stability_marker(status):
    """Extract a comparable flap counter or last-change marker from status."""
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
    """Build checks that link stability markers did not change during a test."""
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

        passed = post_value == baseline_value
        detail = "{} {} baseline={!r} post={!r}".format(
            port,
            baseline_field,
            baseline_value,
            post_value,
        )
        checks.append(("dom_link_stability_{}".format(port), passed, detail))

    return checks


def _read_dom_sensor_snapshots(dom_ports, dom_db_reader):
    """Read current DOM sensor STATE_DB hashes for all DOM ports."""
    read_sensor = dom_db_reader["sensor"]
    return {
        port: read_sensor(port)
        for port in dom_ports
    }


def _build_dom_freshness_checks(snapshot_by_port, dom_port_context, parse_dom_update_time, now_utc):
    """Build freshness check tuples for configured DOM ports."""
    checks = []
    for port, context in dom_port_context.items():
        dom_attrs = context["dom"]
        max_age_min = dom_attrs.get("data_max_age_min")
        if max_age_min is None:
            continue

        sensor_data = snapshot_by_port.get(port, {})
        check_name = "dom_data_freshness_{}".format(port)
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
            "{} last_update_time age_min={:.2f}, limit={}".format(
                port,
                age_minutes,
                max_age_min,
            ),
        ))

    return checks


@pytest.fixture(autouse=True, scope="session")
def _dom_session_prerequisites(
    duthost,
    port_attributes_dict,
    presence_verified,
    gold_fw_verified,
    links_verified,
):
    """Opt DOM tests into shared prerequisite gates and DOM polling checks."""
    dom_ports = _dom_enabled_ports_from_attrs(port_attributes_dict)
    if not dom_ports:
        pytest.skip("No ports with non-empty DOM_ATTRIBUTES found for DOM tests")

    failures = _build_dom_polling_failures(duthost, port_attributes_dict)
    if failures:
        pytest.skip("dom polling prerequisite failed - " + "; ".join(failures))

    logger.info("DOM session prerequisites passed for %d port(s)", len(dom_ports))


@pytest.fixture(scope="module")
def dom_port_context(port_attributes_dict):
    """Return per-port base and DOM attributes for configured DOM ports."""
    context = {}
    for port, attrs in port_attributes_dict.items():
        dom_attrs = attrs.get(DOM_ATTRIBUTES_KEY, {})
        if not isinstance(dom_attrs, dict) or not dom_attrs:
            continue
        context[port] = {
            "base": attrs.get(BASE_ATTRIBUTES_KEY, {}),
            "dom": dom_attrs,
        }

    if not context:
        pytest.skip("No ports with non-empty DOM_ATTRIBUTES found in port_attributes_dict")

    return context


@pytest.fixture(scope="module")
def dom_ports(dom_port_context):
    """Return DOM-enabled ports in deterministic interface order."""
    return sorted(dom_port_context.keys(), key=port_sort_key)


@pytest.fixture(scope="module")
def dom_availability_plan_by_port(dom_port_context):
    """Return expected TC1 STATE_DB sensor fields and configuration errors."""
    plan_by_port = {}
    for port, context in dom_port_context.items():
        dom_attrs = context["dom"]
        lane_count = get_lane_count(context["base"])
        expected_fields = set()
        errors = []

        for attr_name in sorted(dom_attrs):
            if not attr_name.endswith(OPERATIONAL_SUFFIX):
                continue
            if LANE_NUM_PLACEHOLDER in attr_name and lane_count <= 0:
                errors.append(
                    "{} uses {} but {} has no media_lane_count/host_lane_count "
                    "in {}".format(
                        attr_name,
                        LANE_NUM_PLACEHOLDER,
                        port,
                        BASE_ATTRIBUTES_KEY,
                    )
                )
                continue
            expected_fields.update(expand_operational_fields(attr_name, lane_count))

        plan_by_port[port] = {
            "expected_fields": sorted(expected_fields),
            "errors": errors,
        }

    return plan_by_port


@pytest.fixture(scope="module")
def dom_db_reader(duthost):
    """Return DOM STATE_DB reader helpers backed by common db_helpers."""
    def _read_sensor(port):
        namespace = _port_namespace(duthost, port)
        return hgetall_dict(
            duthost,
            STATE_DB,
            STATE_DB_SENSOR_KEY_TEMPLATE.format(port),
            namespace=namespace,
        )

    return {
        "sensor": _read_sensor,
    }


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
    """Capture DOM snapshots and run DOM-specific per-test checks."""
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
    snapshots["baseline"]["sensor_by_port"] = _read_dom_sensor_snapshots(dom_ports, dom_db_reader)
    pre_checks = _build_dom_link_liveness_checks(
        snapshots["baseline"]["interface_by_port"],
        "pre-test",
    )
    pre_checks += _build_dom_freshness_checks(
        snapshots["baseline"]["sensor_by_port"],
        dom_port_context,
        parse_dom_update_time,
        snapshots["baseline"]["captured_at"],
    )
    run_pre_check(request, pre_checks, health_check_events)

    yield snapshots

    snapshots["post"]["captured_at"] = dom_now_utc()
    snapshots["post"]["interface_by_port"] = _read_dom_interface_status(duthost, dom_ports)
    snapshots["post"]["sensor_by_port"] = _read_dom_sensor_snapshots(dom_ports, dom_db_reader)
    post_checks = _build_dom_link_liveness_checks(
        snapshots["post"]["interface_by_port"],
        "post-test",
    )
    post_checks += _build_dom_link_stability_checks(
        snapshots["baseline"]["interface_by_port"],
        snapshots["post"]["interface_by_port"],
    )
    post_checks += _build_dom_freshness_checks(
        snapshots["post"]["sensor_by_port"],
        dom_port_context,
        parse_dom_update_time,
        snapshots["post"]["captured_at"],
    )
    run_post_check(request, post_checks, health_check_events)


@pytest.fixture
def dom_sensor_by_port(dom_per_test_snapshots):
    """Return baseline TRANSCEIVER_DOM_SENSOR data captured for this test."""
    return dom_per_test_snapshots["baseline"]["sensor_by_port"]


@pytest.fixture(scope="module")
def parse_dom_numeric():
    """Return the shared DOM numeric parser."""
    return parse_numeric


@pytest.fixture(scope="module")
def parse_dom_update_time():
    """Return the shared DOM last_update_time parser."""
    return parse_update_time


@pytest.fixture(scope="module")
def dom_operational_suffix():
    """Return the DOM operational-range attribute suffix."""
    return OPERATIONAL_SUFFIX


@pytest.fixture(scope="module")
def dom_lane_num_placeholder():
    """Return the DOM lane placeholder used by lane-expanded attributes."""
    return LANE_NUM_PLACEHOLDER


@pytest.fixture(scope="module")
def dom_expand_operational_fields():
    """Return the DOM operational field expansion helper."""
    return expand_operational_fields


@pytest.fixture(scope="module")
def dom_get_lane_count():
    """Return the DOM lane-count helper."""
    return get_lane_count


@pytest.fixture(scope="module")
def dom_now_utc(duthost):
    """Return a callable UTC clock based on DUT time with local fallback."""
    def _now():
        result = duthost.command("date +%s", module_ignore_errors=True)
        if result.get("rc", 1) == 0:
            text = result.get("stdout", "").strip()
            if text.isdigit():
                return datetime.fromtimestamp(int(text), tz=timezone.utc)
        return datetime.now(tz=timezone.utc)

    return _now
