import logging
from datetime import datetime, timezone

import pytest

from tests.transceiver.dom.utils.dom_constants import (
    CONSISTENCY_VARIATION_RULES,
    DOM_CATEGORY_KEY,
    STATE_DB_SENSOR_KEY_TEMPLATE,
    STATE_DB_THRESHOLD_KEY_TEMPLATE,
)
from tests.transceiver.dom.utils.dom_field_mapper import (
    build_operational_field_range_map,
    get_lane_count,
    parse_consistency_variation_thresholds,
    port_sort_key,
    threshold_field_map,
)
from tests.transceiver.dom.utils.dom_state_db_reader import (
    parse_numeric,
    parse_update_time,
    read_state_db_hash,
)
from tests.transceiver.conftest import health_check_events
from tests.transceiver.common.health_checks import run_post_check, run_pre_check

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True, scope="session")
def _dom_session_prerequisites(presence_verified, gold_fw_verified, links_verified):
    """Opt DOM tests into the shared transceiver session prerequisite gates."""
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
        poll_count_raw = dom_attrs.get("consistency_check_poll_count")
        poll_interval_raw = dom_attrs.get("max_update_time_sec")
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


@pytest.fixture(autouse=True)
def dom_per_test_snapshots(
    request,
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
        },
        "post": {
            "captured_at": None,
            "sensor_by_port": {},
        },
    }

    snapshots["baseline"]["sensor_by_port"] = _read_dom_sensor_snapshots(dom_ports, dom_db_reader)
    _log_dom_snapshot("pre-test", snapshots["baseline"]["sensor_by_port"])
    pre_checks = _build_dom_freshness_checks(
        snapshots["baseline"]["sensor_by_port"],
        dom_port_context,
        parse_dom_update_time,
        snapshots["baseline"]["captured_at"],
    )
    _log_dom_freshness_checks("pre-test", pre_checks)
    run_pre_check(request, pre_checks, health_check_events)

    yield snapshots

    snapshots["post"]["captured_at"] = dom_now_utc()
    snapshots["post"]["sensor_by_port"] = _read_dom_sensor_snapshots(dom_ports, dom_db_reader)
    _log_dom_snapshot("post-test", snapshots["post"]["sensor_by_port"])
    post_checks = _build_dom_freshness_checks(
        snapshots["post"]["sensor_by_port"],
        dom_port_context,
        parse_dom_update_time,
        snapshots["post"]["captured_at"],
    )
    _log_dom_freshness_checks("post-test", post_checks)
    run_post_check(request, post_checks, health_check_events)


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
