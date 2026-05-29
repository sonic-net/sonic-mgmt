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
from tests.transceiver.dom.utils.dom_health_check import (
    build_dom_post_test_report,
    collect_dom_health_snapshot,
    validate_dom_post_test_cleanup,
    validate_dom_pre_test_environment,
)


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


@pytest.fixture(scope="module")
def dom_sensor_by_port(duthost, dom_ports):
    """Read the TRANSCEIVER_DOM_SENSOR hash once for each DOM port.

    Args:
        duthost: DUT host fixture used to execute STATE_DB commands.
        dom_ports: DOM-enabled ports selected for the module.

    Returns:
        dict: Mapping from port name to ``TRANSCEIVER_DOM_SENSOR`` hash contents.
    """
    return {
        port: read_state_db_hash(duthost, STATE_DB_SENSOR_KEY_TEMPLATE.format(port))
        for port in dom_ports
    }


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


@pytest.fixture(scope="module")
def dom_health_baseline(duthost):
    """Capture the DOM health baseline before optional health guard checks.

    Args:
        duthost: DUT host fixture used to collect health baseline data.

    Returns:
        dict: Baseline core-file, syslog cursor, and xcvrd status data.
    """
    return collect_dom_health_snapshot(duthost)


@pytest.fixture(scope="module")
def dom_health_checker(duthost, dom_ports, dom_port_context, dom_health_baseline):
    """Return callable DOM health precheck, postcheck, and report helpers.

    Args:
        duthost: DUT host fixture used to run health checks.
        dom_ports: DOM-enabled ports selected for the module.
        dom_port_context: Per-port DOM context produced by ``dom_port_context``.
        dom_health_baseline: Baseline health snapshot captured before checks.

    Returns:
        dict: Health helper callables keyed by ``precheck``, ``postcheck``, and ``report``.
    """
    def _precheck(check_logs=True, check_lldp=True):
        """Run DOM pre-test system health and transceiver baseline checks.

        Args:
            check_logs: Whether to scan existing syslog DOM errors.
            check_lldp: Whether to validate LLDP neighbors when LLDP is enabled.

        Returns:
            dict: Pre-test validation errors and details.
        """
        return validate_dom_pre_test_environment(
            duthost,
            dom_ports,
            check_logs=check_logs,
            check_lldp=check_lldp,
        )

    def _postcheck(check_logs=True):
        """Run DOM post-test monitoring, service, core-file, and log checks.

        Args:
            check_logs: Whether to scan syslog errors introduced after the baseline.

        Returns:
            dict: Post-test cleanup validation errors and details.
        """
        return validate_dom_post_test_cleanup(
            duthost,
            dom_port_context,
            baseline=dom_health_baseline,
            check_logs=check_logs,
        )

    def _report(precheck_result=None, cleanup_result=None):
        """Build a compact summary from optional precheck and cleanup results.

        Args:
            precheck_result: Optional pre-test validation result.
            cleanup_result: Optional post-test cleanup validation result.

        Returns:
            dict: Summary report containing pass/fail state, counts, errors, and details.
        """
        return build_dom_post_test_report(precheck_result=precheck_result, cleanup_result=cleanup_result)

    return {
        "baseline": dom_health_baseline,
        "precheck": _precheck,
        "postcheck": _postcheck,
        "report": _report,
    }


@pytest.fixture(scope="module")
def dom_health_guard(dom_health_checker):
    """Fail a module when explicit DOM health precheck or postcheck guards fail.

    Args:
        dom_health_checker: Health helper fixture with precheck, postcheck, and report callables.

    Yields:
        dict: Pre-test health validation result for tests that opt into this guard.
    """
    precheck_result = dom_health_checker["precheck"]()
    if precheck_result["errors"]:
        pytest.fail("DOM pre-test health check failures:\n" + "\n".join(precheck_result["errors"]))

    yield precheck_result

    cleanup_result = dom_health_checker["postcheck"]()
    if cleanup_result["errors"]:
        report = dom_health_checker["report"](
            precheck_result=precheck_result,
            cleanup_result=cleanup_result,
        )
        pytest.fail(
            "DOM post-test cleanup/health failures:\n{}\nReport: {}".format(
                "\n".join(cleanup_result["errors"]),
                report,
            )
        )
