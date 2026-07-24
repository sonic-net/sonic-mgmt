import logging
from datetime import datetime, timezone

import pytest
from natsort import natsorted

from tests.transceiver.dom.dom_helpers import (
    build_dom_availability_plan,
    build_dom_freshness_result,
    build_dom_polling_failures,
    dom_enabled_ports_from_attrs,
    dom_non_primary_ports_from_attrs,
    read_dom_sensor_snapshots,
)

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def dom_ports(port_attributes_dict, lport_to_first_subport_mapping):
    """Return DOM-capable primary subports in deterministic interface order."""
    ports = dom_enabled_ports_from_attrs(
        port_attributes_dict,
        lport_to_first_subport_mapping,
    )
    if not ports:
        pytest.skip("No primary subports with non-empty DOM_ATTRIBUTES found for DOM tests")
    return ports


@pytest.fixture(scope="session")
def dom_non_primary_ports(port_attributes_dict, lport_to_first_subport_mapping):
    """Return DOM-capable non-primary breakout subports."""
    return dom_non_primary_ports_from_attrs(
        port_attributes_dict,
        lport_to_first_subport_mapping,
    )


@pytest.fixture(autouse=True, scope="session")
def _dom_session_prerequisites(
    duthost,
    dom_ports,
    presence_verified,
    gold_fw_verified,
    links_verified,
):
    """Opt DOM tests into shared prerequisite gates and DOM polling checks."""
    failures = build_dom_polling_failures(duthost, dom_ports)
    if failures:
        pytest.skip("dom polling prerequisite failed - " + "; ".join(failures))

    logger.info("DOM session prerequisites passed for %d port(s)", len(dom_ports))


@pytest.fixture(scope="module")
def dom_availability_plan_by_port(port_attributes_dict, dom_ports):
    """Return expected TC1 STATE_DB sensor fields and configuration errors."""
    return build_dom_availability_plan(port_attributes_dict, dom_ports)


@pytest.fixture(autouse=True)
def dom_per_test_snapshots(
    duthost,
    dom_ports,
    dom_non_primary_ports,
):
    """Capture baseline DOM sensor snapshots for test-body validation."""
    sensor_ports = natsorted(set(dom_ports) | set(dom_non_primary_ports))
    sensor_by_port, sensor_read_errors = read_dom_sensor_snapshots(duthost, sensor_ports)

    return {
        "baseline": {
            "sensor_read_errors": sensor_read_errors,
            "sensor_by_port": {
                port: sensor_by_port.get(port, {})
                for port in dom_ports
            },
            "non_primary_sensor_by_port": {
                port: sensor_by_port.get(port, {})
                for port in dom_non_primary_ports
            },
        },
    }


@pytest.fixture
def dom_sensor_by_port(dom_per_test_snapshots):
    """Return baseline TRANSCEIVER_DOM_SENSOR data for primary DOM ports."""
    return dom_per_test_snapshots["baseline"]["sensor_by_port"]


@pytest.fixture
def dom_non_primary_sensor_by_port(dom_per_test_snapshots):
    """Return baseline TRANSCEIVER_DOM_SENSOR data for non-primary DOM subports."""
    return dom_per_test_snapshots["baseline"]["non_primary_sensor_by_port"]


@pytest.fixture
def dom_sensor_read_errors(dom_per_test_snapshots):
    """Return bulk STATE_DB read errors captured with the DOM sensor snapshot."""
    return dom_per_test_snapshots["baseline"]["sensor_read_errors"]


@pytest.fixture(scope="module")
def dom_freshness_result():
    """Return a callable that validates DOM freshness and reports age."""
    return build_dom_freshness_result


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
