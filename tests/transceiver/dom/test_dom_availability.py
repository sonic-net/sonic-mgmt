import logging
import math

import pytest
from natsort import natsorted

from tests.transceiver.common.db_helpers import parse_numeric
from tests.transceiver.dom.dom_helpers import (
    build_dom_availability_plan,
    read_dom_sensor_data,
    validate_dom_plan_fields,
)

logger = logging.getLogger(__name__)


def _availability_field_check(field, _mapped_field, raw_value):
    """Validate one expected DOM field is present with a finite numeric value."""
    value = parse_numeric(raw_value)
    if value is None or not math.isfinite(value):
        return "expected DOM field {} has no valid finite value (got {!r})".format(
            field,
            raw_value,
        )
    return None


def _validate_dom_non_primary_ports(dom_non_primary_ports, sensor_by_port):
    """Validate non-primary breakout subports do not publish DOM sensor data."""
    failures = []
    checked_port_count = 0

    for port in dom_non_primary_ports:
        checked_port_count += 1
        sensor_data = sensor_by_port.get(port, {})
        if sensor_data:
            failures.append(
                "{}:\n  non-primary breakout subport unexpectedly has "
                "TRANSCEIVER_DOM_SENSOR data (fields: {})".format(
                    port, ", ".join(natsorted(sensor_data)) or "none"
                )
            )
            continue
        logger.debug(
            "DOM availability PASS %s: non-primary breakout subport has no TRANSCEIVER_DOM_SENSOR data",
            port,
        )

    return failures, checked_port_count


def test_dom_data_availability_verification(
    duthost,
    dom_primary_ports,
    dom_non_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify configured DOM sensor data is present and fresh in STATE_DB."""
    sensor_ports = natsorted(set(dom_primary_ports) | set(dom_non_primary_ports))
    sensor_by_port, sensor_read_errors = read_dom_sensor_data(duthost, sensor_ports)
    availability_plan_by_port = build_dom_availability_plan(
        port_attributes_dict,
        dom_primary_ports,
        lport_to_first_subport_mapping,
    )

    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in sensor_read_errors]
    primary_failures, checked_field_count, checked_primary_port_count = validate_dom_plan_fields(
        duthost,
        dom_primary_ports,
        sensor_by_port,
        availability_plan_by_port,
        _availability_field_check,
        include_freshness_only=True,
    )
    non_primary_failures, checked_non_primary_port_count = _validate_dom_non_primary_ports(
        dom_non_primary_ports,
        sensor_by_port,
    )
    all_failures.extend(primary_failures)
    all_failures.extend(non_primary_failures)

    if not (all_failures or checked_primary_port_count or checked_non_primary_port_count):
        pytest.skip("No DOM availability checks configured from DOM_ATTRIBUTES")

    if all_failures:
        pytest.fail("DOM availability validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM availability validation passed: %d expected field(s) across %d port(s)",
        checked_field_count,
        checked_primary_port_count,
    )

    if checked_non_primary_port_count:
        logger.info(
            "DOM availability validation passed: %d non-primary breakout subport(s) had no sensor data",
            checked_non_primary_port_count,
        )
