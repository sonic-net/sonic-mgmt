import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import DOM_ATTRIBUTES_KEY
from tests.transceiver.dom.dom_helpers import (
    OPERATIONAL_SUFFIX,
    build_dom_availability_plan,
    dom_field_in_operational_range,
    read_dom_sensor_data,
    validate_dom_plan_fields,
)

logger = logging.getLogger(__name__)


def _has_operational_range_attributes(port_attributes_dict, dom_primary_ports):
    """Return True when any primary port has configured operational-range checks."""
    for port in dom_primary_ports:
        dom_attrs = port_attributes_dict.get(port, {}).get(DOM_ATTRIBUTES_KEY, {})
        if any(attr_name.endswith(OPERATIONAL_SUFFIX) for attr_name in dom_attrs):
            return True
    return False


def test_dom_sensor_operational_range_validation(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify configured DOM sensor values are fresh and within operational ranges."""
    availability_plan_by_port = build_dom_availability_plan(
        port_attributes_dict,
        dom_primary_ports,
        lport_to_first_subport_mapping,
    )
    if not _has_operational_range_attributes(port_attributes_dict, dom_primary_ports):
        pytest.skip("No *_operational_range attributes configured for DOM operational range validation")

    sensor_by_port, sensor_read_errors = read_dom_sensor_data(duthost, dom_primary_ports)
    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in sensor_read_errors]
    range_failures, checked_field_count, checked_port_count = validate_dom_plan_fields(
        duthost,
        dom_primary_ports,
        sensor_by_port,
        availability_plan_by_port,
        dom_field_in_operational_range,
    )
    all_failures.extend(range_failures)

    if all_failures:
        pytest.fail("DOM operational range validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM operational range validation passed: %d field(s) across %d port(s)",
        checked_field_count,
        checked_port_count,
    )
