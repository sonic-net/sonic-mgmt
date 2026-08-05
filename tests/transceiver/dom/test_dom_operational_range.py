import logging
import math

import pytest

from tests.transceiver.common.db_helpers import parse_numeric
from tests.transceiver.dom.dom_helpers import (
    build_dom_availability_plan,
    read_dom_sensor_data,
    validate_dom_plan_fields,
)

logger = logging.getLogger(__name__)


def _parse_operational_range(mapped_field):
    """Return ``(min_value, max_value, error)`` for one mapped DOM field."""
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


def _operational_range_field_check(field, mapped_field, raw_value):
    """Validate one DOM sensor value is finite and within its configured range."""
    min_value, max_value, range_error = _parse_operational_range(mapped_field)
    if range_error:
        return range_error

    numeric_value = parse_numeric(raw_value)
    if numeric_value is None or not math.isfinite(numeric_value):
        return "{} missing/non-finite operational value in STATE_DB (raw={!r})".format(
            field,
            raw_value,
        )

    if not min_value <= numeric_value <= max_value:
        return "{} value {} out of range [{}, {}]".format(
            field,
            numeric_value,
            min_value,
            max_value,
        )

    return None


def test_dom_sensor_operational_range_validation(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify configured DOM sensor values are fresh and within operational ranges."""
    sensor_by_port, sensor_read_errors = read_dom_sensor_data(duthost, dom_primary_ports)
    availability_plan_by_port = build_dom_availability_plan(
        port_attributes_dict,
        dom_primary_ports,
        lport_to_first_subport_mapping,
    )

    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in sensor_read_errors]
    range_failures, checked_field_count, checked_port_count = validate_dom_plan_fields(
        duthost,
        dom_primary_ports,
        sensor_by_port,
        availability_plan_by_port,
        _operational_range_field_check,
    )
    all_failures.extend(range_failures)

    if not (all_failures or checked_port_count):
        pytest.skip("No *_operational_range attributes configured for DOM operational range validation")

    if all_failures:
        pytest.fail("DOM operational range validation failures:\n" + "\n".join(all_failures))

    logger.info(
        "DOM operational range validation passed: %d field(s) across %d port(s)",
        checked_field_count,
        checked_port_count,
    )
