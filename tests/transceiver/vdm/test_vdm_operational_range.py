import logging

import pytest

from tests.transceiver.vdm.vdm_helpers import (
    build_vdm_field_plan, read_vdm_real_values, validate_vdm_operational_ranges,
)

logger = logging.getLogger(__name__)


def test_vdm_operational_range(
    duthost, vdm_primary_ports, port_attributes_dict, lport_to_first_subport_mapping,
):
    """Verify authored VDM fields are fresh and within inclusive operational ranges."""
    field_plan = build_vdm_field_plan(
        port_attributes_dict, vdm_primary_ports, lport_to_first_subport_mapping,
    )
    rows, read_errors = read_vdm_real_values(duthost, vdm_primary_ports)
    range_failures, checked_fields = validate_vdm_operational_ranges(
        duthost, vdm_primary_ports, rows, field_plan,
    )
    failures = read_errors + range_failures
    if failures:
        pytest.fail("VDM operational range failures:\n" + "\n".join(failures))
    logger.info(
        "VDM operational range validation passed: %d field(s) across %d primary port(s)",
        checked_fields, len(vdm_primary_ports),
    )
