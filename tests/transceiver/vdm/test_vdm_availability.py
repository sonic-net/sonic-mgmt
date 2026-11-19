import logging

import pytest

from tests.transceiver.vdm.vdm_helpers import (
    build_vdm_field_plan, read_vdm_real_values, validate_vdm_availability,
)

logger = logging.getLogger(__name__)


def test_vdm_data_availability(
    duthost,
    vdm_primary_ports,
    vdm_non_primary_ports,
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Verify authored VDM fields are present, numeric, and fresh."""
    ports = vdm_primary_ports + vdm_non_primary_ports
    real_value_by_port, read_errors = read_vdm_real_values(duthost, ports)
    field_plan = build_vdm_field_plan(
        port_attributes_dict, vdm_primary_ports,
        lport_to_first_subport_mapping,
    )

    availability_failures, checked_fields = validate_vdm_availability(
        duthost, vdm_primary_ports, vdm_non_primary_ports,
        real_value_by_port, field_plan,
    )
    failures = read_errors + availability_failures

    if failures:
        pytest.fail("VDM availability failures:\n" + "\n".join(failures))

    logger.info(
        "VDM availability passed: %d field(s) across %d primary port(s); "
        "%d non-primary subport(s) had no duplicate row",
        checked_fields, len(vdm_primary_ports), len(vdm_non_primary_ports),
    )
