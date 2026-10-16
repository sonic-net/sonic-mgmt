import logging

import pytest

from tests.transceiver.vdm.vdm_helpers import (
    build_vdm_field_plan, build_vdm_threshold_plan, read_vdm_thresholds, validate_vdm_thresholds,
)

logger = logging.getLogger(__name__)


def test_vdm_threshold_validation(
    duthost, vdm_primary_ports, port_attributes_dict, lport_to_first_subport_mapping,
):
    """Verify all authored fields threshold hierarchy and optional exact values."""
    field_plan = build_vdm_field_plan(
        port_attributes_dict, vdm_primary_ports, lport_to_first_subport_mapping,
    )
    threshold_plan = build_vdm_threshold_plan(port_attributes_dict, vdm_primary_ports, field_plan)
    rows, read_errors = read_vdm_thresholds(duthost, vdm_primary_ports)
    threshold_failures, checked_fields, equality_checks = validate_vdm_thresholds(
        vdm_primary_ports, rows, threshold_plan,
    )
    failures = read_errors + threshold_failures
    if failures:
        pytest.fail("VDM threshold validation failures:\n" + "\n".join(failures))
    if not equality_checks:
        logger.warning("VDM threshold equality is not covered: no optional _threshold_range values authored")
    logger.info(
        "VDM threshold validation passed: %d field(s), %d exact equality check(s) across %d primary port(s)",
        checked_fields, equality_checks, len(vdm_primary_ports),
    )
