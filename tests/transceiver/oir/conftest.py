"""Physical OIR category conftest.

Opts the OIR test category into the cross-category session-level prerequisites
defined in ``tests/transceiver/conftest.py``.  Per the prerequisite matrix in
``docs/testplan/transceiver/test_plan.md``, OIR consumes ``presence_verified``
and ``links_verified`` (every module under test must start seated and linked
up); ``gold_fw_verified`` is intentionally NOT requested because OIR behaviour
is firmware-version independent.
"""
import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    PHYSICAL_OIR_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.oir import oir_helpers

logger = logging.getLogger(__name__)

_DUT_SCOPED_OIR_ATTRIBUTES = (
    "ports_under_test",
    "oir_method",
    "physical_oir_timeout_min",
    "simultaneous_oir",
    "physical_oir_stress_iteration",
    "hot_swap_ports_under_test",
)


@pytest.fixture(autouse=True, scope="package")
def _oir_session_prerequisites(presence_verified, links_verified):
    """Autouse wrapper pulling in the session gates consumed by OIR tests."""
    return


@pytest.fixture(scope="session")
def physical_oir_attributes(port_attributes_dict):
    """Resolved ``PHYSICAL_OIR_ATTRIBUTES`` shard for each logical port."""
    attrs_by_port = {
        port: attrs[PHYSICAL_OIR_ATTRIBUTES_KEY]
        for port, attrs in port_attributes_dict.items()
        if attrs.get(PHYSICAL_OIR_ATTRIBUTES_KEY)
    }
    if not attrs_by_port:
        pytest.skip("No PHYSICAL_OIR_ATTRIBUTES configured for this DUT")
    return attrs_by_port


@pytest.fixture(scope="session")
def physical_oir_dut_attributes(physical_oir_attributes):
    """DUT/platform-scoped physical OIR settings, identical across port shards."""
    reference_port, reference_attrs = next(iter(physical_oir_attributes.items()))
    missing = [key for key in _DUT_SCOPED_OIR_ATTRIBUTES if key not in reference_attrs]
    if missing:
        pytest.fail(
            f"PHYSICAL_OIR_ATTRIBUTES for {reference_port} missing DUT-scoped setting(s): {missing}"
        )

    dut_attrs = {key: reference_attrs[key] for key in _DUT_SCOPED_OIR_ATTRIBUTES}
    inconsistent = {
        port: [key for key, value in dut_attrs.items() if attrs.get(key) != value]
        for port, attrs in physical_oir_attributes.items()
    }
    inconsistent = {port: keys for port, keys in inconsistent.items() if keys}
    if inconsistent:
        pytest.fail(f"DUT-scoped PHYSICAL_OIR_ATTRIBUTES differ by port: {inconsistent}")
    return dut_attrs


@pytest.fixture(scope="session")
def oir_system_attributes(port_attributes_dict):
    """Representative ``SYSTEM_ATTRIBUTES`` shard, for the port settle budgets."""
    return next(iter(port_attributes_dict.values()))[SYSTEM_ATTRIBUTES_KEY]


@pytest.fixture(autouse=True, scope="package")
def _skip_unimplemented_oir_method(physical_oir_dut_attributes):
    """Only the operator-driven ``manual`` method is implemented today."""
    method = physical_oir_dut_attributes["oir_method"]
    if method != oir_helpers.OIR_METHOD_MANUAL:
        pytest.skip(f"oir_method '{method}' is not implemented yet")


@pytest.fixture(scope="session")
def oir_pport_to_lports(physical_oir_dut_attributes, get_lport_to_pport_mapping):
    """``{physical index: [logical ports]}`` for the configured ``ports_under_test``."""
    pports = physical_oir_dut_attributes["ports_under_test"]
    if not pports:
        pytest.skip("physical OIR 'ports_under_test' is empty")
    mapping = oir_helpers.resolve_pport_to_lports(get_lport_to_pport_mapping, pports)
    unmapped = [pport for pport, lports in mapping.items() if not lports]
    if unmapped:
        pytest.fail(f"ports_under_test physical port(s) {unmapped} have no logical port on this DUT")
    logger.info("Physical OIR ports under test: %s", mapping)
    return mapping


@pytest.fixture(autouse=True)
def _restore_transceivers(request, duthost, physical_oir_dut_attributes, oir_pport_to_lports):
    """Re-seat any module a test left out of its cage before the next test runs."""
    yield

    presence = oir_helpers.get_pport_presence_all_asics(duthost)
    absent = [pport for pport in oir_pport_to_lports if not presence.get(pport)]
    if not absent:
        return
    logger.warning("Physical OIR teardown: re-seating %d module(s) left removed", len(absent))
    failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_dut_attributes, absent, present=True,
        action="INSERT the original transceiver(s) - test teardown",
    )
    if failures:
        logger.warning("Physical OIR teardown could not restore: %s", "; ".join(failures))
