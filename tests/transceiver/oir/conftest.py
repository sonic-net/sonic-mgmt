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

from tests.common.platform.interface_utils import get_pport_presence_data
from tests.transceiver.attribute_parser.attribute_keys import PHYSICAL_OIR_ATTRIBUTES_KEY
from tests.transceiver.common.port_selectors import select_attribute_ports
from tests.transceiver.oir import oir_helpers

logger = logging.getLogger(__name__)

_DUT_SCOPED_OIR_ATTRIBUTES = (
    "ports_under_test",
    "oir_method",
    "physical_oir_timeout_min",
    "simultaneous_oir",
    "physical_oir_stress_iteration",
)


@pytest.fixture(autouse=True, scope="package")
def _oir_session_prerequisites(presence_verified, links_verified):
    """Autouse wrapper pulling in the session gates consumed by OIR tests."""
    return


@pytest.fixture(scope="session")
def physical_oir_attribute_ports(port_attributes_dict):
    """Select ports with physical OIR attributes and validate DUT-scoped settings.

    Per-transceiver settings stay in ``port_attributes_dict`` and are read from
    each port's ``PHYSICAL_OIR_ATTRIBUTES`` shard by the tests. The selected
    logical port names are returned only after the DUT-scoped settings have
    been validated across every configured port.
    """
    ports = select_attribute_ports(
        port_attributes_dict,
        PHYSICAL_OIR_ATTRIBUTES_KEY,
    ).primary_ports
    if not ports:
        pytest.skip("No PHYSICAL_OIR_ATTRIBUTES configured for this DUT")

    reference_port = ports[0]
    reference_attrs = port_attributes_dict[reference_port][PHYSICAL_OIR_ATTRIBUTES_KEY]
    missing = [key for key in _DUT_SCOPED_OIR_ATTRIBUTES if key not in reference_attrs]
    if missing:
        pytest.fail(
            f"PHYSICAL_OIR_ATTRIBUTES for {reference_port} missing DUT-scoped setting(s): {missing}"
        )

    inconsistent = {}
    for port in ports:
        category_attrs = port_attributes_dict[port][PHYSICAL_OIR_ATTRIBUTES_KEY]
        differing_keys = [
            key
            for key in _DUT_SCOPED_OIR_ATTRIBUTES
            if category_attrs.get(key) != reference_attrs[key]
        ]
        if differing_keys:
            inconsistent[port] = differing_keys
    if inconsistent:
        pytest.fail(f"DUT-scoped PHYSICAL_OIR_ATTRIBUTES differ by port: {inconsistent}")
    return ports


@pytest.fixture(autouse=True, scope="package")
def _skip_unimplemented_oir_method(port_attributes_dict, physical_oir_attribute_ports):
    """Only the operator-driven ``manual`` method is implemented today."""
    method = port_attributes_dict[
        physical_oir_attribute_ports[0]
    ][PHYSICAL_OIR_ATTRIBUTES_KEY]["oir_method"]
    if method != oir_helpers.OIR_METHOD_MANUAL:
        pytest.skip(f"oir_method '{method}' is not implemented yet")


@pytest.fixture(scope="session")
def oir_pport_to_lports(
    port_attributes_dict,
    physical_oir_attribute_ports,
    get_lport_to_pport_mapping,
):
    """``{physical index: [logical ports]}`` for the configured ``ports_under_test``."""
    pports = port_attributes_dict[
        physical_oir_attribute_ports[0]
    ][PHYSICAL_OIR_ATTRIBUTES_KEY]["ports_under_test"]
    if not pports:
        pytest.skip("physical OIR 'ports_under_test' is empty")

    mapping = oir_helpers.resolve_pport_to_lports(get_lport_to_pport_mapping, pports)
    unmapped = [pport for pport, lports in mapping.items() if not lports]
    if unmapped:
        pytest.fail(f"ports_under_test physical port(s) {unmapped} have no logical port on this DUT")

    attribute_ports = set(physical_oir_attribute_ports)
    unconfigured = [
        port
        for lports in mapping.values()
        for port in lports
        if port not in attribute_ports
    ]
    if unconfigured:
        pytest.fail(f"port(s) under test without PHYSICAL_OIR_ATTRIBUTES: {unconfigured}")

    logger.info("Physical OIR ports under test: %s", mapping)
    return mapping


@pytest.fixture(autouse=True)
def _restore_transceivers(
    request,
    duthost,
    port_attributes_dict,
    physical_oir_attribute_ports,
    oir_pport_to_lports,
):
    """Re-seat any module a test left out of its cage before the next test runs."""
    yield

    presence = get_pport_presence_data(duthost)
    missing = [pport for pport in oir_pport_to_lports if pport not in presence]
    if missing:
        pytest.exit(
            "Physical OIR teardown could not determine transceiver presence: "
            f"physical port(s) {missing} missing from CLI output",
            returncode=1,
        )

    absent = [pport for pport in oir_pport_to_lports if not presence[pport]]
    if not absent:
        return
    logger.warning("Physical OIR teardown: re-seating %d module(s) left removed", len(absent))
    oir_attrs = port_attributes_dict[
        physical_oir_attribute_ports[0]
    ][PHYSICAL_OIR_ATTRIBUTES_KEY]
    failures = oir_helpers.perform_oir(
        request, duthost, oir_attrs, absent, present=True,
        action="INSERT the original transceiver(s) - test teardown",
    )
    if failures:
        # The session-scoped presence/link gates do not re-run, so continuing
        # would test a switch with modules still out of their cages.
        pytest.exit(
            "Physical OIR teardown could not re-seat the transceiver(s): "
            + "; ".join(failures),
            returncode=1,
        )
