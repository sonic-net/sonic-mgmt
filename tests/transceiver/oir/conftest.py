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
from tests.transceiver.attribute_parser.attribute_keys import (
    PHYSICAL_OIR_ATTRIBUTES_KEY,
    SYSTEM_ATTRIBUTES_KEY,
)
from tests.transceiver.oir import oir_helpers

logger = logging.getLogger(__name__)


@pytest.fixture(autouse=True, scope="package")
def _oir_session_prerequisites(presence_verified, links_verified):
    """Autouse wrapper pulling in the session gates consumed by OIR tests."""
    return


@pytest.fixture(scope="session")
def physical_oir_attributes(port_attributes_dict):
    """Representative ``PHYSICAL_OIR_ATTRIBUTES`` shard (uniform across ports)."""
    if not port_attributes_dict:
        pytest.skip("No transceiver ports in the inventory")
    attrs = next(iter(port_attributes_dict.values())).get(PHYSICAL_OIR_ATTRIBUTES_KEY, {})
    if not attrs:
        pytest.skip("No PHYSICAL_OIR_ATTRIBUTES configured for this DUT")
    return attrs


@pytest.fixture(scope="session")
def oir_system_attributes(port_attributes_dict):
    """Representative ``SYSTEM_ATTRIBUTES`` shard, for the port settle budgets."""
    return next(iter(port_attributes_dict.values()))[SYSTEM_ATTRIBUTES_KEY]


@pytest.fixture(autouse=True, scope="package")
def _skip_unimplemented_oir_method(physical_oir_attributes):
    """Only the operator-driven ``manual`` method is implemented today."""
    method = physical_oir_attributes["oir_method"]
    if method != oir_helpers.OIR_METHOD_MANUAL:
        pytest.skip(f"oir_method '{method}' is not implemented yet")


@pytest.fixture(scope="session")
def oir_pport_to_lports(physical_oir_attributes, get_lport_to_pport_mapping):
    """``{physical index: [logical ports]}`` for the configured ``ports_under_test``."""
    pports = physical_oir_attributes["ports_under_test"]
    if not pports:
        pytest.skip("physical OIR 'ports_under_test' is empty")
    mapping = oir_helpers.resolve_pport_to_lports(get_lport_to_pport_mapping, pports)
    unmapped = [pport for pport, lports in mapping.items() if not lports]
    if unmapped:
        pytest.fail(f"ports_under_test physical port(s) {unmapped} have no logical port on this DUT")
    logger.info("Physical OIR ports under test: %s", mapping)
    return mapping


@pytest.fixture(autouse=True)
def _restore_transceivers(request, duthost, physical_oir_attributes, oir_pport_to_lports):
    """Re-seat any module a test left out of its cage before the next test runs."""
    yield

    presence = get_pport_presence_data(duthost)
    absent = [pport for pport in oir_pport_to_lports if not presence.get(pport)]
    if not absent:
        return
    logger.warning("Physical OIR teardown: re-seating %d module(s) left removed", len(absent))
    failures = oir_helpers.perform_oir(
        request, duthost, physical_oir_attributes, absent, present=True,
        action="INSERT the original transceiver(s) - test teardown",
    )
    if failures:
        logger.warning("Physical OIR teardown could not restore: %s", "; ".join(failures))
