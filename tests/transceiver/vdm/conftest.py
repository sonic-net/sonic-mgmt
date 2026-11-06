import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import (
    EEPROM_ATTRIBUTES_KEY,
    VDM_ATTRIBUTES_KEY,
)
from tests.transceiver.common.port_selectors import select_attribute_ports
from tests.transceiver.common.prerequisites import build_dom_polling_failures

logger = logging.getLogger(__name__)


def _vdm_supported(port, port_attrs):
    supported = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {}).get("vdm_supported")
    if supported is not True:
        logger.info(
            "%s excluded from VDM tests: vdm_supported=%r",
            port, supported,
        )
    return supported is True


@pytest.fixture(scope="session")
def vdm_capable_port_selection(
    port_attributes_dict,
    lport_to_first_subport_mapping,
):
    """Return VDM-capable primary and non-primary subports."""
    return select_attribute_ports(
        port_attributes_dict,
        VDM_ATTRIBUTES_KEY,
        lport_to_first_subport_mapping,
        predicate=_vdm_supported,
        include_non_primary=True,
    )


@pytest.fixture(scope="session")
def vdm_primary_ports(vdm_capable_port_selection):
    """Return VDM-capable primary subports in deterministic interface order."""
    ports = vdm_capable_port_selection.primary_ports
    if not ports:
        pytest.skip("No VDM-capable primary subports found for VDM tests")
    return ports


@pytest.fixture(scope="session")
def vdm_non_primary_ports(vdm_capable_port_selection):
    """Return VDM-capable non-primary breakout subports."""
    return vdm_capable_port_selection.non_primary_ports


@pytest.fixture(autouse=True, scope="package")
def _vdm_session_prerequisites(
    duthost,
    vdm_primary_ports,
    presence_verified,
    gold_fw_verified,
    links_verified,
):
    """Opt VDM tests into shared prerequisite gates and polling checks."""
    failures = build_dom_polling_failures(duthost, vdm_primary_ports)
    if failures:
        pytest.fail("VDM polling prerequisite failed - " + "; ".join(failures))

    logger.info("VDM session prerequisites passed for %d port(s)", len(vdm_primary_ports))
