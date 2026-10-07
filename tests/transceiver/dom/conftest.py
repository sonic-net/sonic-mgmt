import logging

import pytest

from tests.transceiver.attribute_parser.attribute_keys import DOM_ATTRIBUTES_KEY
from tests.transceiver.common.port_selectors import select_attribute_ports
from tests.transceiver.dom.dom_helpers import build_dom_polling_failures

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def dom_port_selection(port_attributes_dict, lport_to_first_subport_mapping):
    """Return DOM-capable primary subports and non-primary complement."""
    return select_attribute_ports(
        port_attributes_dict,
        DOM_ATTRIBUTES_KEY,
        lport_to_first_subport_mapping,
        include_non_primary=True,
    )


@pytest.fixture(scope="session")
def dom_primary_ports(dom_port_selection):
    """Return DOM-capable primary subports in deterministic interface order."""
    ports = dom_port_selection.primary_ports
    if not ports:
        pytest.skip("No primary subports with non-empty DOM_ATTRIBUTES found for DOM tests")
    return ports


@pytest.fixture(scope="session")
def dom_non_primary_ports(dom_port_selection):
    """Return DOM-capable non-primary breakout subports."""
    return dom_port_selection.non_primary_ports


@pytest.fixture(autouse=True, scope="package")
def _dom_session_prerequisites(
    duthost,
    dom_primary_ports,
    presence_verified,
    gold_fw_verified,
    links_verified,
):
    """Opt DOM tests into shared prerequisite gates and DOM polling checks."""
    failures = build_dom_polling_failures(duthost, dom_primary_ports)
    if failures:
        pytest.fail("dom polling prerequisite failed - " + "; ".join(failures))

    logger.info("DOM session prerequisites passed for %d port(s)", len(dom_primary_ports))
