import logging

import pytest
from natsort import natsorted

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def port_config_ports(port_attributes_dict):
    """Return every inventory port in deterministic interface order.

    Port Config tests are read-only CONFIG_DB queries, so per the test plan
    they consume no session-level prerequisite gates.
    """
    ports = natsorted(port_attributes_dict)
    if not ports:
        pytest.skip("No transceiver ports found in port_attributes_dict")
    logger.info("Port Config tests cover %d port(s)", len(ports))
    return ports
