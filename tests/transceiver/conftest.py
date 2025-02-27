import os
import pytest
import logging
from .inventory.parser import TransceiverInventory

from tests.common.platform.interface_utils import get_physical_port_indices


@pytest.fixture(scope="module")
def transceiver_inventory():
    """
    Fixture to provide transceiver inventory information.
    """
    base_path = os.path.dirname(os.path.realpath(__file__))
    inventory = TransceiverInventory(base_path)
    return inventory.get_transceiver_info()


@pytest.fixture(scope="module")
def get_lport_to_pport_mapping(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    Fixture to get the mapping of logical ports to physical ports.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lport_to_pport_mapping = get_physical_port_indices(duthost)

    logging.info("Logical to Physical Port Mapping: {}".format(lport_to_pport_mapping))
    return lport_to_pport_mapping
