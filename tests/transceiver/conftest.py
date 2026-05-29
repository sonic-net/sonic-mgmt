import os
import pytest
import logging
from .inventory.parser import TransceiverInventory

from tests.common.platform.interface_utils import get_physical_port_indices


@pytest.fixture(scope="session")
def transceiver_inventory_obj():
    """
    Fixture to provide a single TransceiverInventory object for the session.
    """
    base_path = os.path.dirname(os.path.realpath(__file__))
    return TransceiverInventory(base_path)


@pytest.fixture(scope="session")
def get_transceiver_inventory(transceiver_inventory_obj):
    """
    Fixture to provide transceiver inventory information.
    """
    return transceiver_inventory_obj.get_transceiver_info()


@pytest.fixture(scope="session")
def get_transceiver_common_attributes(transceiver_inventory_obj):
    """
    Fixture to provide common attributes from TransceiverInventory.
    """
    return transceiver_inventory_obj.common_attributes


@pytest.fixture(scope="session")
def get_dev_transceiver_details(duthost, get_transceiver_inventory):
    """
    Get transceiver details from transceiver_inventory for the given DUT.

    @param duthost: DUT host
    @param get_transceiver_inventory: Transceiver inventory
    @return: Returns transceiver details in a dictionary for the given DUT with port as key
    """
    hostname = duthost.hostname
    details = get_transceiver_inventory.get(hostname, {})
    if not details:
        logging.error(f"No transceiver details found for host: {hostname}")
    return details


@pytest.fixture(scope="module")
def get_lport_to_pport_mapping(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture to get the mapping of logical ports to physical ports.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lport_to_pport_mapping = get_physical_port_indices(duthost)

    logging.info("Logical to Physical Port Mapping: {}".format(lport_to_pport_mapping))
    return lport_to_pport_mapping
