"""
Contains utility functions for extracting transceiver information
from the already parsed transceiver inventory.
"""
import logging

logger = logging.getLogger(__name__)


def get_dev_transceiver_details(duthost, transceiver_inventory):
    """
    Get transceiver details from transceiver_inventory for the given DUT.

    @param duthost: DUT host
    @param transceiver_inventory: Transceiver inventory
    @return: Returns transceiver details in a dictionary for the given DUT with port as key
    """
    hostname = duthost.hostname
    details = transceiver_inventory.get(hostname, {})
    if not details:
        logger.error(f"No transceiver details found for host: {hostname}")
    return details
