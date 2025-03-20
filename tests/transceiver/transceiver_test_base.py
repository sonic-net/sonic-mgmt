"""
Transceiver Test Base Class
=================================
This module contains a base class for transceiver tests.
It sets up the test environment by initializing the necessary components such as
the DUT host and the device connection.
It also provides a fixture to retrieve transceiver details and logical to physical port mapping.
The test class is designed to be inherited by specific test cases that require
transceiver information.
"""
import pytest
import logging

from tests.common.platform.interface_utils import get_dev_conn
from tests.transceiver.utils.inventory import get_dev_transceiver_details

logger = logging.getLogger(__name__)


@pytest.mark.topology('ptp-256')
@pytest.mark.usefixtures("setup")
class TransceiverTestBase:
    @pytest.fixture(scope="class", autouse=True)
    def setup(self, request, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
              enum_frontend_asic_index, conn_graph_facts, transceiver_inventory, get_lport_to_pport_mapping):
        """
        Fixture to set up the test environment.
        """
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        _, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)
        dev_transceiver_details = get_dev_transceiver_details(duthost, transceiver_inventory)
        logger.info("Dev transceiver details: {}".format(dev_transceiver_details))
        if request.cls is not None:
            request.cls.duthost = duthost
            request.cls.enum_frontend_asic_index = enum_frontend_asic_index
            request.cls.dev_conn = dev_conn
            request.cls.dev_transceiver_details = dev_transceiver_details
            request.cls.lport_to_pport_mapping = get_lport_to_pport_mapping
