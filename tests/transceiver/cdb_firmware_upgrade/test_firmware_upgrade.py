"""
Tests to perform CDB firmware upgrade on CMIS transceivers.
"""
import logging
import pytest

from tests.transceiver.transceiver_test_base import TransceiverTestBase


pytestmark = [
    pytest.mark.topology('ptp-256')
]

logger = logging.getLogger(__name__)


class TestFirmwareUpgrade(TransceiverTestBase):
    """
    @summary: Test class to perform CDB firmware upgrade on CMIS transceivers.
    """
    def test_transceiver_firmware_download(self):
        """
        @summary: Perform CDB firmware download on all transceivers of the DUT
        Needs to be implemented.
        """
        logger.info("Firmware download to the transceiver is yet to be implemented.")
