"""
Basic test for show int transceiver info CLI.
This file is created to verify the parsing logic of transceiver inventory in conftest.py.
"""
import logging

from tests.transceiver.common import cli_helpers
from tests.transceiver.transceiver_test_base import TransceiverTestBase


logger = logging.getLogger(__name__)


class TestTransceiverInfoValidator(TransceiverTestBase):
    """
    @summary: Test class to validate
    transceiver inventory against the parsed EEPROM data.
    """

    EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING = {
        "Vendor Date Code(YYYY-MM-DD Lot)": "vendor_date",
        "Vendor OUI": "vendor_oui",
        "Vendor Rev": "vendor_rev",
        "Vendor SN": "vendor_sn",
        "Vendor PN": "vendor_pn",
        "Active Firmware": "active_firmware",
        "Inactive Firmware": "inactive_firmware",
        "CMIS Rev": "cmis_rev",
        "Vendor Name": "vendor_name",
    }

    def validate_parsed_eeprom(self, parsed_eeprom):
        for intf in self.dev_conn:
            port_parsed_eeprom = parsed_eeprom[intf]
            port_transceiver_details = self.dev_transceiver_details.get(self.lport_to_pport_mapping[intf], {})
            for cli_key, transceiver_inv_key in self.EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING.items():
                assert cli_key in port_parsed_eeprom, "{}: {} not present in parsed_eeprom".format(intf, cli_key)
                assert transceiver_inv_key in port_transceiver_details, (
                    "{}: {} not present in transceiver_inventory".format(intf, transceiver_inv_key)
                )
                assert port_parsed_eeprom[cli_key] == port_transceiver_details[transceiver_inv_key], (
                    "{}: {} mismatch for {}: expected {}, got {}".format(
                        intf, cli_key, self.lport_to_pport_mapping[intf],
                        port_transceiver_details[transceiver_inv_key],
                        port_parsed_eeprom[cli_key]
                    )
                )
        logger.info("All transceiver EEPROM contents matched successfully.")

    def test_check_show_int_transceiver_info(self):
        """
        @summary: Check SFP EEPROM using 'show interfaces transceiver info'
        """
        # Single source of truth for command string + parser + rc-handling: the
        # shared cli_helpers wrapper (same one the EEPROM-content tests use).
        parsed_eeprom, err = cli_helpers.show_interfaces_transceiver_info(self.duthost)
        assert err is None, err

        # Validate the parsed_eeprom against the transceiver inventory
        self.validate_parsed_eeprom(parsed_eeprom)
