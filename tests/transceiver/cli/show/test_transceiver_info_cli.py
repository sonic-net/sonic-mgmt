"""
Basic test for show int transceiver info CLI.
This file is created to verify the parsing logic of transceiver inventory in conftest.py.
"""
import logging
import pytest

from tests.transceiver.transceiver_test_base import TransceiverTestBase
from tests.transceiver.utils.cli_parser_helper import parse_eeprom

pytestmark = [
    pytest.mark.topology('ptp-256')
]

CMD_SFP_EEPROM = "show interfaces transceiver info"
ERROR_CHASSIS_LOAD = 2

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
        @summary: Check SFP EEPROM using 'show interfaces transceiver eeprom'
        """
        logger.info("Check output of '{}'".format(CMD_SFP_EEPROM))
        sfp_eeprom = self.duthost.command(CMD_SFP_EEPROM, module_ignore_errors=True)

        # For vs testbed, we will get expected Error code `ERROR_CHASSIS_LOAD = 2` here.
        if self.duthost.facts["asic_type"] == "vs" and sfp_eeprom['rc'] == ERROR_CHASSIS_LOAD:
            return
        assert sfp_eeprom['rc'] == 0, "Run command '{}' failed".format(CMD_SFP_EEPROM)

        parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])

        # Validate the parsed_eeprom against the transceiver inventory
        self.validate_parsed_eeprom(parsed_eeprom)
