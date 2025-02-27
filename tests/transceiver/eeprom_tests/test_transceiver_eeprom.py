"""
Basic test for show int transceiver eeprom
This file is created to verify the parsing logical of transceiver inventory in conftest.py.
In future, we plan to add more tests and enhance the existing test in this file.
"""
import logging

import pytest

from tests.common.platform.interface_utils import get_dev_conn
from tests.transceiver.utils.transceiver_inv_utils import get_dev_transceiver_details
from tests.transceiver.utils.cli_parser_helper import parse_eeprom

pytestmark = [
    pytest.mark.topology('ptp-256')
]

CMD_SFP_EEPROM = "show interfaces transceiver eeprom"
ERROR_CHASSIS_LOAD = 2

logger = logging.getLogger(__name__)

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


def validate_parsed_eeprom(parsed_eeprom, dev_transceiver_details, dev_conn, get_lport_to_pport_mapping):
    for intf in dev_conn:
        port_parsed_eeprom = parsed_eeprom[intf]
        port_transceiver_details = dev_transceiver_details.get(get_lport_to_pport_mapping[intf], {})
        for cli_key, transceiver_inv_key in EEPROM_EXPECTED_CLI_KEY_TO_TRANSCEIVER_INV_KEY_MAPPING.items():
            assert cli_key in port_parsed_eeprom, "{}: {} not present in parsed_eeprom".format(intf, cli_key)
            assert transceiver_inv_key in port_transceiver_details, (
                "{}: {} not present in transceiver_inventory".format(intf, transceiver_inv_key)
            )
            assert port_parsed_eeprom[cli_key] == port_transceiver_details[transceiver_inv_key], (
                "{}: {} mismatch for {}: expected {}, got {}".format(
                    intf, cli_key, get_lport_to_pport_mapping[intf],
                    port_transceiver_details[transceiver_inv_key],
                    port_parsed_eeprom[cli_key]
                )
            )
    logging.info("All transceiver EEPROM contents matched successfully.")


def test_check_show_int_transceiver_eeprom(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                           enum_frontend_asic_index, conn_graph_facts,
                                           transceiver_inventory, get_lport_to_pport_mapping):
    """
    @summary: Check SFP EEPROM using 'show interfaces transceiver eeprom'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get the logical ports which have transceivers connected to them
    _, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)

    logging.info("Check output of '{}'".format(CMD_SFP_EEPROM))
    sfp_eeprom = duthost.command(CMD_SFP_EEPROM, module_ignore_errors=True)

    # For vs testbed, we will get expected Error code `ERROR_CHASSIS_LOAD = 2` here.
    if duthost.facts["asic_type"] == "vs" and sfp_eeprom['rc'] == ERROR_CHASSIS_LOAD:
        return
    assert sfp_eeprom['rc'] == 0, "Run command '{}' failed".format(CMD_SFP_EEPROM)

    parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])

    dev_transceiver_details = get_dev_transceiver_details(duthost, transceiver_inventory)
    logging.info("Dev transceiver details: {}".format(dev_transceiver_details))

    # Validate the parsed_eeprom against the transceiver inventory
    validate_parsed_eeprom(parsed_eeprom, dev_transceiver_details, dev_conn,
                           get_lport_to_pport_mapping)
