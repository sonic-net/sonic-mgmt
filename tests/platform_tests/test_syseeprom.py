"""
Tests to ensure we can properly query and parse data from the system EEPROM of the device
"""

import logging

import pytest


CMD_PLATFORM_SYSEEPROM = "show platform syseeprom"

pytestmark = [
    pytest.mark.disable_loganalyzer  # disable automatic loganalyzer
]


def test_show_platform_syseeprom(duthost):
    """
    @summary: Check output of 'show platform syseeprom'
    """
    logging.info("Check output of '%s'" % CMD_PLATFORM_SYSEEPROM)
    show_output = duthost.command(CMD_PLATFORM_SYSEEPROM)
    if duthost.facts["asic_type"] in ["mellanox"]:
        expected_fields = [
            "Product Name",
            "Part Number",
            "Serial Number",
            "Base MAC Address",
            "Manufacture Date",
            "Device Version",
            "MAC Addresses",
            "Manufacturer",
            "Vendor Extension",
            "ONIE Version",
            "CRC-32"]
        utility_cmd = "sudo python -c \"import imp; \
            m = imp.load_source('eeprom', '/usr/share/sonic/device/%s/plugins/eeprom.py'); \
            t = m.board('board', '', '', ''); e = t.read_eeprom(); t.decode_eeprom(e)\"" % duthost.facts["platform"]
        utility_cmd_output = duthost.command(utility_cmd)

        for field in expected_fields:
            assert show_output["stdout"].find(field) >= 0, "Expected field %s is not found" % field
            assert utility_cmd_output["stdout"].find(field) >= 0, "Expected field %s is not found" % field

        for line in utility_cmd_output["stdout_lines"]:
            assert line in show_output["stdout"], \
                "Line %s is not found in output of '%s'" % (line, CMD_PLATFORM_SYSEEPROM)
