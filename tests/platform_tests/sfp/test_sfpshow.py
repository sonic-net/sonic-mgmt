"""
Check SFP status using sfpshow.

This script covers test case 'Check SFP status and configure SFP' in the SONiC platform test plan:
https://github.com/sonic-net/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""

import logging
import pytest

from .util import parse_eeprom
from .util import parse_output
from .util import get_dev_conn

cmd_sfp_presence = "sudo sfpshow presence"
cmd_sfp_eeprom = "sudo sfpshow eeprom"


pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]


def test_check_sfp_presence(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                            enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
    """
    @summary: Check SFP presence using 'sfputil show presence'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)

    logging.info("Check output of '{}'".format(cmd_sfp_presence))
    sfp_presence = duthost.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_presence, (
                "Interface '{}' is not in the output of '{}'. "
                "This indicates that the SFP presence information for the interface is missing. "
                "Possible causes include:\n"
                "1. The SFP module is not properly seated or is missing from the interface.\n"
                "2. The platform API or driver is not reporting the presence status correctly.\n"
                "3. There is an issue with the 'sfputil show presence' command or its output parsing.\n"
                "4. The interface is incorrectly excluded from the test or is not part of the expected connections.\n\n"
                "Suggested debugging steps:\n"
                "1. Verify that the SFP module is physically present and properly seated in the interface '{}'.\n"
                "2. Run the command '{}' manually on the DUT and check if the interface '{}' appears in the output.\n"
                "3. Inspect the DUT logs for any errors related to SFP detection or platform drivers.\n"
                "4. Ensure that the connection graph and testbed configuration are correct and include the interface '{}'."
                .format(intf, cmd_sfp_presence, intf, cmd_sfp_presence, intf, intf)
            )
            assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"


def test_check_sfpshow_eeprom(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
    """
    @summary: Check SFP presence using 'sfputil show presence'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)

    logging.info("Check output of '{}'".format(cmd_sfp_eeprom))
    sfp_eeprom = duthost.command(cmd_sfp_eeprom)
    parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])
    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert intf in parsed_eeprom, "Interface is not in output of 'sfputil show eeprom'"
            assert parsed_eeprom[intf] == "SFP EEPROM detected", (
                "The EEPROM information for interface '{}' is not as expected. "
                "Expected: 'SFP EEPROM detected', but got: '{}'. "
                "This indicates that the SFP EEPROM data for the interface is either missing or incorrect. "
                "Possible causes include:\n"
                "1. The SFP module is not properly inserted or detected.\n"
                "2. The SFP module is faulty or incompatible with the device.\n"
                "3. The 'sfputil show eeprom' command did not execute correctly or returned incomplete data.\n"
                "4. The interface is not correctly mapped in the device connection graph.\n\n"
                "Please verify the following:\n"
                "- Ensure the SFP module is properly inserted and operational.\n"
                "- Check the compatibility of the SFP module with the device.\n"
                "- Verify the output of the 'sfputil show eeprom' command manually.\n"
                "- Check the DUT logs for any errors or warnings related to SFP detection or EEPROM reading."
                .format(intf, parsed_eeprom.get(intf, "No data found"))
            )
