"""
Check SFP status using sfpshow.

This script covers test case 'Check SFP status and configure SFP' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""

import logging
import pytest

from util import parse_eeprom
from util import parse_output
from util import get_dev_conn

cmd_sfp_presence = "sudo sfpshow presence"
cmd_sfp_eeprom = "sudo sfpshow eeprom"


pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]


def test_check_sfp_presence(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
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
            assert intf in parsed_presence, "Interface is not in output of '{}'".format(cmd_sfp_presence)
            assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"


def test_check_sfpshow_eeprom(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
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
            assert parsed_eeprom[intf] == "SFP EEPROM detected"
