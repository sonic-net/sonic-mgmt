"""
Check SFP status using 'show interface transciever'.

This script covers test case 'Check SFP status and configure SFP' in the SONiC platform test plan:
https://github.com/sonic-net/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""

import logging
import pytest

from .util import parse_eeprom
from .util import parse_output
from .util import get_dev_conn
from .util import validate_transceiver_lpmode

cmd_sfp_presence = "show interface transceiver presence"
cmd_sfp_eeprom = "show interface transceiver eeprom"
cmd_sfp_lpmode = "show interface transceiver lpmode"

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
            assert intf in parsed_presence, "Interface is not in output of '{}'".format(cmd_sfp_presence)
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
            assert parsed_eeprom[intf] == "SFP EEPROM detected"


def test_check_show_lpmode(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                           enum_frontend_asic_index, conn_graph_facts, xcvr_skip_list):
    """
    Verify port mode in 'show interface transceiver lpmode'
    Args:
    - duthosts: dictionary containing DUT hosts
    - enum_rand_one_per_hwsku_frontend_hostname: enumeration to select one DUT per hardware SKU
    - enum_frontend_asic_index: enumeration for frontend ASIC index
    - conn_graph_facts: facts about connectivity graph
    Returns:
    - None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    portmap, dev_conn = get_dev_conn(
        duthost, conn_graph_facts, enum_frontend_asic_index)
    sfp_lpmode = duthost.command(cmd_sfp_lpmode, module_ignore_errors=True)

    # For vs testbed, we will get expected Error code `ERROR_CHASSIS_LOAD = 2` here.
    if duthost.facts["asic_type"] == "vs" and sfp_lpmode['rc'] == 2:
        return
    assert sfp_lpmode['rc'] == 0, "Run command '{}' failed".format(cmd_sfp_presence)

    for intf in dev_conn:
        if intf not in xcvr_skip_list[duthost.hostname]:
            assert validate_transceiver_lpmode(
                sfp_lpmode['stdout']), "Interface mode incorrect in 'show interface transceiver lpmode'"
