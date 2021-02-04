"""
Check SFP status and configure SFP

This script covers test case 'Check SFP status and configure SFP' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import os
import time
import copy

import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.platform.interface_utils import get_port_map

ans_host = None

def teardown_module():
    logging.info("remove script to retrieve port mapping")
    file_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/getportmap.py')
    ans_host.file(path=file_path, state='absent')

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

def parse_output(output_lines):
    """
    @summary: For parsing command output. The output lines should have format 'key value'.
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    res = {}
    for line in output_lines:
        fields = line.split()
        if len(fields) != 2:
            continue
        res[fields[0]] = fields[1]
    return res


def parse_eeprom(output_lines):
    """
    @summary: Parse the SFP eeprom information from command output
    @param output_lines: Command output lines
    @return: Returns result in a dictionary
    """
    res = {}
    for line in output_lines:
        if re.match(r"^Ethernet\d+: .*", line):
            fields = line.split(":")
            res[fields[0]] = fields[1].strip()
    return res

def test_check_sfp_status_and_configure_sfp(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, conn_graph_facts, tbinfo):
    """
    @summary: Check SFP status and configure SFP

    This case is to use the sfputil tool and show command to check SFP status and configure SFP. Currently the
    only configuration is to reset SFP. Commands to be tested:
    * sfputil show presence
    * show interface transceiver presence
    * sfputil show eeprom
    * show interface transceiver eeprom
    * sfputil reset <interface name>
    """
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='sfp_cfg')
        loganalyzer.load_common_config()

        loganalyzer.ignore_regex.append("kernel.*Eeprom query failed*")
        marker = loganalyzer.init()

    dev_conn = conn_graph_facts["device_conn"][duthost.hostname]

    # Get the interface pertaining to that asic
    portmap = get_port_map(duthost, enum_frontend_asic_index)
    logging.info("Got portmap {}".format(portmap))

    if enum_frontend_asic_index is not None:
        # Check if the interfaces of this AISC is present in conn_graph_facts
        dev_conn = {k:v for k, v in portmap.items() if k in conn_graph_facts["device_conn"][duthost.hostname]}
        logging.info("ASIC {} interface_list {}".format(enum_frontend_asic_index, dev_conn))

    cmd_sfp_presence = "sudo sfputil show presence"
    cmd_sfp_eeprom = "sudo sfputil show eeprom"
    cmd_sfp_reset = "sudo sfputil reset"
    cmd_xcvr_presence = "show interface transceiver presence"
    cmd_xcvr_eeprom = "show interface transceiver eeprom"

    global ans_host
    ans_host = duthost

    logging.info("Check output of '%s'" % cmd_sfp_presence)
    sfp_presence = duthost.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in dev_conn:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_sfp_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check output of '%s'" % cmd_xcvr_presence)
    xcvr_presence = duthost.command(cmd_xcvr_presence)
    parsed_presence = parse_output(xcvr_presence["stdout_lines"][2:])
    for intf in dev_conn:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_xcvr_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check output of '%s'" % cmd_sfp_eeprom)
    sfp_eeprom = duthost.command(cmd_sfp_eeprom)
    parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])
    for intf in dev_conn:
        assert intf in parsed_eeprom, "Interface is not in output of 'sfputil show eeprom'"
        assert parsed_eeprom[intf] == "SFP EEPROM detected"

    logging.info("Check output of '%s'" % cmd_xcvr_eeprom)
    xcvr_eeprom = duthost.command(cmd_xcvr_eeprom)
    parsed_eeprom = parse_eeprom(xcvr_eeprom["stdout_lines"])
    for intf in dev_conn:
        assert intf in parsed_eeprom, "Interface is not in output of '%s'" % cmd_xcvr_eeprom
        assert parsed_eeprom[intf] == "SFP EEPROM detected"

    logging.info("Test '%s <interface name>'" % cmd_sfp_reset)
    tested_physical_ports = set()
    for intf in dev_conn:
        phy_intf = portmap[intf][0]
        if phy_intf in tested_physical_ports:
            logging.info("skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
            continue
        tested_physical_ports.add(phy_intf)
        logging.info("resetting {} physical interface {}".format(intf, phy_intf))
        reset_result = duthost.command("%s %s" % (cmd_sfp_reset, intf))
        assert reset_result["rc"] == 0, "'%s %s' failed" % (cmd_sfp_reset, intf)
        time.sleep(5)
    logging.info("Wait some time for SFP to fully recover after reset")
    time.sleep(60)

    logging.info("Check sfp presence again after reset")
    sfp_presence = duthost.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in dev_conn:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_sfp_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check interface status")
    namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    # TODO Remove this logic when minigraph facts supports namespace in multi_asic
    up_ports = mg_facts["minigraph_ports"]
    if enum_frontend_asic_index is not None:
        # Check if the interfaces of this AISC is present in conn_graph_facts
        up_ports = {k:v for k, v in portmap.items() if k in mg_facts["minigraph_ports"]}
    intf_facts = duthost.interface_facts(namespace=namespace, up_ports=up_ports)["ansible_facts"]
    assert len(intf_facts["ansible_interface_link_down_ports"]) == 0, \
        "Some interfaces are down: %s" % str(intf_facts["ansible_interface_link_down_ports"])

    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer.analyze(marker)


def test_check_sfp_low_power_mode(duthosts, rand_one_dut_hostname, enum_frontend_asic_index, conn_graph_facts, tbinfo):
    """
    @summary: Check SFP low power mode

    This case is to use the sfputil tool command to check and set SFP low power mode
    * sfputil show lpmode
    * sfputil lpmode off
    * sfputil lpmode on
    """
    duthost = duthosts[rand_one_dut_hostname]
    asichost = duthost.get_asic(enum_frontend_asic_index)
    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='sfp_lpm')
        loganalyzer.load_common_config()

        loganalyzer.ignore_regex.append("Eeprom query failed")
        marker = loganalyzer.init()

    dev_conn = conn_graph_facts["device_conn"][duthost.hostname]

    # Get the interface pertaining to that asic
    portmap = get_port_map(duthost, enum_frontend_asic_index)
    logging.info("Got portmap {}".format(portmap))

    if enum_frontend_asic_index is not None:
        # Check if the interfaces of this AISC is present in conn_graph_facts
        dev_conn = {k:v for k, v in portmap.items() if k in conn_graph_facts["device_conn"][duthost.hostname]}
        logging.info("ASIC {} interface_list {}".format(enum_frontend_asic_index, dev_conn))

    cmd_sfp_presence = "sudo sfputil show presence"
    cmd_sfp_show_lpmode = "sudo sfputil show lpmode"
    cmd_sfp_set_lpmode = "sudo sfputil lpmode"

    global ans_host
    ans_host = duthost

    logging.info("Check output of '%s'" % cmd_sfp_show_lpmode)
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    original_lpmode = copy.deepcopy(parsed_lpmode)
    for intf in dev_conn:
        assert intf in parsed_lpmode, "Interface is not in output of '%s'" % cmd_sfp_show_lpmode
        assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Try to change SFP lpmode")
    tested_physical_ports = set()

    not_supporting_lpm_physical_ports = set()
    for intf in dev_conn:
        phy_intf = portmap[intf][0]
        if phy_intf in tested_physical_ports:
            logging.info("skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
            continue

        sfp_type_cmd = 'redis-cli -n 6 hget "TRANSCEIVER_INFO|{}" type'.format(intf)
        sfp_type_docker_cmd = asichost.get_docker_cmd(sfp_type_cmd, "database")
        sfp_type = duthost.command(sfp_type_docker_cmd)["stdout"]

        power_class_cmd = 'redis-cli -n 6 hget "TRANSCEIVER_INFO|{}" ext_identifier'.format(intf)
        power_class_docker_cmd = asichost.get_docker_cmd(power_class_cmd, "database")
        power_class = duthost.command(power_class_docker_cmd)["stdout"]

        if not "QSFP" in sfp_type or "Power Class 1" in power_class:
            logging.info("skip testing port {} which doesn't support LPM".format(intf))
            not_supporting_lpm_physical_ports.add(phy_intf)
            continue
        tested_physical_ports.add(phy_intf)
        logging.info("setting {} physical interface {}".format(intf, phy_intf))
        new_lpmode = "off" if original_lpmode[intf].lower() == "on" else "on"
        lpmode_set_result = duthost.command("%s %s %s" % (cmd_sfp_set_lpmode, new_lpmode, intf))
        assert lpmode_set_result["rc"] == 0, "'%s %s %s' failed" % (cmd_sfp_set_lpmode, new_lpmode, intf)
    time.sleep(10)

    if len(tested_physical_ports) == 0:
        pytest.skip("None of the ports supporting LPM, skip the test")

    logging.info("Check SFP lower power mode again after changing SFP lpmode")
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    for intf in dev_conn:
        assert intf in parsed_lpmode, "Interface is not in output of '%s'" % cmd_sfp_show_lpmode
        assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Try to change SFP lpmode")
    tested_physical_ports = set()
    for intf in dev_conn:
        phy_intf = portmap[intf][0]
        if phy_intf in not_supporting_lpm_physical_ports:
            logging.info("skip testing port {} which doesn't support LPM".format(intf))
            continue
        if phy_intf in tested_physical_ports:
            logging.info("skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
            continue
        tested_physical_ports.add(phy_intf)
        logging.info("restoring {} physical interface {}".format(intf, phy_intf))
        new_lpmode = original_lpmode[intf].lower()
        lpmode_set_result = duthost.command("%s %s %s" % (cmd_sfp_set_lpmode, new_lpmode, intf))
        assert lpmode_set_result["rc"] == 0, "'%s %s %s' failed" % (cmd_sfp_set_lpmode, new_lpmode, intf)
    time.sleep(10)

    logging.info("Check SFP lower power mode again after changing SFP lpmode")
    lpmode_show = duthost.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    for intf in dev_conn:
        assert intf in parsed_lpmode, "Interface is not in output of '%s'" % cmd_sfp_show_lpmode
        assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Check sfp presence again after setting lpmode")
    sfp_presence = duthost.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in dev_conn:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_sfp_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check interface status")
    namespace = duthost.get_namespace_from_asic_id(enum_frontend_asic_index)
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    # TODO Remove this logic when minigraph facts supports namespace in multi_asic
    up_ports = mg_facts["minigraph_ports"]
    if enum_frontend_asic_index is not None:
        # Check if the interfaces of this AISC is present in conn_graph_facts
        up_ports = {k:v for k, v in portmap.items() if k in mg_facts["minigraph_ports"]}
    intf_facts = duthost.interface_facts(namespace=namespace, up_ports=up_ports)["ansible_facts"]
    assert len(intf_facts["ansible_interface_link_down_ports"]) == 0, \
        "Some interfaces are down: %s" % str(intf_facts["ansible_interface_link_down_ports"])

    if duthost.facts["asic_type"] in ["mellanox"]:
        loganalyzer.analyze(marker)
