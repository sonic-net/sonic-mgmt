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
import json

import pytest

from platform_fixtures import conn_graph_facts
from common.plugins.loganalyzer import LogAnalyzer

ans_host = None
port_mapping = None

def teardown_module():
    logging.info("remove script to retrieve port mapping")
    file_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/getportmap.py')
    ans_host.file(path=file_path, state='absent')

pytestmark = [
    pytest.mark.disable_loganalyzer  # disable automatic loganalyzer
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


def get_port_map(testbed_devices):
    """
    @summary: Get the port mapping info from the DUT
    @return: a dictionary containing the port map
    """
    global port_mapping
    global ans_host

    # we've already retrieve port mapping for the DUT, just return it
    if not port_mapping is None:
        logging.info("Return the previously retrievd port mapping")
        return port_mapping

    # this is the first running
    logging.info("Retrieving port mapping from DUT")
    # copy the helper to DUT
    ans_host = testbed_devices["dut"]
    src_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files/getportmap.py')
    dest_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/getportmap.py')
    ans_host.copy(src=src_path, dest=dest_path)

    # execute command on the DUT to get portmap
    get_portmap_cmd = 'docker exec pmon python /usr/share/sonic/platform/plugins/getportmap.py'
    portmap_json_string = ans_host.command(get_portmap_cmd)["stdout"]

    # parse the json
    port_mapping = json.loads(portmap_json_string)
    assert port_mapping, "Retrieve port mapping from DUT failed"

    return port_mapping


def test_check_sfp_status_and_configure_sfp(testbed_devices, conn_graph_facts):
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
    ans_host = testbed_devices["dut"]

    if ans_host.facts["asic_type"] in ["mellanox"]:
        loganalyzer = LogAnalyzer(ansible_host=ans_host, marker_prefix='sfp_cfg')
        loganalyzer.load_common_config()

        loganalyzer.ignore_regex.append("kernel.*Eeprom query failed*")
        marker = loganalyzer.init()

    cmd_sfp_presence = "sudo sfputil show presence"
    cmd_sfp_eeprom = "sudo sfputil show eeprom"
    cmd_sfp_reset = "sudo sfputil reset"
    cmd_xcvr_presence = "show interface transceiver presence"
    cmd_xcvr_eeprom = "show interface transceiver eeprom"

    portmap = get_port_map(testbed_devices)
    logging.info("Got portmap {}".format(portmap))

    logging.info("Check output of '%s'" % cmd_sfp_presence)
    sfp_presence = ans_host.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_sfp_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check output of '%s'" % cmd_xcvr_presence)
    xcvr_presence = ans_host.command(cmd_xcvr_presence)
    parsed_presence = parse_output(xcvr_presence["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_xcvr_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check output of '%s'" % cmd_sfp_eeprom)
    sfp_eeprom = ans_host.command(cmd_sfp_eeprom)
    parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_eeprom, "Interface is not in output of 'sfputil show eeprom'"
        assert parsed_eeprom[intf] == "SFP EEPROM detected"

    logging.info("Check output of '%s'" % cmd_xcvr_eeprom)
    xcvr_eeprom = ans_host.command(cmd_xcvr_eeprom)
    parsed_eeprom = parse_eeprom(xcvr_eeprom["stdout_lines"])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_eeprom, "Interface is not in output of '%s'" % cmd_xcvr_eeprom
        assert parsed_eeprom[intf] == "SFP EEPROM detected"

    logging.info("Test '%s <interface name>'" % cmd_sfp_reset)
    tested_physical_ports = set()
    for intf in conn_graph_facts["device_conn"]:
        phy_intf = portmap[intf][0]
        if phy_intf in tested_physical_ports:
            logging.info("skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
            continue
        tested_physical_ports.add(phy_intf)
        logging.info("resetting {} physical interface {}".format(intf, phy_intf))
        reset_result = ans_host.command("%s %s" % (cmd_sfp_reset, intf))
        assert reset_result["rc"] == 0, "'%s %s' failed" % (cmd_sfp_reset, intf)
        time.sleep(5)
    logging.info("Wait some time for SFP to fully recover after reset")
    time.sleep(60)

    logging.info("Check sfp presence again after reset")
    sfp_presence = ans_host.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_sfp_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check interface status")
    mg_facts = ans_host.minigraph_facts(host=ans_host.hostname)["ansible_facts"]
    intf_facts = ans_host.interface_facts(up_ports=mg_facts["minigraph_ports"])["ansible_facts"]
    assert len(intf_facts["ansible_interface_link_down_ports"]) == 0, \
        "Some interfaces are down: %s" % str(intf_facts["ansible_interface_link_down_ports"])

    if ans_host.facts["asic_type"] in ["mellanox"]:
        loganalyzer.analyze(marker)


def test_check_sfp_low_power_mode(testbed_devices, conn_graph_facts):
    """
    @summary: Check SFP low power mode

    This case is to use the sfputil tool command to check and set SFP low power mode
    * sfputil show lpmode
    * sfputil lpmode off
    * sfputil lpmode on
    """
    ans_host = testbed_devices["dut"]

    if ans_host.facts["asic_type"] in ["mellanox"]:
        loganalyzer = LogAnalyzer(ansible_host=ans_host, marker_prefix='sfp_lpm')
        loganalyzer.load_common_config()

        loganalyzer.ignore_regex.append("Eeprom query failed")
        marker = loganalyzer.init()

    cmd_sfp_presence = "sudo sfputil show presence"
    cmd_sfp_show_lpmode = "sudo sfputil show lpmode"
    cmd_sfp_set_lpmode = "sudo sfputil lpmode"

    portmap = get_port_map(testbed_devices)
    logging.info("Got portmap {}".format(portmap))

    logging.info("Check output of '%s'" % cmd_sfp_show_lpmode)
    lpmode_show = ans_host.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    original_lpmode = copy.deepcopy(parsed_lpmode)
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_lpmode, "Interface is not in output of '%s'" % cmd_sfp_show_lpmode
        assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Try to change SFP lpmode")
    tested_physical_ports = set()
    for intf in conn_graph_facts["device_conn"]:
        phy_intf = portmap[intf][0]
        if phy_intf in tested_physical_ports:
            logging.info("skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
            continue
        tested_physical_ports.add(phy_intf)
        logging.info("setting {} physical interface {}".format(intf, phy_intf))
        new_lpmode = "off" if original_lpmode[intf].lower() == "on" else "on"
        lpmode_set_result = ans_host.command("%s %s %s" % (cmd_sfp_set_lpmode, new_lpmode, intf))
        assert lpmode_set_result["rc"] == 0, "'%s %s %s' failed" % (cmd_sfp_set_lpmode, new_lpmode, intf)
    time.sleep(10)

    logging.info("Check SFP lower power mode again after changing SFP lpmode")
    lpmode_show = ans_host.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_lpmode, "Interface is not in output of '%s'" % cmd_sfp_show_lpmode
        assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Try to change SFP lpmode")
    tested_physical_ports = set()
    for intf in conn_graph_facts["device_conn"]:
        phy_intf = portmap[intf][0]
        if phy_intf in tested_physical_ports:
            logging.info("skip tested SFPs {} to avoid repeating operating physical interface {}".format(intf, phy_intf))
            continue
        tested_physical_ports.add(phy_intf)
        logging.info("restoring {} physical interface {}".format(intf, phy_intf))
        new_lpmode = original_lpmode[intf].lower()
        lpmode_set_result = ans_host.command("%s %s %s" % (cmd_sfp_set_lpmode, new_lpmode, intf))
        assert lpmode_set_result["rc"] == 0, "'%s %s %s' failed" % (cmd_sfp_set_lpmode, new_lpmode, intf)
    time.sleep(10)

    logging.info("Check SFP lower power mode again after changing SFP lpmode")
    lpmode_show = ans_host.command(cmd_sfp_show_lpmode)
    parsed_lpmode = parse_output(lpmode_show["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_lpmode, "Interface is not in output of '%s'" % cmd_sfp_show_lpmode
        assert parsed_lpmode[intf].lower() == "on" or parsed_lpmode[intf].lower() == "off", "Unexpected SFP lpmode"

    logging.info("Check sfp presence again after setting lpmode")
    sfp_presence = ans_host.command(cmd_sfp_presence)
    parsed_presence = parse_output(sfp_presence["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_presence, "Interface is not in output of '%s'" % cmd_sfp_presence
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check interface status")
    mg_facts = ans_host.minigraph_facts(host=ans_host.hostname)["ansible_facts"]
    intf_facts = ans_host.interface_facts(up_ports=mg_facts["minigraph_ports"])["ansible_facts"]
    assert len(intf_facts["ansible_interface_link_down_ports"]) == 0, \
        "Some interfaces are down: %s" % str(intf_facts["ansible_interface_link_down_ports"])

    if ans_host.facts["asic_type"] in ["mellanox"]:
        loganalyzer.analyze(marker)
