"""
Check SFP status and configure SFP

This script covers test case 'Check SFP status and configure SFP' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import os
import time

from ansible_host import ansible_host


def parse_presence(output_lines):
    """
    @summary: Parse the SFP presence information from command output
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


def test_check_sfp_status_and_configure_sfp(localhost, ansible_adhoc, testbed):
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
    hostname = testbed['dut']
    ans_host = ansible_host(ansible_adhoc, hostname)
    localhost.command("who")
    lab_conn_graph_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), \
        "../../ansible/files/lab_connection_graph.xml")
    conn_graph_facts = localhost.conn_graph_facts(host=hostname, filename=lab_conn_graph_file).\
        contacted['localhost']['ansible_facts']

    logging.info("Check output of 'sfputil show presence'")
    sfp_presence = ans_host.command("sudo sfputil show presence")
    parsed_presence = parse_presence(sfp_presence["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_presence, "Interface is not in output of 'sfputil show presence'"
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check output of 'show interface transceiver presence'")
    sfp_presence = ans_host.command("show interface transceiver presence")
    parsed_presence = parse_presence(sfp_presence["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_presence, "Interface is not in output of 'show interface transceiver presence'"
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"

    logging.info("Check output of 'sfputil show eeprom'")
    sfp_eeprom = ans_host.command("sudo sfputil show eeprom")
    parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_eeprom, "Interface is not in output of 'sfputil show eeprom'"
        assert parsed_eeprom[intf] == "SFP EEPROM detected"

    logging.info("Check output of 'show interface transceiver eeprom'")
    sfp_eeprom = ans_host.command("show interface transceiver eeprom")
    parsed_eeprom = parse_eeprom(sfp_eeprom["stdout_lines"])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_eeprom, "Interface is not in output of 'show interface transceiver eeprom'"
        assert parsed_eeprom[intf] == "SFP EEPROM detected"

    logging.info("Test 'sfputil reset <interface name>'")
    for intf in conn_graph_facts["device_conn"]:
        reset_result = ans_host.command("sudo sfputil reset " + intf)
        assert reset_result["rc"] == 0, "'sudo sfputil reset %s failed" % intf
    time.sleep(120)  # Wait some time for SFP to fully recover after reset

    logging.info("Check sfp presence again after reset")
    sfp_presence = ans_host.command("sudo sfputil show presence")
    parsed_presence = parse_presence(sfp_presence["stdout_lines"][2:])
    for intf in conn_graph_facts["device_conn"]:
        assert intf in parsed_presence, "Interface is not in output of 'sfputil show presence'"
        assert parsed_presence[intf] == "Present", "Interface presence is not 'Present'"
