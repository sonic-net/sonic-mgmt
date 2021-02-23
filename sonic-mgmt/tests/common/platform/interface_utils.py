"""
Helper script for checking status of interfaces

This script contains re-usable functions for checking status of interfaces on SONiC.
"""
import logging
from transceiver_utils import all_transceivers_detected


def parse_intf_status(lines):
    """
    @summary: Parse the output of command "show interface description".
    @param lines: The output lines of command "show interface description".
    @return: Return a dictionary like:
        {
            "Ethernet0": {
                "oper": "up",
                "admin": "up",
                "alias": "etp1",
                "desc": "ARISTA01T2:Ethernet1"
            },
            ...
        }
    """
    result = {}
    for line in lines:
        fields = line.split()
        if len(fields) >= 5:
            intf = fields[0]
            oper, admin, alias, desc = fields[1], fields[2], fields[3], ' '.join(fields[4:])
            result[intf] = {"oper": oper, "admin": admin, "alias": alias, "desc": desc}
    return result


def check_interface_status(dut, interfaces):
    """
    @summary: Check the admin and oper status of the specified interfaces on DUT.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check interface status using cmd 'show interface'")
    mg_ports = dut.minigraph_facts(host=dut.hostname)["ansible_facts"]["minigraph_ports"]
    output = dut.command("show interface description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    check_intf_presence_command = 'show interface transceiver presence {}'
    for intf in interfaces:
        expected_oper = "up" if intf in mg_ports else "down"
        expected_admin = "up" if intf in mg_ports else "down"
        if intf not in intf_status:
            logging.info("Missing status for interface %s" % intf)
            return False
        if intf_status[intf]["oper"] != expected_oper:
            logging.info("Oper status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["oper"],
                                                                               expected_oper))
            return False
        if intf_status[intf]["admin"] != expected_admin:
            logging.info("Admin status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["admin"],
                                                                                expected_admin))
            return False

        # Cross check the interface SFP presence status
        check_presence_output = dut.command(check_intf_presence_command.format(intf))
        presence_list = check_presence_output["stdout_lines"][2].split()
        assert intf in presence_list, "Wrong interface name in the output: %s" % str(presence_list)
        assert 'Present' in presence_list, "Status is not expected, presence status: %s" % str(presence_list)

    logging.info("Check interface status using the interface_facts module")
    intf_facts = dut.interface_facts(up_ports=mg_ports)["ansible_facts"]
    down_ports = intf_facts["ansible_interface_link_down_ports"]
    if len(down_ports) != 0:
        logging.info("Some interfaces are down: %s" % str(down_ports))
        return False

    return True


def check_interface_information(dut, interfaces):
    if not all_transceivers_detected(dut, interfaces):
        logging.info("Not all transceivers are detected")
        return False
    if not check_interface_status(dut, interfaces):
        logging.info("Not all interfaces are up")
        return False

    return True
