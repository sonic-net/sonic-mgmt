"""
Helper script for checking status of interfaces

This script contains re-usable functions for checking status of interfaces on SONiC.
"""
import logging


def parse_intf_status(lines):
    """
    @summary: Parse the output of command "intfutil description".
    @param lines: The output lines of command "intfutil description".
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
    @param hostname:
    @param interfaces: List of interfaces that need to be checked.
    """
    logging.info("Check interface status using cmd 'intfutil'")
    mg_ports  = dut.minigraph_facts(host=dut.hostname)["ansible_facts"]["minigraph_ports"]
    output = dut.command("intfutil description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    for intf in interfaces:
        expected_oper = "up" if intf in mg_ports else "down"
        expected_admin = "up" if intf in mg_ports else "down"
        if not intf in intf_status:
            logging.info("Missing status for interface %s" % intf)
            return False
        if intf_status[intf]["oper"] != expected_oper:
            logging.info("Oper status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["oper"], expected_oper))
            return False
        if intf_status[intf]["admin"] != expected_admin:
            logging.info("Admin status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["admin"], expected_admin))
            return False

    logging.info("Check interface status using the interface_facts module")
    intf_facts = dut.interface_facts(up_ports=mg_ports)["ansible_facts"]
    down_ports = intf_facts["ansible_interface_link_down_ports"]
    if len(down_ports) != 0:
        logging.info("Some interfaces are down: %s" % str(down_ports))
        return False

    return True
