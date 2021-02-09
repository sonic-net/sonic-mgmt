"""
Helper script for checking status of interfaces

This script contains re-usable functions for checking status of interfaces on SONiC.
"""
import json
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


def check_interface_status(dut, asic_index, interfaces, xcvr_skip_list):
    """
    @summary: Check the admin and oper status of the specified interfaces on DUT.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    asichost = dut.get_asic(asic_index)
    namespace = asichost.get_asic_namespace()
    logging.info("Check interface status using cmd 'show interface'")
    #TODO Remove this logic when minigraph facts supports namespace in multi_asic
    mg_ports = dut.minigraph_facts(host=dut.hostname)["ansible_facts"]["minigraph_ports"]
    if asic_index is not None:
        portmap = get_port_map(dut, asic_index)
        # Check if the interfaces of this AISC is present in mg_ports
        interface_list = {k:v for k, v in portmap.items() if k in mg_ports}
        mg_ports = interface_list
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
        if intf not in xcvr_skip_list:
            check_presence_output = dut.command(check_intf_presence_command.format(intf))
            presence_list = check_presence_output["stdout_lines"][2].split()
            assert intf in presence_list, "Wrong interface name in the output: %s" % str(presence_list)
            assert 'Present' in presence_list, "Status is not expected, presence status: %s" % str(presence_list)

    logging.info("Check interface status using the interface_facts module")
    intf_facts = dut.interface_facts(up_ports=mg_ports, namespace=namespace)["ansible_facts"]
    down_ports = intf_facts["ansible_interface_link_down_ports"]
    if len(down_ports) != 0:
        logging.info("Some interfaces are down: %s" % str(down_ports))
        return False

    return True

# This API to check the interface information actoss all front end ASIC's
def check_all_interface_information(dut, interfaces, xcvr_skip_list):
    for asic_index in dut.get_frontend_asic_ids():
        # Get the interfaces pertaining to that asic
        interface_list = get_port_map(dut, asic_index)
        interfaces_per_asic = {k:v for k, v in interface_list.items() if k in interfaces}
        if not all_transceivers_detected(dut, asic_index, interfaces_per_asic, xcvr_skip_list):
            logging.info("Not all transceivers are detected")
            return False
        if not check_interface_status(dut, asic_index, interfaces_per_asic, xcvr_skip_list):
            logging.info("Not all interfaces are up")
            return False

    return True

# This API to check the interface information per asic.
def check_interface_information(dut, asic_index, interfaces, xcvr_skip_list):
    if not all_transceivers_detected(dut, asic_index, interfaces, xcvr_skip_list):
        logging.info("Not all transceivers are detected on asic %s" % asic_index)
        return False
    if not check_interface_status(dut, asic_index, interfaces, xcvr_skip_list):
        logging.info("Not all interfaces are up on asic %s" % asic_index)
        return False

    return True

def get_port_map(dut, asic_index=None):
    """
    @summary: Get the port mapping info from the DUT
    @return: a dictionary containing the port map
    """
    logging.info("Retrieving port mapping from DUT")
    # copy the helper to DUT
    src_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files/getportmap.py')
    dest_path = os.path.join('/usr/share/sonic/device', dut.facts['platform'], 'plugins/getportmap.py')
    dut.copy(src=src_path, dest=dest_path)

    # execute command on the DUT to get portmap
    get_portmap_cmd = "docker exec pmon python /usr/share/sonic/platform/plugins/getportmap.py -asicid {}".format(asic_index)
    portmap_json_string = dut.command(get_portmap_cmd)["stdout"]

    # parse the json
    port_mapping = json.loads(portmap_json_string)
    assert port_mapping, "Retrieve port mapping from DUT failed"

    return port_mapping

