"""
Helper script for checking status of interfaces

This script contains re-usable functions for checking status of interfaces on SONiC.
"""

import re
import logging
from natsort import natsorted
from .transceiver_utils import all_transceivers_detected


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
        intf = fields[0]
        oper, admin, alias, desc = None, None, None, None

        if len(fields) == 4:  # when port description is empty string ""
            oper, admin, alias, desc = fields[1], fields[2], fields[3], ''
        if len(fields) > 4:
            oper, admin, alias, desc = fields[1], fields[2], fields[3], ' '.join(fields[4:])

        if oper and admin and alias:
            result[intf] = {"oper": oper, "admin": admin, "alias": alias, "desc": desc}

    return result


def check_interface_status_of_up_ports(duthost):
    if duthost.is_multi_asic:
        up_ports = []
        for asic in duthost.frontend_asics:
            asic_cfg_facts = asic.config_facts(host=duthost.hostname, source="running", namespace=asic.namespace)['ansible_facts']
            asic_up_ports = [p for p, v in asic_cfg_facts['PORT'].items() if v.get('admin_status', None) == 'up']
            up_ports.extend(asic_up_ports)
    else:
        cfg_facts = duthost.get_running_config_facts()
        up_ports = [p for p, v in cfg_facts['PORT'].items() if v.get('admin_status', None) == 'up']

    intf_facts = duthost.interface_facts(up_ports=up_ports)['ansible_facts']
    if len(intf_facts['ansible_interface_link_down_ports']) != 0:
        return False
    return True


def check_interface_status(dut, asic_index, interfaces, xcvr_skip_list):
    """
    @summary: Check the admin and oper status of the specified interfaces on DUT.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    asichost = dut.asic_instance(asic_index)
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
    if dut.is_multi_asic:
        check_intf_presence_command = 'show interface transceiver presence -n {} {}'.format(namespace, {})
    else:
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
        if intf not in xcvr_skip_list[dut.hostname]:
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
    namespace = dut.get_namespace_from_asic_id(asic_index)
    config_facts = dut.config_facts(host=dut.hostname, source="running",namespace=namespace)['ansible_facts']
    port_mapping = config_facts['port_index_map']
    for k,v in port_mapping.items():
        port_mapping[k] = [v]

    return port_mapping

def get_physical_port_indices(duthost, logical_intfs=None):
    """
    @summary: Returns dictionary map of logical ports to corresponding physical port indices
    @param logical_intfs: List of logical interfaces of the DUT
    """
    physical_port_index_dict = {}

    if logical_intfs is None:
        intf_facts = duthost.interface_facts()['ansible_facts']['ansible_interface_facts']
        phy_port = re.compile(r'^Ethernet\d+$')
        logical_intfs = [k for k in intf_facts.keys() if re.match(phy_port, k)]
        logical_intfs = natsorted(logical_intfs)
        logging.info("physical interfaces = {}".format(logical_intfs))

    for asic_index in duthost.get_frontend_asic_ids():
        # Get interfaces of this asic
        interface_list = get_port_map(duthost, asic_index)
        interfaces_per_asic = {k: v for k, v in interface_list.items() if k in logical_intfs}
        # logging.info("ASIC index={} interfaces = {}".format(asic_index, interfaces_per_asic))
        for intf in interfaces_per_asic:
            if asic_index is not None:
                cmd = 'sonic-db-cli -n asic{} CONFIG_DB HGET "PORT|{}" index'.format(asic_index, intf)
            else:
                cmd = 'sonic-db-cli CONFIG_DB HGET "PORT|{}" index'.format(intf)
            index = duthost.command(cmd)["stdout"]
            physical_port_index_dict[intf] = (int(index))

    return physical_port_index_dict
