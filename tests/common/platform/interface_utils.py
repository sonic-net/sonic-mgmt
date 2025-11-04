"""
Helper script for checking status of interfaces

This script contains re-usable functions for checking status of interfaces on SONiC.
"""

import re
import logging
import json
import functools
from collections import defaultdict
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


def get_dut_interfaces_status(duthost):
    output = duthost.command("show interface description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    return intf_status


def check_interface_status_of_up_ports(duthost):
    if duthost.facts['asic_type'] == 'vs' and duthost.is_supervisor_node():
        return True

    if duthost.is_multi_asic:
        up_ports = []
        for asic in duthost.frontend_asics:
            asic_cfg_facts = asic.config_facts(host=duthost.hostname, source="running",
                                               namespace=asic.namespace)['ansible_facts']
            asic_up_ports = [p for p, v in list(asic_cfg_facts['PORT'].items()) if v.get('admin_status', None) == 'up']
            up_ports.extend(asic_up_ports)
    else:
        cfg_facts = duthost.get_running_config_facts()
        up_ports = [p for p, v in list(cfg_facts['PORT'].items()) if v.get('admin_status', None) == 'up']

    intf_facts = duthost.interface_facts(up_ports=up_ports)['ansible_facts']
    if len(intf_facts['ansible_interface_link_down_ports']) != 0:
        return False
    return True


def expect_interface_status(dut, interface_name, expected_op_status):
    """
    Compare the operational status of a given interface name to an
    expected value, return True if they are equal False otherwise.
    Raises Exception if given interface name does not exist.
    """
    output = dut.command("show interface description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    status = intf_status.get(interface_name)
    if status is None:
        raise Exception(f'interface name {interface_name} does not exist')
    return status['oper'] == expected_op_status


def check_interface_status(dut, asic_index, interfaces, xcvr_skip_list):
    """
    @summary: Check the admin and oper status of the specified interfaces on DUT.
    @param dut: The AnsibleHost object of DUT. For interacting with DUT.
    @param interfaces: List of interfaces that need to be checked.
    """
    asichost = dut.asic_instance(asic_index)
    namespace = asichost.get_asic_namespace()
    logging.info("Check interface status using cmd 'show interface'")
    # TODO Remove this logic when minigraph facts supports namespace in multi_asic
    mg_ports = dut.minigraph_facts(host=dut.hostname)["ansible_facts"]["minigraph_ports"]
    if asic_index is not None:
        portmap = get_port_map(dut, asic_index)
        # Check if the interfaces of this AISC is present in mg_ports
        interface_list = {k: v for k, v in list(portmap.items()) if k in mg_ports}
        mg_ports = interface_list
    output = dut.command("show interface description")
    intf_status = parse_intf_status(output["stdout_lines"][2:])
    if dut.is_multi_asic:
        check_intf_presence_command = 'show interface transceiver presence -n {}'.format(namespace)
    else:
        check_intf_presence_command = 'show interface transceiver presence'
    check_inerfaces_presence_output = dut.command(check_intf_presence_command)["stdout_lines"][2:]
    check_inerfaces_presence_output = (
        {ports_presence.split()[0]: ports_presence.split()[1] for ports_presence in check_inerfaces_presence_output}
    )
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
            assert intf in check_inerfaces_presence_output, "Wrong interface name in the output for: %s" % str(intf)
            interface_presence = check_inerfaces_presence_output.get(intf, '')
            assert 'Present' in interface_presence, \
                "Status is not expected, presence status: %s" % str({intf: interface_presence})

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
        interfaces_per_asic = {k: v for k, v in list(interface_list.items()) if k in interfaces}
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


@functools.lru_cache(maxsize=1)
def get_port_map(dut, asic_index=None):
    """
    @summary: Get the port mapping info from the DUT
    @return: a dictionary containing the port map
    """
    logging.info("Retrieving port mapping from DUT")
    namespace = dut.get_namespace_from_asic_id(asic_index)
    config_facts = dut.config_facts(host=dut.hostname, source="running", namespace=namespace)['ansible_facts']
    port_mapping = config_facts['port_index_map']
    for k, v in list(port_mapping.items()):
        port_mapping[k] = [v]

    return port_mapping


def get_dev_conn(duthost, conn_graph_facts, asic_index):
    dev_conn = conn_graph_facts.get("device_conn", {}).get(duthost.hostname, {})

    # Get the interface pertaining to that asic
    portmap = get_port_map(duthost, asic_index)
    logging.info("Got portmap {}".format(portmap))

    if asic_index is not None:
        # Check if the interfaces of this ASIC is present in conn_graph_facts
        dev_conn = {k: v for k, v in list(portmap.items()) if k in conn_graph_facts["device_conn"][duthost.hostname]}
        logging.info("ASIC {} interface_list {}".format(asic_index, dev_conn))

    return portmap, dev_conn


def get_physical_port_indices(duthost, logical_intfs=None):
    """
    @summary: Returns dictionary map of logical ports to corresponding physical port indices
    @param logical_intfs: List of logical interfaces of the DUT
    """
    physical_port_index_dict = {}

    if logical_intfs is None:
        intf_facts = duthost.interface_facts()['ansible_facts']['ansible_interface_facts']
        phy_port = re.compile(r'^Ethernet\d+$')
        logical_intfs = [k for k in list(intf_facts.keys()) if re.match(phy_port, k)]
        logical_intfs = natsorted(logical_intfs)
        logging.info("physical interfaces = {}".format(logical_intfs))

    for asic_index in duthost.get_frontend_asic_ids():
        # Get interfaces of this asic
        interface_list = get_port_map(duthost, asic_index)
        interfaces_per_asic = {k: v for k, v in list(interface_list.items()) if k in logical_intfs}
        logging.debug("ASIC index={} interfaces = {}".format(asic_index, interfaces_per_asic))
        asic_subcommand = f'-n asic{asic_index}' if asic_index is not None else ''
        cmd_keys = f'sonic-db-cli {asic_subcommand} CONFIG_DB KEYS "PORT|Ethernet*"'
        cmd_hget = f'sonic-db-cli {asic_subcommand} CONFIG_DB HGET $key index'
        cmd = f'for key in $({cmd_keys}); do echo "$key : $({cmd_hget})" ; done'  # noqa: E702,E203
        cmd_out = duthost.command(cmd, _uses_shell=True)["stdout_lines"]
        cmd_out_dict = {}
        for line in cmd_out:
            key, index = line.split(':')
            intf_name = key.split('|')[1].strip()
            cmd_out_dict[intf_name] = int(index.strip())
        for logical_intf in interfaces_per_asic:
            physical_port_index_dict[logical_intf] = cmd_out_dict.get(logical_intf, None)

    return physical_port_index_dict


def get_dpu_npu_ports_from_hwsku(duthost):
    dpu_npu_port_list = []
    platform, hwsku = duthost.facts["platform"], duthost.facts["hwsku"]
    hwsku_file = f'/usr/share/sonic/device/{platform}/{hwsku}/hwsku.json'
    if duthost.shell(f"ls {hwsku_file}", module_ignore_errors=True)['rc'] != 0:
        return dpu_npu_port_list
    hwsku_content = duthost.shell(f"cat {hwsku_file}")["stdout"]
    hwsku_dict = json.loads(hwsku_content)
    dpu_npu_role_value = "Dpc"

    for intf, intf_config in hwsku_dict.get("interfaces").items():
        if intf_config.get("role") == dpu_npu_role_value:
            dpu_npu_port_list.append(intf)
    logging.info(f"DPU NPU ports in hwsku.json are {dpu_npu_port_list}")
    return dpu_npu_port_list


def get_fec_eligible_interfaces(duthost, supported_speeds):
    """
    Get interfaces that are operationally up, SFP present and have supported speeds.

    Args:
        duthost: The device under test.
        supported_speeds (list): A list of supported speeds for validation.

    Returns:
        interfaces (list): A list of interface names with SFP present, oper status up
        and speed in supported_speeds.
    """
    logging.info("Get output of 'show interface status'")
    intf_status = duthost.show_and_parse("show interface status")
    logging.info("Interface status: {intf_status}")

    logging.info("Get output of 'sudo sfpshow presence'")
    sfp_presence_output = duthost.show_and_parse("sudo sfpshow presence")
    logging.info("SFP presence: {sfp_presence_output}")

    sfp_presence_dict = {entry['port']: entry.get('presence', '').lower() for entry in sfp_presence_output}

    interfaces = []
    for intf in intf_status:
        intf_name = intf['interface']
        presence = sfp_presence_dict.get(intf_name, '')

        if presence != "present":
            continue

        oper = intf.get('oper', '').lower()
        speed = intf.get('speed', '')

        if oper == "up" and speed in supported_speeds:
            interfaces.append(intf_name)
        else:
            logging.info(f"Skip for {intf_name}: oper_state: {oper} speed: {speed}")

    return interfaces


def get_physical_to_logical_port_mapping(physical_port_indices):
    """
    @summary: Returns dictionary map of physical ports to corresponding logical port indices
    """
    pport_to_lport_mapping = defaultdict(list)
    for k, v in physical_port_indices.items():
        pport_to_lport_mapping[v].append(k)
    logging.debug("Physical to Logical Port Mapping: {}".format(pport_to_lport_mapping))
    return pport_to_lport_mapping


def get_lport_to_first_subport_mapping(duthost, logical_intfs=None):
    """
    @summary: Returns the first subport of logical ports.
    """
    physical_port_indices = get_physical_port_indices(duthost, logical_intfs)
    pport_to_lport_mapping = get_physical_to_logical_port_mapping(physical_port_indices)
    first_subport_dict = {k: pport_to_lport_mapping[v][0] for k, v in physical_port_indices.items()}
    logging.debug("First subports mapping: {}".format(first_subport_dict))
    return first_subport_dict
