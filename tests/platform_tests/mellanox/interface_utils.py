"""
Helper utilities for interface operations specific to Mellanox platforms.

This module contains functions for working with interface information,
physical paths, and port mappings on Mellanox devices.
"""

import re
import json
import functools
from tests.common.platform.interface_utils import get_lport_to_first_subport_mapping


@functools.lru_cache(maxsize=1)
def get_interfaces_info(duthost):
    asics_name_list = [f' -n {asic.namespace}' for asic in duthost.frontend_asics] if duthost.is_multi_asic else ['']
    interfaces_info = {}
    for asic in asics_name_list:
        cmd = f"sonic-cfggen{asic} -d --print-data"
        db_output = json.loads(duthost.command(cmd)["stdout"])
        interfaces_info.update(db_output["PORT"])
    return interfaces_info


def get_alias_number(port_alias):
    """
    :param port_alias:  the sonic port alias, e.g. 'etp1', 'etp1a' etc.
    :return: the number in the alias, e.g. 1
    """
    return re.search(r'etp(\d+)', port_alias).group(1)


def get_alias_letter(port_alias):
    """
    :param port_alias:  the sonic port alias, e.g. 'etp1', 'etp1a' etc.
    :return: empty string for etp<number> (no split) or the letter in the alias for etp<number><letter>
    """
    match = re.search(r'etp(\d+)([a-z])?', port_alias)
    if match and match.group(2):
        return match.group(2)
    return ''


def convert_letter_to_number(letter):
    """
    :param letter: a single letter (a-z)
    :return: corresponding number (1-26)
    """
    if letter == '':
        return '0'
    return str(ord(letter.lower()) - ord('a') + 1)


@functools.lru_cache(maxsize=1)
def get_interface_index_and_subport(duthost, interface):
    interfaces_info = get_interfaces_info(duthost)
    interface_alias = interfaces_info[interface]["alias"]
    interface_index = get_alias_number(interface_alias)
    interface_subport = convert_letter_to_number(get_alias_letter(interface_alias))
    return interface_index, interface_subport


def get_interfaces_physical_path(duthost, interfaces):
    interfaces_full_path = {}
    lport_to_first_subport_mapping = get_lport_to_first_subport_mapping(duthost, interfaces)
    first_port_in_split = set(lport_to_first_subport_mapping.values())
    for intf in interfaces:
        intf_idx, intf_subport = get_interface_index_and_subport(duthost, intf)
        interfaces_full_path[intf] = f"{intf_idx}/{intf_subport}" if intf not in first_port_in_split else intf_idx
    return interfaces_full_path


def get_physical_index_to_interfaces_map(duthost, only_ports_index_up=False):
    """
    @summary: Get mapping of physical port indices to their corresponding Ethernet ports.
    @return: A dictionary where key is the physical index and value is a list of Ethernet ports
             Example: {1: ["Ethernet0", "Ethernet1"], 2: ["Ethernet3"]}
    """
    physical_index_to_interfaces_map = {}
    interfaces_info = get_interfaces_info(duthost)
    for interface, info in interfaces_info.items():
        physical_index = info["index"]
        if only_ports_index_up and info.get("admin_status", "down") != "up":
            continue
        physical_index_to_interfaces_map.setdefault(physical_index, []).append(interface)
    return physical_index_to_interfaces_map
