#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_inventory
version_added: '1.0.0'
short_description: Collect information from Pure Storage FlashBlade
description:
  - Collect information from a Pure Storage FlashBlade running the
    Purity//FB operating system. By default, the module will collect basic
    information including hosts, host groups, protection
    groups and volume counts. Additional information can be collected
    based on the configured set of arguements.
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
extends_documentation_fragment:
  - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: collect FlashBlade inventory
  purestorage.flashblade.purefb_inventory:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: blade_info
- name: show default information
  debug:
    msg: "{{ blade_info['purefb_info'] }}"
"""

RETURN = r"""
purefb_inventory:
  description: Returns the inventory information for the FlashBlade
  returned: always
  type: dict
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


PART_NUMBER_API_VERSION = "2.8"


def generate_hardware_dict(blade):
    api_version = list(blade.get_versions().items)
    hw_info = {
        "modules": {},
        "ethernet": {},
        "mgmt_ports": {},
        "fans": {},
        "bays": {},
        "controllers": {},
        "blades": {},
        "chassis": {},
        "power": {},
        "switch": {},
    }
    components = list(blade.get_hardware(filter="type='fm'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["modules"][component_name] = {
            "slot": components[component].slot,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
            "identify": components[component].identify_enabled,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["modules"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='eth'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["ethernet"][component_name] = {
            "slot": components[component].slot,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
            "speed": components[component].speed,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["ethernet"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='mgmt_port'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["mgmt_ports"][component_name] = {
            "slot": components[component].slot,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
            "speed": components[component].speed,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["mgmt_ports"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='fan'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["fans"][component_name] = {
            "slot": components[component].slot,
            "status": components[component].status,
            "identify": components[component].identify_enabled,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["fans"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='fb'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["blades"][component_name] = {
            "slot": components[component].slot,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
            "temperature": components[component].temperature,
            "identify": components[component].identify_enabled,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["blades"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='pwr'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["power"][component_name] = {
            "slot": components[component].slot,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["power"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='xfm'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["switch"][component_name] = {
            "slot": components[component].slot,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["switch"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='ch'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["chassis"][component_name] = {
            "slot": components[component].slot,
            "index": components[component].index,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["chassis"][component_name]["part_number"] = components[
                component
            ].part_number
    components = list(blade.get_hardware(filter="type='bay'").items)
    for component in range(len(components)):
        component_name = components[component].name
        hw_info["bays"][component_name] = {
            "slot": components[component].slot,
            "index": components[component].index,
            "status": components[component].status,
            "serial": components[component].serial,
            "model": components[component].model,
            "identify": components[component].identify_enabled,
        }
        if PART_NUMBER_API_VERSION in api_version:
            hw_info["bays"][component_name]["part_number"] = components[
                component
            ].part_number

    return hw_info


def main():
    argument_spec = purefb_argument_spec()

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    blade = get_system(module)
    module.exit_json(changed=False, purefb_info=generate_hardware_dict(blade))


if __name__ == "__main__":
    main()
