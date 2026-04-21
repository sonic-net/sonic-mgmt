#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: ndo_virtual_port_channel_interface
short_description: Manage Virtual Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Virtual Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.2 (NDO v4.4) and later.
author:
- Gaspard Micol (@gmicol)
options:
  template:
    description:
    - The name of the Fabric Resource template.
    - This parameter or O(template_id) is required.
    type: str
    aliases: [ fabric_resource_template ]
  template_id:
    description:
    - The ID of the Fabric Policy template.
    - This parameter or O(template) is required.
    type: str
    aliases: [ fabric_resource_template_id ]
  name:
    description:
    - The name of the Virtual Port Channel Interface.
    type: str
    aliases: [ virtual_port_channel_interface, virtual_port_channel, vpc ]
  uuid:
    description:
    - The UUID of the Virtual Port Channel Interface.
    - This parameter can be used instead of O(virtual_port_channel_interface)
      when an existing Virtual Port Channel Interface is updated.
    - This parameter is required when parameter O(name) is updated.
    type: str
    aliases: [ virtual_port_channel_interface_uuid, virtual_port_channel_uuid, vpc_uuid ]
  description:
    description:
    - The description of the Virtual Port Channel Interface.
    type: str
  node_1:
    description:
    - The first node ID.
    type: str
  node_2:
    description:
    - The second node ID.
    type: str
  interfaces_node_1:
    description:
    - The list of used Interface IDs for the first node.
    - Ranges of Interface IDs can be used.
    - This parameter is required when creating a new Virtual Port Channel Interface.
    type: list
    elements: str
    aliases: [ interfaces_1, members_1 ]
  interfaces_node_2:
    description:
    - The list of used Interface IDs for the second node.
    - Ranges of Interface IDs can be used.
    - This parameter is required when creating a new Virtual Port Channel Interface.
    - If O(interfaces_node_2=[mirror]) and O(interfaces_node_1) is clearly defined,
      the interfaces of O(interfaces_node_1) will be mirrored in O(interfaces_node_2).
    type: list
    elements: str
    aliases: [ interfaces_2, members_2 ]
  interface_policy_group_uuid:
    description:
    - The UUID of the Port Channel Interface Policy Group.
    - This parameter is required when creating a new Virtual Port Channel Interface.
    type: str
    aliases: [ policy_uuid, interface_policy_uuid, interface_setting_uuid ]
  interface_policy_group:
    description:
    - The Port Channel Interface Policy Group.
    - This parameter can be used instead of O(interface_policy_group_uuid).
    type: dict
    suboptions:
      name:
        description:
        - The name of the Interface Policy Group.
        type: str
        required: true
      template:
        description:
        - The name of the template in which the Interface Policy Group has been created.
        type: str
        required: true
    aliases: [ policy, interface_policy, interface_setting ]
  interface_descriptions:
    description:
    - The list of interface descriptions of the Virtual Port Channel Interface.
    - Providing a new list of O(interface_descriptions) will completely
      replace an existing one from the Virtual Port Channel Interface.
    - Providing an empty list will remove the O(interface_descriptions=[])
      from the Virtual Port Channel Interface.
    type: list
    elements: dict
    suboptions:
      node:
        description:
        - The node ID.
        type: str
        required: true
      interface_id:
        description:
        - The interface ID or a range of interface IDs.
        - Using a range of interface IDs will
          apply the same O(interface_descriptions.description) for every ID in range.
        type: str
        required: true
      description:
        description:
        - The description of the interface or group of interfaces.
        type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Fabric Resource template.
- The O(interface_policy_group) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_interface_setting) to create the Interface Policy Group of type Port Channel.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_interface_setting
"""

EXAMPLES = r"""
- name: Create a new Virtual Port Channel Interface
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    description: My Ansible Port Channel
    name: ansible_virtual_port_channel_interface
    node_1: 101
    node_2: 102
    interfaces_node_1:
      - 1/1
      - 1/10-11
    interfaces_node_2:
      - 1/2
    interface_policy_group:
      name: ansible_policy_group
      template: ansible_fabric_policy_template
    interface_descriptions:
      - node: 101
        interface_id: 1/1
        description: My single Ansible Interface for first node
      - node: 101
        interface_id: 1/10-11
        description: My group of Ansible Interface for first node
      - node: 102
        interface_id: 1/2
        description: My single Ansible Interface for second node
    state: present
  register: virtual_port_channel_interface_1

- name: Update a Virtual Port Channel Interface's interfaces and their descriptions
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    description: My Ansible Port Channel
    name: ansible_virtual_port_channel_interface
    node_1: 101
    node_2: 102
    interfaces_node_1:
      - 1/1
      - 1/5-7
    interfaces_node_2:
      - 1/1-2
    interface_descriptions:
      - node: 101
        interface_id: 1/1
        description: My single unchanged Ansible Interface for first node
      - node: 101
        interface_id: 1/5-7
        description: My new group of Ansible Interface for first node
      - node: 102
        interface_id: 1/1-2
        description: My new group of Ansible Interfaces for second node
    state: present

- name: Update a Virtual Port Channel Interface by mirroring node 1 and node 2 interfaces
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    description: My Ansible Port Channel
    name: ansible_virtual_port_channel_interface
    node_1: 101
    node_2: 102
    interfaces_node_1:
      - 1/1-9
      - 1/11-15
    interfaces_node_2: mirror
    state: present

- name: Update a Virtual Port Channel Interface's name with UUID
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    name: ansible_virtual_port_channel_interface_changed
    uuid: "{{ virtual_port_channel_interface_1.current.uuid }}"
    state: present

- name: Query a Virtual Port Channel Interface with name
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    name: ansible_virtual_port_channel_interface_changed
    state: query
  register: query_name

- name: Query a Virtual Port Channel Interface with UUID
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    uuid: "{{ virtual_port_channel_interface_1.current.uuid }}"
    state: query
  register: query_uuid

- name: Query all Virtual Port Channel Interfaces in a Fabric Resource Template
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    state: query
  register: query_all

- name: Delete a Virtual Port Channel Interface with name
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    name: ansible_virtual_port_channel_interface_changed
    state: absent

- name: Delete a Virtual Port Channel Interface with UUID
  cisco.mso.ndo_virtual_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    uuid: "{{ virtual_port_channel_interface_1.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
    format_interface_descriptions,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", aliases=["fabric_resource_template"]),
        template_id=dict(type="str", aliases=["fabric_resource_template_id"]),
        name=dict(type="str", aliases=["virtual_port_channel_interface", "virtual_port_channel", "vpc"]),
        uuid=dict(type="str", aliases=["virtual_port_channel_interface_uuid", "virtual_port_channel_uuid", "vpc_uuid"]),
        description=dict(type="str"),
        node_1=dict(type="str"),
        node_2=dict(type="str"),
        interfaces_node_1=dict(type="list", elements="str", aliases=["interfaces_1", "members_1"]),
        interfaces_node_2=dict(type="list", elements="str", aliases=["interfaces_2", "members_2"]),
        interface_policy_group=dict(
            type="dict",
            options=dict(
                name=dict(type="str", required=True),
                template=dict(type="str", required=True),
            ),
            aliases=["policy", "interface_policy", "interface_setting"],
        ),
        interface_policy_group_uuid=dict(type="str", aliases=["policy_uuid", "interface_policy_uuid", "interface_setting_uuid"]),
        interface_descriptions=dict(
            type="list",
            elements="dict",
            options=dict(
                node=dict(type="str", required=True),
                interface_id=dict(type="str", required=True),
                description=dict(type="str"),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["name", "uuid"], True],
        ],
        required_one_of=[
            ("template", "template_id"),
        ],
        mutually_exclusive=[
            ("template", "template_id"),
            ("interface_policy_group", "interface_policy_group_uuid"),
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    node_1 = module.params.get("node_1")
    node_2 = module.params.get("node_2")
    interfaces_node_1 = module.params.get("interfaces_node_1")
    if isinstance(interfaces_node_1, list):
        interfaces_node_1 = ",".join(interfaces_node_1)
    interfaces_node_2 = module.params.get("interfaces_node_2")
    if isinstance(interfaces_node_2, list):
        if interfaces_node_2[0] == "mirror" and interfaces_node_1:
            interfaces_node_2 = interfaces_node_1
        else:
            interfaces_node_2 = ",".join(interfaces_node_2)
    interface_policy_group = module.params.get("interface_policy_group")
    interface_policy_group_uuid = module.params.get("interface_policy_group_uuid")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    match = None
    ops = []

    mso_template = MSOTemplate(mso, "fabric_resource", template, template_id)
    mso_template.validate_template("fabricResource")

    existing_virtual_port_channel_interfaces = mso_template.template.get("fabricResourceTemplate", {}).get("template", {}).get("virtualPortChannels", [])
    object_description = "Virtual Port Channel Interface"

    if state in ["query", "absent"] and not existing_virtual_port_channel_interfaces:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        mso.existing = existing_virtual_port_channel_interfaces
    elif existing_virtual_port_channel_interfaces and (name or uuid):
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_virtual_port_channel_interfaces,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)

    if state != "query":
        virtual_port_channel_attrs_path = "/fabricResourceTemplate/template/virtualPortChannels/{0}".format(match.index if match else "-")

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if interface_policy_group:
            fabric_policy_template = MSOTemplate(mso, "fabric_policy", interface_policy_group.get("template"))
            fabric_policy_template.validate_template("fabricPolicy")
            interface_policy_group_uuid = fabric_policy_template.get_interface_policy_group_uuid(interface_policy_group.get("name"))

        if match:
            mso_values = {
                "name": name,
                "description": description,
                ("node1Details", "node"): node_1,
                ("node1Details", "memberInterfaces"): interfaces_node_1,
                ("node2Details", "node"): node_2,
                ("node2Details", "memberInterfaces"): interfaces_node_2,
                "policy": interface_policy_group_uuid,
                "interfaceDescriptions": format_interface_descriptions(mso, interface_descriptions),
            }
            append_update_ops_data(ops, match.details, virtual_port_channel_attrs_path, mso_values)
            mso.sanitize(match.details, collate=True)

        else:
            mso_values = {
                "name": name,
                "description": description,
                "node1Details": {
                    "node": node_1,
                    "memberInterfaces": interfaces_node_1,
                },
                "node2Details": {
                    "node": node_2,
                    "memberInterfaces": interfaces_node_2,
                },
                "policy": interface_policy_group_uuid,
                "interfaceDescriptions": format_interface_descriptions(mso, interface_descriptions),
            }
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=virtual_port_channel_attrs_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=virtual_port_channel_attrs_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        virtual_port_channel_interfaces = response.get("fabricResourceTemplate", {}).get("template", {}).get("virtualPortChannels", []) or []
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            virtual_port_channel_interfaces,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
