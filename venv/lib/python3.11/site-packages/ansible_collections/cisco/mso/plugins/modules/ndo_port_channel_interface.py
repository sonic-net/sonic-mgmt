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
module: ndo_port_channel_interface
short_description: Manage Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Port Channel Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.2 (NDO v4.4) and later.
author:
- Gaspard Micol (@gmicol)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Fabric Resource template.
    type: str
    required: true
  name:
    description:
    - The name of the Port Channel Interface.
    type: str
    aliases: [ port_channel_interface, port_channel ]
  uuid:
    description:
    - The UUID of the Port Channel Interface.
    - This parameter can be used instead of O(port_channel_interface)
      when an existing Port Channel Interface is updated.
    - This parameter is required when parameter O(port_channel_interface) is updated.
    type: str
    aliases: [ port_channel_interface_uuid, port_channel_uuid ]
  description:
    description:
    - The description of the Port Channel Interface.
    type: str
  node:
    description:
    - The node ID.
    - This is only required when creating a new Port Channel Interface.
    type: str
  interfaces:
    description:
    - The list of used Interface IDs.
    - Ranges of Interface IDs can be used.
    - This is only required when creating a new Port Channel Interface.
    type: list
    elements: str
    aliases: [ members ]
  interface_policy_group_uuid:
    description:
    - The UUID of the Port Channel Interface Policy Group.
    - This is only required when creating a new Port Channel Interface.
    type: str
    aliases: [ policy_uuid, interface_policy_uuid, interface_setting_uuid ]
  interface_policy_group:
    description:
    - The Port Channel Interface Policy Group.
    - This parameter can be used instead of O(interface_policy_group_uuid).
    - If both parameter are used, O(interface_policy_group) will be ignored.
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
    - The list of interface descriptions of the Port Channel Interface.
    - Providing a new list of O(interface_descriptions) will completely
      replace an existing one from the Port Channel Interface.
    - Providing an empty list will remove the O(interface_descriptions=[])
      from the Port Channel Interface.
    type: list
    elements: dict
    suboptions:
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
- name: Create a new Port Channel Interface
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    description: My Ansible Port Channel
    name: ansible_port_channel_interface
    node: 101
    interfaces:
      - 1/1
      - 1/10-11
    interface_policy_group:
      name: ansible_policy_group
      template: ansible_fabric_policy_template
    interface_descriptions:
      - interface_id: 1/1
        description: My single Ansible Interface
      - interface_id: 1/10-11
        description: My group of Ansible Interfaces
    state: present
  register: port_channel_interface_1

- name: Update a Port Channel Interface's name with UUID
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    name: ansible_port_channel_interface_changed
    uuid: "{{ port_channel_interface_1.current.uuid }}"
    state: present

- name: Update a Port Channel Interface's interfaces and their descriptions
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    name: ansible_port_channel_interface_changed
    interfaces:
      - 1/1
      - 1/3
      - 1/5-7
    interface_descriptions:
      - interface_id: 1/1
        description: My single unchanged Ansible Interface
      - interface_id: 1/3
        description: My new single Ansible Interface
      - interface_id: 1/5-7
        description: My new group of Ansible Interfaces
    state: present

- name: Query a Port Channel Interface with name
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    name: ansible_port_channel_interface_changed
    state: query
  register: query_name

- name: Query a Port Channel Interface with UUID
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    uuid: "{{ port_channel_interface_1.current.uuid }}"
    state: query
  register: query_uuid

- name: Query all Port Channel Interfaces in a Fabric Resource Template
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    state: query
  register: query_all

- name: Delete a Port Channel Interface with name
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    name: ansible_port_channel_interface_changed
    state: absent

- name: Delete a Port Channel Interface with UUID
  cisco.mso.ndo_port_channel_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_fabric_resource_template
    uuid: "{{ port_channel_interface_1.current.uuid }}"
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
        template=dict(type="str", required=True),
        name=dict(type="str", aliases=["port_channel_interface", "port_channel"]),
        uuid=dict(type="str", aliases=["port_channel_interface_uuid", "port_channel_uuid"]),
        description=dict(type="str"),
        node=dict(type="str"),
        interfaces=dict(type="list", elements="str", aliases=["members"]),
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
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    node = module.params.get("node")
    interfaces = module.params.get("interfaces")
    if isinstance(interfaces, list):
        interfaces = ",".join(interfaces)
    interface_policy_group = module.params.get("interface_policy_group")
    interface_policy_group_uuid = module.params.get("interface_policy_group_uuid")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")

    existing_port_channel_interfaces = mso_template.template.get("fabricResourceTemplate", {}).get("template", {}).get("portChannels", [])
    object_description = "Port Channel Interface"
    port_channel_attrs_path = None
    match = None

    policy_match = dict()

    if state in ["query", "absent"] and not existing_port_channel_interfaces:
        mso.exit_json()
    elif state == "query" and not (name or uuid):
        for port_channel in existing_port_channel_interfaces:
            policy_match = mso_template.get_fabric_template_object_by_key_value(
                "pcPolicyGroup", "Interface Settings", [KVPair("uuid", port_channel.get("policy"))]
            )
            port_channel["policyName"] = policy_match.get("name")
        mso.existing = existing_port_channel_interfaces
    elif existing_port_channel_interfaces and (name or uuid):
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_port_channel_interfaces,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            port_channel_attrs_path = "/fabricResourceTemplate/template/portChannels/{0}".format(match.index)

            policy_match = mso_template.get_fabric_template_object_by_key_value(
                "pcPolicyGroup", "Interface Settings", [KVPair("uuid", match.details.get("policy"))]
            )
            match.details["policyName"] = policy_match.get("name")

            mso.existing = mso.previous = copy.deepcopy(match.details)

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if interface_policy_group_uuid:
            policy_match = mso_template.get_fabric_template_object_by_key_value(
                "pcPolicyGroup", "Interface Settings", [KVPair("uuid", interface_policy_group_uuid)]
            )
        elif interface_policy_group and interface_policy_group.get("name"):
            policy_match = mso_template.get_fabric_template_object_by_key_value(
                "pcPolicyGroup",
                "Interface Settings",
                [KVPair("name", interface_policy_group.get("name")), KVPair("templateName", interface_policy_group.get("template"))],
                True,
            )
            interface_policy_group_uuid = policy_match.get("uuid")

        mso_values = dict(
            name=name,
            node=node,
            memberInterfaces=interfaces,
            policy=interface_policy_group_uuid,
            description=description,
        )

        if mso.existing and match:
            if node and interface_descriptions:
                interface_descriptions = format_interface_descriptions(mso, interface_descriptions, node)
            elif node and interface_descriptions is None and mso.existing.get("interfaceDescriptions"):
                interface_descriptions = format_interface_descriptions(mso, mso.existing["interfaceDescriptions"], node)
            elif node is None and interface_descriptions:
                interface_descriptions = format_interface_descriptions(mso, interface_descriptions, mso.existing["node"])
            mso_values["interfaceDescriptions"] = interface_descriptions
            append_update_ops_data(ops, match.details, port_channel_attrs_path, copy.deepcopy(mso_values))
            mso_values["policyName"] = policy_match.get("name")
            mso.sanitize(match.details, collate=True)
        else:
            if not node:
                mso.fail_json(msg=("Missing parameter 'node' for creating a Port Channel Interface"))
            mso_values["interfaceDescriptions"] = format_interface_descriptions(mso, interface_descriptions, node)
            ops.append(dict(op="add", path="/fabricResourceTemplate/template/portChannels/-", value=copy.deepcopy(mso_values)))
            mso_values["policyName"] = policy_match.get("name")
            mso.sanitize(mso_values)

    elif state == "absent":
        if mso.existing and match:
            ops.append(dict(op="remove", path=port_channel_attrs_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        port_channel_interfaces = response.get("fabricResourceTemplate", {}).get("template", {}).get("portChannels", []) or []
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            port_channel_interfaces,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            policy_match = mso_template.get_fabric_template_object_by_key_value(
                "pcPolicyGroup", "Interface Settings", [KVPair("uuid", match.details.get("policy"))]
            )
            match.details["policyName"] = policy_match.get("name")
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
