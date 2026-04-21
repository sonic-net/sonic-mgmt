#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>
# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_physical_interface
short_description: Manage Physical Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Physical Interfaces on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.2 (NDO v4.4) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric resource policy template.
    type: str
    required: true
  name:
    description:
    - The name of the Physical Interface.
    type: str
    aliases: [ physical_interface ]
  uuid:
    description:
    - The UUID of the Physical Interface.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ physical_interface_uuid ]
  description:
    description:
    - The description of the Physical Interface.
    type: str
  nodes:
    description:
    - The node IDs where the Physical Interface policy will be deployed.
    - Each element can either be a single node ID or a range of IDs.
    type: list
    elements: str
  interfaces:
    description:
    - The interface names where the policy will be deployed.
    - The old O(interfaces) will be replaced with the new O(interfaces) during an update.
    type: list
    elements: str
  physical_interface_type:
    description:
    - The type of the interface policy group.
    type: str
    choices: [ physical, breakout ]
  physical_policy_uuid:
    description:
    - The UUID of the Interface Setting Policy.
    - This is only required when creating a new Interface Setting Policy.
    - This parameter is required when O(physical_interface_type) is C(physical).
    - This parameter can be used instead of O(physical_policy).
    type: str
    aliases: [ policy_uuid, interface_policy_uuid , interface_policy_group_uuid, interface_setting_uuid]
  physical_policy:
    description:
    - The interface group policy required for physical Interface Setting Policy.
    - This parameter is required when O(physical_interface_type) is C(physical).
    - This parameter can be used instead of O(physical_policy_uuid).
    type: dict
    suboptions:
      name:
        description:
        - The name of the Interface Setting Policy.
        type: str
      template:
        description:
        - The name of the template in which is referred the Interface Setting Policy.
        type: str
    aliases: [ policy, interface_policy, interface_policy_group, interface_setting ]
  breakout_mode:
    description:
    - Breakout mode enables breaking down an ethernet port into multiple low-speed ports.
    - This parameter is available only when O(physical_interface_type) is C(breakout).
    - The default value is C(4x10G).
    type: str
    choices: [ 4x10G, 4x25G, 4x100G ]
  interface_descriptions:
    description:
    - The interface settings defined in the interface settings policy will be applied to the interfaces on the node IDs configured in C(nodes).
    - This parameter when set to an empty list during an update will clear all the existing interface descriptions.
    - The API will trigger an error when there are duplicate interface IDs in the list.
    type: list
    elements: dict
    suboptions:
      interface_id:
        description:
        - The interface ID.
        type: str
      description:
        description:
        - The description of the interface.
        type: str
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
notes:
- The O(template) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_template) to create the Tenant template.
- The O(physical_policy) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_interface_setting) to create the Interface Setting Policy.
- The O(physical_policy_uuid) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_interface_setting) to create the Interface Setting Policy UUID.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a Physical Interface with physical_interface_type set to physical
  cisco.mso.ndo_physical_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_physical_interface_physical
    description: "Physical Interface for Ansible Test"
    nodes: [101, 102, 103-105]
    interfaces: "1/1"
    physical_interface_type: physical
    physical_policy: ansible_test_interface_setting_policy_uuid
    state: present
  register: create_physical_interface_type_physical

- name: Create a Physical Interface with physical_interface_type set to breakout
  cisco.mso.ndo_physical_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_physical_interface_breakout
    description: "breakout interface for Ansible Test"
    nodes: [101, 102, 103-105]
    interfaces: "1/1"
    physical_interface_type: breakout
    breakout_mode: 4x25G
    interface_descriptions:
      - interface_id: "1/1"
        description: "Interface description for 1/1"
    state: present
  register: create_physical_interface_type_breakout

- name: Query all physical interfaces
  cisco.mso.ndo_physical_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    state: query
  register: query_all

- name: Query a specific Physical Interface with name
  cisco.mso.ndo_physical_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_physical_interface_physical
    state: query
  register: query_one_name

- name: Query a specific Physical Interface with UUID
  cisco.mso.ndo_physical_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    uuid: "{{ create_physical_interface_type_breakout.current.uuid }}"
    state: query
  register: query_one_uuid

- name: Delete a Physical Interface with name
  cisco.mso.ndo_physical_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_physical_interface_physical
    state: absent

- name: Delete a Physical Interface with UUID
  cisco.mso.ndo_physical_interface:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    uuid: "{{ query_one_uuid.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
    format_interface_descriptions,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dict(
            template=dict(type="str", required=True),
            name=dict(type="str", aliases=["physical_interface"]),
            uuid=dict(type="str", aliases=["physical_interface_uuid"]),
            description=dict(type="str"),
            nodes=dict(type="list", elements="str"),
            interfaces=dict(type="list", elements="str"),
            physical_interface_type=dict(type="str", choices=["physical", "breakout"]),
            physical_policy_uuid=dict(type="str", aliases=["policy_uuid", "interface_policy_uuid", "interface_policy_group_uuid", "interface_setting_uuid"]),
            physical_policy=dict(
                type="dict",
                options=dict(
                    name=dict(type="str"),
                    template=dict(type="str"),
                ),
                aliases=["policy", "interface_policy", "interface_policy_group", "interface_setting"],
            ),
            breakout_mode=dict(type="str", choices=["4x10G", "4x25G", "4x100G"]),
            interface_descriptions=dict(
                type="list",
                elements="dict",
                options=dict(
                    interface_id=dict(type="str"),
                    description=dict(type="str"),
                ),
            ),
            state=dict(type="str", default="query", choices=["absent", "query", "present"]),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name", "uuid"], True],
            ["state", "absent", ["name", "uuid"], True],
        ],
        mutually_exclusive=[("physical_policy", "breakout_mode"), ("physical_policy", "physical_policy_uuid")],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    nodes = module.params.get("nodes")
    interfaces = module.params.get("interfaces")
    if interfaces:
        interfaces = ",".join(interfaces)
    physical_interface_type = module.params.get("physical_interface_type")
    physical_policy_uuid = module.params.get("physical_policy_uuid")
    physical_policy = module.params.get("physical_policy")
    breakout_mode = module.params.get("breakout_mode")
    interface_descriptions = module.params.get("interface_descriptions")
    state = module.params.get("state")

    ops = []
    match = None
    physical_interface_attrs_path = None

    mso_template = MSOTemplate(mso, "fabric_resource", template)
    mso_template.validate_template("fabricResource")
    object_description = "Physical Interface Profile"
    path = "/fabricResourceTemplate/template/interfaceProfiles"

    existing_physical_interfaces = mso_template.template.get("fabricResourceTemplate", {}).get("template", {}).get("interfaceProfiles") or []

    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_physical_interfaces,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            physical_interface_attrs_path = "{0}/{1}".format(path, match.index)
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_physical_interfaces

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        if physical_policy and not physical_policy_uuid:
            fabric_policy_template = MSOTemplate(mso, "fabric_policy", physical_policy.get("template"))
            fabric_policy_template.validate_template("fabricPolicy")
            physical_policy_uuid = fabric_policy_template.get_interface_policy_group_uuid(physical_policy.get("name"))

        mso_values = dict(
            name=name,
            description=description,
            nodes=nodes,
            interfaces=interfaces,
            policyGroupType=physical_interface_type,
        )

        if physical_interface_type == "physical" and physical_policy_uuid:
            mso_values["policy"] = physical_policy_uuid

        if physical_interface_type == "breakout" and breakout_mode:
            mso_values["breakoutMode"] = breakout_mode

        if interface_descriptions:
            mso_values["interfaceDescriptions"] = format_interface_descriptions(mso, interface_descriptions, "")

        if mso.existing and match:
            proposed_payload = copy.deepcopy(mso.existing)
            mso_values_remove = list()

            if physical_interface_type and match.details.get("policyGroupType") != physical_interface_type:
                mso.fail_json(msg="ERROR: Physical Interface type cannot be changed.")

            if interface_descriptions == [] and proposed_payload.get("interfaceDescriptions"):
                mso_values_remove.append("interfaceDescriptions")

            append_update_ops_data(ops, match.details, physical_interface_attrs_path, mso_values, mso_values_remove)
            mso.sanitize(match.details, collate=True)

        else:
            if not nodes:
                mso.fail_json(msg=("ERROR: Missing 'nodes' for creating a Physical Interface."))

            if not physical_interface_type:
                mso.fail_json(msg=("ERROR: Missing Physical Interface type for creating a Physical Interface."))

            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=physical_interface_attrs_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        physical_interfaces = response.get("fabricResourceTemplate", {}).get("template", {}).get("interfaceProfiles") or []
        match = mso_template.get_object_by_key_value_pairs(object_description, physical_interfaces, [KVPair("uuid", uuid) if uuid else KVPair("name", name)])
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
