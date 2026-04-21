#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_fex_device
short_description: Manage FEX Devices on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage FEX Devices on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is supported on ND v3.2 (NDO v4.4) and later.
author:
- Shreyas Srish (@shrsr)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric resource policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a fabric resource policy template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the FEX Device.
    type: str
    aliases: [ fex_device_name ]
  uuid:
    description:
    - The UUID of the FEX Device.
    - This parameter is required when the O(name) needs to be updated.
    - This parameter can be used instead of O(name) when an existing FEX device is updated or queried.
    type: str
    aliases: [ fex_device_uuid ]
  description:
    description:
    - The description of the FEX Device.
    type: str
  fex_id:
    description:
    - The FEX ID.
    - The value must be in the range 101 - 199.
    - This parameter is required when O(state=present).
    type: int
    aliases: [ fex_device_id ]
  nodes:
    description:
    - The list of node IDs where the FEX Device will be deployed.
    - Each element can either be a single node ID or a range of IDs.
    - This parameter is required when O(state=present).
    type: list
    elements: str
  interfaces:
    description:
    - The interface names connected to the FEX Device.
    - This parameter is required when O(state=present).
    type: list
    elements: str
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
  Use M(cisco.mso.ndo_template) to create the Fabric Policy template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a FEX Device
  cisco.mso.ndo_fex_device:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_fex_device
    description: "FEX Device for Ansible"
    fex_id: 102
    nodes: [101, 102, 103-105]
    interfaces: ["1/1"]
    state: present
  register: create_fex_device

- name: Query a FEX Device by name
  cisco.mso.ndo_fex_device:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_fex_device
    state: query
  register: query_name

- name: Query a FEX Device by UUID
  cisco.mso.ndo_fex_device:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    uuid: '{{ create_fex_device.current.uuid }}'
    state: query
  register: query_uuid

- name: Query all FEX Devices
  cisco.mso.ndo_fex_device:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    state: query
  register: query_all

- name: Delete a FEX Device by name
  cisco.mso.ndo_fex_device:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    name: ansible_test_fex_device
    state: absent

- name: Delete a FEX Device by UUID
  cisco.mso.ndo_fex_device:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test_template
    uuid: '{{ create_fex_device.current.uuid }}'
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)
from ansible_collections.cisco.mso.plugins.module_utils.template import (
    MSOTemplate,
    KVPair,
)
from ansible_collections.cisco.mso.plugins.module_utils.utils import (
    append_update_ops_data,
)
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["fex_device_name"]),
        uuid=dict(type="str", aliases=["fex_device_uuid"]),
        description=dict(type="str"),
        fex_id=dict(type="int", aliases=["fex_device_id"]),
        nodes=dict(type="list", elements="str"),
        interfaces=dict(type="list", elements="str"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name", "uuid"], True],
            ["state", "absent", ["name", "uuid"], True],
            ["state", "present", ["fex_id", "nodes", "interfaces"]],
        ],
        required_one_of=[["template", "template_id"]],
        mutually_exclusive=[
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    fex_id = module.params.get("fex_id")
    nodes = module.params.get("nodes")
    interfaces = module.params.get("interfaces")
    if interfaces:
        interfaces = ",".join(interfaces)
    state = module.params.get("state")

    ops = []
    match = None
    fex_device_path = None

    mso_template = MSOTemplate(mso, "fabric_resource", template, template_id)
    mso_template.validate_template("fabricResource")
    object_description = "Fex Device"
    path = "/fabricResourceTemplate/template/fexDevices"

    existing_fex_devices = mso_template.template.get("fabricResourceTemplate", {}).get("template", {}).get("fexDevices") or []

    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_fex_devices,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            fex_device_path = "{0}/{1}".format(path, match.index)
            mso_template.update_config_with_template_and_references(match.details)
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = [mso_template.update_config_with_template_and_references(device) for device in existing_fex_devices]

    if state == "present":
        mso_values = dict(
            name=name,
            description=description,
            fexId=fex_id,
            nodes=nodes,
            interfaces=interfaces,
        )

        if match:
            append_update_ops_data(ops, match.details, fex_device_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="{0}/-".format(path), value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=fex_device_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        fex_devices = response.get("fabricResourceTemplate", {}).get("template", {}).get("fexDevices") or []
        match = mso_template.get_object_by_key_value_pairs(object_description, fex_devices, [KVPair("uuid", uuid) if uuid else KVPair("name", name)])
        if match:
            mso_template.update_config_with_template_and_references(match.details)
            mso.existing = match.details
        else:
            mso.existing = {}
    elif module.check_mode and state != "query":
        mso_template.update_config_with_template_and_references(mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
