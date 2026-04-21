#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_vlan_pool
short_description: Manage VLAN Pools on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage VLAN Pools on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be a fabric policy template.
    type: str
    required: true
  vlan_pool:
    description:
    - The name of the VLAN Pool.
    type: str
    aliases: [ name ]
  vlan_pool_uuid:
    description:
    - The uuid of the VLAN Pool.
    - This parameter is required when the O(vlan_pool) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the VLAN Pool.
    type: str
  vlan_ranges:
    description:
    - A list of vlan ranges attached to the VLAN Pool.
    - The list of configured vlan ranges must contain at least one entry.
    - When the list of vlan ranges is null the update will not change existing entry configuration.
    type: list
    elements: dict
    suboptions:
      from_vlan:
        description:
        - The start of the VLAN range.
        type: int
        required: true
        aliases: [ from ]
      to_vlan:
        description:
        - The end of the VLAN range.
        type: int
        required: true
        aliases: [ to ]
  state:
    description:
    - Use C(absent) for removing.
    - Use C(query) for listing an object or multiple objects.
    - Use C(present) for creating or updating.
    type: str
    choices: [ absent, query, present ]
    default: query
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a new vlan pool
  cisco.mso.ndo_vlan_pool:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    vlan_pool: ansible_test_vlan_pool
    vlan_ranges:
      - from_vlan: 100
        to_vlan: 200
      - from_vlan: 300
        to_vlan: 400
    state: present
  register: create

- name: Query a vlan pool with name
  cisco.mso.ndo_vlan_pool:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    vlan_pool: ansible_test_vlan_pool
    state: query
  register: query_one

- name: Query a vlan pool with UUID
  cisco.mso.ndo_vlan_pool:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    vlan_pool_uuid: '{{ create.current.uuid }}'
    state: query
  register: query_with_uuid

- name: Query all vlan pools in the template
  cisco.mso.ndo_vlan_pool:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete a vlan pool
  cisco.mso.ndo_vlan_pool:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    vlan_pool: ansible_test_vlan_pool
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True),
        vlan_pool=dict(type="str", aliases=["name"]),
        vlan_pool_uuid=dict(type="str", aliases=["uuid"]),
        description=dict(type="str"),
        vlan_ranges=dict(
            type="list",
            elements="dict",
            options=dict(
                from_vlan=dict(type="int", required=True, aliases=["from"]),
                to_vlan=dict(type="int", required=True, aliases=["to"]),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["vlan_pool"]],
            ["state", "present", ["vlan_pool"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    vlan_pool = module.params.get("vlan_pool")
    vlan_pool_uuid = module.params.get("vlan_pool_uuid")
    vlan_ranges = get_vlan_ranges_payload(module.params.get("vlan_ranges")) if module.params.get("vlan_ranges") else []
    description = module.params.get("description")
    state = module.params.get("state")

    ops = []
    match = None

    mso_template = MSOTemplate(mso, "fabric_policy", template)
    mso_template.validate_template("fabricPolicy")

    path = "/fabricPolicyTemplate/template/vlanPools"
    match = get_fabric_policy_vlan_pool(mso_template, vlan_pool_uuid, vlan_pool)

    if vlan_pool_uuid or vlan_pool:
        if match:
            match.details["vlan_ranges"] = match.details["encapBlocks"]
            mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = [vlan_pool.update({"vlan_ranges": vlan_pool["encapBlocks"]}) for vlan_pool in match]  # Query all objects

    if state == "present":
        err_message_min_vlan_ranges = "At least one vlan range is required when state is present."

        if match:
            if module.params.get("vlan_ranges") is not None and len(vlan_ranges) == 0:
                mso.fail_json(msg=err_message_min_vlan_ranges)

            if vlan_pool and match.details.get("name") != vlan_pool:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=vlan_pool))
                match.details["name"] = vlan_pool

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if module.params.get("vlan_ranges") is not None and match.details.get("encapBlocks") != vlan_ranges:
                ops.append(dict(op="replace", path="{0}/{1}/encapBlocks".format(path, match.index), value=vlan_ranges))
                match.details["vlan_ranges"] = vlan_ranges
                match.details["encapBlocks"] = vlan_ranges

            mso.sanitize(match.details)

        else:
            if not vlan_ranges:
                mso.fail_json(msg=err_message_min_vlan_ranges)

            payload = {"name": vlan_pool, "allocMode": "static", "encapBlocks": vlan_ranges}
            if description:
                payload["description"] = description

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            payload["vlan_ranges"] = vlan_ranges
            mso.sanitize(payload)
        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))
        mso.existing = {}

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = get_fabric_policy_vlan_pool(mso_template, vlan_pool_uuid, vlan_pool)
        if match:
            match.details["vlan_ranges"] = match.details["encapBlocks"]
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_vlan_ranges_payload(vlan_ranges):
    payload = []
    for vlan_range in vlan_ranges:
        vlan_range_payload = {
            "range": {
                "from": vlan_range.get("from_vlan"),
                "to": vlan_range.get("to_vlan"),
                "allocMode": "static",
            }
        }
        payload.append(vlan_range_payload)
    return payload


def get_fabric_policy_vlan_pool(mso_template, uuid=None, name=None, fail_module=False):
    """
    Get the Fabric Policy VLAN Pool by UUID or Name.
    :param uuid: UUID of the Fabric Policy VLAN Pool to search for -> Str
    :param name: Name of the Fabric Policy VLAN Pool to search for -> Str
    :param fail_module: When match is not found fail the ansible module -> Bool
    :return: Dict | None | List[Dict] | List[]: The processed result which could be:
              When the UUID | Name is existing in the search list -> Dict
              When the UUID | Name is not existing in the search list -> None
              When both UUID and Name are None, and the search list is not empty -> List[Dict]
              When both UUID and Name are None, and the search list is empty -> List[]
    """
    match = mso_template.template.get("fabricPolicyTemplate", {}).get("template", {}).get("vlanPools", [])
    if uuid or name:  # Query a specific object
        return mso_template.get_object_by_key_value_pairs("VLAN Pool", match, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
    return match  # Query all objects


if __name__ == "__main__":
    main()
