#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_route_map_policy_multicast
short_description: Manage Multicast Route Map Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Multicast Route Map Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Akini Ross (@akinross)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    type: str
    required: true
  route_map_policy:
    description:
    - The name of the Multicast Route Map Policy.
    type: str
    aliases: [ name ]
  route_map_policy_uuid:
    description:
    - The uuid of the Multicast Route Map Policy.
    - This parameter is required when the O(route_map_policy) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the Multicast Route Map Policy.
    type: str
  entries:
    description:
    - A list of entries attached to the Multicast Route Map Policy.
    - The list of configured entries must contain at least one entry.
    - When the list of entries is null the update will not change existing entry configuration.
    type: list
    elements: dict
    suboptions:
      order:
        description:
        - The order of the entry.
        type: int
        required: true
      group:
        description:
        - The name of the entry.
        type: str
        required: true
      source:
        description:
        - The data of the entry.
        type: str
        required: true
      rp:
        description:
        - The rendezvous point of the entry.
        type: str
        aliases: [ rendezvous_point ]
      action:
        description:
        - The action of the entry.
        type: str
        choices: [ permit, deny ]
        default: permit
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
- name: Create a new multicast route map policy
  cisco.mso.ndo_route_map_policy_multicast:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    entries:
      - order: 1
        group: 226.2.2.0/24
        source: 1.1.1.1/24
        rp: 1.1.1.2
        action: permit
    state: present
  register: create

- name: Query a multicast route map policy with name
  cisco.mso.ndo_route_map_policy_multicast:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    state: query
  register: query_one

- name: Query a multicast route map policy with UUID
  cisco.mso.ndo_route_map_policy_multicast:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy_uuid: '{{ create.current.uuid }}'
    state: query
  register: query_with_uuid

- name: Query all multicast route map policy in the template
  cisco.mso.ndo_route_map_policy_multicast:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete a multicast route map policy
  cisco.mso.ndo_route_map_policy_multicast:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
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
        route_map_policy=dict(type="str", aliases=["name"]),
        route_map_policy_uuid=dict(type="str", aliases=["uuid"]),
        description=dict(type="str"),
        entries=dict(
            type="list",
            elements="dict",
            options=dict(
                order=dict(type="int", required=True),
                group=dict(type="str", required=True),
                source=dict(type="str", required=True),
                rp=dict(type="str", aliases=["rendezvous_point"]),
                action=dict(type="str", choices=["permit", "deny"], default="permit"),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["route_map_policy"]],
            ["state", "present", ["route_map_policy"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    route_map_policy = module.params.get("route_map_policy")
    route_map_policy_uuid = module.params.get("route_map_policy_uuid")
    entries = get_entries_payload(module.params.get("entries")) if module.params.get("entries") else []
    description = module.params.get("description")
    state = module.params.get("state")

    ops = []
    match = None
    err_message_min_entries = "At least one entry is required when state is present."

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")

    path = "/tenantPolicyTemplate/template/mcastRouteMapPolicies"
    match = get_multicast_route_map_policy(mso_template, route_map_policy_uuid, route_map_policy)

    if route_map_policy_uuid or route_map_policy:
        if match:  # Query a specific object
            mso.existing = copy.deepcopy(match.details)
            mso.previous = copy.deepcopy(match.details)
    elif match:
        mso.existing = match  # Query all objects

    if state == "present":
        if match:
            if module.params.get("entries") is not None and len(entries) == 0:
                mso.fail_json(msg=err_message_min_entries)

            if route_map_policy and match.details.get("name") != route_map_policy:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=route_map_policy))
                match.details["name"] = route_map_policy

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if module.params.get("entries") is not None and match.details.get("mcastRtMapEntryList") != entries:
                ops.append(dict(op="replace", path="{0}/{1}/mcastRtMapEntryList".format(path, match.index), value=entries))
                match.details["mcastRtMapEntryList"] = entries

            mso.sanitize(match.details)

        else:
            if not entries:
                mso.fail_json(msg=err_message_min_entries)

            payload = {"name": route_map_policy, "mcastRtMapEntryList": entries}
            if description:
                payload["description"] = description

            ops.append(dict(op="add", path="{0}/-".format(path), value=copy.deepcopy(payload)))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))
        mso.existing = {}

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = get_multicast_route_map_policy(mso_template, route_map_policy_uuid, route_map_policy)
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_entries_payload(entries):
    payload = []
    for entry in entries:
        entries_payload = {
            "order": entry.get("order"),
            "group": entry.get("group"),
            "source": entry.get("source"),
            "action": entry.get("action"),
        }
        if entry.get("rp"):
            entries_payload["rp"] = entry.get("rp")
        payload.append(entries_payload)
    return payload


def get_multicast_route_map_policy(mso_template, uuid=None, name=None, fail_module=False):
    """
    Get the Multicast Route Map Policy by UUID or Name.
    :param uuid: UUID of the Multicast Route Map Policy to search for -> Str
    :param name: Name of the Multicast Route Map Policy to search for -> Str
    :param fail_module: When match is not found fail the ansible module -> Bool
    :return: Dict | None | List[Dict] | List[]: The processed result which could be:
              When the UUID | Name is existing in the search list -> Dict
              When the UUID | Name is not existing in the search list -> None
              When both UUID and Name are None, and the search list is not empty -> List[Dict]
              When both UUID and Name are None, and the search list is empty -> List[]
    """
    match = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("mcastRouteMapPolicies", [])
    if uuid or name:  # Query a specific object
        return mso_template.get_object_by_key_value_pairs(
            "Multicast Route Map Policy", match, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
        )
    return match  # Query all objects


if __name__ == "__main__":
    main()
