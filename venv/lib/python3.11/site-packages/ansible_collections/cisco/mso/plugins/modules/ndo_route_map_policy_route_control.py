#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_route_map_policy_route_control
version_added: "2.12.0"
short_description: Manage Route Map Policy for Route Control on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Route Map Policy for Route Control on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v4.1 and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  template:
    description:
    - The name of the template.
    - The template must be a tenant template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the tenant template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the Route Map Policy for Route Control.
    type: str
  uuid:
    description:
    - The UUID of the Route Map Policy for Route Control.
    - This parameter is required when the O(name) needs to be updated.
    type: str
  description:
    description:
    - The description of the Route Map Policy for Route Control.
    type: str
  match_type:
    description:
    - The match type of the Route Map Policy for Route Control.
    - Defaults to C(routing_policy_only) when unset during creation.
    type: str
    choices: [ prefix_and_routing_policy, routing_policy_only ]
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
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add Route Map Policy for Route Control
  cisco.mso.ndo_route_map_policy_route_control:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: route_map_policy_1
    state: present
  register: add_route_map_policy

- name: Update Route Map Policy for Route Control name using UUID
  cisco.mso.ndo_route_map_policy_route_control:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: route_map_policy_1_updated
    uuid: "{{ add_route_map_policy.current.uuid }}"
    match_type: prefix_and_routing_policy
    state: present

- name: Query Route Map Policy for Route Control using name
  cisco.mso.ndo_route_map_policy_route_control:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: route_map_policy_1_updated
    state: query
  register: query_one_with_name

- name: Query Route Map Policy for Route Control using UUID
  cisco.mso.ndo_route_map_policy_route_control:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ add_route_map_policy.current.uuid }}"
    state: query
  register: query_one_with_uuid

- name: Query all Route Map Policy for Route Controls
  cisco.mso.ndo_route_map_policy_route_control:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Remove Route Map Policy for Route Control using name
  cisco.mso.ndo_route_map_policy_route_control:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    name: route_map_policy_1_updated
    state: absent

- name: Remove Route Map Policy for Route Control using UUID
  cisco.mso.ndo_route_map_policy_route_control:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    uuid: "{{ add_route_map_policy.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""


import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.constants import ROUTE_MAP_POLICY_MATCH_TYPE
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str"),
        uuid=dict(type="str"),
        description=dict(type="str"),
        match_type=dict(type="str", choices=list(ROUTE_MAP_POLICY_MATCH_TYPE)),
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
            ["template", "template_id"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = mso.params.get("template")
    template_id = mso.params.get("template_id")
    name = mso.params.get("name")
    uuid = mso.params.get("uuid")
    description = mso.params.get("description")
    match_type = ROUTE_MAP_POLICY_MATCH_TYPE.get(mso.params.get("match_type"))
    state = mso.params.get("state")

    ops = []
    match = None
    path = None

    mso_template = mso_templates.get_template("tenant", template_name, template_id)
    mso_template.validate_template("tenantPolicy")

    match = mso_template.get_route_map_policy(uuid, name)
    if (uuid or name) and match:  # Query a specific object
        mso.existing = mso.previous = copy.deepcopy(mso_template.update_config_with_template_and_references(match.details))
    elif match:  # Query all objects
        mso.existing = [mso_template.update_config_with_template_and_references(obj) for obj in match]

    if state != "query":
        path = "/tenantPolicyTemplate/template/routeMapPolicies/{0}".format(match.index if match else "-")

    if state == "present":
        mso_values = {
            "name": name,
            "description": description,
            "routeMapType": match_type,
        }
        if match:
            append_update_ops_data(ops, match.details, path, mso_values)
            mso.sanitize(mso_values, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=path, value=mso.sent))

    elif state == "absent" and match:
        ops.append(dict(op="remove", path=path))

    if mso.proposed:
        mso.proposed = copy.deepcopy(mso.proposed)
        mso_template.update_config_with_template_and_references(mso.proposed)

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_route_map_policy(uuid, name, template_object=response)
        if match:
            mso.existing = mso_template.update_config_with_template_and_references(match.details)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
