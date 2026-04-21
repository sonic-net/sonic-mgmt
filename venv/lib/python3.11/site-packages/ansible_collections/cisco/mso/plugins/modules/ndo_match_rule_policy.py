#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_match_rule_policy
version_added: "2.12.0"
short_description: Manage Match Rule Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Match Rule Policies on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v4.1 (NDO v5.1) and later.
author:
- Gaspard Micol (@gmicol)
options:
  template:
    description:
    - The name of the template.
    - The template must be a Tenant Policy template.
    - This parameter or O(template_id) is required.
    type: str
  template_id:
    description:
    - The ID of the template.
    - The template must be a Tenant Policy template.
    - This parameter or O(template) is required.
    type: str
  name:
    description:
    - The name of the Match Rule Policy.
    type: str
    aliases: [ match_rule_policy ]
  uuid:
    description:
    - The UUID of the Match Rule Policy.
    - This parameter is required when the O(name) needs to be updated.
    type: str
    aliases: [ match_rule_policy_uuid ]
  description:
    description:
    - The description of the Match Rule Policy.
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
  Use M(cisco.mso.ndo_template) to create the Tenant Policy template.
seealso:
- module: cisco.mso.ndo_template
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a Match Rule Policy
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_match_rule_policy
    description: Ansible Match Rule Policy
    state: present
  register: create_match_rule_policy

- name: Update a Match Rule Policy using name
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_match_rule_policy
    description: Updated Ansible Match Rule Policy
    state: present

- name: Update a Match Rule Policy using UUID
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_match_rule_policy_changed
    uuid: "{{ create_match_rule_policy.current.uuid }}"
    state: present

- name: Query a Match Rule Policy using name
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_match_rule_policy
    state: query
  register: query_with_name

- name: Query a Match Rule Policy using UUID
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    uuid: "{{ create_match_rule_policy.current.uuid }}"
    state: query
  register: query_with_uuid

- name: Query all Match Rule Policies in a template
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    state: query
  register: query_all_objects

- name: Delete a Match Rule Policy using its name
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    name: ansible_match_rule_policy
    state: absent

- name: Delete a Match Rule Policy using UUID
  cisco.mso.ndo_match_rule_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: ansible_test
    uuid: "{{ create_match_rule_policy.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        name=dict(type="str", aliases=["match_rule_policy"]),
        uuid=dict(type="str", aliases=["match_rule_policy_uuid"]),
        description=dict(type="str"),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
        ],
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

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    name = module.params.get("name")
    uuid = module.params.get("uuid")
    description = module.params.get("description")
    state = module.params.get("state")

    mso_template = mso_templates.get_template("tenant", template_name, template_id)
    mso_template.validate_template("tenantPolicy")

    match = mso_template.get_match_rule_policy_object(uuid, name)

    if (uuid or name) and match:
        mso.existing = mso.previous = copy.deepcopy(mso_template.update_config_with_template_and_references(match.details))  # Query a specific object
    elif match:
        mso.existing = [mso_template.update_config_with_template_and_references(obj) for obj in match]  # Query all objects

    match_rule_policy_path = "/tenantPolicyTemplate/template/matchRulePolicies/{0}".format(match.index if match else "-")

    ops = []

    if state == "present":

        mso_values = {
            "name": name,
            "description": description,
        }

        if match:
            append_update_ops_data(ops, match.details, match_rule_policy_path, mso_values)
            mso.sanitize(mso_values, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=match_rule_policy_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=match_rule_policy_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = mso_template.get_match_rule_policy_object(uuid, name, search_object=response)
        if match:
            mso.existing = mso_template.update_config_with_template_and_references(match.details)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        if mso.proposed:
            mso_template.update_config_with_template_and_references(mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


if __name__ == "__main__":
    main()
