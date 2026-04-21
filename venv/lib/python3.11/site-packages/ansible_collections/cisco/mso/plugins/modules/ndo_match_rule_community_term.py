#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_match_rule_community_term
version_added: "2.12.0"
short_description: Manage Match Community Terms on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Match Community Terms inside a Match Rule Policy on Cisco Nexus Dashboard Orchestrator (NDO).
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
  match_rule_policy:
    description:
    - The name of the Match Rule Policy.
    - This parameter or O(match_rule_policy_uuid) is required.
    type: str
  match_rule_policy_uuid:
    description:
    - The UUID of the Match Rule Policy.
    - This parameter or O(match_rule_policy) is required.
    type: str
  name:
    description:
    - The name of the Match Community Term.
    type: str
    aliases: [ match_community_term ]
  description:
    description:
    - The description of the Match Community Term.
    type: str
    aliases: [ match_community_term_description ]
  match_community_factors:
    description:
    - The list of Match Community Factors.
    type: list
    elements: dict
    suboptions:
      community_factor:
        description:
        - The Community Factor to match.
        - e.g., regular:as2-nn2:4:15, extended:as4-nn2:5:16,
          extended:color:35, no-export, no-advertise, etc.
        type: str
        aliases: [ community ]
      scope:
        description:
        - The scope of the Match Community Factor.
        - Defaults to C(transitive) when unset during creation.
        type: str
        choices: [ transitive, non_transitive ]
      description:
        description:
        - The description of the Match Community Factor.
        type: str
        aliases: [ match_community_description ]
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
- The O(match_rule_policy) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_match_rule_policy) to create the Match Rule Policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_match_rule_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Create a Match Community Term
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    name: ansible_match_community_term
    description: Ansible Match Community Term
    match_community_factors:
      - community_factor: no-export
        scope: transitive
        description: no export and transitive
    state: present
  register: create_match_name

- name: Update a Match Community Term using Match Rule Policy's name
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    name: ansible_match_community_term
    description: Updated Ansible Match Community Term
    match_community_factors:
      - community_factor: no-export
        scope: non_transitive
        description: no export and non-transitive
      - community_factor: no-advertise
        scope: transitive
        description: no advertise and transitive
    state: present

- name: Update a Match Community Term using Match Rule Policy's UUID
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy_uuid: "{{ create_match_name.current.matchRulePolicyUuid }}"
    name: ansible_match_community_term
    description: Updated Ansible Match Community Term
    match_community_factors:
      - community_factor: no-export
        scope: non_transitive
        description: no export and non-transitive
      - community_factor: no-advertise
        scope: transitive
        description: no advertise and transitive
    state: present

- name: Update a Match Community Term by removing a Match Community
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    name: ansible_match_community_term
    description: Updated Ansible Match Community Term
    match_community_factors:
      - community_factor: no-advertise
        scope: transitive
        description: no advertise and transitive
    state: present

- name: Update a Match Community Term by removing all Match Communities
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    name: ansible_match_community_term
    description: Updated Ansible Match Community Term
    match_community_factors: []
    state: present

- name: Query a Match Community Term using Match Rule Policy's name
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    name: ansible_match_community_term
    state: query
  register: query_with_name

- name: Query a Match Community Term using  Match Rule Policy's UUID
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy_uuid: "{{ create_match_name.current.matchRulePolicyUuid }}"
    name: ansible_match_community_term
    state: query
  register: query_with_uuid

- name: Query all Match Community Terms in a Match Rule Policy
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    state: query
  register: query_all_objects

- name: Delete a Match Community Term using Match Rule Policy's name
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    name: ansible_match_community_term
    state: absent

- name: Delete a Match Community Term using Match Rule Policy's UUID
  cisco.mso.ndo_match_rule_community_term:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: ansible_test
    match_rule_policy_uuid: "{{ create_match_name.current.matchRulePolicyUuid }}"
    name: ansible_match_community_term
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.constants import MATCH_COMMUNITY_SCOPE_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data
import copy


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        match_rule_policy=dict(type="str"),
        match_rule_policy_uuid=dict(type="str"),
        name=dict(type="str", aliases=["match_community_term"]),
        description=dict(type="str", aliases=["match_community_term_description"]),
        match_community_factors=dict(
            type="list",
            elements="dict",
            options=dict(
                community_factor=dict(type="str", aliases=["community"]),
                scope=dict(type="str", choices=list(MATCH_COMMUNITY_SCOPE_MAP)),
                description=dict(type="str", aliases=["match_community_description"]),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ("template", "template_id"),
            ["match_rule_policy", "match_rule_policy_uuid"],
        ],
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
        required_one_of=[
            ["template", "template_id"],
            ["match_rule_policy", "match_rule_policy_uuid"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    match_rule_policy = module.params.get("match_rule_policy")
    match_rule_policy_uuid = module.params.get("match_rule_policy_uuid")
    name = module.params.get("name")
    description = module.params.get("description")
    match_community_factors = module.params.get("match_community_factors")
    if not isinstance(match_community_factors, list):
        match_community_factors = []
    from_name = module.params.get("from_name")
    to_name = module.params.get("to_name")
    state = module.params.get("state")

    mso_template = mso_templates.get_template("tenant", template_name, template_id)
    mso_template.validate_template("tenantPolicy")

    match_rule_policy_object = mso_template.get_match_rule_policy_object(match_rule_policy_uuid, match_rule_policy)
    if not match_rule_policy_object:
        mso.fail_json(
            msg="The Match Rule Policy with the following {0[0]} '{0[1]}' does not exist".format(
                ("UUID", match_rule_policy_uuid) if match_rule_policy_uuid else ("name", match_rule_policy)
            )
        )
    match_identifiers = {"name": name}
    match = mso_template.get_direct_child_object(match_rule_policy_object, "Match Community Term", "matchCommunityTermsList", match_identifiers)

    if name and match:
        mso.existing = mso.previous = copy.deepcopy(
            mso_template.update_match_rule_policy_child_object_with_template_and_parent(match_rule_policy_object.details, match.details)
        )  # Query a specific object
    elif match:
        mso.existing = [
            mso_template.update_match_rule_policy_child_object_with_template_and_parent(match_rule_policy_object.details, obj) for obj in match
        ]  # Query all objects

    match_name_path = "/tenantPolicyTemplate/template/matchRulePolicies/{0}/matchCommunityTermsList/{1}".format(
        match_rule_policy_object.index,
        match.index if match else "-",
    )

    ops = []

    if state == "present":

        mso_values = {
            "name": name,
            "matchCommunityList": [
                {
                    "community": match_community.get("community_factor"),
                    "scope": MATCH_COMMUNITY_SCOPE_MAP.get(match_community.get("scope")),
                    "description": match_community.get("description"),
                }
                for match_community in match_community_factors
            ],
            "description": description,
            "fromPfxLen": from_name,
            "toPfxLen": to_name,
        }

        if match:
            append_update_ops_data(ops, match.details, match_name_path, mso_values)
            mso.sanitize(mso_values, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=match_name_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=match_name_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match_rule_policy_object = mso_template.get_match_rule_policy_object(match_rule_policy_uuid, match_rule_policy, search_object=response)
        match = mso_template.get_direct_child_object(match_rule_policy_object, "Match Community Term", "matchCommunityTermsList", match_identifiers)
        if match:
            mso.existing = mso_template.update_match_rule_policy_child_object_with_template_and_parent(
                match_rule_policy_object.details, match.details
            )  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        if mso.proposed:
            mso_template.update_match_rule_policy_child_object_with_template_and_parent(match_rule_policy_object.details, mso.proposed)
        mso.existing = mso.proposed if state == "present" else {}
    mso.exit_json()


if __name__ == "__main__":
    main()
