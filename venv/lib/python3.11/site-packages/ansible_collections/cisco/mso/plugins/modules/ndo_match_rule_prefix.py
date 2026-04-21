#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_match_rule_prefix
version_added: "2.12.0"
short_description: Manage Match Prefix List on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Match Prefix List inside a Match Rule Policy on Cisco Nexus Dashboard Orchestrator (NDO).
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
  prefix:
    description:
    - The Prefix IP to match.
    type: str
  description:
    description:
    - The description of the Match Prefix.
    type: str
  aggregate:
    description:
    - The aggregate flag enabling route aggregation.
    - Defaults to C(false) when unset during creation.
    type: bool
  from_prefix:
    description:
    - The subnet value from which to aggregate.
    - The value must be below O(to_prefix) and above the subnet of the Prefix IP.
    - The value must be between 0 and 32.
    - Defaults to C(0) when unset during creation.
    type: int
    aliases: [ from ]
  to_prefix:
    description:
    - The subnet value to which to aggregate.
    - The value must be above O(from_prefix) and above the subnet of the Prefix IP.
    - The value must be between 0 and 32.
    - Defaults to C(0) when unset during creation.
    type: int
    aliases: [ to ]
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
- name: Create a Match Prefix
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    prefix: 10.10.10.1/24
    description: Ansible Match Prefix
    aggregate: false
    from_prefix: 0
    to_prefix: 0
    state: present
  register: create_match_prefix

- name: Update a Match Prefix using Match Rule Policy's name
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    prefix: 10.10.10.1/24
    description: Updated Ansible Match Prefix
    aggregate: true
    from_prefix: 25
    to_prefix: 31
    state: present

- name: Update a Match Prefix using Match Rule Policy's UUID
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy_uuid: "{{ create_match_prefix.current.matchRulePolicyUuid }}"
    prefix: 10.10.10.1/24
    description: Updated Ansible Match Prefix
    aggregate: true
    from_prefix: 25
    to_prefix: 31
    state: present

- name: Query a Match Prefix using Match Rule Policy's name
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    prefix: 10.10.10.1/24
    state: query
  register: query_with_name

- name: Query a Match Prefix using  Match Rule Policy's UUID
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy_uuid: "{{ create_match_prefix.current.matchRulePolicyUuid }}"
    prefix: 10.10.10.1/24
    state: query
  register: query_with_uuid

- name: Query all Match Prefixes in a Match Rule Policy
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    state: query
  register: query_all_objects

- name: Delete a Match Prefix using Match Rule Policy's name
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_test
    match_rule_policy: ansible_match_rule_policy
    prefix: 10.10.10.1/24
    state: absent

- name: Delete a Match Prefix using Match Rule Policy's UUID
  cisco.mso.ndo_match_rule_prefix:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template_id: ansible_test
    match_rule_policy_uuid: "{{ create_match_prefix.current.matchRulePolicyUuid }}"
    prefix: 10.10.10.1/24
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
        match_rule_policy=dict(type="str"),
        match_rule_policy_uuid=dict(type="str"),
        prefix=dict(type="str"),
        description=dict(type="str"),
        aggregate=dict(type="bool"),
        from_prefix=dict(type="int", aliases=["from"]),
        to_prefix=dict(type="int", aliases=["to"]),
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
            ["state", "absent", ["prefix"]],
            ["state", "present", ["prefix"]],
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
    prefix = module.params.get("prefix")
    description = module.params.get("description")
    aggregate = module.params.get("aggregate")
    from_prefix = module.params.get("from_prefix")
    to_prefix = module.params.get("to_prefix")
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
    match_identifiers = {"prefix": prefix}
    match = mso_template.get_direct_child_object(match_rule_policy_object, "Match Prefix", "matchPrefixList", match_identifiers)

    if prefix and match:
        mso.existing = mso.previous = copy.deepcopy(
            mso_template.update_match_rule_policy_child_object_with_template_and_parent(match_rule_policy_object.details, match.details)
        )  # Query a specific object
    elif match:
        mso.existing = [
            mso_template.update_match_rule_policy_child_object_with_template_and_parent(match_rule_policy_object.details, obj) for obj in match
        ]  # Query all objects

    match_prefix_path = "/tenantPolicyTemplate/template/matchRulePolicies/{0}/matchPrefixList/{1}".format(
        match_rule_policy_object.index,
        match.index if match else "-",
    )

    ops = []

    if state == "present":

        mso_values = {
            "prefix": prefix,
            "aggregate": aggregate,
            "description": description,
            "fromPfxLen": from_prefix,
            "toPfxLen": to_prefix,
        }

        if match:
            append_update_ops_data(ops, match.details, match_prefix_path, mso_values)
            mso.sanitize(mso_values, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path=match_prefix_path, value=mso.sent))

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path=match_prefix_path))

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match_rule_policy_object = mso_template.get_match_rule_policy_object(match_rule_policy_uuid, match_rule_policy, search_object=response)
        match = mso_template.get_direct_child_object(match_rule_policy_object, "Match Prefix", "matchPrefixList", match_identifiers)
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
