#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_route_map_policy_route_control_context
version_added: "2.12.0"
short_description: Manage Route Map Policy for Route Control Context on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage Route Map Policy for Route Control Context on Cisco Nexus Dashboard Orchestrator (NDO).
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
  route_map_policy:
    description:
    - The name of the Route Map Policy for Route Control.
    - This parameter or O(route_map_policy_uuid) is required.
    type: str
  route_map_policy_uuid:
    description:
    - The UUID of the Route Map Policy for Route Control.
    - This parameter or O(route_map_policy) is required.
    type: str
  name:
    description:
    - The name of the Route Control context.
    type: str
  description:
    description:
    - The description of the Route Control context.
    - Providing an empty string O(description="") will remove description from the Route Control context.
    type: str
  order:
    description:
    - The order of the Route Control context.
    - The value must be a number between 0 and 9.
    - Defaults to C(0) when unset during creation.
    type: int
  action:
    description:
    - The action of the Route Control context.
    - Defaults to C(permit) when unset during creation.
    type: str
    choices: [ permit, deny ]
  set_rule:
    description:
    - The Set Rule Policy reference details for the Route Control context.
    - Providing an empty dictionary O(set_rule={}) will remove Set Rule Policy from the Route Control context.
    type: dict
    suboptions:
      uuid:
        description:
        - The UUID of the Set Rule Policy.
        - This parameter can be used instead of O(set_rule.reference).
        type: str
      reference:
        description:
        - The reference details of the Set Rule Policy.
        - This parameter can be used instead of O(set_rule.uuid).
        type: dict
        aliases: [ ref ]
        suboptions:
          name:
            description:
            - The name of the Set Rule Policy.
            type: str
          template:
            description:
            - The template associated with the Set Rule Policy.
            - This parameter or O(set_rule.reference.template_id) is required.
            type: str
          template_id:
            description:
            - The template ID associated with the Set Rule Policy.
            - This parameter or O(set_rule.reference.template) is required.
            type: str
  match_rules:
    description:
    - The list of Match Rule Policy references.
    - Providing an empty list O(match_rules=[]) will remove Match Rule Policies from the Route Control context.
    - When the O(match_rules) is null the update will not change existing configuration.
    - The old O(match_rules) list will be replaced by the new list during an update.
    type: list
    elements: dict
    suboptions:
      uuid:
        description:
        - The UUID of the Match Rule Policy.
        - This parameter can be used instead of O(match_rules.reference).
        type: str
      reference:
        description:
        - The reference of the Match Rule Policy.
        - This parameter can be used instead of O(match_rules.uuid).
        aliases: [ ref ]
        type: dict
        suboptions:
          name:
            description:
            - The name of the Match Rule Policy.
            type: str
          template:
            description:
            - The template associated with the Match Rule Policy.
            - This parameter or O(match_rules.reference.template_id) is required.
            type: str
          template_id:
            description:
            - The template ID associated with the Match Rule Policy.
            - This parameter or O(match_rules.reference.template) is required.
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
- The O(route_map_policy) must exist before using this module in your playbook.
  Use M(cisco.mso.ndo_route_map_policy_route_control) to create the Route Map Policy for Route Control.
- The O(set_rule) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_set_rule_policy) to create the Set Rule Policy.
- The O(match_rules) must exist before using it with this module in your playbook.
  Use M(cisco.mso.ndo_match_rule_policy) to create the Match Rule Policy.
seealso:
- module: cisco.mso.ndo_template
- module: cisco.mso.ndo_route_map_policy_route_control
- module: cisco.mso.ndo_set_rule_policy
- module: cisco.mso.ndo_match_rule_policy
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add Route Map Policy for Route Control Context
  cisco.mso.ndo_route_map_policy_route_control_context:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    name: route_map_policy_context_1
    order: 1
    set_rule:
      uuid: "{{ add_set_rule_policy_1.current.uuid }}"
    match_rules:
      - uuid: "{{ add_match_rule_policy_1.current.uuid }}"
      - reference:
          template_id: "{{ add_ansible_tenant_template.current.templateId }}"
          name: ansible_match_rule_policy_2
    state: present

- name: Update Route Map Policy for Route Control Context
  cisco.mso.ndo_route_map_policy_route_control_context:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    name: route_map_policy_context_1
    order: 2
    set_rule:
      reference:
        template_id: "{{ add_ansible_tenant_template.current.templateId }}"
        name: ansible_set_rule_policy_2
    match_rules:
      - reference:
          template_id: "{{ add_ansible_tenant_template.current.templateId }}"
          name: ansible_match_rule_policy_2
    state: present

- name: Update and remove Set Rule and Match Rules from Route Map Policy for Route Control Context
  cisco.mso.ndo_route_map_policy_route_control_context:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    name: route_map_policy_context_1
    order: 2
    set_rule: {}
    match_rules: []
    state: present

- name: Query Route Map Policy for Route Control Context using name
  cisco.mso.ndo_route_map_policy_route_control_context:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    name: route_map_policy_context_1
    state: query
  register: query_one

- name: Query all Route Map Policy for Route Control Context
  cisco.mso.ndo_route_map_policy_route_control_context:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    state: query
  register: query_one

- name: Delete Route Map Policy for Route Control Context
  cisco.mso.ndo_route_map_policy_route_control_context:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    route_map_policy: ansible_test_route_map_policy
    name: route_map_policy_context_1
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import KVPair
from ansible_collections.cisco.mso.plugins.module_utils.templates import MSOTemplates
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data, check_if_all_elements_are_none


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str"),
        template_id=dict(type="str"),
        route_map_policy=dict(type="str"),
        route_map_policy_uuid=dict(type="str"),
        name=dict(type="str"),
        description=dict(type="str"),
        order=dict(type="int"),
        action=dict(type="str", choices=["permit", "deny"]),
        set_rule=dict(
            type="dict",
            options=dict(
                uuid=dict(type="str"),
                reference=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str"),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                    ),
                    required_by={
                        "template": "name",
                        "template_id": "name",
                    },
                    aliases=["ref"],
                ),
            ),
        ),
        match_rules=dict(
            type="list",
            elements="dict",
            options=dict(
                uuid=dict(type="str"),
                reference=dict(
                    type="dict",
                    options=dict(
                        name=dict(type="str"),
                        template=dict(type="str"),
                        template_id=dict(type="str"),
                    ),
                    required_by={
                        "template": "name",
                        "template_id": "name",
                    },
                    aliases=["ref"],
                ),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name"]],
            ["state", "absent", ["name"]],
        ],
        required_one_of=[
            ["template", "template_id"],
            ["route_map_policy", "route_map_policy_uuid"],
        ],
    )

    mso = MSOModule(module)
    mso_templates = MSOTemplates(mso)
    ops = []
    match = None
    path = None

    template_name = module.params.get("template")
    template_id = module.params.get("template_id")
    route_map_policy = module.params.get("route_map_policy")
    route_map_policy_uuid = module.params.get("route_map_policy_uuid")
    name = module.params.get("name")
    description = module.params.get("description")
    order = module.params.get("order")
    action = module.params.get("action")
    set_rule = module.params.get("set_rule")
    match_rules = module.params.get("match_rules")
    state = module.params.get("state")

    mso_template = mso_templates.get_template("tenant", template_name, template_id)
    mso_template.validate_template("tenantPolicy")
    route_map_policy_object = mso_template.get_route_map_policy(route_map_policy_uuid, route_map_policy, template_object=None, fail_module=True)
    reference_details = {
        "matchRule": {
            "name": "matchRuleName",
            "reference": "matchRuleRef",
            "type": "matchRule",
            "template": "matchRuleTemplateName",
            "templateId": "matchRuleTemplateId",
        },
        "setRule": {
            "name": "setRuleName",
            "reference": "setRuleRef",
            "type": "setRule",
            "template": "setRuleTemplateName",
            "templateId": "setRuleTemplateId",
        },
    }

    if name:  # Query a specific object
        match = mso_template.get_object_by_key_value_pairs(
            "Route Map Policy Route Control Context", route_map_policy_object.details.get("contexts", []), [KVPair("name", name)]
        )
        if match:
            if match.details.get("matchRules"):
                match.details["matchRules"] = match_rules_list_to_dict(match.details.get("matchRules"))
            mso.previous = mso.existing = mso_template.update_config_with_template_and_references(copy.deepcopy(match.details), reference_details, False)
    elif route_map_policy_object.details.get("contexts", []):  # Query all objects
        for obj in route_map_policy_object.details.get("contexts", []):
            if obj.get("matchRules"):
                obj["matchRules"] = match_rules_list_to_dict(obj.get("matchRules"))
            mso_template.update_config_with_template_and_references(obj, reference_details, False)
        mso.existing = route_map_policy_object.details.get("contexts", [])  # Query all

    if state != "query":
        path = "/tenantPolicyTemplate/template/routeMapPolicies/{0}/contexts/{1}".format(route_map_policy_object.index, match.index if match else "-")

    if state == "present":
        set_rule_uuid = None
        if set_rule:
            set_rule_uuid = set_rule.get("uuid")
            set_rule_reference = set_rule.get("reference")
            if not set_rule_uuid and set_rule_reference and not check_if_all_elements_are_none(set_rule_reference.values()):
                set_rule_template = mso_templates.get_template("tenant", set_rule_reference.get("template"), set_rule_reference.get("template_id"))
                set_rule_policy_match = set_rule_template.get_set_rule_policy_object(
                    uuid=None, name=set_rule_reference.get("name"), search_object=None, fail_module=True
                )
                set_rule_uuid = set_rule_policy_match.details.get("uuid")

        match_rule_uuids = []
        if match_rules:
            for match_rule in match_rules:
                if match_rule and match_rule.get("uuid"):
                    match_rule_uuids.append(match_rule.get("uuid"))
                elif match_rule and not check_if_all_elements_are_none(match_rule.get("reference", {}).values()):
                    ref = match_rule.get("reference")
                    match_rule_template = mso_templates.get_template("tenant", ref.get("template"), ref.get("template_id"))
                    match_rule_policy_match = match_rule_template.get_match_rule_policy_object(
                        uuid=None, name=ref.get("name"), search_object=None, fail_module=True
                    )
                    match_rule_uuids.append(match_rule_policy_match.details.get("uuid"))

        mso_values = {
            "name": name,
            "action": action,
            "description": description,
            "matchRules": match_rule_uuids,
            "setRuleRef": set_rule_uuid if set_rule_uuid else "",
        }

        if order is not None:
            mso_values["order"] = order

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
        mso.proposed["matchRules"] = match_rules_list_to_dict(mso.proposed.get("matchRules", []))
        proposed_reference_details = copy.deepcopy(reference_details)
        if mso.proposed.get("setRuleRef") == "":
            proposed_reference_details.pop("setRule", None)
        mso_template.update_config_with_template_and_references(mso.proposed, proposed_reference_details, False)

    if not module.check_mode and ops:
        response = mso.request(mso_template.template_path, method="PATCH", data=ops)
        route_map_policy_object = mso_template.get_route_map_policy(
            route_map_policy_uuid, route_map_policy, template_object=response, fail_module=True
        ).details
        match = mso_template.get_object_by_key_value_pairs(
            "Route Map Policy Route Control Context", route_map_policy_object.get("contexts", []), [KVPair("name", name)]
        )
        if match:
            if match.details.get("matchRules"):
                match.details["matchRules"] = match_rules_list_to_dict(match.details.get("matchRules"))
            mso.existing = mso_template.update_config_with_template_and_references(match.details, reference_details, False)  # When the state is present
        else:
            mso.existing = {}  # When the state is absent

    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def match_rules_list_to_dict(match_rules):
    return [{"matchRuleRef": mr} for mr in match_rules]


if __name__ == "__main__":
    main()
