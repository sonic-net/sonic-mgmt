#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_tenant_igmp_snooping_policy
short_description: Manage Internet Group Management Protocol (IGMP) Snooping Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage IGMP Snooping Policies in Tenant Policy Templates on Cisco Nexus Dashboard Orchestrator (NDO).
- This module is only supported on ND v3.1 (NDO v4.3) and later.
author:
- Anvitha Jain (@anvjain)
options:
  template:
    description:
    - The name of the tenant template.
    type: str
    aliases: [ tenant_template ]
    required: true
  name:
    description:
    - The name of the IGMP Snooping Policy.
    type: str
    aliases: [ igmp_snooping_policy ]
  uuid:
    description:
    - The UUID of the IGMP Snooping Policy.
    - This parameter is required when the IGMP Snooping Policy O(name) needs to be updated.
    type: str
  description:
    description:
    - The description of the IGMP Snooping Policy.
    - Providing an empty string will remove the O(description="") from the IGMP Snooping Policy.
    type: str
  admin_state:
    description:
    - The administrative state of the IGMP Snooping Policy.
    - Defaults to C(enabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  fast_leave_control:
    description:
    - The fast leave control of the IGMP Snooping Policy.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  querier_control:
    description:
    - The querier control of the IGMP Snooping Policy.
    - Defaults to C(disabled) when unset during creation.
    type: str
    choices: [ enabled, disabled ]
  querier_version:
    description:
    - The querier version of the IGMP Snooping Policy.
    - Defaults to C(v3) when unset during creation.
    type: str
    choices: [ v2, v3 ]
  query_interval:
    description:
    - The query interval value in seconds.
    - The query interval of the IGMP Snooping Policy.
    - Defaults to 125 when unset during creation.
    - The value must be between 1 and 18000.
    type: int
  query_response_interval:
    description:
    - The query response interval value in seconds.
    - The query response interval of the IGMP Snooping Policy.
    - Defaults to 10 when unset during creation.
    - The value must be between 1 and 25.
    type: int
  last_member_query_interval:
    description:
    - The last member query interval value in seconds.
    - The last member query interval of the IGMP Snooping Policy.
    - Defaults to 1 when unset during creation.
    - The value must be between 1 and 25.
    type: int
  start_query_interval:
    description:
    - The start query interval value in seconds.
    - The start query interval of the IGMP Snooping Policy.
    - Defaults to 31 when unset during creation.
    - The value must be between 1 and 18000.
    type: int
  start_query_count:
    description:
    - The start query count of the IGMP Snooping Policy.
    - Defaults to 2 when unset during creation.
    - The value must be between 1 and 10.
    type: int
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
- name: Create a new IGMP Snooping Policy object
  cisco.mso.ndo_tenant_igmp_snooping_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: igmp_snooping_policy_1
    admin_state: enabled
    fast_leave_control: enabled
    querier_control: enabled
    querier_version: v2
    query_interval: 100
    query_response_interval: 5
    last_member_query_interval: 2
    start_query_interval: 25
    start_query_count: 1
    state: present
  register: igmp_snooping_policy_1

- name: Update a IGMP Snooping Policy object name with UUID
  cisco.mso.ndo_tenant_igmp_snooping_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: igmp_snooping_policy_2
    uuid: "{{ igmp_snooping_policy_1.current.uuid }}"
    state: present

- name: Query a IGMP Snooping Policy object with name
  cisco.mso.ndo_tenant_igmp_snooping_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: igmp_snooping_policy_1
    state: query
  register: query_uuid

- name: Query a IGMP Snooping Policy object with UUID
  cisco.mso.ndo_tenant_igmp_snooping_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    uuid: "{{ igmp_snooping_policy_1.current.uuid }}"
    state: query
  register: query_uuid

- name: Query all IGMP Snooping Policy objects in a Tenant Template
  cisco.mso.ndo_tenant_igmp_snooping_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    state: query
  register: query_all

- name: Delete a IGMP Snooping Policy object with name
  cisco.mso.ndo_tenant_igmp_snooping_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    name: igmp_snooping_policy_1
    state: absent

- name: Delete a IGMP Snooping Policy object with UUID
  cisco.mso.ndo_tenant_igmp_snooping_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: tenant_template
    uuid: "{{ igmp_snooping_policy_1.current.uuid }}"
    state: absent
"""

RETURN = r"""
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec
from ansible_collections.cisco.mso.plugins.module_utils.template import MSOTemplate, KVPair
from ansible_collections.cisco.mso.plugins.module_utils.constants import ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import append_update_ops_data


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        template=dict(type="str", required=True, aliases=["tenant_template"]),
        name=dict(type="str", aliases=["igmp_snooping_policy"]),
        uuid=dict(type="str"),
        description=dict(type="str"),
        admin_state=dict(type="str", choices=["enabled", "disabled"]),
        fast_leave_control=dict(type="str", choices=["enabled", "disabled"]),
        querier_control=dict(type="str", choices=["enabled", "disabled"]),
        querier_version=dict(type="str", choices=["v2", "v3"]),
        query_interval=dict(type="int"),
        query_response_interval=dict(type="int"),
        last_member_query_interval=dict(type="int"),
        start_query_interval=dict(type="int"),
        start_query_count=dict(type="int"),
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
    admin_state = module.params.get("admin_state")
    fast_leave_control = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("fast_leave_control"))
    querier_control = ENABLED_OR_DISABLED_TO_BOOL_STRING_MAP.get(module.params.get("querier_control"))
    querier_version = module.params.get("querier_version")
    query_interval = module.params.get("query_interval")
    query_response_interval = module.params.get("query_response_interval")
    last_member_query_interval = module.params.get("last_member_query_interval")
    start_query_interval = module.params.get("start_query_interval")
    start_query_count = module.params.get("start_query_count")
    state = module.params.get("state")

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")

    existing_mld_snooping_policies = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("igmpSnoopPolicies", [])
    object_description = "IGMP Snooping Policy"
    igmp_snooping_policy_attrs_path = None
    match = None

    if name or uuid:
        match = mso_template.get_object_by_key_value_pairs(
            object_description,
            existing_mld_snooping_policies,
            [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
        )
        if match:
            igmp_snooping_policy_attrs_path = "/tenantPolicyTemplate/template/igmpSnoopPolicies/{0}".format(match.index)
            mso.existing = mso.previous = copy.deepcopy(match.details)
    else:
        mso.existing = mso.previous = existing_mld_snooping_policies

    ops = []

    if state == "present":
        if uuid and not mso.existing:
            mso.fail_json(msg="{0} with the UUID: '{1}' not found".format(object_description, uuid))

        mso_values = dict(
            name=name,
            description=description,
            enableAdminState=admin_state,
            enableFastLeaveControl=fast_leave_control,
            enableQuerierControl=querier_control,
            igmpQuerierVersion=querier_version,
            queryInterval=query_interval,
            queryResponseInterval=query_response_interval,
            lastMemberQueryInterval=last_member_query_interval,
            startQueryInterval=start_query_interval,
            startQueryCount=start_query_count,
        )

        if mso.existing and match:
            append_update_ops_data(ops, match.details, igmp_snooping_policy_attrs_path, mso_values)
            mso.sanitize(match.details, collate=True)
        else:
            mso.sanitize(mso_values)
            ops.append(dict(op="add", path="/tenantPolicyTemplate/template/igmpSnoopPolicies/-", value=mso.sent))

    elif state == "absent":
        if mso.existing and match:
            ops.append(dict(op="remove", path=igmp_snooping_policy_attrs_path))

    if not module.check_mode and ops:
        response_object = mso.request(mso_template.template_path, method="PATCH", data=ops)
        existing_mld_snooping_policies = response_object.get("tenantPolicyTemplate", {}).get("template", {}).get("igmpSnoopPolicies", [])
        match = mso_template.get_object_by_key_value_pairs(
            object_description, existing_mld_snooping_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)]
        )
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


if __name__ == "__main__":
    main()
