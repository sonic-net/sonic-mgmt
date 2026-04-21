#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: ndo_dhcp_option_policy
short_description: Manage DHCP Option Policies on Cisco Nexus Dashboard Orchestrator (NDO).
description:
- Manage DHCP Option Policies on Cisco Nexus Dashboard Orchestrator (NDO).
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
  option_policy:
    description:
    - The name of the DHCP Option Policy.
    type: str
    aliases: [ name ]
  option_policy_uuid:
    description:
    - The uuid of the DHCP Option Policy.
    - This parameter is required when the O(option_policy) needs to be updated.
    type: str
    aliases: [ uuid ]
  description:
    description:
    - The description of the DHCP Option Policy.
    type: str
  options:
    description:
    - A list of options attached to the DHCP Option Policy.
    - The list of configured options must contain at least one option.
    - When the list of options is null the update will not change existing option configuration.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the option.
        type: str
        required: true
      id:
        description:
        - The id of the option.
        type: int
      data:
        description:
        - The data of the option.
        type: str
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
- name: Create a new dhcp option policy
  cisco.mso.ndo_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    option_policy: ansible_test_option_policy
    options:
      - name: option_1
        id: 1
        data: data_1
    state: present
  register: create

- name: Query a dhcp option policy with name
  cisco.mso.ndo_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    option_policy: ansible_test_option_policy
    state: query
  register: query_one

- name: Query a dhcp option policy with UUID
  cisco.mso.ndo_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    option_policy_uuid: '{{ create.current.uuid }}'
    state: query
  register: query_uuid

- name: Query all dhcp option policy in the template
  cisco.mso.ndo_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    state: query
  register: query_all

- name: Delete a dhcp option policy
  cisco.mso.ndo_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    template: ansible_tenant_template
    option_policy: ansible_test_option_policy
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
        option_policy=dict(type="str", aliases=["name"]),
        option_policy_uuid=dict(type="str", aliases=["uuid"]),
        description=dict(type="str"),
        options=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str", required=True),
                id=dict(type="int"),
                data=dict(type="str"),
            ),
        ),
        state=dict(type="str", default="query", choices=["absent", "query", "present"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["option_policy"]],
            ["state", "present", ["option_policy"]],
        ],
    )

    mso = MSOModule(module)

    template = module.params.get("template")
    option_policy = module.params.get("option_policy")
    option_policy_uuid = module.params.get("option_policy_uuid")
    options = get_options_payload(module.params.get("options")) if module.params.get("options") else []
    description = module.params.get("description")
    state = module.params.get("state")

    ops = []
    match = None
    err_message_min_options = "At least one option is required when state is present."

    mso_template = MSOTemplate(mso, "tenant", template)
    mso_template.validate_template("tenantPolicy")

    path = "/tenantPolicyTemplate/template/dhcpOptionPolicies"

    match = get_dhcp_option_policy(mso_template, option_policy_uuid, option_policy)

    if option_policy_uuid or option_policy:
        if match:
            mso.existing = mso.previous = copy.deepcopy(match.details)  # Query a specific object
    elif match:
        mso.existing = match  # Query all objects

    if state == "present":
        if match:
            if module.params.get("options") is not None and len(options) == 0:
                mso.fail_json(msg=err_message_min_options)

            if option_policy and match.details.get("name") != option_policy:
                ops.append(dict(op="replace", path="{0}/{1}/name".format(path, match.index), value=option_policy))
                match.details["name"] = option_policy

            if description is not None and match.details.get("description") != description:
                ops.append(dict(op="replace", path="{0}/{1}/description".format(path, match.index), value=description))
                match.details["description"] = description

            if module.params.get("options") is not None and match.details.get("options") != options:
                ops.append(dict(op="replace", path="{0}/{1}/options".format(path, match.index), value=options))
                match.details["options"] = options

            mso.sanitize(match.details)

        else:
            if not options:
                mso.fail_json(msg=err_message_min_options)

            payload = {"name": option_policy, "options": options}
            if description:
                payload["description"] = description

            ops.append(dict(op="add", path="{0}/-".format(path), value=payload))

            mso.sanitize(payload)

        mso.existing = mso.proposed

    elif state == "absent":
        if match:
            ops.append(dict(op="remove", path="{0}/{1}".format(path, match.index)))
        mso.existing = {}

    if not module.check_mode and ops:
        mso_template.template = mso.request(mso_template.template_path, method="PATCH", data=ops)
        match = get_dhcp_option_policy(mso_template, option_policy_uuid, option_policy)
        if match:
            mso.existing = match.details  # When the state is present
        else:
            mso.existing = {}  # When the state is absent
    elif module.check_mode and state != "query":  # When the state is present/absent with check mode
        mso.existing = mso.proposed if state == "present" else {}

    mso.exit_json()


def get_dhcp_option_policy(mso_template, uuid=None, name=None, fail_module=False):
    existing_dhcp_option_policies = mso_template.template.get("tenantPolicyTemplate", {}).get("template", {}).get("dhcpOptionPolicies", [])
    if uuid or name:  # Query a specific object
        return mso_template.get_object_by_key_value_pairs(
            "DHCP Option Policy", existing_dhcp_option_policies, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
        )
    return existing_dhcp_option_policies  # Query all objects


def get_options_payload(options):
    payload = []
    for option in options:
        option_payload = {"name": option.get("name")}
        if option.get("id") and id != 0:
            option_payload["id"] = option.get("id")
        if option.get("data"):
            option_payload["data"] = option.get("data")
        payload.append(option_payload)
    return payload


if __name__ == "__main__":
    main()
