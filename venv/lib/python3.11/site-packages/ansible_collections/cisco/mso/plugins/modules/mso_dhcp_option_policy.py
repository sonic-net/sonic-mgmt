#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# Copyright: (c) 2020, Jorge Gomez (@jgomezve) <jgomezve@cisco.com> (based on mso_dhcp_relay_policy module)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: mso_dhcp_option_policy
short_description: Manage DHCP Option policies.
description:
- Manage DHCP Option policies on Cisco Multi-Site Orchestrator.
- This module is only supported on NDO version prior to v4.0.
author:
- Lionel Hercot (@lhercot)
options:
  dhcp_option_policy:
    description:
    - Name of the DHCP Option Policy
    type: str
    aliases: [ name ]
  description:
    description:
    - Description of the DHCP Option Policy
    type: str
  tenant:
    description:
    - Tenant where the DHCP Option Policy is located.
    type: str
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new DHCP Option Policy
  cisco.mso.mso_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_option_policy: my_test_dhcp_policy
    description: "My Test DHCP Policy"
    tenant: ansible_test
    state: present

- name: Remove DHCP Option Policy
  cisco.mso.mso_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_option_policy: my_test_dhcp_policy
    state: absent

- name: Query a DHCP Option Policy
  cisco.mso.mso_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_option_policy: my_test_dhcp_policy
    state: query
  register: query_result

- name: Query all DHCP Option Policies
  cisco.mso.mso_dhcp_option_policy:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    state: query
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dhcp_option_policy=dict(type="str", aliases=["name"]),
        description=dict(type="str"),
        tenant=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["dhcp_option_policy"]],
            ["state", "present", ["dhcp_option_policy", "tenant"]],
        ],
    )

    dhcp_option_policy = module.params.get("dhcp_option_policy")
    description = module.params.get("description")
    tenant = module.params.get("tenant")
    state = module.params.get("state")

    mso = MSOModule(module)

    path = "policies/dhcp/option"

    # Query for existing object(s)
    if dhcp_option_policy:
        mso.existing = mso.get_obj(path, name=dhcp_option_policy, key="DhcpRelayPolicies")
        if mso.existing:
            policy_id = mso.existing.get("id")
            # If we found an existing object, continue with it
            path = "{0}/{1}".format(path, policy_id)
    else:
        mso.existing = mso.query_objs(path, key="DhcpRelayPolicies")

    mso.previous = mso.existing

    if state == "absent":
        if mso.existing:
            if module.check_mode:
                mso.existing = {}
            else:
                mso.existing = mso.request(path, method="DELETE", data=mso.sent)

    elif state == "present":
        tenant_id = mso.lookup_tenant(tenant)
        payload = dict(
            name=dhcp_option_policy,
            desc=description,
            policyType="dhcp",
            policySubtype="option",
            tenantId=tenant_id,
        )
        mso.sanitize(payload, collate=True)

        if mso.existing:
            if mso.check_changed():
                if module.check_mode:
                    mso.existing = mso.proposed
                else:
                    mso.existing = mso.request(path, method="PUT", data=mso.sent)
        else:
            if module.check_mode:
                mso.existing = mso.proposed
            else:
                mso.existing = mso.request(path, method="POST", data=mso.sent)

    mso.exit_json()


if __name__ == "__main__":
    main()
