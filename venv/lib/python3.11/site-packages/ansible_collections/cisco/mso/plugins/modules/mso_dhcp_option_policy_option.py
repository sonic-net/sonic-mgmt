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
module: mso_dhcp_option_policy_option
short_description: Manage DHCP options in a DHCP Option policy.
description:
- Manage DHCP options in a DHCP Option policy on Cisco Multi-Site Orchestrator.
- This module is only supported on NDO version prior to v4.0.
author:
- Lionel Hercot (@lhercot)
options:
  dhcp_option_policy:
    description:
    - Name of the DHCP Option Policy
    type: str
    required: true
  name:
    description:
    - Name of the option in the DHCP Option Policy
    type: str
    aliases: [ option ]
  id:
    description:
    - Id of the option in the DHCP Option Policy
    type: int
  data:
    description:
    - Data of the DHCP option in the DHCP Option Policy
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
- name: Add a new option to a DHCP Option Policy
  cisco.mso.mso_dhcp_option_policy_option:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_option_policy: my_test_dhcp_policy
    name: ansible_test
    id: 1
    data: Data stored in the option
    state: present

- name: Remove a option to a DHCP Option Policy
  cisco.mso.mso_dhcp_option_policy_option:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_option_policy: my_test_dhcp_policy
    name: ansible_test
    state: absent

- name: Query a option to a DHCP Option Policy
  cisco.mso.mso_dhcp_option_policy_option:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_option_policy: my_test_dhcp_policy
    name: ansible_test
    state: query
  register: query_result

- name: Query all option of a DHCP Option Policy
  cisco.mso.mso_dhcp_option_policy_option:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    dhcp_option_policy: my_test_dhcp_policy
    state: query
  register: query_result
"""

RETURN = r"""
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import (
    MSOModule,
    mso_argument_spec,
)


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        dhcp_option_policy=dict(type="str", required=True),
        name=dict(type="str", aliases=["option"]),
        id=dict(type="int"),
        data=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name", "id", "data"]],
            ["state", "absent", ["name"]],
        ],
    )

    dhcp_option_policy = module.params.get("dhcp_option_policy")
    option_id = module.params.get("id")
    name = module.params.get("name")
    data = module.params.get("data")
    state = module.params.get("state")

    mso = MSOModule(module)

    path = "policies/dhcp/option"

    option_index = None
    previous_option = {}

    # Query for existing object(s)
    dhcp_option_obj = mso.get_obj(path, name=dhcp_option_policy, key="DhcpRelayPolicies")
    if "id" not in dhcp_option_obj:
        mso.fail_json(msg="DHCP Option Policy '{0}' is not a valid DHCP Option Policy name.".format(dhcp_option_policy))
    policy_id = dhcp_option_obj.get("id")
    options = []
    if "dhcpOption" in dhcp_option_obj:
        options = dhcp_option_obj.get("dhcpOption")
        for index, opt in enumerate(options):
            if opt.get("name") == name:
                previous_option = opt
                option_index = index

    # If we found an existing object, continue with it
    path = "{0}/{1}".format(path, policy_id)

    if state == "query":
        mso.existing = options
        if name is not None:
            mso.existing = previous_option
        mso.exit_json()

    mso.previous = previous_option
    if state == "absent":
        option = {}
        if previous_option and option_index is not None:
            options.pop(option_index)

    elif state == "present":
        option = dict(
            id=str(option_id),
            name=name,
            data=data,
        )
        if option_index is not None:
            options[option_index] = option
        else:
            options.append(option)

    if module.check_mode:
        mso.existing = option
    else:
        mso.existing = dhcp_option_obj
        dhcp_option_obj["dhcpOption"] = options
        mso.sanitize(dhcp_option_obj, collate=True)
        new_dhcp_option_obj = mso.request(path, method="PUT", data=mso.sent)
        mso.existing = {}
        for index, opt in enumerate(new_dhcp_option_obj.get("dhcpOption")):
            if opt.get("name") == name:
                mso.existing = opt

    mso.exit_json()


if __name__ == "__main__":
    main()
