#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_userpolicy
version_added: '1.6.0'
short_description: Manage FlashBlade Object Store User Access Policies
description:
- Add or Remove FlashBlade Object Store Access Policies for Account User
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the Object Store User
    - The user to have the policy request applied to
    type: str
  account:
    description:
    - Name of the Object Store Account associated with the user
    type: str
  state:
    description:
    - Define whether the Access Policy should be added or deleted
    - Option to list all available policies
    default: present
    choices: [ absent, present, show ]
    type: str
  policy:
    description:
    - Policies to added or deleted from the Object Store User
    - Only valid policies can be used
    - use I(list) to see available policies
    type: list
    elements: str
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: "1.22.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: List existng ruser access policies for a specific user
  purestorage.flashblade.purefb_userpolicy:
    state: show
    account: foo
    name: bar
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
  register: policy_list

- name: List all available user access policies
  purestorage.flashblade.purefb_userpolicy:
    state: show
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
  register: policy_list

- name: Add user access policies to account user foo/bar
  purestorage.flashblade.purefb_userpolicy:
    name: bar
    account: foo
    policy:
      - pure:policy/bucket-create
      - pure:policy/bucket-delete
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3

- name: Delete user access policies to account user foo/bar
  purestorage.flashblade.purefb_userpolicy:
    name: bar
    account: foo
    policy:
      - pure:policy/bucket-create
      - pure:policy/bucket-delete
    state: absent
    fb_url: 10.10.10.2
    api_token: T-68618f31-0c9e-4e57-aa44-5306a2cf10e3
"""

RETURN = r"""
policy_list:
  description:
  - Returns the list of access policies for a user
  - If no user specified returns all available access policies
  returned: always
  type: list
  elements: str
  sample: ['pure:policy/object-list', 'pure:policy/bucket-list', 'pure:policy/object-read', 'pure:policy/bucket-delete', 'pure:policy/full-access']
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

CONTEXT_API_VERSION = "2.17"


def _check_valid_policy(module, blade, policy):
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        return bool(
            blade.get_object_store_access_policies(
                names=[policy], context_names=[module.params["context"]]
            )
        )
    return bool(blade.get_object_store_access_policies(names=[policy]))


def add_policy(module, blade):
    """Add a single or list of policies to an account user"""
    changed = False
    api_version = list(blade.get_versions().items)
    user_policy_list = []
    policy_list = module.params["policy"]
    for policy in range(len(policy_list)):
        if not _check_valid_policy(module, blade, policy_list[policy]):
            module.fail_json(msg="Policy {0} is not valid.".format(policy_list[policy]))
    username = module.params["account"] + "/" + module.params["name"]
    for policy in range(len(policy_list)):
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_object_store_users_object_store_access_policies(
                member_names=[username],
                policy_names=[policy_list[policy]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_object_store_users_object_store_access_policies(
                member_names=[username], policy_names=[policy_list[policy]]
            )
        if not list(res.items):
            if not module.check_mode:
                changed = True
                if CONTEXT_API_VERSION in api_version:
                    res = blade.post_object_store_access_policies_object_store_users(
                        member_names=[username],
                        policy_names=[policy_list[policy]],
                        context_names=[module.params["context"]],
                    )
                    res = blade.post_object_store_access_policies_object_store_users(
                        member_names=[username], policy_names=[policy_list[policy]]
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to add policy {0}. Error: {1}".format(
                                policy_list[policy], res.errors[0].message
                            )
                        )
                if CONTEXT_API_VERSION in api_version:
                    user_policies = list(
                        blade.get_object_store_access_policies_object_store_users(
                            member_names=[username],
                            context_names=[module.params["context"]],
                        ).items
                    )
                else:
                    user_policies = list(
                        blade.get_object_store_access_policies_object_store_users(
                            member_names=[username]
                        ).items
                    )
                for user_policy in range(len(user_policies)):
                    user_policy_list.append(user_policies[user_policy].policy.name)
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add policy {0} to account user {1}. Error: {2}".format(
                            policy_list[policy], username, res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed, policy_list=user_policy_list)


def remove_policy(module, blade):
    """Remove a single or list of policies to an account user"""
    changed = False
    api_version = list(blade.get_versions().items)
    user_policy_list = []
    policy_list = module.params["policy"]
    for policy in range(len(policy_list)):
        if not _check_valid_policy(module, blade, policy):
            module.fail_json(msg="Policy {0} is not valid.".format(policy))
    username = module.params["account"] + "/" + module.params["name"]
    for policy in range(len(policy_list)):
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_object_store_users_object_store_access_policies(
                member_names=[username],
                policy_names=[policy_list[policy]],
                context_names=[module.params["context"]],
            ).total_item_count
        else:
            res = blade.get_object_store_users_object_store_access_policies(
                member_names=[username], policy_names=[policy_list[policy]]
            ).total_item_count
        if res == 1:
            if not module.check_mode:
                changed = True
                if CONTEXT_API_VERSION in api_version:
                    res = blade.delete_object_store_access_policies_object_store_users(
                        member_names=[username],
                        policy_names=[policy_list[policy]],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.delete_object_store_access_policies_object_store_users(
                        member_names=[username], policy_names=[policy_list[policy]]
                    )
                if CONTEXT_API_VERSION in api_version:
                    user_policies = list(
                        blade.get_object_store_access_policies_object_store_users(
                            member_names=[username],
                            context_names=[module.params["context"]],
                        ).items
                    )
                else:
                    user_policies = list(
                        blade.get_object_store_access_policies_object_store_users(
                            member_names=[username]
                        ).items
                    )
                for user_policy in range(len(user_policies)):
                    user_policy_list.append(user_policies[user_policy].policy.name)
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to remove policy {0} from account user {1}. Error: {2}".format(
                            policy_list[policy], username, res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed, policy_list=user_policy_list)


def list_policy(module, blade):
    """List Object Store User Access Policies"""
    changed = True
    api_version = list(blade.get_versions().items)
    policy_list = []
    if not module.check_mode:
        if module.params["account"] and module.params["name"]:
            username = module.params["account"] + "/" + module.params["name"]
            if CONTEXT_API_VERSION in api_version:
                user_policies = list(
                    blade.get_object_store_access_policies_object_store_users(
                        member_names=[username],
                        context_names=[module.params["context"]],
                    ).items
                )
            else:
                user_policies = list(
                    blade.get_object_store_access_policies_object_store_users(
                        member_names=[username]
                    ).items
                )
            for user_policy in range(len(user_policies)):
                policy_list.append(user_policies[user_policy].policy.name)
        else:
            if CONTEXT_API_VERSION in api_version:
                policies = blade.get_object_store_access_policies(
                    context_names=[module.params["context"]]
                )
            else:
                policies = blade.get_object_store_access_policies()
            p_list = list(policies.items)
            if policies.status_code != 200:
                module.fail_json(msg="Failed to get Object Store User Access Policies")
            for policy in range(len(p_list)):
                policy_list.append(p_list[policy].name)
    module.exit_json(changed=changed, policy_list=policy_list)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            state=dict(
                type="str", default="present", choices=["absent", "present", "show"]
            ),
            name=dict(type="str"),
            account=dict(type="str"),
            policy=dict(type="list", elements="str"),
            context=dict(type="str", default=""),
        )
    )
    required_if = [
        ["state", "present", ["name", "account", "policy"]],
        ["state", "absent", ["name", "account", "policy"]],
    ]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    blade = get_system(module)

    state = module.params["state"]
    if (
        blade.get_object_store_users(
            names=[module.params["account"] + "/" + module.params["name"]]
        ).status_code
        != 200
        and state != "show"
    ):
        module.fail_json(
            msg="Account User {0}/{1} does not exist".format(
                module.params["account"], module.params["name"]
            )
        )
    if state == "show":
        list_policy(module, blade)
    elif state == "present":
        add_policy(module, blade)
    elif state == "absent":
        remove_policy(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
