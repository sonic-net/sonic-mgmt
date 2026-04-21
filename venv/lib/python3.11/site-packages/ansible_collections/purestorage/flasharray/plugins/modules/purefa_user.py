#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefa_user
version_added: '1.0.0'
short_description: Create, modify or delete FlashArray local user account
description:
- Create, modify or delete local users on a Pure Stoage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create, delete or update local user account
    default: present
    type: str
    choices: [ absent, present ]
  name:
    description:
    - The name of the local user account
    type: str
    required: true
  role:
    description:
    - Sets the local user's access level to the array
    type: str
    default: readonly
    choices: [ readonly, ops_admin, storage_admin, array_admin ]
  password:
    description:
    - Password for the local user.
    type: str
  old_password:
    description:
    - If changing an existing password, you must provide the old password for security
    type: str
  api:
    description:
    - Define whether to create an API token for this user
    - Token can be exposed using the I(debug) module
    type: bool
    default: false
  timeout:
    description:
      - The duration of API token validity.
      - Valid values are weeks (w), days(d), hours(h), minutes(m) and seconds(s).
    type: str
    default: "0"
    version_added: "1.34.0"
  public_key:
    description:
      - Public key for SSH access.
      - To remove existing key use an empty string
    type: str
    version_added: "1.34.0"
  ad_user:
    description:
      - Whether the user is in the AD system
      - Not required for local users
    type: bool
    default: false
    version_added: "1.37.0"
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new user ansible with API token
  purestorage.flasharray.purefa_user:
    name: ansible
    password: apassword
    role: storage_admin
    api: true
    timeout: 2d
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: result

  debug:
    msg: "API Token: {{ result['user_info']['user_api'] }}"

- name: Overwrite/add SSH public key for existing user
  purestorage.flasharray.purefa_user:
    name: ansible
    role: array_admin
    public_key: "{{lookup('file', 'id_rsa.pub') }}"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Remove existing SSH public key from user
  purestorage.flasharray.purefa_user:
    name: ansible
    role: array_admin
    public_key: ""
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Change role type for existing user
  purestorage.flasharray.purefa_user:
    name: ansible
    role: array_admin
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Change password type for existing user (NOT IDEMPOTENT)
  purestorage.flasharray.purefa_user:
    name: ansible
    password: anewpassword
    old_password: apassword
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create an API token (TTL of 2 days) and assign a public key to an AD user
  purestorage.flasharray.purefa_user:
    name: ansible-ad
    ad_user: true
    public_key: "{{lookup('file', 'id_rsa.pub') }}"
    api: true
    timeout: 2d
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Change API token and token timeout for existing user
  purestorage.flasharray.purefa_user:
    name: ansible
    api: true
    role: array_admin
    timeout: 1d
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: result

  debug:
    msg: "API Token: {{ result['user_info']['user_api'] }}"
"""

RETURN = r"""
"""


HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import AdminPost, AdminPatch, AdminRole
except ImportError:
    HAS_PURESTORAGE = False

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.common import (
    convert_time_to_millisecs,
)


def get_user(module, array):
    """Return Local User Account or None"""
    res = array.get_admins(names=[module.params["name"]])
    if res.status_code != 200:
        return None
    return list(res.items)[0]


def create_local_user(module, array, user):
    """Create or Update Local User Account"""
    changed = key_changed = api_changed = role_changed = passwd_changed = False
    role = module.params["role"]
    api_token = "No API token created"
    if not user:
        changed = True
        if not module.check_mode:
            res = array.post_admins(
                names=[module.params["name"]],
                admin=AdminPost(
                    role=AdminRole(name=role),
                    password=module.params["password"],
                ),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create user {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            if module.params["api"]:
                ttl = convert_time_to_millisecs(module.params["timeout"])
                res = array.post_admins_api_tokens(
                    names=[module.params["name"]], timeout=ttl
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create API token. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
                api_token = list(res.items)[0].api_token.token
            if module.params["public_key"]:
                res = array.patch_admins(
                    names=[module.params["name"]],
                    admin=AdminPatch(public_key=module.params["public_key"]),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to add SSH key. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
    else:
        if module.params["password"] and not module.params["old_password"]:
            module.exit_json(changed=changed)
        if (
            module.params["password"]
            and module.params["old_password"]
            and module.params["password"] != module.params["old_password"]
        ):
            passwd_changed = True
            if not module.check_mode:
                res = array.patch_admins(
                    names=[module.params["name"]],
                    admin=AdminPatch(
                        password=module.params["password"],
                        old_password=module.params["old_password"],
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Local User {0} password reset failed. Error: {1}"
                        "Check old password.".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        if module.params["api"]:
            api_changed = True
            ttl = convert_time_to_millisecs(module.params["timeout"])
            res = array.delete_admins_api_tokens(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete original API token. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            res = array.post_admins_api_tokens(
                names=[module.params["name"]], timeout=ttl
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to recreate API token. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            api_token = list(res.items)[0].api_token.token
        if module.params["role"] and module.params["role"] != getattr(
            user.role, "name", None
        ):
            if module.params["name"] != "pureuser":
                role_changed = True
                if not module.check_mode:
                    res = array.patch_admins(
                        names=[module.params["name"]],
                        admin=AdminPatch(role=AdminRole(name=module.params["role"])),
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Local User {0} role changed failed. Error: {1}".format(
                                module.params["name"], res.errors[0].message
                            )
                        )
            else:
                module.warn("Role for 'pureuser' cannot be modified.")
        if module.params["public_key"] is not None and module.params[
            "public_key"
        ] != getattr(user, "public_key", ""):
            key_changed = True
            res = array.patch_admins(
                names=[module.params["name"]],
                admin=AdminPatch(public_key=module.params["public_key"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to change SSH key. Error: {0}".format(
                        res.errors[0].message
                    )
                )
        changed = bool(passwd_changed or role_changed or api_changed or key_changed)
    module.exit_json(changed=changed, user_info=api_token)


def update_ad_user(module, array, user):
    """Update AD user API token and/or SSH key"""
    api_token = "No API token created"
    api_changed = ssh_changed = False
    if module.params["api"]:
        if user:
            api_changed = True
            ttl = convert_time_to_millisecs(module.params["timeout"])
            res = array.delete_admins_api_tokens(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete original API token. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            res = array.post_admins_api_tokens(
                names=[module.params["name"]], timeout=ttl
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to recreate API token. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            api_token = list(res.items)[0].api_token.token
        else:
            api_changed = True
            ttl = convert_time_to_millisecs(module.params["timeout"])
            res = array.post_admins_api_tokens(
                names=[module.params["name"]], timeout=ttl
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create API token. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            api_token = list(res.items)[0].api_token.token
    if module.params["public_key"]:
        ssh_changed = True
        res = array.patch_admins(
            names=[module.params["name"]],
            admin=AdminPatch(public_key=module.params["public_key"]),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to add SSH key. Error: {0}".format(res.errors[0].message)
            )
    changed = bool(api_changed or ssh_changed)
    module.exit_json(changed=changed, user_info=api_token)


def delete_local_user(module, array):
    """Delete Local User Account"""
    changed = True
    if not module.check_mode:
        res = array.delete_admins(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="User Account {0} deletion failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_ad_user(module, array, user):
    """Delete AD User Account references"""
    changed = False
    if not module.check_mode:
        if user:
            changed = True
            res = array.delete_admins_api_tokens(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="AD Account {0} API token deletion failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            if hasattr(user, "public_key"):
                res = array.patch_admins(
                    names=[module.params["name"]],
                    admin=AdminPatch(public_key=""),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="AD Account {0} public key deletion failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True, type="str"),
            role=dict(
                type="str",
                choices=["readonly", "ops_admin", "storage_admin", "array_admin"],
                default="readonly",
            ),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            password=dict(type="str", no_log=True),
            old_password=dict(type="str", no_log=True),
            api=dict(type="bool", default=False),
            timeout=dict(type="str", default="0"),
            public_key=dict(type="str", no_log=True),
            ad_user=dict(type="bool", default=False),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    array = get_array(module)
    pattern = re.compile("^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$")
    if not pattern.match(module.params["name"]):
        module.fail_json(
            msg="name must contain a minimum of 1 and a maximum of 32 characters "
            "(alphanumeric or `-`). All letters must be lowercase."
        )
    user = get_user(module, array)
    local_user = getattr(user, "is_local", False)
    if state == "present" and not local_user and module.params["ad_user"]:
        update_ad_user(module, array, user)
    if state == "absent" and local_user:
        delete_local_user(module, array)
    if state == "absent" and not local_user:
        delete_ad_user(module, array, user)
    elif state == "present" and not module.params["ad_user"]:
        create_local_user(module, array, user)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
