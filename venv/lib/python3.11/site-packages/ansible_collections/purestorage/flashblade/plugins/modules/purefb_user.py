#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
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
module: purefb_user
version_added: '1.0.0'
short_description: Create, modify or delete FlashBlade user accounts
description:
- Modify user on a Pure Stoage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create, delete or update local user account
    default: present
    type: str
    choices: [ absent, present ]
    version_added: "1.21.0"
  name:
    description:
    - The name of the user account
    type: str
    required: true
  role:
    description:
    - Sets the local user's access level to the system
    type: str
    default: readonly
    choices: [ readonly, ops_admin, storage_admin, array_admin ]
    version_added: "1.21.0"
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
    version_added: "1.21.0"
  timeout:
    description:
      - The duration of API token validity.
      - Valid values are weeks (w), days(d), hours(h), minutes(m) and seconds(s).
    type: str
    default: "0"
    version_added: "1.21.0"
  public_key:
    description:
    - The API clients PEM formatted (Base64 encoded) RSA public key.
    - Include the I(—–BEGIN PUBLIC KEY—–) and I(—–END PUBLIC KEY—–) lines
    type: str
    version_added: "1.8.0"
  clear_lock:
    description:
    - Clear user lockout flag
    type: bool
    default: false
    version_added: "1.8.0"
  ad_user:
    description:
      - Whether the user is in the AD system
      - Not required for local users
    type: bool
    default: false
    version_added: "1.21.0"
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Change password for local user (NOT IDEMPOTENT)
  purestorage.flashblade.purefb_user:
    name: pureuser
    password: anewpassword
    old_password: apassword
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Set public key for user
  purestorage.flashblade.purefb_user:
    name: fred
    public_key: "{{lookup('file', 'public_pem_file') }}"
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Clear user lockout
  purestorage.flashblade.purefb_user:
    name: fred
    clear_lock: true
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6

- name: Create an API token (TTL of 2 days) and assign a public key to an AD user
  purestorage.flashblade.purefb_user:
    name: ansible-ad
    ad_user: true
    public_key: "{{lookup('file', 'id_rsa.pub') }}"
    api: true
    timeout: 2d
    fb_url: 10.10.10.2
    api_token: T-9f276a18-50ab-446e-8a0c-666a3529a1b6
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flashblade import (
        AdminPatch,
        AdminPost,
        AdminRole,
        ReferenceWritable,
    )
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.common import (
    convert_time_to_millisecs,
)
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)
import re

MIN_LOCAL_USER = "2.15"
MIN_EXPOSE_API = "2.18"


def get_user(module, blade):
    """Return Local User Account or None"""
    user = None
    res = blade.get_admins(names=[module.params["name"]])
    if res.status_code != 200:
        return None
    else:
        return list(res.items)[0]


def create_local_user(module, blade, user):
    """Create or Update Local User Account"""
    changed = key_changed = api_changed = role_changed = passwd_changed = False
    role = module.params["role"]
    api_token = "No API token created"
    if not user:
        changed = True
        if not module.check_mode:
            res = blade.post_admins(
                names=[module.params["name"]],
                admin=AdminPost(
                    role=ReferenceWritable(name=role),
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
                res = blade.post_admins_api_tokens(
                    admin_names=[module.params["name"]], timeout=ttl
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create API token. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
                api_token = list(res.items)[0].api_token.token
            if module.params["public_key"]:
                res = blade.patch_admin(
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
                res = blade.patch_admins(
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
            res = blade.delete_admins_api_tokens(admin_names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete original API token. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            res = blade.post_admins_api_tokens(
                admin_names=[module.params["name"]], timeout=ttl
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to recreate API token. Error: {0}".format(
                        res.errors[0].message
                    )
                )
            api_token = list(res.items)[0].api_token.token
        if (
            module.params["role"]
            and module.params["role"] != getattr(user.role, "name", None)
            and user.is_local
        ):
            if module.params["name"] != "pureuser":
                role_changed = True
                if not module.check_mode:
                    res = blade.patch_admins(
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
            res = blade.patch_admins(
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


def update_ad_user(module, blade, user):
    """Update AD user API token and/or SSH key"""
    api_token = "No API token created"
    api_changed = ssh_changed = False
    if module.params["api"]:
        if user:
            api_changed = True
            ttl = convert_time_to_millisecs(module.params["timeout"])
            if getattr(user.api_token, "token"):
                res = blade.delete_admins_api_tokens(
                    admin_names=[module.params["name"]]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete original API token. Error: {0}".format(
                            res.errors[0].message
                        )
                    )
            res = blade.post_admins_api_tokens(
                admin_names=[module.params["name"]], timeout=ttl
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
            res = blade.post_admins_api_tokens(
                admin_names=[module.params["name"]], timeout=ttl
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
        res = blade.patch_admins(
            names=[module.params["name"]],
            admin=AdminPatch(public_key=module.params["public_key"]),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to add SSH key. Error: {0}".format(res.errors[0].message)
            )
    changed = bool(api_changed or ssh_changed)
    module.exit_json(changed=changed, user_info=api_token)


def delete_ad_user(module, blade, user):
    """Delete AD User Account references"""
    changed = False
    if not module.check_mode:
        if user:
            changed = True
            res = blade.delete_admins_api_tokens(admin_names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="AD Account {0} API token deletion failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            if hasattr(user, "public_key"):
                res = blade.patch_admins(
                    names=[module.params["name"]],
                    admin=AdminPatch(public_key=""),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="AD Account {0} public key deletion failed. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
        res = blade.delete_admins_cache(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Admin Cache deleteion failed for AD user {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_local_user(module, blade):
    """Delete Local User Account"""
    changed = True
    if not module.check_mode:
        res = blade.delete_admins(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="User Account {0} deletion failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            public_key=dict(type="str", no_log=True),
            password=dict(type="str", no_log=True),
            old_password=dict(type="str", no_log=True),
            clear_lock=dict(type="bool", default=False),
            role=dict(
                type="str",
                choices=["readonly", "ops_admin", "storage_admin", "array_admin"],
                default="readonly",
            ),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            api=dict(type="bool", default=False),
            ad_user=dict(type="bool", default=False),
            timeout=dict(type="str", default="0"),
        )
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )

    blade = get_system(module)
    api_version = list(blade.get_versions().items)
    if MIN_LOCAL_USER not in api_version:
        module.fail_json(
            msg="Purity//FB must be upgraded to support managing local users."
        )

    state = module.params["state"]
    pattern = re.compile("^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$")
    user = get_user(module, blade)
    local_user = getattr(user, "is_local", False)
    if not pattern.match(module.params["name"]):
        module.fail_json(
            msg="name must contain a minimum of 1 and a maximum of 32 characters "
            "(alphanumeric or `-`). All letters must be lowercase."
        )

    if state == "present" and not local_user and module.params["ad_user"]:
        update_ad_user(module, blade, user)
    if state == "absent" and local_user:
        delete_local_user(module, blade)
    if state == "absent" and not local_user:
        delete_ad_user(module, blade, user)
    elif state == "present" and not module.params["ad_user"]:
        create_local_user(module, blade, user)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
