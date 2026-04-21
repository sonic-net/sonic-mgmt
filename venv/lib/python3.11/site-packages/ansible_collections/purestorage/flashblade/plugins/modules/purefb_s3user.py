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
module: purefb_s3user
version_added: '1.0.0'
short_description: Create or delete FlashBlade Object Store account users
description:
- Create or delete object store account users on a Pure Stoage FlashBlade.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    description:
    - Create or delete object store account user
    - Remove a specified access key for a user
    default: present
    choices: [ absent, present, remove_key, keystate ]
    type: str
  name:
    description:
    - The name of object store user
    type: str
    required: true
  account:
    description:
    - The name of object store account associated with user
    type: str
    required: true
  access_key:
    description:
    - Create secret access key.
    - Key can be exposed using the I(debug) module
    - If enabled this will override I(imported_key)
    type: bool
    default: false
  multiple_keys:
    description:
    - Allow multiple access keys to be created for the user.
    type: bool
    default: false
    version_added: "1.12.0"
  key_name:
    aliases: [ remove_key ]
    description:
    - Access key to be modified
    type: str
    version_added: "1.5.0"
  enable_key:
    description:
    - Is the access key enabled?
    type: bool
    default: true
    version_added: "1.20.0"
  imported_key:
    description:
    - Access key of imported credentials
    type: str
    version_added: "1.4.0"
  imported_secret:
    description:
    - Access key secret for access key to import
    type: str
    version_added: "1.4.0"
  policy:
    description:
    - User Access Policies to be assigned to user on creation
    - To amend policies use the I(purestorage.flashblade.purefb_userpolicy) module
    - If not specified, I(pure\:policy/full-access) will be added
    type: list
    elements: str
    version_added: "1.6.0"
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
- name: Create object store user (with access ID and key) foo in account bar
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    access_key: true
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: result

- debug:
    msg: "S3 User: {{ result['s3user_info'] }}"

- name: Create object store user (with access ID and key) foo in account bar with access policy
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    access_key: true
    policy:
      - pure:policy/object-write
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Create object store user foo using imported key/secret in account bar
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    imported_key: "PSABSSZRHPMEDKHMAAJPJBONPJGGDDAOFABDGLBJLHO"
    imported_secret: "BAG61F63105e0d3669/e066+5C5DFBE2c127d395LBGG"
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete object store user foo in account bar
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Change state of object store access key to disabled
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    key_name: PSFBSAZRDHFKAMIEGIBLIEDDOFLHGEEEEFCBPBFCLJ
    state: keystate
    enable_key: false
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete object store access key
  purestorage.flashblade.purefb_s3user:
    name: foo
    account: bar
    key_name: PSFBSAZRDHFKAMIEGIBLIEDDOFLHGEEEEFCBPBFCLJ
    state: remove_key
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = r"""
"""


HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import ObjectStoreAccessKey, ObjectStoreAccessKeyPost
except ImportError:
    HAS_PYPURECLIENT = False


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

CONTEXT_API_VERSION = "2.17"


def get_s3acc(module, blade):
    """Return Object Store Account or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_object_store_accounts(
            names=[module.params["account"]], context_names=[module.params["context"]]
        )
    else:
        res = blade.get_object_store_accounts(names=[module.params["account"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_s3user(module, blade):
    """Return Object Store Account or None"""
    api_version = list(blade.get_versions().items)
    full_user = module.params["account"] + "/" + module.params["name"]
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_object_store_users(
            names=[full_user], context_names=[module.params["context"]]
        )
    else:
        res = blade.get_object_store_users(names=[full_user])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def update_s3user(module, blade):
    """Update Object Store User"""
    changed = False
    api_version = list(blade.get_versions().items)
    exists = False
    s3user_facts = {}
    user = module.params["account"] + "/" + module.params["name"]
    if module.params["access_key"] or module.params["imported_key"]:
        key_count = 0
        if CONTEXT_API_VERSION in api_version:
            keys = list(
                blade.get_object_store_access_keys(
                    context_names=[module.params["context"]]
                ).items
            )
        else:
            keys = list(blade.get_object_store_access_keys().items)
        for key in range(len(keys)):
            if module.params["imported_key"]:
                if keys[key].name == module.params["imported_key"]:
                    module.warn("Imported key provided already belongs to a user")
                    exists = True
            if keys[key].user.name == user:
                key_count += 1
        if not exists:
            if key_count < 2:
                if module.params["access_key"] and module.params["imported_key"]:
                    module.warn("'access_key: true' overrides imported keys")
                if module.params["access_key"]:
                    if key_count == 0 or (
                        key_count >= 1 and module.params["multiple_keys"]
                    ):
                        changed = True
                        if not module.check_mode:
                            if CONTEXT_API_VERSION in api_version:
                                res = blade.post_object_store_access_keys(
                                    object_store_access_key=ObjectStoreAccessKeyPost(
                                        user={"name": user}
                                    ),
                                    context_names=[module.params["context"]],
                                )
                            else:
                                res = blade.post_object_store_access_keys(
                                    object_store_access_key=ObjectStoreAccessKeyPost(
                                        user={"name": user}
                                    )
                                )
                            if res.status_code == 200:
                                result = list(res.items)[0]
                                if not module.params["enable_key"]:
                                    if CONTEXT_API_VERSION in api_version:
                                        blade.patch_object_store_access_keys(
                                            names=[result.name],
                                            object_store_access_key=ObjectStoreAccessKey(
                                                enabled=False
                                            ),
                                            context_names=[module.params["context"]],
                                        )
                                    else:
                                        blade.patch_object_store_access_keys(
                                            names=[result.name],
                                            object_store_access_key=ObjectStoreAccessKey(
                                                enabled=False
                                            ),
                                        )
                                s3user_facts["fb_s3user"] = {
                                    "user": user,
                                    "enabled": module.params["enable_key"],
                                    "access_key": result.secret_access_key,
                                    "access_id": result.name,
                                }
                            else:
                                module.fail_json(
                                    msg="Object Store User {0} access Key import failed. "
                                    "Error: {1}".format(
                                        user,
                                        res.errors[0].message,
                                    )
                                )
                else:
                    changed = True
                    if not module.check_mode:
                        if CONTEXT_API_VERSION in api_version:
                            res = blade.post_object_store_access_keys(
                                names=[module.params["imported_key"]],
                                object_store_access_key=ObjectStoreAccessKeyPost(
                                    user={"name": user},
                                    secret_access_key=module.params["imported_secret"],
                                ),
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = blade.post_object_store_access_keys(
                                names=[module.params["imported_key"]],
                                object_store_access_key=ObjectStoreAccessKeyPost(
                                    user={"name": user},
                                    secret_access_key=module.params["imported_secret"],
                                ),
                            )
                        if res.status_code == 200:
                            result = list(res.items)[0]
                            if not module.params["enable_key"]:
                                if CONTEXT_API_VERSION in api_version:
                                    blade.patch_object_store_access_keys(
                                        names=[result.name],
                                        object_store_access_key=ObjectStoreAccessKey(
                                            enabled=False
                                        ),
                                        context_names=[module.params["context"]],
                                    )
                                else:
                                    blade.patch_object_store_access_keys(
                                        names=[result.name],
                                        object_store_access_key=ObjectStoreAccessKey(
                                            enabled=False
                                        ),
                                    )
                        else:
                            module.fail_json(
                                msg="Object Store User {0} access Key creation failed. "
                                "Error: {1}".format(
                                    user,
                                    res.errors[0].message,
                                )
                            )
            else:
                module.warn(
                    "Object Store User {0}: Maximum Access Key count reached".format(
                        user
                    )
                )
    module.exit_json(changed=changed, s3user_info=s3user_facts)


def create_s3user(module, blade):
    """Create Object Store Account"""
    s3user_facts = {}
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        user = module.params["account"] + "/" + module.params["name"]
        if CONTEXT_API_VERSION in api_version:
            res = blade.post_object_store_users(
                names=[user], context_names=[module.params["context"]]
            )
        else:
            res = blade.post_object_store_users(names=[user])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create account {0}. Error:{1}".format(
                    user, res.errors[0].message
                )
            )
        if module.params["access_key"] and module.params["imported_key"]:
            module.warn("'access_key: true' overrides imported keys")
        if module.params["access_key"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_object_store_access_keys(
                    object_store_access_key=ObjectStoreAccessKeyPost(
                        user={"name": user}
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_object_store_access_keys(
                    object_store_access_key=ObjectStoreAccessKeyPost(
                        user={"name": user}
                    )
                )
            if res.status_code == 200:
                result = list(res.items)[0]
                if not module.params["enable_key"]:
                    if CONTEXT_API_VERSION in api_version:
                        blade.patch_object_store_access_keys(
                            names=[result.name],
                            object_store_access_key=ObjectStoreAccessKey(enabled=False),
                            context_names=[module.params["context"]],
                        )
                    else:
                        blade.patch_object_store_access_keys(
                            names=[result.name],
                            object_store_access_key=ObjectStoreAccessKey(enabled=False),
                        )
                s3user_facts["fb_s3user"] = {
                    "user": user,
                    "enabled": module.params["enable_key"],
                    "access_key": result.secret_access_key,
                    "access_id": result.name,
                }
            else:
                delete_s3user(module, blade, True)
                module.fail_json(
                    msg="Object Store User {0} creation failed. Error: {1}".format(
                        user, res.errors[0].message
                    )
                )
        else:
            if module.params["imported_key"]:
                if CONTEXT_API_VERSION in api_version:
                    res = blade.post_object_store_access_keys(
                        names=[module.params["imported_key"]],
                        object_store_access_key=ObjectStoreAccessKeyPost(
                            user={"name": user},
                            secret_access_key=module.params["imported_secret"],
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.post_object_store_access_keys(
                        names=[module.params["imported_key"]],
                        object_store_access_key=ObjectStoreAccessKeyPost(
                            user={"name": user},
                            secret_access_key=module.params["imported_secret"],
                        ),
                    )
                if res.status_code == 200:
                    result = list(res.items)[0]
                    if not module.params["enable_key"]:
                        if CONTEXT_API_VERSION in api_version:
                            blade.patch_object_store_access_keys(
                                names=[result.name],
                                object_store_access_key=ObjectStoreAccessKey(
                                    enabled=False
                                ),
                                context_names=[module.params["context"]],
                            )
                        else:
                            blade.patch_object_store_access_keys(
                                names=[result.name],
                                object_store_access_key=ObjectStoreAccessKey(
                                    enabled=False
                                ),
                            )
                else:
                    delete_s3user(module, blade)
                    module.fail_json(
                        msg="Object Store User {0} creation failed with imported access key. "
                        "Error: {1}".format(user, res.errors[0].message)
                    )
        if module.params["policy"]:
            policy_list = module.params["policy"]
            for policy in range(len(policy_list)):
                if CONTEXT_API_VERSION in api_version:
                    res = blade.get_object_store_access_policies(
                        names=[policy_list[policy]],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.get_object_store_access_policies(
                        names=[policy_list[policy]]
                    )
                if res.status_code != 200:
                    module.warn(
                        "Policy {0} is not valid. Ignoring...".format(
                            policy_list[policy]
                        )
                    )
                    policy_list.remove(policy_list[policy])
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
                    if CONTEXT_API_VERSION in api_version:
                        res = (
                            blade.post_object_store_access_policies_object_store_users(
                                member_names=[username],
                                policy_names=[policy_list[policy]],
                                context_names=[module.params["context"]],
                            )
                        )
                    else:
                        res = (
                            blade.post_object_store_access_policies_object_store_users(
                                member_names=[username],
                                policy_names=[policy_list[policy]],
                            )
                        )
                    if res.status_code != 200:
                        module.warn(
                            "Failed to add policy {0} to account user {1}. Error: {2}. Skipping...".format(
                                policy_list[policy],
                                username,
                                res.errors[0].message,
                            )
                        )
            if "pure:policy/full-access" not in policy_list:
                # User Create adds the pure:policy/full-access policy by default
                # If we are specifying a list then remove this default value
                blade.delete_object_store_access_policies_object_store_users(
                    member_names=[username],
                    policy_names=["pure:policy/full-access"],
                )
    module.exit_json(changed=changed, s3user_info=s3user_facts)


def remove_key(module, blade):
    """Remove Access Key from User"""
    changed = False
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_object_store_access_keys(
            names=[module.params["key_name"]], context_names=[module.params["context"]]
        )
    else:
        res = blade.get_object_store_access_keys(names=[module.params["key_name"]])
    if res.status_code == 200:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_object_store_access_keys(
                    names=[module.params["key_name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_object_store_access_keys(
                    names=[module.params["key_name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete access key {0}. "
                    "Error: {1}".format(
                        module.params["key_name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def change_key(module, blade):
    """Change state of Access Key"""
    changed = False
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_object_store_access_keys(
                names=[module.params["key_name"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_object_store_access_keys(names=[module.params["key_name"]])
        if res.status_code == 200:
            key = list(res.items)[0]
            if key.enabled != module.params["enable_key"]:
                changed = True
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_object_store_access_keys(
                        names=[module.params["key_name"]],
                        object_store_access_key=ObjectStoreAccessKey(
                            enabled=module.params["enable_key"]
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_object_store_access_keys(
                        names=[module.params["key_name"]],
                        object_store_access_key=ObjectStoreAccessKey(
                            enabled=module.params["enable_key"]
                        ),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change state of access key {0}. "
                        "Error: {1}".format(
                            module.params["key_name"], res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def delete_s3user(module, blade, internal=False):
    """Delete Object Store Account"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        user = module.params["account"] + "/" + module.params["name"]
        if CONTEXT_API_VERSION in api_version:
            res = blade.delete_object_store_users(
                names=[user], context_names=[module.params["context"]]
            )
        else:
            res = blade.delete_object_store_users(names=[user])
        if res.status_code != 200:
            module.fail_json(
                msg="Object Store Account {0}: Deletion failed".format(
                    module.params["name"]
                )
            )
    if internal:
        return
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True, type="str"),
            account=dict(required=True, type="str"),
            access_key=dict(default="false", type="bool"),
            multiple_keys=dict(default="false", type="bool"),
            imported_key=dict(type="str", no_log=False),
            key_name=dict(type="str", no_log=False, aliases=["remove_key"]),
            enable_key=dict(type="bool", default=True),
            imported_secret=dict(type="str", no_log=True),
            policy=dict(type="list", elements="str"),
            state=dict(
                default="present",
                choices=["present", "absent", "remove_key", "keystate"],
            ),
            context=dict(type="str", default=""),
        )
    )

    required_together = [["imported_key", "imported_secret"]]
    required_if = [["state", "remove_key", ["key_name"]]]

    module = AnsibleModule(
        argument_spec,
        required_together=required_together,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)

    upper = False
    for element in module.params["account"]:
        if element.isupper():
            upper = True
            break
    if upper:
        module.warn("Changing account name to lowercase...")
        module.params["account"] = module.params["account"].lower()

    s3acc = get_s3acc(module, blade)
    if not s3acc:
        module.fail_json(
            msg="Object Store Account {0} does not exist".format(
                module.params["account"]
            )
        )

    s3user = get_s3user(module, blade)

    if state == "absent" and s3user:
        delete_s3user(module, blade)
    elif state == "present" and s3user:
        update_s3user(module, blade)
    elif not s3user and state == "present":
        create_s3user(module, blade)
    elif state == "remove_key" and s3user:
        remove_key(module, blade)
    elif state == "keystate" and s3user:
        change_key(module, blade)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
