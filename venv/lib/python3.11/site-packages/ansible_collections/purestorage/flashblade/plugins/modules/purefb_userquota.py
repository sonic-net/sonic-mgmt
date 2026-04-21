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


DOCUMENTATION = """
---
module: purefb_userquota
version_added: "1.7.0"
short_description:  Manage filesystem user quotas
description:
    - This module manages user hard quotas for filesystems on Pure Storage FlashBlade.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Filesystem Name.
    required: true
    type: str
  state:
    description:
      - Create, delete or modifies a quota.
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  quota:
    description:
      - User quota in M, G, T or P units. This cannot be 0.
      - This value will override the file system's default user quota.
    type: str
  uid:
    description:
      - The user id on which the quota is enforced.
      - Cannot be combined with I(uname)
    type: int
  uname:
    description:
      - The user name on which the quota is enforced.
      - Cannot be combined with I(uid)
    type: str
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

EXAMPLES = """
- name: Create new user (using UID) quota for filesystem named foo
  purestorage.flashblade.purefb_userquota:
    name: foo
    quota: 1T
    uid: 1234
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Create new user (using username) quota for filesystem named foo
  purestorage.flashblade.purefb_userquota:
    name: foo
    quota: 1T
    uname: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete user quota on filesystem foo for user by UID
  purestorage.flashblade.purefb_userquota:
    name: foo
    uid: 1234
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete user quota on filesystem foo for user by username
  purestorage.flashblade.purefb_userquota:
    name: foo
    uname: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Update user quota on filesystem foo for user by username
  purestorage.flashblade.purefb_userquota:
    name: foo
    quota: 20G
    uname: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Update user quota on filesystem foo for user by UID
  purestorage.flashblade.purefb_userquota:
    name: foo
    quota: 20G
    uid: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import UserQuotaPost, UserQuotaPatch
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule, human_to_bytes
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

CONTEXT_API_VERSION = "2.17"


def get_fs(module, blade):
    """Return Filesystem or None"""
    versions = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in versions:
        res = blade.get_file_systems(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        res = blade.get_file_systems(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_quota(module, blade):
    """Return Filesystem User Quota or None"""
    versions = list(blade.get_versions().items)
    if module.params["uid"]:
        if CONTEXT_API_VERSION in versions:
            res = blade.get_quotas_users(
                file_system_names=[module.params["name"]],
                filter="user.id=" + str(module.params["uid"]),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_quotas_users(
                file_system_names=[module.params["name"]],
                filter="user.id=" + str(module.params["uid"]),
            )
    else:
        if CONTEXT_API_VERSION in versions:
            res = blade.get_quotas_users(
                file_system_names=[module.params["name"]],
                filter="user.name='" + module.params["uname"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_quotas_users(
                file_system_names=[module.params["name"]],
                filter="user.name='" + module.params["uname"] + "'",
            )
    if res.status_code == 200 and res.total_item_count != 0:
        return list(res.items)[0]
    return None


def create_quota(module, blade):
    """Create Filesystem User Quota"""
    changed = True
    versions = list(blade.get_versions().items)
    quota = int(human_to_bytes(module.params["quota"]))
    if not module.check_mode:
        if module.params["uid"]:
            if CONTEXT_API_VERSION in versions:
                res = blade.post_quotas_users(
                    file_system_names=[module.params["name"]],
                    uids=[module.params["uid"]],
                    quota=UserQuotaPost(quota=quota),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_quotas_users(
                    file_system_names=[module.params["name"]],
                    uids=[module.params["uid"]],
                    quota=UserQuotaPost(quota=quota),
                )
        else:
            if CONTEXT_API_VERSION in versions:
                res = blade.post_quotas_users(
                    file_system_names=[module.params["name"]],
                    user_names=[module.params["uname"]],
                    quota=UserQuotaPost(quota=quota),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_quotas_users(
                    file_system_names=[module.params["name"]],
                    user_names=[module.params["uname"]],
                    quota=UserQuotaPost(quota=quota),
                )
        if res.status_code != 200:
            if module.params["uid"]:
                module.fail_json(
                    msg="Failed to create quote for UID {0} on filesystem {1}. Error: {2}".format(
                        module.params["uid"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
            else:
                module.fail_json(
                    msg="Failed to create quote for username {0} on filesystem {1}. Error: {2}".format(
                        module.params["uname"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def update_quota(module, blade):
    """Upodate Filesystem User Quota"""
    changed = False
    versions = list(blade.get_versions().items)
    current_quota = get_quota(module, blade)
    quota = int(human_to_bytes(module.params["quota"]))
    if current_quota.quota != quota:
        changed = True
        if not module.check_mode:
            if module.params["uid"]:
                if CONTEXT_API_VERSION in versions:
                    res = blade.patch_quotas_users(
                        file_system_names=[module.params["name"]],
                        uids=[module.params["uid"]],
                        quota=UserQuotaPatch(quota=quota),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_quotas_users(
                        file_system_names=[module.params["name"]],
                        uids=[module.params["uid"]],
                        quota=UserQuotaPatch(quota=quota),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update quota for UID {0} on filesystem {1}. Error: {2}".format(
                            module.params["uid"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
            else:
                if CONTEXT_API_VERSION in versions:
                    res = blade.patch_quotas_users(
                        file_system_names=[module.params["name"]],
                        user_names=[module.params["uname"]],
                        quota=UserQuotaPatch(quota=quota),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_quotas_users(
                        file_system_names=[module.params["name"]],
                        user_names=[module.params["uname"]],
                        quota=UserQuotaPatch(quota=quota),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update quota for UID {0} on filesystem {1}. Error: {2}".format(
                            module.params["uname"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
    module.exit_json(changed=changed)


def delete_quota(module, blade):
    """Delete Filesystem User Quota"""
    changed = True
    versions = list(blade.get_versions().items)
    if not module.check_mode:
        if module.params["uid"]:
            if CONTEXT_API_VERSION in versions:
                res = blade.delete_quotas_users(
                    file_system_names=[module.params["name"]],
                    uids=[module.params["uid"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_quotas_users(
                    file_system_names=[module.params["name"]],
                    uids=[module.params["uid"]],
                )
        else:
            if CONTEXT_API_VERSION in versions:
                res = blade.delete_quotas_users(
                    file_system_names=[module.params["name"]],
                    user_names=[module.params["uname"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_quotas_users(
                    file_system_names=[module.params["name"]],
                    user_names=[module.params["uname"]],
                )
        if res.status_code != 200:
            if module.params["uid"]:
                module.fail_json(
                    msg="Failed to delete quota for UID {0} on filesystem {1}. Error: {2}".format(
                        module.params["uid"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
            else:
                module.fail_json(
                    msg="Failed to delete quota for username {0} on filesystem {1}. Error: {2}".format(
                        module.params["uname"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            uid=dict(type="int"),
            uname=dict(type="str"),
            state=dict(default="present", choices=["present", "absent"]),
            quota=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    mutually_exclusive = [["uid", "uname"]]
    required_if = [["state", "present", ["quota"]]]
    module = AnsibleModule(
        argument_spec,
        mutually_exclusive=mutually_exclusive,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)
    fsys = get_fs(module, blade)
    if not fsys:
        module.fail_json(
            msg="Filesystem {0} does not exist.".format(module.params["name"])
        )
    quota = get_quota(module, blade)

    if state == "present" and not quota:
        create_quota(module, blade)
    elif state == "present" and quota:
        update_quota(module, blade)
    elif state == "absent" and quota:
        delete_quota(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
