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
module: purefb_groupquota
version_added: "1.7.0"
short_description:  Manage filesystem group quotas
description:
    - This module manages group quotas for filesystems on Pure Storage FlashBlade.
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
      - Group quota in M, G, T or P units. This cannot be 0.
      - This value will override the file system's default group quota.
    type: str
  gid:
    description:
      - The group id on which the quota is enforced.
      - Cannot be combined with I(gname)
    type: int
  gname:
    description:
      - The group name on which the quota is enforced.
      - Cannot be combined with I(gid)
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
- name: Create new group (using GID) quota for filesystem named foo
  purestorage.flashblade.purefb_groupquota:
    name: foo
    quota: 1T
    gid: 1234
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Create new group (using groupname) quota for filesystem named foo
  purestorage.flashblade.purefb_groupquota:
    name: foo
    quota: 1T
    gname: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete group quota on filesystem foo for group by GID
  purestorage.flashblade.purefb_groupquota:
    name: foo
    gid: 1234
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete group quota on filesystem foo for group by groupname
  purestorage.flashblade.purefb_groupquota:
    name: foo
    gname: bar
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Update group quota on filesystem foo for group by groupname
  purestorage.flashblade.purefb_groupquota:
    name: foo
    quota: 20G
    gname: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Update group quota on filesystem foo for group by GID
  purestorage.flashblade.purefb_groupquota:
    name: foo
    quota: 20G
    gid: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import GroupQuotaPost, GroupQuotaPatch
except ImportError:
    HAS_PURITY_FB = False

CONTEXT_API_VERSION = "2.17"

from ansible.module_utils.basic import AnsibleModule, human_to_bytes
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


def get_fs(module, blade):
    """Return Filesystem or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
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
    api_version = list(blade.get_versions().items)
    if module.params["gid"]:
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_quotas_groups(
                file_system_names=[module.params["name"]],
                filter="group.id=" + str(module.params["gid"]),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_quotas_groups(
                file_system_names=[module.params["name"]],
                filter="group.id=" + str(module.params["gid"]),
            )
    else:
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_quotas_groups(
                file_system_names=[module.params["name"]],
                filter="group.name='" + module.params["gname"] + "'",
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_quotas_groups(
                file_system_names=[module.params["name"]],
                filter="group.name='" + module.params["gname"] + "'",
            )
    if res.status_code == 200 and res.total_item_count != 0:
        return list(res.items)[0]
    return None


def create_quota(module, blade):
    """Create Filesystem User Quota"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if module.params["gid"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_quotas_groups(
                    file_system_names=[module.params["name"]],
                    gids=[module.params["gid"]],
                    quota=GroupQuotaPost(
                        quota=int(human_to_bytes(module.params["quota"]))
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_quotas_groups(
                    file_system_names=[module.params["name"]],
                    gids=[module.params["gid"]],
                    quota=GroupQuotaPost(
                        quota=int(human_to_bytes(module.params["quota"]))
                    ),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create quote for UID {0} on filesystem {1}. Error: {2}".format(
                        module.params["gid"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
        else:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_quotas_groups(
                    file_system_names=[module.params["name"]],
                    group_names=[module.params["gname"]],
                    quota=GroupQuotaPost(
                        quota=int(human_to_bytes(module.params["quota"]))
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_quotas_groups(
                    file_system_names=[module.params["name"]],
                    group_names=[module.params["gname"]],
                    quota=GroupQuotaPost(
                        quota=int(human_to_bytes(module.params["quota"]))
                    ),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create quote for groupname {0} on filesystem {1}. Error: {2}".format(
                        module.params["gname"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def update_quota(module, blade):
    """Upodate Filesystem User Quota"""
    changed = False
    api_version = list(blade.get_versions().items)
    current_quota = get_quota(module, blade)
    if current_quota.quota != human_to_bytes(module.params["quota"]):
        changed = True
        if not module.check_mode:
            if module.params["gid"]:
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_quotas_groups(
                        file_system_names=[module.params["name"]],
                        gids=[module.params["gid"]],
                        quota=GroupQuotaPatch(
                            quota=int(human_to_bytes(module.params["quota"]))
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_quotas_groups(
                        file_system_names=[module.params["name"]],
                        gids=[module.params["gid"]],
                        quota=GroupQuotaPatch(
                            quota=int(human_to_bytes(module.params["quota"]))
                        ),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update quota for UID {0} on filesystem {1}. Error: {2}".format(
                            module.params["gid"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
            else:
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_quotas_groups(
                        file_system_names=[module.params["name"]],
                        group_names=[module.params["gname"]],
                        quota=GroupQuotaPatch(
                            quota=int(human_to_bytes(module.params["quota"]))
                        ),
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_quotas_groups(
                        file_system_names=[module.params["name"]],
                        group_names=[module.params["gname"]],
                        quota=GroupQuotaPatch(
                            quota=int(human_to_bytes(module.params["quota"]))
                        ),
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to update quota for UID {0} on filesystem {1}. Error: {2}".format(
                            module.params["gname"],
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
    module.exit_json(changed=changed)


def delete_quota(module, blade):
    """Delete Filesystem User Quota"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if module.params["gid"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_quotas_groups(
                    file_system_names=[module.params["name"]],
                    gids=[module.params["gid"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_quotas_groups(
                    file_system_names=[module.params["name"]],
                    gids=[module.params["gid"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete quota for UID {0} on filesystem {1}.".format(
                        module.params["gid"], module.params["name"]
                    )
                )
        else:
            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_quotas_groups(
                    file_system_names=[module.params["name"]],
                    group_names=[module.params["gname"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.delete_quotas_groups(
                    file_system_names=[module.params["name"]],
                    group_names=[module.params["gname"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete quota for groupname {0} on filesystem {1}. Error: {2}".format(
                        module.params["gname"],
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
            gid=dict(type="int"),
            gname=dict(type="str"),
            state=dict(default="present", choices=["present", "absent"]),
            quota=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    mutually_exclusive = [["gid", "gname"]]
    required_if = [["state", "present", ["quota"]]]
    module = AnsibleModule(
        argument_spec,
        mutually_exclusive=mutually_exclusive,
        required_if=required_if,
        supports_check_mode=True,
    )

    if not HAS_PURITY_FB:
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
