#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
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
module: purefb_fs_replica
version_added: '1.0.0'
short_description:  Manage filesystem replica links between Pure Storage FlashBlades
description:
    - This module manages filesystem replica links between Pure Storage FlashBlades.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Local Filesystem Name.
    required: true
    type: str
  state:
    description:
      - Creates or modifies a filesystem replica link
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  target_array:
    description:
      - Remote array name to create replica on.
    required: false
    type: str
  target_fs:
    description:
      - Name of target filesystem name
      - If not supplied, will default to I(name).
    type: str
    required: false
  policy:
    description:
      - Name of filesystem snapshot policy to apply to the replica link.
    required: false
    type: str
  in_progress:
    description:
     - Confirmation that you wish to delete a filesystem replica link
     - This may cancel any in-progress replication transfers)
    type: bool
    default: false
extends_documentation_fragment:
    - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = """
- name: Create new filesystem replica from foo to bar on arrayB
  purestorage.flashblade.purefb_fs_replica:
    name: foo
    target_array: arrayB
    target_fs: bar
    policy: daily
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Add new snapshot policy to exisitng filesystem replica link
  purestorage.flashblade.purefb_fs_replica:
    name: foo
    policy: weekly
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete snapshot policy from filesystem replica foo
  purestorage.flashblade.purefb_fs_replica:
    name: foo
    policy: weekly
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PURITY_FB = True
try:
    from pypureclient.flashblade import FileSystemReplicaLink, LocationReference
except ImportError:
    HAS_PURITY_FB = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

DELETE_RL_API_VERSION = "2.10"


def get_local_fs(module, blade):
    """Return Filesystem or None"""
    res = blade.get_file_systems(names=[module.params["name"]])
    if res.status_code == 200:
        return res.items[0]
    return None


def get_local_rl(module, blade):
    """Return Filesystem Replica Link or None"""
    res = blade.file_system_replica_links.list_file_system_replica_links(
        local_file_system_names=[module.params["name"]]
    )
    if res.status_code == 200:
        return res.items[0]
    return None


def _check_connected(module, blade):
    res = blade.get_array_connections()
    connected_blades = list(res.items)
    for target in range(len(connected_blades)):
        if (
            connected_blades[target].remote.name == module.params["target_array"]
            or connected_blades[target].management_address
            == module.params["target_array"]
        ) and connected_blades[target].status in [
            "connected",
            "connecting",
            "partially_connected",
        ]:
            return connected_blades[target]
    return None


def create_rl(module, blade):
    """Create Filesystem Replica Link"""
    changed = True
    if not module.check_mode:
        remote_array = _check_connected(module, blade)
        if remote_array:
            if not module.params["target_fs"]:
                module.params["target_fs"] = module.params["name"]
            if not module.params["policy"]:
                res = blade.post_file_system_replica_links(
                    local_file_system_names=[module.params["name"]],
                    remote_file_system_names=[module.params["target_fs"]],
                    remote_names=[remote_array.remote.name],
                    file_system_replica_link=FileSystemReplicaLink(),
                )
            else:
                res = blade.post_file_system_replica_links(
                    local_file_system_names=[module.params["name"]],
                    remote_file_system_names=[module.params["target_fs"]],
                    remote_names=[remote_array.remote.name],
                    file_system_replica_link=FileSystemReplicaLink(
                        policies=[LocationReference(name=module.params["policy"])]
                    ),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create filesystem replica link for {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
        else:
            module.fail_json(
                msg="Target array {0} is not connected".format(
                    module.params["target_array"]
                )
            )
    module.exit_json(changed=changed)


def add_rl_policy(module, blade):
    """Add Policy to Filesystem Replica Link"""
    changed = False
    if not module.params["target_array"]:
        res = blade.get_file_system_replica_links(
            local_file_system_names=[module.params["name"]]
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to get replica link for {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        module.params["target_array"] = list(res.items)[0].remote.name
    remote_array = _check_connected(module, blade)
    res = blade.get_file_system_replica_links_policies(
        local_file_system_names=[module.params["name"]],
        policy_names=[module.params["policy"]],
        remote_names=[remote_array.remote.name],
    )
    if res.status_code != 200:
        changed = True
        if not module.check_mode:
            res = blade.post_file_system_replica_links_policies(
                policy_names=[module.params["policy"]],
                local_file_system_names=[module.params["name"]],
                remote_names=[remote_array.remote.name],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to add policy {0} to replica link {1}. Error: {2}".format(
                        module.params["policy"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def delete_rl_policy(module, blade):
    """Delete Policy from Filesystem Replica Link"""
    changed = True
    if not module.check_mode:
        res = blade.get_file_system_replica_links_policies(
            local_file_system_names=[module.params["name"]],
            policy_names=[module.params["policy"]],
        )
        if res.status_code != 200:
            current_policy = list(res.items)[0]
            res = blade.delete_file_system_replica_links_policies(
                policy_names=[module.params["policy"]],
                local_file_system_names=[module.params["name"]],
                remote_names=[current_policy.link.remote.name],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to remove policy {0} from replica link {1}. Error: {2}".format(
                        module.params["policy"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
        else:
            changed = False
    module.exit_json(changed=changed)


def delete_rl(module, blade):
    """Delete filesystem replica link"""
    changed = True
    if not module.check_mode:
        res = blade.delete_file_system_replica_links(
            local_file_system_names=[module.params["name"]],
            remote_file_system_names=[module.params["target_fs"]],
            remote_names=[module.params["target_array"]],
            cancel_in_progress_transfers=module.params["in_progress"],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete replica link from {0} to {1}:{2}. Error: {3}".format(
                    module.params["name"],
                    module.params["target_array"],
                    module.params["target_fs"],
                    res.errors[0].message,
                )
            )
    module.exit_jsob(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            target_fs=dict(type="str"),
            target_array=dict(type="str"),
            policy=dict(type="str"),
            in_progress=dict(type="bool", default=False),
            state=dict(default="present", choices=["present", "absent"]),
        )
    )

    required_if = [["state", "absent", ["policy"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    state = module.params["state"]
    blade = get_system(module)
    versions = list(blade.get_versions().items)

    local_fs = get_local_fs(module, blade)
    local_replica_link = get_local_rl(module, blade)

    if not local_fs:
        module.fail_json(
            msg="Selected local filesystem {0} does not exist.".format(
                module.params["name"]
            )
        )

    policy = True
    if module.params["policy"]:
        res = blade.get_file_system_replica_links_policies(
            policy_names=[module.params["policy"]]
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Selected policy {0} does not exist.".format(
                    module.params["policy"]
                )
            )
    else:
        policy = None
    if state == "present" and not local_replica_link:
        create_rl(module, blade)
    elif state == "absent" and local_replica_link:
        if DELETE_RL_API_VERSION not in versions:
            module.fail_json("Deleting a replica link requires REST 2.10 or higher")
        else:
            delete_rl(module, blade)
    elif state == "present" and local_replica_link and policy:
        add_rl_policy(module, blade)
    elif state == "absent" and policy:
        delete_rl_policy(module, blade)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
