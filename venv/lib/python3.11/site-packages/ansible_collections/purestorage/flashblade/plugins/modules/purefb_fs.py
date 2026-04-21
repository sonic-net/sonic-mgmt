#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Simon Dodsley (simon@purestorage.com)
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
module: purefb_fs
version_added: "1.0.0"
short_description:  Manage filesystemon Pure Storage FlashBlade`
description:
    - This module manages filesystems on Pure Storage FlashBlade.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Filesystem Name.
    required: true
    type: str
  state:
    description:
      - Create, delete or modifies a filesystem.
    required: false
    default: present
    type: str
    choices: [ "present", "absent" ]
  eradicate:
    description:
      - Define whether to eradicate the filesystem on delete or leave in trash.
    required: false
    type: bool
    default: false
  size:
    description:
      - Volume size in M, G, T or P units. See examples.
      - If size is not set at filesystem creation time the filesystem size becomes unlimited.
    type: str
    required: false
  nfsv3:
    description:
      - Define whether to NFSv3 protocol is enabled for the filesystem.
    required: false
    type: bool
    default: true
  nfsv4:
    description:
      - Define whether to NFSv4.1 protocol is enabled for the filesystem.
    required: false
    type: bool
    default: true
  nfs_rules:
    description:
      - Define the NFS rules in operation.
      - If not set at filesystem creation time it defaults to I(*(rw,no_root_squash))
      - Supported binary options are ro/rw, secure/insecure, fileid_32bit/no_fileid_32bit,
        root_squash/no_root_squash, all_squash/no_all_squash and atime/noatime
      - Supported non-binary options are anonuid=#, anongid=#, sec=(sys|krb5)
      - Superceeded by I(export_policy) if provided
    required: false
    type: str
  smb:
    description:
      - Define whether to SMB protocol is enabled for the filesystem.
    required: false
    type: bool
    default: false
  smb_aclmode:
    description:
      - Specify the ACL mode for the SMB protocol.
      - Deprecated from Purity//FB 3.1.1. Use I(access_control) instead.
    required: false
    type: str
    default: shared
    choices: [ "shared", "native" ]
  http:
    description:
      - Define whether to HTTP/HTTPS protocol is enabled for the filesystem.
    required: false
    type: bool
    default: false
  snapshot:
    description:
      - Define whether a snapshot directory is enabled for the filesystem.
    required: false
    type: bool
    default: false
  writable:
    description:
      - Define if a filesystem is writable.
    required: false
    type: bool
  promote:
    description:
      - Promote/demote a filesystem.
      - Can only demote the file-system if it is in a replica-link relationship.
    required: false
    type: bool
  fastremove:
    description:
      - Define whether the fast remove directory is enabled for the filesystem.
    required: false
    type: bool
    default: false
  hard_limit:
    description:
      - Define whether the capacity for a filesystem is a hard limit.
      - CAUTION This will cause the filesystem to go Read-Only if the
        capacity has already exceeded the logical size of the filesystem.
    required: false
    type: bool
    default: false
  user_quota:
    description:
      - Default quota in M, G, T or P units for a user under this file system.
    required: false
    type: str
  group_quota:
    description:
      - Default quota in M, G, T or P units for a group under this file system.
    required: false
    type: str
  policy:
    description:
      - Filesystem policy to assign to or remove from a filesystem.
    required: false
    type: str
  policy_state:
    description:
    - Add or delete a policy from a filesystem
    required: false
    default: present
    type: str
    choices: [ "absent", "present" ]
  delete_link:
    description:
      - Define if the filesystem can be deleted even if it has a replica link
    required: false
    default: false
    type: bool
  discard_snaps:
    description:
      - Allow a filesystem to be demoted.
    required: false
    default: false
    type: bool
  access_control:
    description:
      - The access control style that is utilized for client actions such
        as setting file and directory ACLs.
    type: str
    default: shared
    choices: [ 'nfs', 'smb', 'shared', 'independent', 'mode-bits' ]
  safeguard_acls:
    description:
      - Safeguards ACLs on a filesystem.
      - Performs different roles depending on the filesystem protocol enabled.
      - See Purity//FB documentation for detailed description.
    type: bool
    default: true
  export_policy:
    description:
    - Name of NFS export policy to assign to filesystem
    - Overrides I(nfs_rules)
    type: str
    version_added: "1.9.0"
  share_policy:
    description:
    - Name of SMB share policy to assign to filesystem
    - Only valid with REST 2.10 or higher
    - Remove policy with empty string
    type: str
    version_added: "1.12.0"
  client_policy:
    description:
    - Name of SMB client policy to assign to filesystem
    - Only valid with REST 2.10 or higher
    - Remove policy with empty string
    type: str
    version_added: "1.12.0"
  continuous_availability:
    description:
    - Defines if the file system will be continuously available during
      disruptive scenarios such as network disruption, blades failover, etc
    type: bool
    default: true
    version_added: "1.15.0"
  group_ownership:
    description:
    - The group ownership for new files and directories in a file system
    type: str
    choices: [ 'creator', 'parent-directory' ]
    default: creator
    version_added: "1.17.0"
  ignore_usage:
    description:
    - Allow update operations that lead to a hard_limit_enabled file
      system with usage over its limiting value
    type: bool
    default: false
    version_added: "1.22.0"
  cancel_in_progress:
    description:
    - Whether to cancel any existing storage class transitons that are in progress
      if the file system is requested to changed to another storage class
    type: bool
    default: false
    version_added: "1.22.0"
  storage_class:
    description:
    - Name of storage class in Fusion fleet file system is associated with
    type: str
    version_added: "1.22.0"
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
- name: Create new filesystem named foo
  purestorage.flashblade.purefb_fs:
    name: foo
    size: 1T
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete filesystem named foo
  purestorage.flashblade.purefb_fs:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Recover filesystem named foo
  purestorage.flashblade.purefb_fs:
    name: foo
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Eradicate filesystem named foo
  purestorage.flashblade.purefb_fs:
    name: foo
    state: absent
    eradicate: true
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Promote filesystem named foo ready for failover
  purestorage.flashblade.purefb_fs:
    name: foo
    promote: true
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Demote filesystem named foo after failover
  purestorage.flashblade.purefb_fs:
    name: foo
    promote: false
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Modify attributes of an existing filesystem named foo
  purestorage.flashblade.purefb_fs:
    name: foo
    size: 2T
    nfsv3: false
    nfsv4: true
    user_quota: 10K
    group_quota: 25M
    nfs_rules: '10.21.200.0/24(ro)'
    snapshot: true
    fastremove: true
    hard_limit: true
    smb: true
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
"""

RETURN = """
"""

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        FileSystemPatch,
        NfsPatch,
        Reference,
        Smb,
        FileSystemPost,
        Nfs,
        SmbPost,
        Http,
        MultiProtocolPost,
        MultiProtocol,
        StorageClassInfo,
    )
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule, human_to_bytes
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)


EXPORT_POLICY_API_VERSION = "2.3"
SMB_POLICY_API_VERSION = "2.10"
CA_API_VERSION = "2.12"
GOWNER_API_VERSION = "2.13"
CONTEXT_API_VERSION = "2.17"


def get_fs(module, blade):
    """Return Filesystem or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_file_systems(
            context_names=[module.params["context"]],
            names=[module.params["name"]],
        )
    else:
        res = blade.get_file_systems(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def create_fs(module, blade):
    """Create Filesystem"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        if not module.params["nfs_rules"]:
            module.params["nfs_rules"] = "*(rw,no_root_squash)"
        if module.params["size"]:
            size = human_to_bytes(module.params["size"])
        else:
            size = 0

        if module.params["user_quota"]:
            user_quota = human_to_bytes(module.params["user_quota"])
        else:
            user_quota = None
        if module.params["group_quota"]:
            group_quota = human_to_bytes(module.params["group_quota"])
        else:
            group_quota = None

        if module.params["access_control"] == "nfs" and not (
            module.params["nfsv3"] or module.params["nfsv4"]
        ):
            module.fail_json(
                msg="Cannot set access_control to nfs when NFS is not enabled."
            )
        if (
            module.params["access_control"] in ["smb", "independent"]
            and not module.params["smb"]
        ):
            module.fail_json(
                msg="Cannot set access_control to smb or independent when SMB is not enabled."
            )
        if module.params["smb"] and not (
            module.params["nfsv3"] or module.params["nfsv4"]
        ):
            module.params["nfs_rules"] = ""
        if module.params["safeguard_acls"] and (
            module.params["access_control"] in ["mode-bits", "independent"]
        ):
            module.fail_json(
                msg="ACL Safeguarding cannot be enabled if access_control is mode-bits or independent."
            )
        fs_obj = FileSystemPost(
            provisioned=size,
            fast_remove_directory_enabled=module.params["fastremove"],
            hard_limit_enabled=module.params["hard_limit"],
            snapshot_directory_enabled=module.params["snapshot"],
            nfs=Nfs(
                v3_enabled=module.params["nfsv3"],
                v4_1_enabled=module.params["nfsv4"],
                rules=module.params["nfs_rules"],
            ),
            smb=SmbPost(enabled=module.params["smb"]),
            http=Http(enabled=module.params["http"]),
            multi_protocol=MultiProtocolPost(
                safeguard_acls=module.params["safeguard_acls"],
                access_control_style=module.params["access_control"],
            ),
            default_user_quota=user_quota,
            default_group_quota=group_quota,
        )
        if CONTEXT_API_VERSION in api_version:
            res = blade.post_file_systems(
                names=[module.params["name"]],
                file_system=fs_obj,
                context_names=[module.params["context"]],
            )
        else:
            res = blade.post_file_systems(
                names=[module.params["name"]], file_system=fs_obj
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create filesystem {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["policy"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.get_policies(
                    names=[module.params["policy"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.get_policies(names=[module.params["policy"]])
            if res.status_code != 200:
                _delete_fs(module, blade)
                module.fail_json(
                    msg="Policy {0} doesn't exist.".format(module.params["policy"])
                )
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_policies_file_systems(
                    policy_names=[module.params["policy"]],
                    member_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_policies_file_systems(
                    policy_names=[module.params["policy"]],
                    member_names=[module.params["name"]],
                )
            if res.status_code != 200:
                _delete_fs(module, blade)
                module.fail_json(
                    msg="Failed to apply policy {0} when creating filesystem {1}. Error: {2}".format(
                        module.params["policy"],
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
        if EXPORT_POLICY_API_VERSION in api_version and module.params["export_policy"]:
            export_attr = FileSystemPatch(
                nfs=NfsPatch(
                    export_policy=Reference(name=module.params["export_policy"])
                )
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=export_attr,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_file_systems(
                    names=[module.params["name"]], file_system=export_attr
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Filesystem {0} created, but failed to assign export "
                    "policy {1}. Error: {2}".format(
                        module.params["name"],
                        module.params["export_policy"],
                        res.errors[0].message,
                    )
                )
        if SMB_POLICY_API_VERSION in api_version:
            if module.params["client_policy"]:
                export_attr = FileSystemPatch(
                    smb=Smb(
                        client_policy=Reference(name=module.params["client_policy"])
                    )
                )
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]],
                        file_system=export_attr,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]], file_system=export_attr
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Filesystem {0} created, but failed to assign client "
                        "policy {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["client_policy"],
                            res.errors[0].message,
                        )
                    )
            if module.params["share_policy"]:
                export_attr = FileSystemPatch(
                    smb=Smb(share_policy=Reference(name=module.params["share_policy"]))
                )
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]],
                        file_system=export_attr,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]],
                        file_system=export_attr,
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Filesystem {0} created, but failed to assign share "
                        "policy {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["share_policy"],
                            res.errors[0].message,
                        )
                    )
            if CA_API_VERSION in api_version:
                ca_attr = FileSystemPatch(
                    smb=Smb(
                        continuous_availability_enabled=module.params[
                            "continuous_availability"
                        ]
                    )
                )
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]],
                        file_system=ca_attr,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]], file_system=ca_attr
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Filesystem {0} created, but failed to set continuous availability"
                        "Error: {1}".format(
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
            if GOWNER_API_VERSION in api_version and module.params["group_ownership"]:
                go_attr = FileSystemPatch(
                    group_ownership=module.params["group_ownership"]
                )
                if CONTEXT_API_VERSION in api_version:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]],
                        file_system=go_attr,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.patch_file_systems(
                        names=[module.params["name"]], file_system=go_attr
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Filesystem {0} created, but failed to set group ownership"
                        "Error: {1}".format(
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
            if CONTEXT_API_VERSION in api_version and module.params["storage_class"]:
                res = blade.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=FileSystemPatch(
                        storage_class=StorageClassInfo(
                            name=module.params["storage_class"]
                        )
                    ),
                    cancel_in_progress_storage_class_transition=False,
                    context_names=[module.params["context"]],
                )

    module.exit_json(changed=changed)


def modify_fs(module, blade):
    """Modify Filesystem"""
    changed = False
    change_client = False
    change_export = False
    change_share = False
    change_ca = False
    change_go = False
    change_sc = False
    mod_fs = False
    api_version = list(blade.get_versions().items)
    if module.params["policy"] and module.params["policy_state"] == "present":
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_policies(
                names=[module.params["policy"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_policies(names=[module.params["policy"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Policy {0} doesn't exist.".format(module.params["policy"])
            )
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_policies_file_systems(
                policy_names=[module.params["policy"]],
                member_names=[module.params["name"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_policies_file_systems(
                policy_names=[module.params["policy"]],
                member_names=[module.params["name"]],
            )
        if res.status_code != 200:
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_policies_file_systems(
                    policy_names=[module.params["policy"]],
                    member_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_policies_file_systems(
                    policy_names=[module.params["policy"]],
                    member_names=[module.params["name"]],
                )
            mod_fs = True
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to add filesystem {0} to policy {1}. Error: {2}".format(
                        module.params["name"],
                        module.params["policy"],
                        res.errors[0].message,
                    )
                )
    if module.params["policy"] and module.params["policy_state"] == "absent":
        if CONTEXT_API_VERSION in api_version:
            res = blade.get_policies(
                names=[module.params["policy"]],
                context_names=[module.params["context"]],
            )
        else:
            res = blade.get_policies(names=[module.params["policy"]])
        if res.status_code == 200:
            if CONTEXT_API_VERSION in api_version:
                res = blade.get_policies_file_systems(
                    policy_names=[module.params["policy"]],
                    member_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.get_policies_file_systems(
                    policy_names=[module.params["policy"]],
                    member_names=[module.params["name"]],
                )
            if res.status_code == 200:
                if CONTEXT_API_VERSION in api_version:
                    res = blade.delete_policies_file_systems(
                        policy_names=[module.params["policy"]],
                        member_names=[module.params["name"]],
                        context_names=[module.params["context"]],
                    )
                else:
                    res = blade.delete_policies_file_systems(
                        policy_names=[module.params["policy"]],
                        member_names=[module.params["name"]],
                    )
                mod_fs = True
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to remove filesystem {0} from policy {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["policy"],
                            res.errors[0].message,
                        )
                    )
    if module.params["user_quota"]:
        user_quota = human_to_bytes(module.params["user_quota"])
    if module.params["group_quota"]:
        group_quota = human_to_bytes(module.params["group_quota"])
    fsys = get_fs(module, blade)
    new_fsys = {
        "destroyed": fsys.destroyed,
        "provisioned": fsys.provisioned,
        "nfsv3": fsys.nfs.v3_enabled,
        "nfsv4": fsys.nfs.v4_1_enabled,
        "nfs_rules": fsys.nfs.rules,
        "default_user_quota": fsys.default_user_quota,
        "default_group_quota": fsys.default_group_quota,
        "group_ownership": fsys.group_ownership,
        "smb": fsys.smb.enabled,
        "http": fsys.http.enabled,
        "snapshot": fsys.snapshot_directory_enabled,
        "fastremove": fsys.fast_remove_directory_enabled,
        "hardlimit": fsys.hard_limit_enabled,
        "safeguard_acls": fsys.multi_protocol.safeguard_acls,
        "acs": fsys.multi_protocol.access_control_style,
        "writable": fsys.writable,
        "promotion_status": fsys.promotion_status,
        "requested_promotion_state": fsys.requested_promotion_state,
        "storage_class": getattr(getattr(fsys, "storage_class", None), "name", None),
    }
    if fsys.destroyed:
        new_fsys["destroyed"] = False
        mod_fs = True
    if module.params["size"]:
        if human_to_bytes(module.params["size"]) != fsys.provisioned:
            new_fsys["provisioned"] = human_to_bytes(module.params["size"])
            mod_fs = True
    if module.params["nfsv3"] != fsys.nfs.v3_enabled:
        new_fsys["nfsv3"] = module.params["nfsv3"]
        mod_fs = True
    if module.params["nfsv4"] != fsys.nfs.v4_1_enabled:
        new_fsys["nfsv4"] = module.params["nfsv4"]
        mod_fs = True
    if module.params["nfs_rules"] is not None:
        if sorted(fsys.nfs.rules) != sorted(module.params["nfs_rules"]):
            new_fsys["nfs_rules"] = module.params["nfs_rules"]
            mod_fs = True
    if module.params["user_quota"] and user_quota != fsys.default_user_quota:
        new_fsys["default_user_quota"] = user_quota
        mod_fs = True
    if module.params["group_quota"] and group_quota != fsys.default_group_quota:
        new_fsys["default_group_quota"] = group_quota
        mod_fs = True
    if module.params["http"] and not fsys.http.enabled:
        new_fsys["http"] = module.params["http"]
        mod_fs = True
    if module.params["snapshot"] and not fsys.snapshot_directory_enabled:
        new_fsys["snapshot_directory_enabled"] = module.params["snapshot"]
        mod_fs = True
    if module.params["fastremove"] and not fsys.fast_remove_directory_enabled:
        new_fsys["fast_remove_directory_enabled"] = module.params["fastremove"]
        mod_fs = True
    if module.params["hard_limit"] and not fsys.hard_limit_enabled:
        new_fsys["hard_limit_enabled"] = module.params["hard_limit"]
        mod_fs = True
    if module.params["safeguard_acls"] and not fsys.multi_protocol.safeguard_acls:
        new_fsys["safeguard_acls"] = module.params["safeguard_acls"]
        mod_fs = True
    if module.params["access_control"] != fsys.multi_protocol.access_control_style:
        new_fsys["acs"] = module.params["access_control"]
        mod_fs = True
    if module.params["writable"] is not None:
        if not module.params["writable"] and fsys.writable:
            new_fsys["writable"] = module.params["writable"]
            mod_fs = True
        if (
            module.params["writable"]
            and not fsys.writable
            and fsys.promotion_status == "promoted"
        ):
            new_fsys["writable"] = module.params["writable"]
            mod_fs = True
    if module.params["promote"] is not None:
        if module.params["promote"] and fsys.promotion_status != "promoted":
            new_fsys["requested_promotion_state"] = "promoted"
            mod_fs = True
        if not module.params["promote"] and fsys.promotion_status == "promoted":
            # Demotion only allowed on filesystems in a replica-link
            if CONTEXT_API_VERSION in api_version:
                res = blade.get_file_system_replica_links(
                    local_file_system_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.get_file_system_replica_links(
                    local_file_system_names=[module.params["name"]]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Filesystem {0} not demoted. Not in a replica-link".format(
                        module.params["name"]
                    )
                )
            new_fsys["requested_promotion_state"] = "demoted"
            mod_fs = True
    if mod_fs:
        changed = True
        if not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                if new_fsys["destroyed"] != fsys.destroyed:
                    delres = blade.patch_file_systems(
                        names=module.params["name"],
                        context_names=[module.params["context"]],
                        file_system=FileSystemPatch(destroyed=new_fsys["destroyed"]),
                    )
                    if delres.status_code != 200:
                        module.fail_json(
                            msg="Failed to update filesystem {0} deleted status. Error {1}".format(
                                module.params["name"], res.errors[0].message
                            )
                        )
                res = blade.patch_file_systems(
                    names=module.params["name"],
                    context_names=[module.params["context"]],
                    file_system=FileSystemPatch(
                        default_group_quota=new_fsys["default_group_quota"],
                        default_user_quota=new_fsys["default_user_quota"],
                        fast_remove_directory_enabled=new_fsys["fastremove"],
                        hard_limit_enabled=new_fsys["hardlimit"],
                        http=Http(enabled=new_fsys["http"]),
                        multi_protocol=MultiProtocol(
                            access_control_style=new_fsys["acs"],
                            safeguard_acls=new_fsys["safeguard_acls"],
                        ),
                        nfs=NfsPatch(
                            rules=new_fsys["nfs_rules"],
                            v3_enabled=new_fsys["nfsv3"],
                            v4_1_enabled=new_fsys["nfsv4"],
                        ),
                        provisioned=new_fsys["provisioned"],
                        requested_promotion_state=new_fsys["requested_promotion_state"],
                        smb=Smb(enabled=new_fsys["smb"]),
                        writable=new_fsys["writable"],
                    ),
                    discard_non_snapshotted_data=module.params["discard_snaps"],
                    ignore_usage=module.params["ignore_usage"],
                )
            else:
                if new_fsys["destroyed"] != fsys.destroyed:
                    delres = blade.patch_file_systems(
                        names=module.params["name"],
                        file_system=FileSystemPatch(destroyed=new_fsys["destroyed"]),
                    )
                    if delres.status_code != 200:
                        module.fail_json(
                            msg="Failed to update filesystem {0} deleted status. Error {1}".format(
                                module.params["name"], res.errors[0].message
                            )
                        )
                res = blade.patch_file_systems(
                    names=module.params["name"],
                    file_system=FileSystemPatch(
                        default_group_quota=new_fsys["default_group_quota"],
                        default_user_quota=new_fsys["default_user_quota"],
                        fast_remove_directory_enabled=new_fsys["fastremove"],
                        hard_limit_enabled=new_fsys["hardlimit"],
                        http=Http(enabled=new_fsys["http"]),
                        multi_protocol=MultiProtocol(
                            access_control_style=new_fsys["acs"],
                            safeguard_acls=new_fsys["safeguard_acls"],
                        ),
                        nfs=NfsPatch(
                            rules=new_fsys["nfs_rules"],
                            v3_enabled=new_fsys["nfsv3"],
                            v4_1_enabled=new_fsys["nfsv4"],
                        ),
                        provisioned=new_fsys["provisioned"],
                        requested_promotion_state=new_fsys["requested_promotion_state"],
                        smb=Smb(enabled=new_fsys["smb"]),
                        writable=new_fsys["writable"],
                    ),
                    discard_non_snapshotted_data=module.params["discard_snaps"],
                    ignore_usage=module.params["ignore_usage"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update filesystem {0}. Error {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    if CONTEXT_API_VERSION in api_version:
        current_fs = list(
            blade.get_file_systems(
                context_names=[module.params["context"]],
                filter="name='" + module.params["name"] + "'",
            ).items
        )[0]
    else:
        current_fs = list(
            blade.get_file_systems(filter="name='" + module.params["name"] + "'").items
        )[0]
    if EXPORT_POLICY_API_VERSION in api_version and module.params["export_policy"]:
        change_export = False
        if (
            current_fs.nfs.export_policy.name
            and current_fs.nfs.export_policy.name != module.params["export_policy"]
        ):
            change_export = True
        if not current_fs.nfs.export_policy.name and module.params["export_policy"]:
            change_export = True
        if change_export and not module.check_mode:
            export_attr = FileSystemPatch(
                nfs=NfsPatch(
                    export_policy=Reference(name=module.params["export_policy"])
                )
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=export_attr,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_file_systems(
                    names=[module.params["name"]], file_system=export_attr
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to modify export policy {1} for "
                    "filesystem {0}. Error: {2}".format(
                        module.params["name"],
                        module.params["export_policy"],
                        res.errors[0].message,
                    )
                )
    if SMB_POLICY_API_VERSION in api_version and module.params["client_policy"]:
        if (
            current_fs.smb.client_policy.name
            and current_fs.smb.client_policy.name != module.params["client_policy"]
        ):
            change_client = True
        if not current_fs.smb.client_policy.name and module.params["client_policy"]:
            change_client = True
        if change_client and not module.check_mode:
            client_attr = FileSystemPatch(
                smb=Smb(client_policy=Reference(name=module.params["client_policy"]))
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=client_attr,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_file_systems(
                    names=[module.params["name"]], file_system=client_attr
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to modify client policy {1} for "
                    "filesystem {0}. Error: {2}".format(
                        module.params["name"],
                        module.params["client_policy"],
                        res.errors[0].message,
                    )
                )
    if SMB_POLICY_API_VERSION in api_version and module.params["share_policy"]:
        if (
            current_fs.smb.share_policy.name
            and current_fs.smb.share_policy.name != module.params["share_policy"]
        ):
            change_share = True
        if not current_fs.smb.share_policy.name and module.params["share_policy"]:
            change_share = True
        if change_share and not module.check_mode:
            share_attr = FileSystemPatch(
                smb=Smb(share_policy=Reference(name=module.params["share_policy"]))
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=share_attr,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_file_systems(
                    names=[module.params["name"]], file_system=share_attr
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to modify share policy {1} for "
                    "filesystem {0}. Error: {2}".format(
                        module.params["name"],
                        module.params["share_policy"],
                        res.errors[0].message,
                    )
                )
    if CA_API_VERSION in api_version:
        if (
            module.params["continuous_availability"]
            != current_fs.smb.continuous_availability_enabled
        ):
            change_ca = True
        if not module.check_mode and change_ca:
            ca_attr = FileSystemPatch(
                smb=Smb(
                    continuous_availability_enabled=module.params[
                        "continuous_availability"
                    ]
                )
            )
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=ca_attr,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_file_systems(
                    names=[module.params["name"]], file_system=ca_attr
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to modify continuous availability for "
                    "filesystem {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    if GOWNER_API_VERSION in api_version:
        if module.params["group_ownership"] != current_fs.group_ownership:
            change_go = True
        if not module.check_mode and change_go:
            go_attr = FileSystemPatch(group_ownership=module.params["group_ownership"])
            if CONTEXT_API_VERSION in api_version:
                res = blade.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=go_attr,
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.patch_file_systems(
                    names=[module.params["name"]], file_system=go_attr
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to modify group ownership for "
                    "filesystem {0}. Error: {1}".format(
                        module.params["name"],
                        res.errors[0].message,
                    )
                )
    if CONTEXT_API_VERSION in api_version and module.params["storage_class"]:
        if module.params["storage_class"] != current_fs.storage_class:
            change_sc = True
        res = blade.patch_file_systems(
            names=[module.params["name"]],
            file_system=FileSystemPatch(
                storage_class=StorageClassInfo(name=module.params["storage_class"])
            ),
            cancel_in_progress_storage_class_transition=module.params[
                "cancel_in_progress"
            ],
            context_names=[module.params["context"]],
        )

    module.exit_json(
        changed=(
            changed
            or change_export
            or change_share
            or change_ca
            or change_go
            or change_sc
            or change_client
        )
    )


def _delete_fs(module, blade):
    """In module Delete Filesystem"""
    res = blade.patch_file_systems(
        name=module.params["name"],
        file_system=FileSystemPatch(
            nfs=NfsPatch(v3_enabled=False, v4_1_enabled=False),
            smb=Smb(enabled=False),
            http=Http(enabled=False),
            multi_protocol=MultiProtocol(access_control_style="shared"),
            destroyed=True,
        ),
    )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to delete filesystem {0}. Error: {1}".format(
                module.params["name"], res.errors[0].message
            )
        )

    res = blade.delete_file_systems(name=module.params["name"])
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to eradicate deleted filesystem {0}. Error: {1}".format(
                module.params["name"], res.errors[0].message
            )
        )


def delete_fs(module, blade):
    """Delete Filesystem"""
    changed = True
    if not module.check_mode:
        res = blade.patch_file_systems(
            names=[module.params["name"]],
            file_system=FileSystemPatch(
                nfs=NfsPatch(v3_enabled=False, v4_1_enabled=False),
                smb=Smb(enabled=False),
                http=Http(enabled=False),
                destroyed=True,
            ),
            delete_link_on_eradication=module.params["delete_link"],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete filesystem {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["eradicate"]:
            res = blade.delete_file_systems(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to eradicate filesystem {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def eradicate_fs(module, blade):
    """Eradicate Filesystem"""
    changed = True
    if not module.check_mode:
        res = blade.delete_file_systems(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to eradicate filesystem {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            eradicate=dict(default="false", type="bool"),
            nfsv3=dict(default="true", type="bool"),
            nfsv4=dict(default="true", type="bool"),
            nfs_rules=dict(type="str"),
            smb=dict(default="false", type="bool"),
            http=dict(default="false", type="bool"),
            snapshot=dict(default="false", type="bool"),
            writable=dict(type="bool"),
            promote=dict(type="bool"),
            fastremove=dict(default="false", type="bool"),
            hard_limit=dict(default="false", type="bool"),
            user_quota=dict(type="str"),
            policy=dict(type="str"),
            group_quota=dict(type="str"),
            smb_aclmode=dict(
                type="str", default="shared", choices=["shared", "native"]
            ),
            group_ownership=dict(
                choices=["creator", "parent-directory"], default="creator"
            ),
            policy_state=dict(default="present", choices=["present", "absent"]),
            state=dict(default="present", choices=["present", "absent"]),
            delete_link=dict(default=False, type="bool"),
            discard_snaps=dict(default=False, type="bool"),
            safeguard_acls=dict(default=True, type="bool"),
            access_control=dict(
                type="str",
                default="shared",
                choices=["nfs", "smb", "shared", "independent", "mode-bits"],
            ),
            size=dict(type="str"),
            export_policy=dict(type="str"),
            share_policy=dict(type="str"),
            client_policy=dict(type="str"),
            continuous_availability=dict(type="bool", default="true"),
            ignore_usage=dict(type="bool", default=False),
            cancel_in_progress=dict(type="bool", default=False),
            context=dict(type="str", default=""),
            storage_class=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    blade = get_system(module)
    fsys = get_fs(module, blade)

    if module.params["eradicate"] and state == "present":
        module.warn("Eradicate flag ignored without state=absent")

    if module.params["smb_aclmode"] == "native":
        module.fail_json(
            msg="Native SMB ACL mode is no longer supported. "
            "Use the access_control parameter."
        )
    if state == "present" and not fsys:
        create_fs(module, blade)
    elif state == "present" and fsys:
        modify_fs(module, blade)
    elif state == "absent" and fsys and not fsys.destroyed:
        delete_fs(module, blade)
    elif state == "absent" and fsys and fsys.destroyed and module.params["eradicate"]:
        eradicate_fs(module, blade)
    elif state == "absent" and not fsys:
        module.exit_json(changed=False)
    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
