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

DOCUMENTATION = r"""
---
module: purefa_export
version_added: '1.5.0'
short_description: Manage FlashArray File System Exports
description:
- Create/Delete FlashArray File Systems Exports
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the export
    type: str
    required: true
  state:
    description:
    - Define whether the export should exist or not.
    - You must specify an NFS or SMB policy, or both on creation and deletion.
    default: present
    choices: [ absent, present ]
    type: str
  filesystem:
    description:
    - Name of the filesystem the export applies to
    type: str
    required: true
  directory:
    description:
    - Name of the managed directory in the file system the export applies to
    type: str
    required: true
  nfs_policy:
    description:
    - Name of NFS Policy to apply to the export
    type: str
  smb_policy:
    description:
    - Name of SMB Policy to apply to the export
    type: str
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.39.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create NFS and SMB exports for directory foo in filesysten bar
  purestorage.flasharray.purefa_export:
    name: export1
    filesystem: bar
    directory: foo
    nfs_policy: nfs-example
    smb_policy: smb-example
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete NFS export for directory foo in filesystem bar
  purestorage.flasharray.purefa_export:
    name: export1
    filesystem: bar
    directory: foo
    nfs_policy: nfs-example
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

MIN_REQUIRED_API_VERSION = "2.3"
CONTEXT_VERSION = "2.42"


def delete_export(module, array):
    """Delete a file system export"""
    changed = False
    api_version = array.get_rest_version()
    all_policies = []
    directory = module.params["filesystem"] + ":" + module.params["directory"]
    if not module.params["nfs_policy"] and not module.params["smb_policy"]:
        module.fail_json(msg="At least one policy must be provided")
    if module.params["nfs_policy"]:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            policy_exists = bool(
                array.get_directory_exports(
                    export_names=[module.params["name"]],
                    policy_names=[module.params["nfs_policy"]],
                    directory_names=[directory],
                    context_names=[module.params["context"]],
                ).status_code
                == 200
            )
        else:
            policy_exists = bool(
                array.get_directory_exports(
                    export_names=[module.params["name"]],
                    policy_names=[module.params["nfs_policy"]],
                    directory_names=[directory],
                ).status_code
                == 200
            )
        if policy_exists:
            all_policies.append(module.params["nfs_policy"])
    if module.params["smb_policy"]:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            policy_exists = bool(
                array.get_directory_exports(
                    export_names=[module.params["name"]],
                    policy_names=[module.params["smb_policy"]],
                    directory_names=[directory],
                    context_names=[module.params["context"]],
                ).status_code
                == 200
            )
        else:
            policy_exists = bool(
                array.get_directory_exports(
                    export_names=[module.params["name"]],
                    policy_names=[module.params["smb_policy"]],
                    directory_names=[directory],
                ).status_code
                == 200
            )
        if policy_exists:
            all_policies.append(module.params["smb_policy"])
    if all_policies:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.delete_directory_exports(
                    export_names=[module.params["name"]],
                    policy_names=all_policies,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.delete_directory_exports(
                    export_names=[module.params["name"]], policy_names=all_policies
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete file system export {0}. {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_export(module, array):
    """Create a file system export"""
    changed = False
    api_version = array.get_rest_version()
    if not module.params["nfs_policy"] and not module.params["smb_policy"]:
        module.fail_json(msg="At least one policy must be provided")
    all_policies = []
    if module.params["nfs_policy"]:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.get_policies_nfs(
                names=[module.params["nfs_policy"]],
                context_names=[module.params["context"]],
            )
        else:
            res = array.get_policies_nfs(names=[module.params["nfs_policy"]])
        if bool(res.status_code != 200):
            module.fail_json(
                msg="NFS Policy {0} does not exist.".format(module.params["nfs_policy"])
            )
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.get_directory_exports(
                export_names=[module.params["name"]],
                policy_names=[module.params["nfs_policy"]],
                context_names=[module.params["context"]],
            )
        else:
            res = array.get_directory_exports(
                export_names=[module.params["name"]],
                policy_names=[module.params["nfs_policy"]],
            )
        if bool(res.status_code != 200):
            all_policies.append(module.params["nfs_policy"])
    if module.params["smb_policy"]:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.get_policies_smb(
                names=[module.params["smb_policy"]],
                context_names=[module.params["context"]],
            )
        else:
            res = array.get_policies_smb(names=[module.params["smb_policy"]])
        if bool(res.status_code != 200):
            module.fail_json(
                msg="SMB Policy {0} does not exist.".format(module.params["smb_policy"])
            )
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.get_directory_exports(
                export_names=[module.params["name"]],
                policy_names=[module.params["smb_policy"]],
                context_names=[module.params["context"]],
            )
        else:
            res = array.get_directory_exports(
                export_names=[module.params["name"]],
                policy_names=[module.params["smb_policy"]],
            )
        if bool(res.status_code != 200):
            all_policies.append(module.params["smb_policy"])
    if all_policies:
        export = flasharray.DirectoryExportPost(export_name=module.params["name"])
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.post_directory_exports(
                    directory_names=[
                        module.params["filesystem"] + ":" + module.params["directory"]
                    ],
                    exports=export,
                    policy_names=all_policies,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.post_directory_exports(
                    directory_names=[
                        module.params["filesystem"] + ":" + module.params["directory"]
                    ],
                    exports=export,
                    policy_names=all_policies,
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create file system exports for {0}:{1}. Error: {2}".format(
                        module.params["filesystem"],
                        module.params["directory"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            filesystem=dict(type="str", required=True),
            directory=dict(type="str", required=True),
            name=dict(type="str", required=True),
            nfs_policy=dict(type="str"),
            smb_policy=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    required_if = [["state", "present", ["filesystem", "directory"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()
    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    state = module.params["state"]

    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        exists = bool(
            array.get_directory_exports(
                export_names=[module.params["name"]],
                context_names=[module.params["context"]],
            ).status_code
            == 200
        )
    else:
        exists = bool(
            array.get_directory_exports(
                export_names=[module.params["name"]]
            ).status_code
            == 200
        )

    if state == "present":
        create_export(module, array)
    elif state == "absent" and exists:
        delete_export(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
