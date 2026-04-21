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
module: purefa_fs
version_added: '1.5.0'
short_description: Manage FlashArray File Systems
description:
- Create/Delete FlashArray File Systems
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the file system
    type: str
    required: true
  state:
    description:
    - Define whether the file system should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
  eradicate:
    description:
    - Define whether to eradicate the file system on delete or leave in trash.
    type: bool
    default: false
  rename:
    description:
    - Value to rename the specified file system to
    - Rename only applies to the container the current filesystem is in.
    - There is no requirement to specify the pod name as this is implied.
    type: str
  move:
    description:
    - Move a filesystem in and out of a pod
    - Provide the name of pod to move the filesystem to
    - Pod names must be unique in the array
    - To move to the local array, specify C(local)
    - This is not idempotent - use C(ignore_errors) in the play
    type: str
    version_added: '1.13.0'
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
- name: Create file system foo
  purestorage.flasharray.purefa_fs:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete and eradicate file system foo
  purestorage.flasharray.purefa_fs:
    name: foo
    eradicate: true
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Rename file system foo to bar
  purestorage.flasharray.purefa_fs:
    name: foo
    rename: bar
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

MIN_REQUIRED_API_VERSION = "2.2"
REPL_SUPPORT_API = "2.13"
CONTEXT_VERSION = "2.38"


def delete_fs(module, array):
    """Delete a file system"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        file_system = flasharray.FileSystemPatch(destroyed=True)
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.patch_file_systems(
                names=[module.params["name"]],
                file_system=file_system,
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_file_systems(
                names=[module.params["name"]], file_system=file_system
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete file system {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        if module.params["eradicate"]:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.delete_file_systems(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.delete_file_systems(names=[module.params["name"]])
            if res.status_code != 200:
                module.fail_json(
                    msg="Eradication of file system {0} failed. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def recover_fs(module, array):
    """Recover a deleted file system"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        file_system = flasharray.FileSystemPatch(destroyed=False)
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.patch_file_systems(
                names=[module.params["name"]],
                file_system=file_system,
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_file_systems(
                names=[module.params["name"]], file_system=file_system
            )
        if res.staus_code != 200:
            module.fail_json(
                msg="Failed to recover file system {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def eradicate_fs(module, array):
    """Eradicate a file system"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.delete_file_systems(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = array.delete_file_systems(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to eradicate file system {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def rename_fs(module, array):
    """Rename a file system"""
    changed = False
    target = None
    api_version = array.get_rest_version()
    target_name = module.params["rename"]
    if "::" in module.params["name"]:
        pod_name = module.params["name"].split("::")[0]
        target_name = pod_name + "::" + module.params["rename"]
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_file_systems(
            names=[target_name], context_names=[module.params["context"]]
        )
    else:
        res = array.get_file_systems(names=[target_name])
    if res.status_code == 200:
        target = list(res.items)[0]
    if not target:
        changed = True
        if not module.check_mode:
            file_system = flasharray.FileSystemPatch(name=target_name)
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.patch_file_systems(
                    names=[module.params["name"]],
                    file_system=file_system,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_file_systems(
                    names=[module.params["name"]], file_system=file_system
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to rename file system {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    else:
        module.fail_json(
            msg="Target file system {0} already exists".format(module.params["rename"])
        )
    module.exit_json(changed=changed)


def create_fs(module, array):
    """Create a file system"""
    changed = True
    api_version = array.get_rest_version()
    if "::" in module.params["name"]:
        pod_name = module.params["name"].split("::")[0]
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.get_pods(
                names=[pod_name], context_names=[module.params["context"]]
            )
        else:
            res = array.get_pods(names=[pod_name])
        if res.status_code == 200:
            pod = list(array.get_pods(names=[pod_name]).items)[0]
        else:
            module.fail_json(
                msg="Failed to create filesystem. Pod {0} does not exist".format(
                    pod_name
                )
            )
        if pod.promotion_status == "demoted":
            module.fail_json(msg="Filesystem cannot be created in a demoted pod")
    if not module.check_mode:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.post_file_systems(
                names=[module.params["name"]], context_names=[module.params["context"]]
            )
        else:
            res = array.post_file_systems(names=[module.params["name"]])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create file system {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def move_fs(module, array):
    """Move filesystem between pods or local array"""
    changed = False
    api_version = array.get_rest_version()
    pod_name = ""
    fs_name = module.params["name"]
    if "::" in module.params["name"]:
        fs_name = module.params["name"].split("::")[1]
        pod_name = module.params["name"].split("::")[0]
    if module.params["move"] == "local":
        target_location = ""
        if "::" not in module.params["name"]:
            module.fail_json(msg="Source and destination [local] cannot be the same.")
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.get_file_systems(
                names=[fs_name], context_names=[module.params["context"]]
            )
        else:
            res = array.get_file_systems(names=[fs_name])
        if res.status_code == 200:
            module.fail_json(msg="Target filesystem {0} already exists".format(fs_name))
    else:
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.get_pods(
                names=[module.params["move"]], context_names=[module.params["context"]]
            )
        else:
            res = array.get_pods(names=[module.params["move"]])
        if res.status_code == 200:
            pod = list(res.items)[0]
            if len(pod.arrays) > 1:
                module.fail_json(msg="Filesystem cannot be moved into a stretched pod")
            if pod.link_target_count != 0:
                module.fail_json(
                    msg="Filesystem cannot be moved into a linked source pod"
                )
            if pod.promotion_status == "demoted":
                module.fail_json(msg="Volume cannot be moved into a demoted pod")
        else:
            module.fail_json(
                msg="Failed to move filesystem. Pod {0} does not exist".format(pod_name)
            )
        if "::" in module.params["name"]:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.get_pods(
                    names=[module.params["move"]],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.get_pods(names=[module.params["move"]])
            if res.status_code == 200:
                pod = list(res.items)[0]
            else:
                module.fail_json(
                    msg="Failed to move filesystem. Pod {0} does not exist".format(
                        pod_name
                    )
                )
            if len(pod.arrays) > 1:
                module.fail_json(
                    msg="Filesystem cannot be moved out of a stretched pod"
                )
            if pod.linked_target_count != 0:
                module.fail_json(
                    msg="Filesystem cannot be moved out of a linked source pod"
                )
            if pod.promotion_status == "demoted":
                module.fail_json(msg="Volume cannot be moved out of a demoted pod")
        target_location = module.params["move"]
    changed = True
    if not module.check_mode:
        file_system = flasharray.FileSystemPatch(
            pod=flasharray.Reference(name=target_location)
        )
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            move_res = array.patch_file_systems(
                names=[module.params["name"]],
                file_system=file_system,
                context_names=[module.params["context"]],
            )
        else:
            move_res = array.patch_file_systems(
                names=[module.params["name"]], file_system=file_system
            )
        if move_res.status_code != 200:
            module.fail_json(
                msg="Move of filesystem {0} failed. Error: {1}".format(
                    module.params["name"], move_res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            eradicate=dict(type="bool", default=False),
            name=dict(type="str", required=True),
            move=dict(type="str"),
            rename=dict(type="str"),
            context=dict(type="str", default=""),
        )
    )

    mutually_exclusive = [["move", "rename"]]
    module = AnsibleModule(
        argument_spec, mutually_exclusive=mutually_exclusive, supports_check_mode=True
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
    if (
        LooseVersion(REPL_SUPPORT_API) > LooseVersion(api_version)
        and "::" in module.params["name"]
    ):
        module.fail_json(
            msg="Filesystem Replication is only supported in Purity//FA 6.3.0 or higher"
        )
    state = module.params["state"]
    esists = False
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_file_systems(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_file_systems(names=[module.params["name"]])
    if res.status_code == 200:
        filesystem = list(res.items)[0]
        exists = True

    if state == "present" and not exists and not module.params["move"]:
        create_fs(module, array)
    elif (
        state == "present"
        and exists
        and module.params["move"]
        and not filesystem.destroyed
    ):
        move_fs(module, array)
    elif (
        state == "present"
        and exists
        and module.params["rename"]
        and not filesystem.destroyed
    ):
        rename_fs(module, array)
    elif (
        state == "present"
        and exists
        and filesystem.destroyed
        and not module.params["rename"]
        and not module.params["move"]
    ):
        recover_fs(module, array)
    elif (
        state == "present" and exists and filesystem.destroyed and module.params["move"]
    ):
        module.fail_json(
            msg="Filesystem {0} exists, but in destroyed state".format(
                module.params["name"]
            )
        )
    elif state == "absent" and exists and not filesystem.destroyed:
        delete_fs(module, array)
    elif (
        state == "absent"
        and exists
        and module.params["eradicate"]
        and filesystem.destroyed
    ):
        eradicate_fs(module, array)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
