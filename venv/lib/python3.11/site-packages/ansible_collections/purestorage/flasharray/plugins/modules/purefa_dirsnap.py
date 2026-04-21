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
module: purefa_dirsnap
version_added: '1.9.0'
short_description: Manage FlashArray File System Directory Snapshots
description:
- Create/Delete FlashArray File System directory snapshots
- A full snapshot name is constructed in the form of DIR.CLIENT_NAME.SUFFIX
  where DIR is the managed directory name, CLIENT_NAME is the client name,
  and SUFFIX is the suffix.
- The client visible snapshot name is CLIENT_NAME.SUFFIX.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - Name of the directory to snapshot
    type: str
    required: true
  state:
    description:
    - Define whether the directory snapshot should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
  filesystem:
    description:
    - Name of the filesystem the directory links to.
    type: str
    required: true
  eradicate:
    description:
    - Define whether to eradicate the snapshot on delete or leave in trash
    type: bool
    default: false
  client:
    description:
    - The client name portion of the client visible snapshot name
    type: str
    required: true
  suffix:
    description:
    - Snapshot suffix to use
    type: str
  new_client:
    description:
    - The new client name when performing a rename
    type: str
    version_added: '1.12.0'
  new_suffix:
    description:
    - The new suffix when performing a rename
    type: str
    version_added: '1.12.0'
  rename:
    description:
    - Whether to rename a directory snapshot
    - The snapshot client name and suffix can be changed
    - Required with I(new_client) ans I(new_suffix)
    type: bool
    default: false
    version_added: '1.12.0'
  keep_for:
    description:
    - Retention period, after which snapshots will be eradicated
    - Specify in seconds. Range 300 - 31536000 (5 minutes to 1 year)
    - Value of 0 will set no retention period.
    - If not specified on create will default to 0 (no retention period)
    type: int
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
- name: Create a snapshot direcotry foo in filesysten bar for client test with suffix test
  purestorage.flasharray.purefa_dirsnap:
    name: foo
    filesystem: bar
    client: test
    suffix: test
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update retention time for a snapshot foo:bar.client.test
  purestorage.flasharray.purefa_dirsnap:
    name: foo
    filesystem: bar
    client: client
    suffix: test
    keep_for: 300  # 5 minutes
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete snapshot foo:bar.client.test
  purestorage.flasharray.purefa_dirsnap:
    name: foo
    filesystem: bar
    client: client
    suffix: test
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Recover deleted snapshot foo:bar.client.test
  purestorage.flasharray.purefa_dirsnap:
    name: foo
    filesystem: bar
    client: client
    suffix: test
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete and eradicate snapshot foo:bar.client.test
  purestorage.flasharray.purefa_dirsnap:
    name: foo
    filesystem: bar
    client: client
    suffix: test
    state: absent
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Eradicate deleted snapshot foo:bar.client.test
  purestorage.flasharray.purefa_dirsnap:
    name: foo
    filesystem: bar
    client: client
    suffix: test
    eradicate: true
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Rename snapshot
  purestorage.flasharray.purefa_dirsnap:
    name: foo
    filesystem: bar
    client: client
    suffix: test
    rename: true
    new_client: client2
    new_suffix: test2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import DirectorySnapshotPost, DirectorySnapshotPatch
except ImportError:
    HAS_PURESTORAGE = False

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

MIN_REQUIRED_API_VERSION = "2.2"
MIN_RENAME_API_VERSION = "2.10"
CONTEXT_VERSION = "2.42"


def eradicate_snap(module, array):
    """Eradicate a filesystem snapshot"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        snapname = (
            module.params["filesystem"]
            + ":"
            + module.params["name"]
            + "."
            + module.params["client"]
            + "."
            + module.params["suffix"]
        )
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.delete_directory_snapshots(
                names=[snapname], context_names=[module.params["context"]]
            )
        else:
            res = array.delete_directory_snapshots(names=[snapname])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to eradicate filesystem snapshot {0}. Error: {1}".format(
                    snapname, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_snap(module, array):
    """Delete a filesystem snapshot"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        snapname = (
            module.params["filesystem"]
            + ":"
            + module.params["name"]
            + "."
            + module.params["client"]
            + "."
            + module.params["suffix"]
        )
        directory_snapshot = DirectorySnapshotPatch(destroyed=True)
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.patch_directory_snapshots(
                names=[snapname],
                directory_snapshot=directory_snapshot,
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_directory_snapshots(
                names=[snapname], directory_snapshot=directory_snapshot
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete filesystem snapshot {0}. Error: {1}".format(
                    snapname, res.errors[0].message
                )
            )
        if module.params["eradicate"]:
            eradicate_snap(module, array)
    module.exit_json(changed=changed)


def update_snap(module, array, snap_detail):
    """Update a filesystem snapshot retention time"""
    api_version = array.get_rest_version()
    changed = False
    snapname = (
        module.params["filesystem"]
        + ":"
        + module.params["name"]
        + "."
        + module.params["client"]
        + "."
        + module.params["suffix"]
    )
    if module.params["rename"]:
        if not module.params["new_client"]:
            new_client = module.params["client"]
        else:
            new_client = module.params["new_client"]
        if not module.params["new_suffix"]:
            new_suffix = module.params["suffix"]
        else:
            new_suffix = module.params["new_suffix"]
        new_snapname = (
            module.params["filesystem"]
            + ":"
            + module.params["name"]
            + "."
            + new_client
            + "."
            + new_suffix
        )
        directory_snapshot = DirectorySnapshotPatch(
            client_name=new_client, suffix=new_suffix
        )
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.patch_directory_snapshots(
                    names=[snapname],
                    directory_snapshot=directory_snapshot,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_directory_snapshots(
                    names=[snapname], directory_snapshot=directory_snapshot
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to rename snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
            else:
                snapname = new_snapname
    if not module.params["keep_for"] or module.params["keep_for"] == 0:
        keep_for = None
    elif 300 <= module.params["keep_for"] <= 31536000:
        keep_for = module.params["keep_for"] * 1000
    else:
        module.fail_json(msg="keep_for not in range of 300 - 31536000")
    if snap_detail.destroyed:
        changed = True
        if not module.check_mode:
            directory_snapshot = DirectorySnapshotPatch(destroyed=False)
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.patch_directory_snapshots(
                    names=[snapname],
                    directory_snapshot=directory_snapshot,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_directory_snapshots(
                    names=[snapname], directory_snapshot=directory_snapshot
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to recover snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
            if keep_for != 0:  # Set a new keep-for after recovery if requested
                directory_snapshot = DirectorySnapshotPatch(keep_for=keep_for)
                if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                    res = array.patch_directory_snapshots(
                        names=[snapname],
                        directory_snapshot=directory_snapshot,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.patch_directory_snapshots(
                        names=[snapname], directory_snapshot=directory_snapshot
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to retention time for snapshot {0}. Error: {1}".format(
                            snapname, res.errors[0].message
                        )
                    )
    if keep_for:
        directory_snapshot = DirectorySnapshotPatch(keep_for=keep_for)
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.patch_directory_snapshots(
                    names=[snapname],
                    directory_snapshot=directory_snapshot,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_directory_snapshots(
                    names=[snapname], directory_snapshot=directory_snapshot
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to retention time for snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
    if module.params["rename"] and keep_for:
        directory_snapshot = DirectorySnapshotPatch(keep_for=keep_for)
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
                res = array.patch_directory_snapshots(
                    names=[new_snapname],
                    directory_snapshot=directory_snapshot,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.patch_directory_snapshots(
                    names=[new_snapname], directory_snapshot=directory_snapshot
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to retention time for renamed snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def create_snap(module, array):
    """Create a filesystem snapshot"""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        if not module.params["keep_for"] or module.params["keep_for"] == 0:
            keep_for = None
        elif 300 <= module.params["keep_for"] <= 31536000:
            keep_for = module.params["keep_for"] * 1000
        else:
            module.fail_json(msg="keep_for not in range of 300 - 31536000")
        directory = module.params["filesystem"] + ":" + module.params["name"]
        if module.params["suffix"]:
            directory_snapshot = DirectorySnapshotPost(
                client_name=module.params["client"],
                keep_for=keep_for,
                suffix=module.params["suffix"],
            )
        else:
            directory_snapshot = DirectorySnapshotPost(
                client_name=module.params["client"], keep_for=keep_for
            )
        if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
            res = array.post_directory_snapshots(
                source_names=[directory],
                directory_snapshot=directory_snapshot,
                context_names=[module.params["context"]],
            )
        else:
            res = array.post_directory_snapshots(
                source_names=[directory], directory_snapshot=directory_snapshot
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create client {0} snapshot for {1}. Error: {2}".format(
                    module.params["client"], directory, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            state=dict(type="str", default="present", choices=["absent", "present"]),
            filesystem=dict(type="str", required=True),
            name=dict(type="str", required=True),
            eradicate=dict(type="bool", default=False),
            client=dict(type="str", required=True),
            suffix=dict(type="str"),
            rename=dict(type="bool", default=False),
            new_client=dict(type="str"),
            new_suffix=dict(type="str"),
            keep_for=dict(type="int"),
            context=dict(type="str", default=""),
        )
    )

    required_if = [["state", "absent", ["suffix"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if module.params["rename"]:
        if not module.params["new_client"] and not module.params["new_suffix"]:
            module.fail_json(msg="Rename requires one of: new_client, new_suffix")

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    client_pattern = re.compile(
        "^(?=.*[a-zA-Z-])[a-zA-Z0-9]([a-zA-Z0-9-]{0,56}[a-zA-Z0-9])?$"
    )
    suffix_pattern = re.compile(
        "^(?=.*[a-zA-Z-])[a-zA-Z0-9]([a-zA-Z0-9-]{0,63}[a-zA-Z0-9])?$"
    )
    if module.params["suffix"]:
        if not suffix_pattern.match(module.params["suffix"]):
            module.fail_json(
                msg="Suffix name {0} does not conform to the suffix name rules.".format(
                    module.params["suffix"]
                )
            )
    if module.params["new_suffix"]:
        if not suffix_pattern.match(module.params["new_suffix"]):
            module.fail_json(
                msg="Suffix rename {0} does not conform to the suffix name rules.".format(
                    module.params["new_suffix"]
                )
            )
    if module.params["client"]:
        if not client_pattern.match(module.params["client"]):
            module.fail_json(
                msg="Client name {0} does not conform to the client name rules.".format(
                    module.params["client"]
                )
            )

    array = get_array(module)
    api_version = array.get_rest_version()
    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )
    if module.params["rename"] and LooseVersion(MIN_RENAME_API_VERSION) > LooseVersion(
        api_version
    ):
        module.fail_json(
            msg="Directory snapshot rename not supported. "
            "Minimum Purity//FA version required: 6.2.1"
        )
    state = module.params["state"]
    snapshot_root = module.params["filesystem"] + ":" + module.params["name"]
    if LooseVersion(CONTEXT_VERSION) <= LooseVersion(api_version):
        res = array.get_directories(
            filter='name="' + snapshot_root + '"',
            total_item_count=True,
            context_names=[module.params["context"]],
        )
    else:
        res = array.get_directories(
            filter='name="' + snapshot_root + '"', total_item_count=True
        )
    if bool(res.total_item_count == 0):
        module.fail_json(msg="Directory {0} does not exist.".format(snapshot_root))
    snap_exists = False
    if module.params["suffix"]:
        snap_detail = array.get_directory_snapshots(
            filter="name='"
            + snapshot_root
            + "."
            + module.params["client"]
            + "."
            + module.params["suffix"]
            + "'",
            total_item_count=True,
        )
        if bool(snap_detail.status_code == 200):
            snap_exists = bool(snap_detail.total_item_count != 0)
    if snap_exists:
        snap_facts = list(snap_detail.items)[0]
    if state == "present" and not snap_exists and not module.params["rename"]:
        create_snap(module, array)
    elif state == "present" and snap_exists and module.params["suffix"]:
        update_snap(module, array, snap_facts)
    elif state == "absent" and snap_exists and not snap_facts.destroyed:
        delete_snap(module, array)
    elif (
        state == "absent"
        and snap_exists
        and snap_facts.destroyed
        and module.params["eradicate"]
    ):
        eradicate_snap(module, array)
    else:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
