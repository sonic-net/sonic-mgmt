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

DOCUMENTATION = r"""
---
module: purefa_snap
version_added: '1.0.0'
short_description: Manage volume snapshots on Pure Storage FlashArrays
description:
- Create or delete volumes and volume snapshots on Pure Storage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the source volume.
    type: str
    required: true
  suffix:
    description:
    - Suffix of snapshot name.
    type: str
  target:
    description:
    - Name of target volume if creating from snapshot.
    - Name of new snapshot suffix if renaming a snapshot
    type: str
  overwrite:
    description:
    - Define whether to overwrite existing volume when creating from snapshot.
    type: bool
    default: false
  offload:
    description:
    - Only valid for Purity//FA 6.1 or higher
    - Name of offload target for the snapshot.
    - Target can be either another FlashArray or an Offload Target
    - This is only applicable for creation, deletion and eradication of snapshots
    - I(state) of I(copy) is not supported.
    type: str
  state:
    description:
    - Define whether the volume snapshot should exist or not.
    choices: [ absent, copy, present, rename ]
    type: str
    default: present
  eradicate:
    description:
    - Define whether to eradicate the snapshot on delete or leave in trash.
    type: bool
    default: false
  ignore_repl:
    description:
    - Only valid for Purity//FA 6.1 or higher
    - If set to true, allow destruction/eradication of snapshots in use by replication.
    - If set to false, allow destruction/eradication of snapshots not in use by replication
    type: bool
    default: false
  throttle:
    description:
    -  If set to true, allows snapshot to fail if array health is not optimal.
    type: bool
    default: false
    version_added: '1.21.0'
  context:
    description:
    - Name of fleet member on which to perform the operation.
    - This requires the array receiving the request is a member of a fleet
      and the context name to be a member of the same fleet.
    type: str
    default: ""
    version_added: '1.33.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create snapshot foo.ansible
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: ansible
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Create R/W clone foo_clone from snapshot foo.snap
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: snap
    target: foo_clone
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Create R/W clone foo_clone from remote mnapshot arrayB:foo.snap
  purestorage.flasharray.purefa_snap:
    name: arrayB:foo
    suffix: snap
    target: foo_clone
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Overwrite existing volume foo_clone with snapshot foo.snap
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: snap
    target: foo_clone
    overwrite: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Delete and eradicate snapshot named foo.snap
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: snap
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename snapshot foo.fred to foo.dave
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: fred
    target: dave
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: rename

- name: Create a remote volume snapshot on offload device arrayB
  purestorage.flasharray.purefa_snap:
    name: foo
    offload: arrayB
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete and eradicate a volume snapshot foo.1 on offload device arrayB
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: 1
    offload: arrayB
    eradicate: true
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
suffix:
    description: Data related to the created snapshot suffix
    type: str
    returned: success
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        RemoteVolumeSnapshotPost,
        VolumeSnapshotPost,
        DestroyedPatchPost,
        VolumeSnapshotPatch,
        VolumePost,
        Reference,
    )
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
from datetime import datetime

THROTTLE_API = "2.25"
SNAPSHOT_SUFFIX_API = "2.28"
CONTEXT_API_VERSION = "2.38"


def _check_offload(module, array):
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_offloads(
            names=[module.params["offload"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_offloads(names=[module.params["offload"]])
    if res.status_code == 200:
        if list(res.items)[0].status == "connected":
            return True
    return False


def _check_target(module, array):
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_array_connections(
            names=[module.params["offload"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_array_connections(names=[module.params["offload"]])
    if res.status_code == 200:
        if list(res.items)[0].status == "connected":
            return True
    return False


def _check_offload_snapshot(module, array):
    """Return Remote Snapshot (active or deleted) or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        source_array = list(
            array.get_arrays(context_names=[module.params["context"]]).items
        )[0].name
    else:
        source_array = list(array.get_arrays().items)[0].name
    snapname = (
        source_array + ":" + module.params["name"] + "." + module.params["suffix"]
    )
    if _check_offload(module, array):
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.get_remote_volume_snapshots(
                on=module.params["offload"],
                names=[snapname],
                destroyed=False,
                context_names=[module.params["context"]],
            )
        else:
            res = array.get_remote_volume_snapshots(
                on=module.params["offload"], names=[snapname], destroyed=False
            )
    else:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.get_volume_snapshots(
                names=[snapname],
                destroyed=False,
                context_names=[module.params["context"]],
            )
        else:
            res = array.get_volume_snapshots(names=[snapname], destroyed=False)
    if res.status_code != 200:
        return None
    return list(res.items)[0]


def get_volume(module, array):
    """Return Volume or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_volumes(
            names=[module.params["name"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_volumes(names=[module.params["name"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_target(module, array):
    """Return Volume or None"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_volumes(
            names=[module.params["target"]], context_names=[module.params["context"]]
        )
    else:
        res = array.get_volumes(names=[module.params["target"]])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def get_deleted_snapshot(module, array):
    """Return Deleted Snapshot"""
    api_version = array.get_rest_version()
    snapname = module.params["name"] + "." + module.params["suffix"]
    if module.params["offload"]:
        source_array = list(array.get_arrays().items)[0].name
        snapname = module.params["name"] + "." + module.params["suffix"]
        full_snapname = source_array + ":" + snapname
        if _check_offload(module, array):
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.get_remote_volume_snapshots(
                    context_names=[module.params["context"]],
                    on=module.params["offload"],
                    names=[full_snapname],
                    destroyed=True,
                )
            else:
                res = array.get_remote_volume_snapshots(
                    on=module.params["offload"], names=[full_snapname], destroyed=True
                )
        else:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.get_volume_snapshots(
                    names=[snapname],
                    destroyed=True,
                    context_names=[module.params["context"]],
                )
            else:
                res = array.get_volume_snapshots(names=[snapname], destroyed=True)
        return bool(res.status_code == 200)
    else:
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            return bool(
                array.get_volume_snapshots(
                    names=[snapname],
                    context_names=[module.params["context"]],
                    destroyed=True,
                ).status_code
                == 200
            )
        return bool(
            array.get_volume_snapshots(names=[snapname], destroyed=True).status_code
            == 200
        )


def get_snapshot(module, array):
    """Return True if snapshot exists, False otherwise"""
    api_version = array.get_rest_version()
    snapname = module.params["name"] + "." + module.params["suffix"]
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        return bool(
            array.get_volume_snapshots(
                names=[snapname],
                destroyed=False,
                context_names=[module.params["context"]],
            ).status_code
            == 200
        )
    return bool(
        array.get_volume_snapshots(names=[snapname], destroyed=False).status_code == 200
    )


def create_snapshot(module, array):
    """Create Snapshot"""
    changed = False
    api_version = array.get_rest_version()
    if module.params["offload"]:
        if LooseVersion(SNAPSHOT_SUFFIX_API) > LooseVersion(api_version):
            module.params["suffix"] = None
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_remote_volume_snapshots(
                    source_names=[module.params["name"]],
                    context_names=[module.params["context"]],
                    on=module.params["offload"],
                    remote_volume_snapshot=RemoteVolumeSnapshotPost(
                        suffix=module.params["suffix"]
                    ),
                )
            else:
                if module.params["suffix"]:
                    res = array.post_remote_volume_snapshots(
                        source_names=[module.params["name"]],
                        on=module.params["offload"],
                        remote_volume_snapshot=RemoteVolumeSnapshotPost(
                            suffix=module.params["suffix"]
                        ),
                    )
                else:
                    res = array.post_remote_volume_snapshots(
                        source_names=[module.params["name"]],
                        on=module.params["offload"],
                    )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create remote snapshot for volume {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            else:
                if LooseVersion(SNAPSHOT_SUFFIX_API) > LooseVersion(api_version):
                    remote_snap = list(res.items)[0].name
                    module.params["suffix"] = remote_snap.split(".")[1]
    else:
        changed = True
        if not module.check_mode:
            if LooseVersion(THROTTLE_API) <= LooseVersion(api_version):
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_volume_snapshots(
                        allow_throttle=module.params["throttle"],
                        context_names=[module.params["context"]],
                        volume_snapshot=VolumeSnapshotPost(
                            suffix=module.params["suffix"]
                        ),
                        source_names=[module.params["name"]],
                    )
                else:
                    res = array.post_volume_snapshots(
                        allow_throttle=module.params["throttle"],
                        volume_snapshot=VolumeSnapshotPost(
                            suffix=module.params["suffix"]
                        ),
                        source_names=[module.params["name"]],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create snapshot for volume {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
            else:
                res = array.post_volume_snapshots(
                    source_names=[module.params["name"]],
                    volume_snapshot=VolumeSnapshotPost(suffix=module.params["suffix"]),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to create snapshot for volume {0}. Error: {1}".format(
                            module.params["name"], res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed, suffix=module.params["suffix"])


def create_from_snapshot(module, array):
    """Create Volume from Snapshot"""
    api_version = array.get_rest_version()
    source = module.params["name"] + "." + module.params["suffix"]
    tgt = get_target(module, array)
    if tgt is None:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_volumes(
                    context_names=[module.params["context"]],
                    volume=VolumePost(source=Reference(name=source)),
                    names=[module.params["target"]],
                )
            else:
                res = array.post_volumes(
                    volume=VolumePost(source=Reference(name=source)),
                    names=[module.params["target"]],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create volume {0} from snapshot {1}. Error: {2}".format(
                        module.params["target"], source, res.errors[9].message
                    )
                )
    elif tgt is not None and module.params["overwrite"]:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.post_volumes(
                    overwrite=module.params["overwrite"],
                    context_names=[module.params["context"]],
                    volume=VolumePost(source=Reference(name=source)),
                    names=[module.params["target"]],
                )
            else:
                res = array.post_volumes(
                    overwrite=module.params["overwrite"],
                    volume=VolumePost(source=Reference(name=source)),
                    names=[module.params["target"]],
                )
    elif tgt is not None and not module.params["overwrite"]:
        changed = False
    module.exit_json(changed=changed)


def recover_snapshot(module, array):
    """Recover Snapshot"""
    api_version = array.get_rest_version()
    changed = False
    snapname = module.params["name"] + "." + module.params["suffix"]
    if module.params["offload"] and _check_offload(module, array):
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            source_array = list(
                array.get_arrays(context_names=[module.params["context"]]).items
            )[0].name
        else:
            source_array = list(array.get_arrays().items)[0].name
        snapname = source_array + module.params["name"] + "." + module.params["suffix"]
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_remote_volume_snapshots(
                    names=[snapname],
                    context_names=[module.params["context"]],
                    on=module.params["offload"],
                    remote_volume_snapshot=DestroyedPatchPost(destroyed=False),
                )
            else:
                res = array.patch_remote_volume_snapshots(
                    names=[snapname],
                    on=module.params["offload"],
                    remote_volume_snapshot=DestroyedPatchPost(destroyed=False),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to recover remote snapshot {0}".format(snapname)
                )
    else:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_volume_snapshot(
                    names=[snapname],
                    context_names=[module.params["context"]],
                    volume_snapshot=VolumeSnapshotPatch(destroyed=False),
                )
            else:
                res = array.patch_volume_snapshot(
                    names=[snapname],
                    volume_snapshot=VolumeSnapshotPatch(destroyed=False),
                )
            if res.sttaus_code != 200:
                module.fail_json(
                    msg="Recovery of snapshot {0} failed. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def update_snapshot(module, array):
    """Update Snapshot - basically just rename..."""
    api_version = array.get_rest_version()
    changed = True
    if not module.check_mode:
        current_name = module.params["name"] + "." + module.params["suffix"]
        new_name = module.params["name"] + "." + module.params["target"]
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_volume_snapshots(
                names=[current_name],
                context_names=[module.params["context"]],
                volume_snapshot=VolumeSnapshotPatch(name=new_name),
            )
        else:
            res = array.patch_volume_snapshots(
                names=[current_name],
                volume_snapshot=VolumeSnapshotPatch(name=new_name),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename {0} to {1}. Error: {2}".format(
                    current_name, new_name, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_snapshot(module, array):
    """Delete Snapshot"""
    api_version = array.get_rest_version()
    changed = False
    snapname = module.params["name"] + "." + module.params["suffix"]
    if module.params["offload"] and _check_offload(module, array):
        source_array = list(array.get_arrays().items)[0].name
        full_snapname = source_array + ":" + snapname
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_remote_volume_snapshots(
                    names=[full_snapname],
                    context_names=[module.params["context"]],
                    on=module.params["offload"],
                    volume_snapshot=VolumeSnapshotPatch(destroyed=True),
                    replication_snapshot=module.params["ignore_repl"],
                )
            else:
                res = array.patch_remote_volume_snapshots(
                    names=[full_snapname],
                    on=module.params["offload"],
                    volume_snapshot=VolumeSnapshotPatch(destroyed=True),
                    replication_snapshot=module.params["ignore_repl"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
            if module.params["eradicate"]:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.delete_remote_volume_snapshots(
                        names=[full_snapname],
                        context_names=[module.params["context"]],
                        on=module.params["offload"],
                        replication_snapshot=module.params["ignore_repl"],
                    )
                else:
                    res = array.delete_remote_volume_snapshots(
                        names=[full_snapname],
                        on=module.params["offload"],
                        replication_snapshot=module.params["ignore_repl"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                            snapname, res.errors[0].message
                        )
                    )
    elif module.params["offload"] and _check_target(module, array):
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_volume_snapshots(
                    names=[snapname],
                    context_names=[module.params["context"]],
                    volume_snapshot=DestroyedPatchPost(destroyed=True),
                    replication_snapshot=module.params["ignore_repl"],
                )
            else:
                res = array.patch_volume_snapshots(
                    names=[snapname],
                    volume_snapshot=DestroyedPatchPost(destroyed=True),
                    replication_snapshot=module.params["ignore_repl"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
            if module.params["eradicate"]:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.delete_volume_snapshots(
                        names=[snapname],
                        replication_snapshot=module.params["ignore_repl"],
                    )
                else:
                    res = array.delete_volume_snapshots(
                        names=[snapname],
                        replication_snapshot=module.params["ignore_repl"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                            snapname, res.errors[0].message
                        )
                    )
    else:
        changed = True
        if not module.check_mode:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.patch_volume_snapshots(
                    names=[snapname],
                    context_names=[module.params["context"]],
                    volume_snapshot=DestroyedPatchPost(destroyed=True),
                    replication_snapshot=module.params["ignore_repl"],
                )
            else:
                res = array.patch_volume_snapshots(
                    names=[snapname],
                    volume_snapshot=DestroyedPatchPost(destroyed=True),
                    replication_snapshot=module.params["ignore_repl"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
            if module.params["eradicate"]:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.delete_volume_snapshots(
                        names=[snapname],
                        context_names=[module.params["context"]],
                        replication_snapshot=module.params["ignore_repl"],
                    )
                else:
                    res = array.delete_volume_snapshots(
                        names=[snapname],
                        replication_snapshot=module.params["ignore_repl"],
                    )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                            snapname, res.errors[0].message
                        )
                    )
    module.exit_json(changed=changed)


def eradicate_snapshot(module, array):
    """Eradicate snapshot"""
    api_version = array.get_rest_version()
    changed = True
    snapname = module.params["name"] + "." + module.params["suffix"]
    if not module.check_mode:
        if module.params["offload"] and _check_offload(module, array):
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                source_array = list(
                    array.get_arrays(context_names=[module.params["context"]]).items
                )[0].name
            else:
                source_array = list(array.get_arrays().items)[0].name
            full_snapname = source_array + ":" + snapname
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.delete_remote_volume_snapshots(
                    names=[full_snapname],
                    context_names=[module.params["context"]],
                    on=module.params["offload"],
                    replication_snapshot=module.params["ignore_repl"],
                )
            else:
                res = array.delete_remote_volume_snapshots(
                    names=[full_snapname],
                    on=module.params["offload"],
                    replication_snapshot=module.params["ignore_repl"],
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
        elif module.params["offload"] and _check_target(module, array):
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.delete_volume_snapshots(
                    context_names=[module.params["context"]],
                    names=[snapname],
                    replication_snapshot=module.params["ignore_repl"],
                )
            else:
                res = array.delete_volume_snapshots(
                    names=[snapname], replication_snapshot=module.params["ignore_repl"]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
        else:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.delete_volume_snapshots(
                    context_names=[module.params["context"]], names=[snapname]
                )
            else:
                res = array.delete_volume_snapshots(names=[snapname])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            suffix=dict(type="str"),
            target=dict(type="str"),
            offload=dict(type="str"),
            throttle=dict(type="bool", default=False),
            ignore_repl=dict(type="bool", default=False),
            overwrite=dict(type="bool", default=False),
            eradicate=dict(type="bool", default=False),
            state=dict(
                type="str",
                default="present",
                choices=["absent", "copy", "present", "rename"],
            ),
            context=dict(type="str", default=""),
        )
    )

    required_if = [("state", "copy", ["target", "suffix"])]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )
    pattern1 = re.compile(
        "^(?=.*[a-zA-Z-])[a-zA-Z0-9]([a-zA-Z0-9-]{0,63}[a-zA-Z0-9])?$"
    )
    pattern2 = re.compile("^([1-9])([0-9]{0,63}[0-9])?$")

    state = module.params["state"]
    if module.params["suffix"] is None:
        suffix = "snap-" + str(
            (datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds()
        )
        module.params["suffix"] = suffix.replace(".", "")
    else:
        if not module.params["offload"]:
            if not (
                pattern1.match(module.params["suffix"])
                or pattern2.match(module.params["suffix"])
            ) and state not in [
                "absent",
                "rename",
            ]:
                module.fail_json(
                    msg="Suffix name {0} does not conform to suffix name rules".format(
                        module.params["suffix"]
                    )
                )
    if state == "rename" and module.params["target"] is not None:
        if not pattern1.match(module.params["target"]):
            module.fail_json(
                msg="Suffix target {0} does not conform to suffix name rules".format(
                    module.params["target"]
                )
            )

    array = get_array(module)
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")
    if module.params["offload"]:
        if not _check_offload(module, array) and not _check_target(module, array):
            module.fail_json(
                msg="Selected offload {0} not connected.".format(
                    module.params["offload"]
                )
            )
    if (
        state == "copy"
        and module.params["offload"]
        and not _check_target(module, array)
    ):
        module.fail_json(
            msg="Snapshot copy is not supported when an offload target is defined"
        )
    destroyed = False
    array_snap = False
    offload_snap = False
    volume = get_volume(module, array)
    if module.params["offload"] and not _check_target(module, array):
        offload_snap = _check_offload_snapshot(module, array)
        if offload_snap is None:
            offload_snap = False
        else:
            offload_snap = not offload_snap.destroyed
    else:
        array_snap = get_snapshot(module, array)
    snap = array_snap or offload_snap

    if not snap:
        destroyed = get_deleted_snapshot(module, array)
    if state == "present" and volume and not destroyed:
        create_snapshot(module, array)
    elif state == "present" and destroyed:
        recover_snapshot(module, array)
    elif state == "rename" and volume and snap:
        update_snapshot(module, array)
    elif state == "copy" and snap:
        create_from_snapshot(module, array)
    elif state == "absent" and snap and not destroyed:
        delete_snapshot(module, array)
    elif state == "absent" and destroyed and module.params["eradicate"]:
        eradicate_snapshot(module, array)
    elif state == "absent" and not snap:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
