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
module: purefa_pgsnap
version_added: '1.0.0'
short_description: Manage protection group snapshots on Pure Storage FlashArrays
description:
- Create or delete protection group snapshots on Pure Storage FlashArray.
- Recovery of replicated snapshots on the replica target array is enabled.
- Support for ActiveCluster and Volume Group protection groups is supported.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the source protection group.
    type: str
    required: true
  suffix:
    description:
    - Suffix of snapshot name.
    - Special case. If I(latest) the module will select the latest snapshot created in the group
    type: str
  state:
    description:
    - Define whether the protection group snapshot should exist or not.
      Copy (added in 2.7) will create a full read/write clone of the
      snapshot.
    type: str
    choices: [ absent, present, copy, rename ]
    default: present
  eradicate:
    description:
    - Define whether to eradicate the snapshot on delete or leave in trash.
    type: bool
    default: false
  restore:
    description:
    - Restore a specific volume from a protection group snapshot.
    - The protection group name is not required. Only provide the name of the
      volume to be restored.
    type: str
  overwrite:
    description:
    - Define whether to overwrite the target volume if it already exists.
    type: bool
    default: false
  target:
    description:
    - Volume to restore a specified volume to.
    - If not supplied this will default to the volume defined in I(restore)
    - Name of new snapshot suffix if renaming a snapshot
    type: str
  offload:
    description:
    - Name of offload target on which the snapshot exists.
    - This is only applicable for deletion and erasure of snapshots
    type: str
  now:
    description:
    - Whether to initiate a snapshot of the protection group immeadiately
    type: bool
    default: false
  apply_retention:
    description:
    - Apply retention schedule settings to the snapshot
    type: bool
    default: false
  remote:
    description:
    - Force immeadiate snapshot to remote targets
    type: bool
    default: false
  throttle:
    description:
    - If set to true, allows snapshot to fail if array health is not optimal.
    type: bool
    default: false
    version_added: '1.21.0'
  with_default_protection:
    description:
    - Whether to add the default container protection groups to
      those specified in I(add_to_pgs) as the inital protection
      of a volume created from a snapshot.
    type: bool
    default: true
    version_added: '1.27.0'
  add_to_pgs:
    description:
    - A volume created from a snapshot will be added to the specified
      protection groups
    type: list
    elements: str
    version_added: '1.27.0'
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
- name: Create protection group snapshot foo.ansible
  purestorage.flasharray.purefa_pgsnap:
    name: foo
    suffix: ansible
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Delete and eradicate protection group snapshot named foo.snap
  purestorage.flasharray.purefa_pgsnap:
    name: foo
    suffix: snap
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Restore volume data from local protection group snapshot named foo.snap to volume data2
  purestorage.flasharray.purefa_pgsnap:
    name: foo
    suffix: snap
    restore: data
    target: data2
    overwrite: true
    with_default_protection: false
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Restore remote protection group snapshot arrayA:pgname.snap.data to local copy
  purestorage.flasharray.purefa_pgsnap:
    name: arrayA:pgname
    suffix: snap
    restore: data
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Restore AC pod  protection group snapshot pod1::pgname.snap.data to pod1::data2
  purestorage.flasharray.purefa_pgsnap:
    name: pod1::pgname
    suffix: snap
    restore: data
    target: pod1::data2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Create snapshot of existing pgroup foo with suffix and force immeadiate copy to remote targets
  purestorage.flasharray.purefa_pgsnap:
    name: pgname
    suffix: force
    now: true
    apply_retention: true
    remote: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete and eradicate snapshot named foo.snap on offload target bar from arrayA
  purestorage.flasharray.purefa_pgsnap:
    name: "arrayA:foo"
    suffix: snap
    offload: bar
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename protection group snapshot foo.fred to foo.dave
  purestorage.flasharray.purefa_pgsnap:
    name: foo
    suffix: fred
    target: dave
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: rename
"""

RETURN = r"""
snapshot:
    description: Suffix of the created protection group snapshot.
    type: str
    returned: success
"""

HAS_PURESTORAGE = True
try:
    from pypureclient.flasharray import (
        ProtectionGroupSnapshot,
        ProtectionGroupSnapshotPatch,
        VolumePost,
        Reference,
        FixedReference,
        DestroyedPatchPost,
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
DEFAULT_API = "2.16"
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
        return bool(list(res.items)[0].status == "connected")
    return False


def get_pgroup(module, array):
    """Return Protection Group"""
    api_version = array.get_rest_version()
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        return bool(
            array.get_protection_groups(
                names=[module.params["name"]], context_names=[module.params["context"]]
            ).status_code
            == 200
        )
    return bool(
        array.get_protection_groups(names=[module.params["name"]]).status_code == 200
    )


def get_pgroupvolume(module, array):
    """Return Protection Group Volume or None"""
    api_version = array.get_rest_version()
    try:
        volumes = []
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            pgroup = list(
                array.get_protection_groups(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                ).items
            )[0]
        else:
            pgroup = list(
                array.get_protection_groups(names=[module.params["name"]]).items
            )[0]
        if pgroup.host_count > 0:  # We have a host PG
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                host_dict = list(
                    array.get_protection_groups_hosts(
                        context_names=[module.params["context"]],
                        group_names=[module.params["name"]],
                    ).items
                )
            else:
                host_dict = list(
                    array.get_protection_groups_hosts(
                        group_names=[module.params["name"]]
                    ).items
                )
            for host in range(0, len(host_dict)):
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    hostvols = list(
                        array.get_connections(
                            context_names=[module.params["context"]],
                            host_names=[host_dict[host].member["name"]],
                        ).items
                    )
                else:
                    hostvols = list(
                        array.get_connections(
                            host_names=[host_dict[host].member["name"]]
                        ).items
                    )
                for hvol in range(0, len(hostvols)):
                    volumes.append(hostvols[hvol].volume["name"])
        elif pgroup.host_group_count > 0:  # We have a hostgroup PG
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                hgroup_dict = list(
                    array.get_protection_groups_host_groups(
                        context_names=[module.params["context"]],
                        group_names=[module.params["name"]],
                    ).items
                )
            else:
                hgroup_dict = list(
                    array.get_protection_groups_host_groups(
                        group_names=[module.params["name"]]
                    ).items
                )
            # First check if there are any volumes in the host groups
            for hgentry in range(0, len(hgroup_dict)):
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    hgvols = list(
                        array.get_connections(
                            context_names=[module.params["context"]],
                            host_group_names=[hgroup_dict[hgentry].member["name"]],
                        ).items
                    )
                else:
                    hgvols = list(
                        array.get_connections(
                            host_group_names=[hgroup_dict[hgentry].member["name"]]
                        ).items
                    )
                for hgvol in range(0, len(hgvols)):
                    volumes.append(hgvols[hgvol].volume["name"])
            # Second check for host specific volumes
            for hgroup in range(0, len(hgroup_dict)):
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    hg_hosts = list(
                        array.get_host_groups_hosts(
                            context_names=[module.params["context"]],
                            group_names=[hgroup_dict[hgroup].member["name"]],
                        ).items
                    )
                else:
                    hg_hosts = list(
                        array.get_host_groups_hosts(
                            group_names=[hgroup_dict[hgroup].member["name"]]
                        ).items
                    )
                for hg_host in range(0, len(hg_hosts)):
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        host_vols = list(
                            array.get_connections(
                                context_names=[module.params["context"]],
                                host_names=[hg_hosts[hg_host].member["name"]],
                            ).items
                        )
                    else:
                        host_vols = list(
                            array.get_connections(
                                host_names=[hg_hosts[hg_host].member["name"]]
                            ).items
                        )
                    for host_vol in range(0, len(host_vols)):
                        volumes.append(host_vols[host_vol].volume["name"])
        else:  # We have a volume PG
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                vol_dict = list(
                    array.get_protection_groups_volumes(
                        context_names=[module.params["context"]],
                        group_names=[module.params["name"]],
                    ).items
                )
            else:
                vol_dict = list(
                    array.get_protection_groups_volumes(
                        group_names=[module.params["name"]]
                    ).items
                )
            for entry in range(0, len(vol_dict)):
                volumes.append(vol_dict[entry].member["name"])
        volumes = list(set(volumes))
        if "::" in module.params["name"]:
            restore_volume = (
                module.params["name"].split("::")[0] + "::" + module.params["restore"]
            )
        else:
            restore_volume = module.params["restore"]
        for volume in volumes:
            if volume == restore_volume:
                return volume
    except Exception:
        return None


def get_rpgsnapshot(module, array):
    """Return Replicated Snapshot or None"""
    api_version = array.get_rest_version()
    snapname = (
        module.params["name"]
        + "."
        + module.params["suffix"]
        + "."
        + module.params["restore"]
    )
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_volume_snapshots(
            names=[snapname], context_names=[module.params["context"]]
        )
    else:
        res = array.get_volume_snapshots(names=[snapname])
    if res.status_code == 200:
        return snapname
    return None


def get_pgsnapshot(module, array):
    """Return Snapshot (active or deleted) or None"""
    api_version = array.get_rest_version()
    snapname = module.params["name"] + "." + module.params["suffix"]
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_protection_group_snapshots(
            names=[snapname], context_names=[module.params["context"]]
        )
    else:
        res = array.get_protection_group_snapshots(names=[snapname])
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def create_pgsnapshot(module, array):
    """Create Protection Group Snapshot"""
    api_version = array.get_rest_version()
    snap_data = None
    changed = True
    if not module.check_mode:
        suffix = ProtectionGroupSnapshot(suffix=module.params["suffix"])
        if LooseVersion(THROTTLE_API) >= LooseVersion(api_version):
            if (
                list(array.get_protection_groups(names=[module.params["name"]]).items)[
                    0
                ].target_count
                > 0
            ):
                if module.params["now"]:
                    res = array.post_protection_group_snapshots(
                        source_names=[module.params["name"]],
                        apply_retention=module.params["apply_retention"],
                        replicate_now=True,
                        protection_group_snapshot=suffix,
                    )
                else:
                    res = array.post_protection_group_snapshots(
                        source_names=[module.params["name"]],
                        apply_retention=module.params["apply_retention"],
                        protection_group_snapshot=suffix,
                        replicate=module.params["remote"],
                    )
            else:
                res = array.post_protection_group_snapshots(
                    source_names=[module.params["name"]],
                    apply_retention=module.params["apply_retention"],
                    protection_group_snapshot=suffix,
                )
        else:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                remote_target = (
                    list(
                        array.get_protection_groups(
                            names=[module.params["name"]],
                            context_names=[module.params["context"]],
                        ).items
                    )[0].target_count
                    > 0
                )
            else:
                remote_target = (
                    list(
                        array.get_protection_groups(names=[module.params["name"]]).items
                    )[0].target_count
                    > 0
                )
            if remote_target:
                if module.params["now"]:
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        res = array.post_protection_group_snapshots(
                            source_names=[module.params["name"]],
                            apply_retention=module.params["apply_retention"],
                            replicate_now=True,
                            allow_throttle=module.params["throttle"],
                            protection_group_snapshot=suffix,
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = array.post_protection_group_snapshots(
                            source_names=[module.params["name"]],
                            apply_retention=module.params["apply_retention"],
                            replicate_now=True,
                            allow_throttle=module.params["throttle"],
                            protection_group_snapshot=suffix,
                        )
                else:
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        res = array.post_protection_group_snapshots(
                            source_names=[module.params["name"]],
                            apply_retention=module.params["apply_retention"],
                            allow_throttle=module.params["throttle"],
                            protection_group_snapshot=suffix,
                            replicate=module.params["remote"],
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = array.post_protection_group_snapshots(
                            source_names=[module.params["name"]],
                            apply_retention=module.params["apply_retention"],
                            allow_throttle=module.params["throttle"],
                            protection_group_snapshot=suffix,
                            replicate=module.params["remote"],
                        )
            else:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_protection_group_snapshots(
                        source_names=[module.params["name"]],
                        apply_retention=module.params["apply_retention"],
                        allow_throttle=module.params["throttle"],
                        protection_group_snapshot=suffix,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_protection_group_snapshots(
                        source_names=[module.params["name"]],
                        apply_retention=module.params["apply_retention"],
                        allow_throttle=module.params["throttle"],
                        protection_group_snapshot=suffix,
                    )

        if res.status_code != 200:
            module.fail_json(
                msg="Snapshot of pgroup {0} failed. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        else:
            snap_data = list(res.items)[0]
    module.exit_json(
        changed=changed,
        suffix=snap_data.suffix,
    )


def restore_pgsnapvolume(module, array):
    """Restore a Protection Group Snapshot Volume"""
    api_version = array.get_rest_version()
    changed = True
    if module.params["suffix"] == "latest":
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            latest_snapshot = list(
                array.get_protection_group_snapshots(
                    names=[module.params["name"]],
                    context_names=[module.params["context"]],
                ).items
            )[-1].suffix
        else:
            latest_snapshot = list(
                array.get_protection_group_snapshots(
                    names=[module.params["name"]]
                ).items
            )[-1].suffix
        module.params["suffix"] = latest_snapshot
    if ":" in module.params["name"] and "::" not in module.params["name"]:
        if get_rpgsnapshot(module, array) is None:
            module.fail_json(
                msg="Selected restore snapshot {0} does not exist in the Protection Group".format(
                    module.params["restore"]
                )
            )
    else:
        if get_pgroupvolume(module, array) is None:
            module.fail_json(
                msg="Selected restore volume {0} does not exist in the Protection Group".format(
                    module.params["restore"]
                )
            )
    source_volume = (
        module.params["name"]
        + "."
        + module.params["suffix"]
        + "."
        + module.params["restore"]
    )
    if "::" in module.params["target"]:
        target_pod_name = module.params["target"].split(":")[0]
        if "::" in module.params["name"]:
            source_pod_name = module.params["name"].split(":")[0]
        else:
            source_pod_name = ""
        if source_pod_name != target_pod_name:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                if (
                    list(
                        array.get_pods(
                            names=[target_pod_name],
                            context_names=[module.params["context"]],
                        ).items
                    )[0].array_count
                    > 1
                ):
                    module.fail_json(msg="Volume cannot be restored to a stretched pod")
            else:
                if (
                    list(array.get_pods(names=[target_pod_name]).items)[0].array_count
                    > 1
                ):
                    module.fail_json(msg="Volume cannot be restored to a stretched pod")
    if not module.check_mode:
        if LooseVersion(DEFAULT_API) <= LooseVersion(array.get_rest_version()):
            if module.params["add_to_pgs"]:
                add_to_pgs = []
                for add_pg in range(0, len(module.params["add_to_pgs"])):
                    add_to_pgs.append(
                        FixedReference(name=module.params["add_to_pgs"][add_pg])
                    )
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    res = array.post_volumes(
                        names=[module.params["target"]],
                        volume=VolumePost(source=Reference(name=source_volume)),
                        with_default_protection=module.params[
                            "with_default_protection"
                        ],
                        add_to_protection_groups=add_to_pgs,
                        context_names=[module.params["context"]],
                    )
                else:
                    res = array.post_volumes(
                        names=[module.params["target"]],
                        volume=VolumePost(source=Reference(name=source_volume)),
                        with_default_protection=module.params[
                            "with_default_protection"
                        ],
                        add_to_protection_groups=add_to_pgs,
                    )
            else:
                if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                    if module.params["overwrite"]:
                        res = array.post_volumes(
                            names=[module.params["target"]],
                            volume=VolumePost(source=Reference(name=source_volume)),
                            overwrite=module.params["overwrite"],
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = array.post_volumes(
                            names=[module.params["target"]],
                            volume=VolumePost(source=Reference(name=source_volume)),
                            overwrite=module.params["overwrite"],
                        )
                else:
                    if module.params["overwrite"]:
                        res = array.post_volumes(
                            names=[module.params["target"]],
                            volume=VolumePost(source=Reference(name=source_volume)),
                            overwrite=module.params["overwrite"],
                        )
                    else:
                        res = array.post_volumes(
                            names=[module.params["target"]],
                            volume=VolumePost(source=Reference(name=source_volume)),
                            with_default_protection=module.params[
                                "with_default_protection"
                            ],
                        )
        else:
            res = array.post_volumes(
                names=[module.params["target"]],
                overwrite=module.params["overwrite"],
                volume=VolumePost(source=Reference(name=source_volume)),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to restore {0} from pgroup {1}. Error: {2}".format(
                    module.params["restore"],
                    module.params["name"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def delete_offload_snapshot(module, array):
    """Delete Offloaded Protection Group Snapshot"""
    changed = False
    api_version = array.get_rest_version()
    snapname = module.params["name"] + "." + module.params["suffix"]
    if ":" in module.params["name"] and module.params["offload"]:
        if _check_offload(module, array):
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.get_remote_protection_group_snapshots(
                    names=[snapname],
                    on=module.params["offload"],
                    context_names=[module.params["context"]],
                )
            else:
                res = array.get_remote_protection_group_snapshots(
                    names=[snapname], on=module.params["offload"]
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Offload snapshot {0} does not exist on {1}".format(
                        snapname, module.params["offload"]
                    )
                )

            rpg_destroyed = list(res.items)[0].destroyed
            if not module.check_mode:
                if not rpg_destroyed:
                    changed = True
                    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                        res = array.patch_remote_protection_group_snapshots(
                            names=[snapname],
                            on=module.params["offload"],
                            remote_protection_group_snapshot=DestroyedPatchPost(
                                destroyed=True
                            ),
                            context_names=[module.params["context"]],
                        )
                    else:
                        res = array.patch_remote_protection_group_snapshots(
                            names=[snapname],
                            on=module.params["offload"],
                            remote_protection_group_snapshot=DestroyedPatchPost(
                                destroyed=True
                            ),
                        )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to delete offloaded snapshot {0} on target {1}. Error: {2}".format(
                                snapname,
                                module.params["offload"],
                                res.errors[0].message,
                            )
                        )
                    if module.params["eradicate"]:
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.delete_remote_protection_group_snapshots(
                                names=[snapname],
                                on=module.params["offload"],
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = array.delete_remote_protection_group_snapshots(
                                names=[snapname], on=module.params["offload"]
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to eradicate offloaded snapshot {0} on target {1}. Error: {2}".format(
                                    snapname,
                                    module.params["offload"],
                                    res.errors[0].message,
                                )
                            )
                else:
                    if module.params["eradicate"]:
                        changed = True
                        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(
                            api_version
                        ):
                            res = array.delete_remote_protection_group_snapshots(
                                names=[snapname],
                                on=module.params["offload"],
                                context_names=[module.params["context"]],
                            )
                        else:
                            res = array.delete_remote_protection_group_snapshots(
                                names=[snapname], on=module.params["offload"]
                            )
                        if res.status_code != 200:
                            module.fail_json(
                                msg="Failed to eradicate offloaded snapshot {0} on target {1}. Error: {2}".format(
                                    snapname,
                                    module.params["offload"],
                                    res.errors[0].message,
                                )
                            )
        else:
            module.fail_json(
                msg="Offload target {0} does not exist or not connected".format(
                    module.params["offload"]
                )
            )
    else:
        module.fail_json(msg="Protection Group name not in the correct format")

    module.exit_json(changed=changed)


def delete_pgsnapshot(module, array):
    """Delete Protection Group Snapshot"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_protection_group_snapshots(
                names=[snapname],
                protection_group_snapshot=ProtectionGroupSnapshotPatch(destroyed=True),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_protection_group_snapshots(
                names=[snapname],
                protection_group_snapshot=ProtectionGroupSnapshotPatch(destroyed=True),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete pgroup {0}. Error {1}".format(
                    snapname, res.errors[0].message
                )
            )
        if module.params["eradicate"]:
            if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
                res = array.delete_protection_group_snapshots(
                    names=[snapname], context_names=[module.params["context"]]
                )
            else:
                res = array.delete_protection_group_snapshots(names=[snapname])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete pgroup {0}. Error {1}".format(
                        snapname, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def eradicate_pgsnapshot(module, array):
    """Eradicate Protection Group Snapshot"""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.delete_protection_group_snapshots(
                names=[snapname], context_names=[module.params["context"]]
            )
        else:
            res = array.delete_protection_group_snapshots(names=[snapname])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete pgroup {0}. Error {1}".format(
                    snapname, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_pgsnapshot(module, array):
    """Update Protection Group Snapshot - basically just rename..."""
    changed = True
    api_version = array.get_rest_version()
    if not module.check_mode:
        current_name = module.params["name"] + "." + module.params["suffix"]
        new_name = module.params["name"] + "." + module.params["target"]
        if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
            res = array.patch_protection_group_snapshots(
                names=[current_name],
                protection_group_snapshot=ProtectionGroupSnapshotPatch(name=new_name),
                context_names=[module.params["context"]],
            )
        else:
            res = array.patch_protection_group_snapshots(
                names=[current_name],
                protection_group_snapshot=ProtectionGroupSnapshotPatch(name=new_name),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename {0} to {1}. Error: {2}".format(
                    current_name, new_name, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            suffix=dict(type="str"),
            restore=dict(type="str"),
            offload=dict(type="str"),
            throttle=dict(type="bool", default=False),
            overwrite=dict(type="bool", default=False),
            target=dict(type="str"),
            eradicate=dict(type="bool", default=False),
            now=dict(type="bool", default=False),
            apply_retention=dict(type="bool", default=False),
            remote=dict(type="bool", default=False),
            state=dict(
                type="str",
                default="present",
                choices=["absent", "present", "copy", "rename"],
            ),
            with_default_protection=dict(type="bool", default=True),
            add_to_pgs=dict(type="list", elements="str"),
            context=dict(type="str", default=""),
        )
    )

    required_if = [("state", "copy", ["suffix", "restore"])]
    mutually_exclusive = [
        ["now", "remote"],
    ]

    module = AnsibleModule(
        argument_spec,
        required_if=required_if,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )
    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is not installed")
    state = module.params["state"]
    pattern = re.compile("^(?=.*[a-zA-Z-])[a-zA-Z0-9]([a-zA-Z0-9-]{0,63}[a-zA-Z0-9])?$")
    if state == "present":
        if module.params["suffix"] is None:
            suffix = "snap-" + str(
                (datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds()
            )
            module.params["suffix"] = suffix.replace(".", "")
        else:
            if module.params["restore"]:
                pattern = re.compile(
                    "^[0-9]{0,63}$|^(?=.*[a-zA-Z-])[a-zA-Z0-9]([a-zA-Z0-9-]{0,63}[a-zA-Z0-9])?$"
                )
            if not pattern.match(module.params["suffix"]):
                module.fail_json(
                    msg="Suffix name {0} does not conform to suffix name rules".format(
                        module.params["suffix"]
                    )
                )

    if not module.params["target"] and module.params["restore"]:
        module.params["target"] = module.params["restore"]

    if state == "rename" and module.params["target"] is not None:
        if not pattern.match(module.params["target"]):
            module.fail_json(
                msg="Suffix target {0} does not conform to suffix name rules".format(
                    module.params["target"]
                )
            )
    array = get_array(module)
    pgroup = get_pgroup(module, array)
    if not pgroup:
        module.fail_json(
            msg="Protection Group {0} does not exist.".format(module.params["name"])
        )
    pgsnap = get_pgsnapshot(module, array)
    if pgsnap:
        pgsnap_deleted = pgsnap.destroyed
    if state != "absent" and module.params["offload"]:
        module.fail_json(
            msg="offload parameter not supported for state {0}".format(state)
        )
    elif state == "copy":
        if module.params["overwrite"] and (
            module.params["add_to_pgs"] or module.params["with_default_protection"]
        ):
            module.fail_json(
                msg="overwrite and add_to_pgs or with_default_protection are incompatable"
            )
        restore_pgsnapvolume(module, array)
    elif state == "present" and not pgsnap:
        create_pgsnapshot(module, array)
    elif state == "present" and pgsnap:
        module.exit_json(changed=False)
    elif (
        state == "absent" and module.params["offload"] and get_pgsnapshot(module, array)
    ):
        delete_offload_snapshot(module, array)
    elif state == "rename" and pgsnap:
        update_pgsnapshot(module, array)
    elif state == "absent" and pgsnap and not pgsnap_deleted:
        delete_pgsnapshot(module, array)
    elif state == "absent" and pgsnap and pgsnap_deleted and module.params["eradicate"]:
        eradicate_pgsnapshot(module, array)
    elif state == "absent" and not pgsnap:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
