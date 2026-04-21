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
module: purefb_snap
version_added: '1.0.0'
short_description: Manage filesystem snapshots on Pure Storage FlashBlades
description:
- Create or delete volumes and filesystem snapshots on Pure Storage FlashBlades.
- Restoring a filesystem from a snapshot is only supported using
  the latest snapshot.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the source filesystem.
    required: true
    type: str
  suffix:
    description:
    - Suffix of snapshot name.
    type: str
  state:
    description:
    - Define whether the filesystem snapshot should exist or not.
    choices: [ absent, present, restore ]
    default: present
    type: str
  target:
    aliases: [ targets ]
    description:
    - Name of target to replicate snapshot to.
    - This is only applicable when I(now) is B(true)
    type: str
    version_added: "1.7.0"
  now:
    description:
    - Whether to initiate a snapshot replication immeadiately
    type: bool
    default: false
    version_added: "1.7.0"
  eradicate:
    description:
    - Define whether to eradicate the snapshot on delete or leave in trash.
    type: bool
    default: false
  latest_replica:
    description:
    - Used when destroying a snapshot.
    - If false, and the snapshot is the
      latest replicated snapshot, then destroy will fail.
    - If true or the snapshot is not the latest replicated snapshot,
      then destroy will be successful.
    type: bool
    default: false
    version_added: "1.21.0"
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
- name: Create snapshot foo.ansible
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: ansible
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Create immeadiate snapshot foo.ansible to connected FB bar
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: ansible
    now: true
    target: bar
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Delete snapshot named foo.snap
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: snap
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Recover deleted snapshot foo.ansible
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: ansible
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Restore filesystem foo (uses latest snapshot)
  purestorage.flashblade.purefb_snap:
    name: foo
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: restore

- name: Eradicate snapshot named foo.snap
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: snap
    eradicate: true
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)

from datetime import datetime

HAS_PYPURECLIENT = True
try:
    from pypureclient.flashblade import (
        FileSystemSnapshotPost,
        FileSystemSnapshot,
        FileSystemPost,
        Reference,
    )
except ImportError:
    HAS_PYPURECLIENT = False

SNAP_NOW_API = "2.10"
CONTEXT_API_VERSION = "2.17"


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


def get_latest_fssnapshot(module, blade):
    """Get the name of the latest snpshot or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_file_system_snapshots(
            names_or_owner_names=[module.params["name"]],
            context_names=[module.params["context"]],
        )
    else:
        res = blade.get_file_system_snapshots(
            names_or_owner_names=[module.params["name"]]
        )
    if res.status_code != 200:
        module.fail_json(
            msg="Failed to get filesystem snapshots. Error: {0}".format(
                res.errors[0].message
            )
        )
    all_snaps = list(res.items)
    last_snap = sorted(all_snaps, key=lambda x: x["created"])[-1]
    if not last_snap.destroyed:
        return last_snap.name
    module.fail_json(
        msg="Latest snapshot {0} is destroyed."
        " Eradicate or recover this first.".format(all_snaps[0].name)
    )
    return None


def get_fssnapshot(module, blade):
    """Return Snapshot or None"""
    api_version = list(blade.get_versions().items)
    if CONTEXT_API_VERSION in api_version:
        res = blade.get_file_system_snapshots(
            names_or_owner_names=[
                module.params["name"] + "." + module.params["suffix"]
            ],
            context_names=[module.params["context"]],
        )
    else:
        res = blade.get_file_system_snapshots(
            names_or_owner_names=[
                module.params["name"] + "." + module.params["suffix"]
            ],
        )
    if res.status_code == 200:
        return list(res.items)[0]
    return None


def create_snapshot(module, blade):
    """Create Snapshot"""
    api_version = list(blade.get_versions().items)
    changed = False
    # Special case as we have changed 'target' to be a string not a list of one string
    # so this provides backwards compatability
    # target = module.params["target"].replace("[", "").replace("'", "").replace("]", "")
    blade_exists = False
    if CONTEXT_API_VERSION in api_version:
        connected_blades = list(
            blade.get_array_connections(context_names=[module.params["context"]]).items
        )
    else:
        connected_blades = list(blade.get_array_connections().items)
    for rem_blade in range(len(connected_blades)):
        if (
            module.params["target"]
            and module.params["target"] == connected_blades[rem_blade].remote.name
            and connected_blades[rem_blade].status == "connected"
        ):
            blade_exists = True
            break
    if not module.params["target"] and blade_exists:
        module.fail_json(msg="Selected target is not a correctly connected system")
    changed = True
    if not module.check_mode:
        if module.params["target"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_file_system_snapshots(
                    source_names=[module.params["name"]],
                    send=module.params["now"],
                    targets=[module.params["target"]],
                    file_system_snapshot=FileSystemSnapshotPost(
                        suffix=module.params["suffix"]
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_file_system_snapshots(
                    source_names=[module.params["name"]],
                    send=module.params["now"],
                    targets=[module.params["target"]],
                    file_system_snapshot=FileSystemSnapshotPost(
                        suffix=module.params["suffix"]
                    ),
                )
        else:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_file_system_snapshots(
                    source_names=[module.params["name"]],
                    file_system_snapshot=FileSystemSnapshotPost(
                        suffix=module.params["suffix"]
                    ),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_file_system_snapshots(
                    source_names=[module.params["name"]],
                    file_system_snapshot=FileSystemSnapshotPost(
                        suffix=module.params["suffix"]
                    ),
                )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to create remote snapshot. Error: {0}".format(
                    res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def restore_snapshot(module, blade):
    """Restore a filesystem back from the latest snapshot"""
    changed = True
    api_version = list(blade.get_versions().items)
    snapname = get_latest_fssnapshot(module, blade)
    if snapname is not None:
        if not module.check_mode:
            if CONTEXT_API_VERSION in api_version:
                res = blade.post_file_systems(
                    names=[module.params["name"]],
                    overwrite=True,
                    discard_non_snapshotted_data=True,
                    file_system=FileSystemPost(source=Reference(name=snapname)),
                    context_names=[module.params["context"]],
                )
            else:
                res = blade.post_file_systems(
                    names=[module.params["name"]],
                    overwrite=True,
                    discard_non_snapshotted_data=True,
                    file_system=FileSystemPost(source=Reference(name=snapname)),
                )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to restore snapshot {0} to filesystem {1}. Error: {2}".format(
                        snapname, module.params["name"], res.errors[0].message
                    )
                )
    else:
        module.fail_json(
            msg="Filesystem {0} has no snapshots to restore from.".format(
                module.params["name"]
            )
        )
    module.exit_json(changed=changed)


def recover_snapshot(module, blade):
    """Recover deleted Snapshot"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        if CONTEXT_API_VERSION in api_version:
            res = blade.patch_file_system_snapshots(
                names=[snapname],
                file_system_snapshot=FileSystemSnapshot(destroyed=False),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_file_system_snapshots(
                names=[snapname],
                file_system_snapshot=FileSystemSnapshot(destroyed=False),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to recover snapshot {0} for filesystem {1}. Error: {2}".format(
                    snapname, module.params["name"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def update_snapshot(module, blade):
    """Update Snapshot"""
    changed = False
    module.exit_json(changed=changed)


def delete_snapshot(module, blade):
    """Delete Snapshot"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        if CONTEXT_API_VERSION in api_version:
            res = blade.patch_file_system_snapshots(
                names=[snapname],
                latest_replica=module.params["latest_replica"],
                file_system_snapshot=FileSystemSnapshot(destroyed=True),
                context_names=[module.params["context"]],
            )
        else:
            res = blade.patch_file_system_snapshots(
                names=[snapname],
                latest_replica=module.params["latest_replica"],
                file_system_snapshot=FileSystemSnapshot(destroyed=True),
            )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to delete snapshot {0}. Error: {1}".format(
                    snapname, res.errors[0].message
                )
            )
        if module.params["eradicate"]:
            if CONTEXT_API_VERSION in api_version:
                res = blade.delete_file_system_snapshots(
                    names=[snapname], context_names=[module.params["context"]]
                )
            else:
                res = blade.delete_file_system_snapshots(names=[snapname])
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to eradicate snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def eradicate_snapshot(module, blade):
    """Eradicate Snapshot"""
    changed = True
    api_version = list(blade.get_versions().items)
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        if CONTEXT_API_VERSION in api_version:
            res = blade.delete_file_system_snapshots(
                names=[snapname], context_names=[module.params["context"]]
            )
        else:
            res = blade.delete_file_system_snapshots(names=[snapname])
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to eradicate snapshot {0}. Error: {1}".format(
                    snapname, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            suffix=dict(type="str"),
            now=dict(type="bool", default=False),
            target=dict(type="str", aliases=["targets"]),
            eradicate=dict(default="false", type="bool"),
            state=dict(default="present", choices=["present", "absent", "restore"]),
            latest_replica=dict(default="false", type="bool"),
            context=dict(type="str", default=""),
        )
    )

    required_if = [["now", True, ["target"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PYPURECLIENT:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    if module.params["suffix"] is None:
        suffix = "snap-" + str(
            (datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds()
        )
        module.params["suffix"] = suffix.replace(".", "")

    state = module.params["state"]
    blade = get_system(module)
    api_version = list(blade.get_versions().items)

    if SNAP_NOW_API not in api_version and module.params["now"]:
        module.fail_json(
            msg="Minimum FlashBlade REST version for immeadiate remote snapshots: {0}".format(
                SNAP_NOW_API
            )
        )
    filesystem = get_fs(module, blade)
    snap = get_fssnapshot(module, blade)
    if state == "present" and filesystem and not filesystem.destroyed and not snap:
        create_snapshot(module, blade)
    elif (
        state == "present"
        and filesystem
        and not filesystem.destroyed
        and snap
        and not snap.destroyed
    ):
        update_snapshot(module, blade)
    elif (
        state == "present"
        and filesystem
        and not filesystem.destroyed
        and snap
        and snap.destroyed
    ):
        recover_snapshot(module, blade)
    elif state == "present" and filesystem and filesystem.destroyed:
        update_snapshot(module, blade)
    elif state == "present" and not filesystem:
        update_snapshot(module, blade)
    elif state == "restore" and filesystem:
        restore_snapshot(module, blade)
    elif state == "absent" and snap and not snap.destroyed:
        delete_snapshot(module, blade)
    elif state == "absent" and snap and snap.destroyed:
        eradicate_snapshot(module, blade)
    elif state == "absent" and not snap:
        module.exit_json(changed=False)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
