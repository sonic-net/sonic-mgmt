#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,too-many-branches,too-many-locals,line-too-long,wrong-import-position

"""This module manages file systems on Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: infini_fs
version_added: 2.3.0
short_description: Create, Delete or Modify filesystems on Infinibox
description:
    - This module creates, deletes or modifies filesystems on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  fs_type:
    description:
      - Specifies the file system type, regular or snapshot.
    type: str
    required: false
    default: master
    choices: [ "master", "snapshot" ]
  name:
    description:
      - File system name.
    required: false
    type: str
  parent_fs_name:
    description:
      - Specify a fs name. This is the fs parent for creating a snapshot. Required if fs_type is snapshot.
    type: str
    required: false
  pool:
    description:
      - Pool that will host file system.
    required: true
    type: str
  restore_fs_from_snapshot:
    description:
      - Specify true to restore a file system (parent_fs_name) from an existing snapshot specified by the name field.
      - State must be set to present and fs_type must be 'snapshot'.
    type: bool
    required: false
    default: false
  serial:
    description:
      - Serial number matching an existing file system.
    required: false
    type: str
  size:
    description:
      - File system size in MB, GB or TB units. See examples.
    required: false
    type: str
  snapshot_lock_expires_at:
    description:
      - This will cause a snapshot to be locked at the specified date-time.
        Uses python's datetime format YYYY-mm-dd HH:MM:SS.ffffff, e.g. 2020-02-13 16:21:59.699700
    type: str
    required: false
  snapshot_lock_only:
    description:
      - This will lock an existing snapshot but will suppress refreshing the snapshot.
    type: bool
    required: false
    default: false
  state:
    description:
      - Creates/Modifies file system when present or removes when absent.
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
    type: str
  thin_provision:
    description:
      - Whether the master file system should be thin or thick provisioned.
    required: false
    default: true
    type: bool
  write_protected:
    description:
      - Specifies if the file system should be write protected. Default will be True for snapshots, False for master file systems.
    type: str
    required: false
    default: "Default"
    choices: ["Default", "True", "False"]
extends_documentation_fragment:
    - infinibox
requirements:
    - capacity
"""

EXAMPLES = r"""
- name: Create new file system named foo under pool named bar
  infini_fs:
    name: foo
    size: 1GB
    pool: bar
    thin_provision: true
    state: present
    user: admin
    password: secret
    system: ibox001
- name: Create snapshot named foo_snap from fs named foo
  infini_fs:
    name: foo_snap
    pool: bar
    fs_type: snapshot
    parent_fs_name: foo
    state: present
    user: admin
    password: secret
    system: ibox001
- name: Stat snapshot, also a fs, named foo_snap
  infini_fs:
    name: foo_snap
    pool: bar
    state: present
    user: admin
    password: secret
    system: ibox001
- name: Remove snapshot, also a fs, named foo_snap
  infini_fs:
    name: foo_snap
    state: absent
    user: admin
    password: secret
    system: ibox001
"""

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

HAS_INFINISDK = True
try:
    from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
        api_wrapper,
        check_snapshot_lock_options,
        get_filesystem,
        get_fs_by_sn,
        get_pool,
        get_system,
        infinibox_argument_spec,
        manage_snapshot_locks,
    )
except ModuleNotFoundError:
    from infinibox import (  # Used when hacking
        api_wrapper,
        check_snapshot_lock_options,
        get_filesystem,
        get_pool,
        get_system,
        infinibox_argument_spec,
        manage_snapshot_locks,
    )
except ImportError:
    HAS_INFINISDK = False

try:
    from infinisdk.core.exceptions import APICommandFailed
    from infinisdk.core.exceptions import ObjectNotFound
except ImportError:
    HAS_INFINISDK = False

CAPACITY_IMP_ERR = None
try:
    from capacity import KiB, Capacity

    HAS_CAPACITY = True
except ImportError:
    HAS_CAPACITY = False


@api_wrapper
def create_filesystem(module, system):
    """ Create Filesystem """
    changed = False
    if not module.check_mode:
        if module.params["thin_provision"]:
            provisioning = "THIN"
        else:
            provisioning = "THICK"

        filesystem = system.filesystems.create(
            name=module.params["name"],
            provtype=provisioning,
            pool=get_pool(module, system),
        )

        if module.params["size"]:
            size = Capacity(module.params["size"]).roundup(64 * KiB)
            filesystem.update_size(size)

        is_write_prot = filesystem.is_write_protected()
        desired_is_write_prot = module.params["write_protected"]
        if is_write_prot != desired_is_write_prot:
            filesystem.update_field("write_protected", desired_is_write_prot)
        changed = True
    return changed


@api_wrapper
def update_filesystem(module, filesystem):
    """ Update Filesystem """
    changed = False

    if module.check_mode:
        return changed

    if module.params["size"]:
        size = Capacity(module.params["size"]).roundup(64 * KiB)
        if filesystem.get_size() != size:
            filesystem.update_size(size)
            changed = True

    if module.params["thin_provision"] is not None:
        provisioning = str(filesystem.get_provisioning())
        if provisioning == "THICK" and module.params["thin_provision"]:
            filesystem.update_provisioning("THIN")
            changed = True
        if provisioning == "THIN" and not module.params["thin_provision"]:
            filesystem.update_provisioning("THICK")
            changed = True

    is_write_prot = filesystem.is_write_protected()
    desired_is_write_prot = module.params["write_protected"]
    if is_write_prot != desired_is_write_prot:
        filesystem.update_field("write_protected", desired_is_write_prot)
        changed = True

    return changed


@api_wrapper
def delete_filesystem(module, filesystem):
    """ Delete Filesystem """
    changed = False
    if not module.check_mode:
        filesystem.delete()
        changed = True
    return changed


@api_wrapper
def create_fs_snapshot(module, system):
    """ Create Snapshot from parent fs """
    snapshot_name = module.params["name"]
    parent_fs_name = module.params["parent_fs_name"]
    changed = False
    if not module.check_mode:
        try:
            parent_fs = system.filesystems.get(name=parent_fs_name)
        except ObjectNotFound:
            msg = f"Cannot create snapshot {snapshot_name}. Parent file system {parent_fs_name} not found"
            module.fail_json(msg=msg)
        if not parent_fs:
            msg = f"Cannot find new snapshot's parent file system named {parent_fs_name}"
            module.fail_json(msg=msg)
        if not module.check_mode:
            if module.params["snapshot_lock_only"]:
                msg = "Snapshot does not exist. Cannot comply with 'snapshot_lock_only: true'."
                module.fail_json(msg=msg)
            check_snapshot_lock_options(module)
            snapshot = parent_fs.create_snapshot(name=snapshot_name)

            is_write_prot = snapshot.is_write_protected()
            desired_is_write_prot = module.params["write_protected"]
            if is_write_prot != desired_is_write_prot:
                snapshot.update_field("write_protected", desired_is_write_prot)

        manage_snapshot_locks(module, snapshot)
        changed = True
    return changed


@api_wrapper
def update_fs_snapshot(module, snapshot):
    """ Update/refresh fs snapshot. May also lock it. """
    refresh_changed = False
    lock_changed = False
    if not module.check_mode:
        if not module.params["snapshot_lock_only"]:
            snap_is_locked = snapshot.get_lock_state() == "LOCKED"
            if not snap_is_locked:
                if not module.check_mode:
                    snapshot.refresh_snapshot()
                refresh_changed = True
            else:
                msg = "File system snapshot is locked and may not be refreshed"
                module.fail_json(msg=msg)

        check_snapshot_lock_options(module)
        lock_changed = manage_snapshot_locks(module, snapshot)

        if module.params["write_protected"] is not None:
            is_write_prot = snapshot.is_write_protected()
            desired_is_write_prot = module.params["write_protected"]
            if is_write_prot != desired_is_write_prot:
                snapshot.update_field("write_protected", desired_is_write_prot)

    return refresh_changed or lock_changed


@api_wrapper
def find_fs_id(module, system, fs_name):
    """ Find the ID of this fs """
    fs_url = f"filesystems?name={fs_name}&fields=id"
    fs = system.api.get(path=fs_url)

    result = fs.get_json()["result"]
    if len(result) != 1:
        module.fail_json(f"Cannot find a file ststem with name '{fs_name}'")

    fs_id = result[0]["id"]
    return fs_id


@api_wrapper
def restore_fs_from_snapshot(module, system):
    """ Use snapshot to restore a file system """
    changed = False
    is_restoring = module.params["restore_fs_from_snapshot"]
    fs_type = module.params["fs_type"]
    snap_name = module.params["name"]
    snap_id = find_fs_id(module, system, snap_name)
    parent_fs_name = module.params["parent_fs_name"]
    parent_fs_id = find_fs_id(module, system, parent_fs_name)

    # Check params
    if not is_restoring:
        raise AssertionError("A programming error occurred. is_restoring is not True")
    if fs_type != "snapshot":
        module.exit_json(msg="Cannot restore a parent file system from snapshot unless the file system type is 'snapshot'")
    if not parent_fs_name:
        module.exit_json(msg="Cannot restore a parent file system from snapshot unless the parent file system name is specified")

    if not module.check_mode:
        restore_url = f"filesystems/{parent_fs_id}/restore?approved=true"
        restore_data = {
            "source_id": snap_id,
        }
        try:
            system.api.post(path=restore_url, data=restore_data)
            changed = True
        except APICommandFailed as err:
            module.fail_json(msg=f"Cannot restore file system {parent_fs_name} from snapshot {snap_name}: {str(err)}")
    return changed


def handle_stat(module):
    """ Handle the stat state """
    system = get_system(module)
    pool = get_pool(module, system)
    if module.params["name"]:
        filesystem = get_filesystem(module, system)
    else:
        filesystem = get_fs_by_sn(module, system)
    fs_type = module.params["fs_type"]

    if fs_type == "master":
        if not pool:
            module.fail_json(msg=f"Pool {module.params['pool']} not found")
    if not filesystem:
        module.fail_json(msg=f"File system {module.params['name']} not found")
    fields = filesystem.get_fields()  # from_cache=True, raw_value=True)

    created_at = str(fields.get("created_at", None))
    filesystem_id = fields.get("id", None)
    filesystem_type = fields.get("type", None)
    has_children = fields.get("has_children", None)
    lock_expires_at = str(filesystem.get_lock_expires_at())
    lock_state = filesystem.get_lock_state()
    mapped = str(fields.get("mapped", None))
    name = fields.get("name", None)
    parent_id = fields.get("parent_id", None)
    provisioning = fields.get("provisioning", None)
    serial = fields.get("serial", None)
    size = str(filesystem.get_size())
    updated_at = str(fields.get("updated_at", None))
    used = str(fields.get("used_size", None))
    write_protected = fields.get("write_protected", None)
    if filesystem_type == "SNAPSHOT":
        msg = "File system snapshot stat found"
    else:
        msg = "File system stat found"

    result = dict(
        changed=False,
        created_at=created_at,
        filesystem_id=filesystem_id,
        filesystem_type=filesystem_type,
        has_children=has_children,
        lock_state=lock_state,
        lock_expires_at=lock_expires_at,
        mapped=mapped,
        msg=msg,
        name=name,
        parent_id=parent_id,
        provisioning=provisioning,
        serial=serial,
        size=size,
        updated_at=updated_at,
        used=used,
        write_protected=write_protected,
    )
    module.exit_json(**result)


def handle_present(module):
    """ Handle the present state """
    system = get_system(module)
    pool = get_pool(module, system)
    if module.params["name"]:
        filesystem = get_filesystem(module, system)
    else:
        filesystem = get_fs_by_sn(module, system)
    fs_type = module.params["fs_type"]
    is_restoring = module.params["restore_fs_from_snapshot"]
    if fs_type == "master":
        if not pool:
            module.fail_json(msg=f"Pool {module.params['pool']} not found")
        if not filesystem:
            changed = create_filesystem(module, system)
            module.exit_json(changed=changed, msg="File system created")
        else:
            changed = update_filesystem(module, filesystem)
            module.exit_json(changed=changed, msg="File system updated")
    elif fs_type == "snapshot":
        snapshot = filesystem
        if is_restoring:
            # Restore fs from snapshot
            changed = restore_fs_from_snapshot(module, system)
            snap_fs_name = module.params["name"]
            parent_fs_name = module.params["parent_fs_name"]
            msg = f"File system {parent_fs_name} restored from snapshot {snap_fs_name}"
            module.exit_json(changed=changed, msg=msg)
        else:
            if not snapshot:
                changed = create_fs_snapshot(module, system)
                module.exit_json(changed=changed, msg="File system snapshot created")
            else:
                changed = update_fs_snapshot(module, filesystem)
                module.exit_json(changed=changed, msg="File system snapshot updated")


def handle_absent(module):
    """ Handle the absent state """
    system = get_system(module)
    pool = get_pool(module, system)
    if module.params["name"]:
        filesystem = get_filesystem(module, system)
    else:
        filesystem = get_fs_by_sn(module, system)

    if filesystem and filesystem.get_lock_state() == "LOCKED":
        msg = "Cannot delete snapshot. Locked."
        module.fail_json(changed=False, msg=msg)

    if not pool or not filesystem:
        module.exit_json(changed=False, msg="File system already absent")

    existing_fs_type = filesystem.get_type()

    if existing_fs_type == "MASTER":
        changed = delete_filesystem(module, filesystem)
        module.exit_json(changed=changed, msg="File system removed")
    elif existing_fs_type == "SNAPSHOT":
        snapshot = filesystem
        changed = delete_filesystem(module, snapshot)
        module.exit_json(changed=changed, msg="Snapshot removed")
    else:
        module.fail_json(msg="A programming error has occured")


def execute_state(module):
    """ Execute states """
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        elif state == "absent":
            handle_absent(module)
        else:
            module.fail_json(msg=f"Internal handler error. Invalid state: {state}")
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    """Verify module options are sane"""
    name = module.params["name"]
    serial = module.params["serial"]
    state = module.params["state"]
    size = module.params["size"]
    pool = module.params["pool"]
    fs_type = module.params["fs_type"]
    parent_fs_name = module.params["parent_fs_name"]

    if state == "stat":
        if not name and not serial:
            msg = "Name or serial parameter must be provided"
            module.fail_json(msg=msg)
    if state in ["present", "absent"]:
        if not name:
            msg = "Name parameter must be provided"
            module.fail_json(msg=msg)

    if state == "present":
        if fs_type == "master":
            if parent_fs_name:
                msg = "parent_fs_name should not be specified "
                msg += "if fs_type is 'master'. Used for snapshots only."
                module.fail_json(msg=msg)
            if not size:
                msg = "Size is required to create a master file system"
                module.fail_json(msg=msg)
            if not pool:
                msg = "For state 'present', pool is required"
                module.fail_json(msg=msg)
        elif fs_type == "snapshot":
            if size:
                msg = "Size should not be specified "
                msg += "for fs_type snapshot"
                module.fail_json(msg=msg)
            if not parent_fs_name:
                msg = "For state 'present' and fs_type 'snapshot', "
                msg += "parent_fs_name is required"
                module.fail_json(msg=msg)
        else:
            msg = "A programming error has occurred"
            module.fail_json(msg=msg)


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            fs_type=dict(choices=["master", "snapshot"], default="master"),
            name=dict(required=False, default=None),
            parent_fs_name=dict(default=None, required=False),
            pool=dict(required=True),
            restore_fs_from_snapshot=dict(default=False, type="bool"),
            serial=dict(required=False, default=None),
            size=dict(),
            snapshot_lock_expires_at=dict(),
            snapshot_lock_only=dict(required=False, type="bool", default=False),
            state=dict(default="present", choices=["stat", "present", "absent"]),
            thin_provision=dict(default=True, type="bool"),
            write_protected=dict(choices=["True", "False", "Default"], default="Default"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if module.params["write_protected"] == "Default":
        if module.params["fs_type"] == "master":  # Use default for master fs
            module.params["write_protected"] = False
        else:  # Use default for snapshot
            module.params["write_protected"] = True
    else:
        module.params["write_protected"] = module.params["write_protected"] == "True"

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    if not HAS_CAPACITY:
        module.fail_json(msg=missing_required_lib("capacity"))

    if module.params["size"]:
        try:
            Capacity(module.params["size"])
        except Exception:  # pylint: disable=broad-exception-caught
            module.fail_json(
                msg="size (Physical Capacity) should be defined in MB, GB, TB or PB units"
            )

    check_options(module)
    execute_state(module)


if __name__ == "__main__":
    main()
