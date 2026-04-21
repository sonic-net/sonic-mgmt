#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_snapshot
short_description: Manages snapshots on Hitachi VSP storage systems.
description:
  - This module allows for the creation, deletion, splitting, syncing, and restoring of snapshots on Hitachi VSP storage systems.
  - It supports various snapshot operations based on the specified task level.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/snapshot.yml)
version_added: '3.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_with_type
notes:
  - The input parameters C(consistency_group_id) and C(enable_quick_mode) were removed in version 3.4.0.
    These were deprecated due to internal API simplification and are no longer supported.
options:
  state:
    description: The level of the snapshot task. Choices are C(present), C(absent), C(split), C(sync), C(restore), C(clone), C(defragment).
    type: str
    required: false
    choices: ['present', 'absent', 'split', 'sync', 'restore', 'clone', 'defragment']
    default: 'present'
  storage_system_info:
    description: Information about the storage system. This field is an optional field.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false
  spec:
    description: Specification for the snapshot task.
    type: dict
    required: true
    suboptions:
      primary_volume_id:
        description: ID of the primary volume.
          Required for the Create a snapshot pair
          /Create snapshot pair with a new consistency group
          /Split a snapshot pair
          /Resync a snapshot pair
          /Create and auto-split a snapshot pair
          /Restore a snapshot pair
          /Create a snapshot pair using an existing consistency group
          /Delete a snapshot pair
          /Delete Thin Image pairs by snapshot tree
          /Clone snapshot pair/Thin Image pair
          /Create and clone snapshot pair
          /Create and clone snapshot pair with copy speed and clones automation
          /Create floating snapshot pair
          /Assign floating snapshot pair
          /Unassign floating snapshot pair
          /Create Thin Image Advanced snapshot pair
          /Set retention period of an existing snapshot pair
          /Set retention period of snapshot pair after split
          /Set retention period of snapshot pair with auto split
          /Deleting garbage data of all Thin Image pairs in a snapshot tree tasks.
        type: str
        required: true
      secondary_volume_id:
        description: Secondary volume id.
          Required for the Create floating snapshot pair
          /Assign floating snapshot pair
          /Unassign floating snapshot pair tasks.
          Optional for the Create Thin Image Advanced snapshot pair task.
        type: str
        required: false
      pool_id:
        description: ID of the pool where the snapshot will be allocated.
          Optional for the Create a snapshot pair
          /Create snapshot pair with a new consistency group
          /Create and auto-split a snapshot pair
          /Create a snapshot pair using an existing consistency group
          /Create and clone snapshot pair
          /Create Thin Image Advanced snapshot pair
          /Set retention period of snapshot pair with auto split tasks.
          Required for the Create and clone snapshot pair with copy speed and clones automation
          /Create floating snapshot pair tasks.
        type: int
        required: false
      snapshot_group_name:
        description: Name of the snapshot group.
          Required for the Create a snapshot pair
          /Create snapshot pair with a new consistency group
          /Create and auto-split a snapshot pair
          /Create a snapshot pair using an existing consistency group
          /Create and clone snapshot pair
          /Create and clone snapshot pair with copy speed and clones automation
          /Create floating snapshot pair
          /Create Thin Image Advanced snapshot pair
          /Set retention period of snapshot pair with auto split tasks.
        type: str
        required: false
      is_data_reduction_force_copy:
        description: Specify whether to forcibly create a pair for a volume for which the capacity saving function is enabled.
          Default is True when capacity savings is not C(disabled).
          Required for the Create a snapshot pair using an existing consistency group
          /Create Thin Image Advanced snapshot pair tasks.
        required: false
        type: bool
      is_clone:
        description: >
          Specify whether to create a pair that has the clone attribute specified.
          If you specify true for this attribute, do not specify the auto_split attribute.
          When creating a Thin Image Advanced pair, you cannot specify true.
          Required for the Create and clone snapshot pair
          /Create and clone snapshot pair with copy speed and clones automation task.
        required: false
        type: bool
      can_cascade:
        description: Specify whether the pair can be cascaded.
          Default is True when capacity savings is not C(disabled), Lun may not required to add to any host group when is it true.
          Required for the Create Thin Image Advanced snapshot pair task.
        required: false
        type: bool
      allocate_new_consistency_group:
        description: Specify whether to allocate a consistency group.
          Required for the Create snapshot pair with a new consistency group task.
        required: false
        type: bool
      mirror_unit_id:
        description: ID of the mirror unit.
          Required for the Split a snapshot pair
          /Resync a snapshot pair
          /Restore a snapshot pair
          /Delete a snapshot pair
          /Clone snapshot pair/Thin Image pair
          /Unassign floating snapshot pair
          /Set retention period of an existing snapshot pair
          /Set retention period of snapshot pair after split tasks.
          Optional for the Create floating snapshot pair
          /Assign floating snapshot pair tasks.
        required: false
        type: int
      auto_split:
        description: Specify whether to automatically split the pair.
        required: false
        type: bool
      retention_period:
        description: >
          Specify the retention period for the snapshot in hours. This can be set when the snapshot status is PSUS.
          This attribute can be used when the storage system is VSP One B20.
          You can specify this attribute only if the auto_split attribute is set to true for new pair.
          Required for the Set retention period of an existing snapshot pair
          /Set retention period of snapshot pair after split
          /Set retention period of snapshot pair with auto split tasks.
        required: false
        type: int
      copy_speed:
        description: >
          Specify the copy speed at which the created pair is to be cloned.
          You can specify this item when true is specified for both the is_clone attribute and the clones_automation attribute.
          Required for the Create and clone snapshot pair with copy speed and clones automation task.
        required: false
        type: str
        choices: ["SLOW", "MEDIUM", "FAST"]
      clones_automation:
        description: >
          Specify whether the pair is to be cloned after the pair is created.
          You can specify this item when true is specified for the is_clone attribute.
          Required for the Create and clone snapshot pair with copy speed and clones automation task.
        required: false
        type: bool
      should_delete_tree:
        description: >
          Specify whether to delete garbage data of all Thin Image pairs in a snapshot tree.
          Required for the Delete Thin Image pairs by snapshot tree task.
        required: false
        type: bool
      operation_type:
        description: >
          Specify the operation type for garbage data deletion.
          This can be set when the should_delete_tree attribute is set to true.
          Required for the Deleting garbage data of all Thin Image pairs in a snapshot tree task.
        required: false
        type: str
        choices: ["start", "stop"]
"""

EXAMPLES = """
- name: Create a snapshot
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: present
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      pool_id: 1
      snapshot_group_name: "snap_group"

- name: Create a thin image advance cascade
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: present
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      pool_id: 1
      snapshot_group_name: "snap_group"
      can_cascade: true
      is_data_reduction_force_copy: true

- name: Create a thin image clone pair
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: present
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      pool_id: 1
      snapshot_group_name: "snap_group"
      is_clone: true

- name: Clone a thin image clone pair
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: clone
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      mirror_unit: 3

- name: Delete a snapshot
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: absent
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      mirror_unit: 10

- name: Split a snapshot
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: split
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      mirror_unit: 10

- name: Resync a snapshot
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: resync
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      mirror_unit: 10

- name: Restore a snapshot
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: restore
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      mirror_unit: 3

- name: Set the retention period for a snapshot
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: split
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      mirror_unit: 3
      retention_period: 500

- name: Set the retention period for a snapshot with auto split.
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: split
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 123
      mirror_unit: 3
      retention_period: 500
      pool_id: 1
      snapshot_group_name: "snap_group"

- name: Create and clone snapshot pair with copy speed and clones automation
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 100
      pool_id: 5
      snapshot_group_name: "snapshot-group-name-1"
      is_clone: true
      copy_speed: "FAST"
      clones_automation: true

- name: Create floating snapshot pair
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 100
      secondary_volume_id: -1
      pool_id: 5
      snapshot_group_name: "snapshot-group-name-1"
      mirror_unit_id: 4

- name: Assign floating snapshot pair
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 100
      secondary_volume_id: 200
      mirror_unit_id: 1

- name: Unassign floating snapshot pair
  hitachivantara.vspone_block.vsp.hv_snapshot:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    spec:
      primary_volume_id: 100
      secondary_volume_id: -1
      mirror_unit_id: 1

- name: Deleting garbage data of all Thin Image pairs in a snapshot tree
  hitachivantara.vspone_block.vsp.hv_snapshot:
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    state: "defragment"
    spec:
      primary_volume_id: 100
      operation_type: "start"
"""

RETURN = """
snapshot_data:
  description: A list of snapshots gathered from the storage system.
  returned: always
  type: list
  elements: dict
  contains:
    can_cascade:
      description: Indicates if the snapshot can be cascaded.
      type: bool
      sample: true
    concordance_rate:
      description: Concordance rate of the snapshot operation.
      type: int
      sample: 100
    copy_pace_track_size:
      description: Copy pace track size.
      type: str
      sample: ""
    copy_rate:
      description: Copy rate of the snapshot.
      type: int
      sample: -1
    is_clone:
      description: Indicates if the snapshot is a clone.
      type: bool
      sample: false
    is_cloned:
      description: Indicates if the snapshot has been cloned.
      type: bool
      sample: false
    is_consistency_group:
      description: Indicates if the snapshot is part of a consistency group.
      type: bool
      sample: true
    is_data_reduction_force_copy:
      description: Indicates if data reduction force copy is enabled.
      type: bool
      sample: true
    is_redirect_on_write:
      description: Indicates if redirect-on-write is enabled.
      type: bool
      sample: true
    is_snapshot_data_read_only:
      description: Indicates if the snapshot data is read-only.
      type: bool
      sample: null
    is_written_in_svol:
      description: Indicates if data is written in the secondary volume.
      type: bool
      sample: false
    mirror_unit_id:
      description: ID of the mirror unit.
      type: int
      sample: 3
    pool_id:
      description: ID of the pool where the snapshot is allocated.
      type: int
      sample: 1
    primary_hex_volume_id:
      description: Hexadecimal ID of the primary volume.
      type: str
      sample: "00:00:A8"
    primary_volume_id:
      description: ID of the primary volume.
      type: int
      sample: 168
    progress_rate:
      description: Progress rate of the snapshot operation.
      type: int
      sample: -1
    pvol_host_groups:
      description: List of host groups for the primary volume.
      type: list
      elements: str
      sample: []
    pvol_nvm_subsystem_name:
      description: NVM subsystem name for the primary volume.
      type: str
      sample: ""
    pvol_processing_status:
      description: Processing status of the primary volume.
      type: str
      sample: "N"
    retention_period_in_hours:
      description: Retention period of the snapshot.
      type: int
      sample: -1
    secondary_hex_volume_id:
      description: Hexadecimal ID of the secondary volume.
      type: str
      sample: "00:00:CD"
    secondary_volume_id:
      description: ID of the secondary volume.
      type: int
      sample: 205
    snapshot_group_name:
      description: Name of the snapshot group.
      type: str
      sample: "snewar-tia-grp-02"
    snapshot_id:
      description: ID of the snapshot.
      type: str
      sample: "168,3"
    split_time:
      description: Time when the snapshot was split.
      type: str
      sample: ""
    status:
      description: Status of the snapshot.
      type: str
      sample: "PFUL"
    svol_host_groups:
      description: List of host groups for the secondary volume.
      type: list
      elements: str
      sample: []
    svol_nvm_subsystem_name:
      description: NVM subsystem name for the secondary volume.
      type: str
      sample: ""
    svol_processing_status:
      description: Processing status of the secondary volume.
      type: str
      sample: ""
    type:
      description: Type of the snapshot.
      type: str
      sample: "CASCADE"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    operation_constants,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPSnapshotArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_snapshot_reconciler import (
    VSPHtiSnapshotReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log_decorator import (
    LogDecorator,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


@LogDecorator.debug_methods
class VSPHtiSnapshotManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPSnapshotArguments().get_snapshot_reconcile_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:

            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = self.params_manager.storage_system_info.serial
            self.spec = self.params_manager.get_snapshot_reconcile_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Snapshot operation ===")
        snapshot_data = None
        registration_message = validate_ansible_product_registration()

        try:

            snapshot_data = self.reconcile_snapshot()
            operation = operation_constants(self.module.params["state"])
            msg = ""
            if operation == "defragmented" and self.spec.operation_type == "start":
                msg = "Started deleting garbage data of all Thin Image pairs in a snapshot tree"
            elif operation == "defragmented" and self.spec.operation_type == "stop":
                msg = "Stopped deleting garbage data of all Thin Image pairs in a snapshot tree"
            else:
                msg = (
                    f"Snapshot {operation} successfully"
                    if not isinstance(snapshot_data, str)
                    else snapshot_data
                )
            resp = {
                "changed": self.connection_info.changed,
                "snapshot_data": (
                    snapshot_data if isinstance(snapshot_data, dict) else ""
                ),
                "msg": msg,
            }

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Snapshot operation ===")
            self.module.fail_json(msg=str(e))

        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Snapshot operation ===")
        self.module.exit_json(**resp)

    def reconcile_snapshot(self):
        reconciler = VSPHtiSnapshotReconciler(
            self.connection_info,
            self.storage_serial_number,
        )
        result = reconciler.reconcile_snapshot(self.spec)
        return result


def main():
    obj_store = VSPHtiSnapshotManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
