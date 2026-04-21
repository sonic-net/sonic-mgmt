#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_snapshot_group
short_description: Manages snapshots in units of snapshot groups on Hitachi VSP storage systems.
description:
  - This module allows for the deletion, splitting, syncing, and restoring of snapshots on Hitachi VSP storage systems.
  - It supports various snapshot operations based on the specified task level.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/snapshot_group.yml)
version_added: '3.2.0'
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
options:
  state:
    description: The level of the snapshot task. Choices are C(absent), C(split), C(sync), C(restore), C(clone), C(defragment).
    type: str
    required: true
    choices: ['split', 'sync', 'restore', 'clone', 'absent', 'defragment']
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
    description: Specification for the snapshot group tasks.
    type: dict
    required: true
    suboptions:
      snapshot_group_name:
        description: The name of the snapshot group.
          Required for the Split the snapshot pairs using group name
          /Restore the snapshot pairs using group name
          /Restore the snapshot pairs using group name and auto split
          /Resync the snapshot pairs using group name
          /Delete the snapshot pairs using group name
          /Set retention period of snapshots using group name
          /Clone the snapshot pairs using group name tasks.
        type: str
        required: true
      auto_split:
        description: Automatically split the snapshot group.
          Required for the Restore the snapshot pairs using group name and auto split task.
        type: bool
        required: false
      retention_period:
        description: Specify the retention period for the snapshot in hours.This can be set when the snapshot status is PSUS.
          Required for the Set retention period of snapshots using group name task.
        type: int
        required: false
      copy_speed:
        description: The speed of the copy operation.
          Optional for the Clone the snapshot pairs using group name task.
        type: str
        required: false
        choices: ['SLOW', 'MEDIUM', 'FAST']
"""

EXAMPLES = """
- name: Split snapshots using snapshot group name
  hitachivantara.vspone_block.vsp.hv_snapshot_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: split
    spec:
      snapshot_group_name: 'NewNameSPG'

- name: Split and set the retention period of the snapshot using group id
  hitachivantara.vspone_block.vsp.hv_snapshot_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: split
    spec:
      snapshot_group_name: 'NewNameSPG'
      retention_period: 60

- name: Restore snapshots using snapshot group name
  hitachivantara.vspone_block.vsp.hv_snapshot_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: restore
    spec:
      snapshot_group_name: 'NewNameSPG'

- name: Resync snapshots using snapshot group name
  hitachivantara.vspone_block.vsp.hv_snapshot_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: sync
    spec:
      snapshot_group_name: 'NewNameSPG'

- name: Delete snapshots using snapshot group name
  hitachivantara.vspone_block.vsp.hv_snapshot_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: absent
    spec:
      snapshot_group_name: 'NewNameSPG'

- name: Clone snapshots using snapshot group name
  hitachivantara.vspone_block.vsp.hv_snapshot_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: clone
    spec:
      snapshot_group_name: 'NewNameSPG'
      copy_speed: 'SLOW'
"""

RETURN = """
snapshot_data:
  description: >
    A list of snapshots gathered from the storage system.
  returned: always
  type: list
  elements: dict
  contains:
    snapshot_group_id:
      description: Unique identifier for the snapshot group.
      type: str
      sample: "SampleNameSPG"
    snapshot_group_name:
      description: Name of the snapshot group.
      type: str
      sample: "SampleNameSPG"
    snapshots:
      description: List of snapshots within the group.
      type: list
      elements: dict
      contains:
        can_cascade:
          description: Indicates if the snapshot can cascade.
          type: bool
          sample: true
        concordance_rate:
          description: Concordance rate for the snapshot.
          type: int
          sample: -1
        copy_pace_track_size:
          description: Track size for the copy pace.
          type: str
          sample: ""
        copy_rate:
          description: Copy rate for the snapshot.
          type: int
          sample: -1
        is_clone:
          description: Indicates if the snapshot is a clone.
          type: bool
          sample: false
        is_consistency_group:
          description: Indicates if the snapshot is part of a consistency group.
          type: bool
          sample: false
        is_redirect_on_write:
          description: Indicates if redirect-on-write is enabled.
          type: bool
          sample: true
        is_snapshot_data_read_only:
          description: Indicates if the snapshot data is read-only.
          type: bool
          sample: null
        is_written_in_svol:
          description: Indicates if data is written in secondary volume.
          type: bool
          sample: false
        mirror_unit_id:
          description: Identifier for the mirror unit.
          type: int
          sample: 3
        pool_id:
          description: Identifier for the pool.
          type: int
          sample: 22
        primary_hex_volume_id:
          description: Hexadecimal identifier for the primary volume.
          type: str
          sample: "00:03:4A"
        primary_volume_id:
          description: Identifier for the primary volume.
          type: int
          sample: 842
        progress_rate:
          description: Progress rate for the snapshot.
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
          description: Processing status for the primary volume.
          type: str
          sample: "N"
        retention_period_in_hours:
          description: Retention period for the snapshot in hours.
          type: int
          sample: -1
        secondary_hex_volume_id:
          description: Hexadecimal identifier for the secondary volume.
          type: str
          sample: "00:06:36"
        secondary_volume_id:
          description: Identifier for the secondary volume.
          type: int
          sample: 1590
        snapshot_group_name:
          description: Name of the snapshot group.
          type: str
          sample: "spc-snapshot"
        snapshot_id:
          description: Identifier for the snapshot.
          type: str
          sample: "842,3"
        split_time:
          description: Time when the snapshot was split.
          type: str
          sample: "2025-06-27T23:28:06"
        status:
          description: Status of the snapshot.
          type: str
          sample: "PSUS"
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
          description: Processing status for the secondary volume.
          type: str
          sample: ""
        type:
          description: Type of the snapshot.
          type: str
          sample: "CASCADE"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPSnapshotArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    operation_constants,
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
class VSPHtiSnapshotGroupManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPSnapshotArguments().snapshot_grp_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:

            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = self.params_manager.storage_system_info.serial
            self.spec = self.params_manager.snapshot_grp_spec()
            self.state = self.params_manager.get_state()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Snapshot Group operation ===")
        snapshot_data = None
        registration_message = validate_ansible_product_registration()

        try:
            snapshot_data = VSPHtiSnapshotReconciler(
                self.connection_info, self.storage_serial_number
            ).snapshot_group_id_reconcile(self.spec, self.state)

            operation = operation_constants(self.module.params["state"])
            msg = (
                f"Snapshot {operation} successfully"
                if not isinstance(snapshot_data, str)
                else snapshot_data
            )
            resp = {
                "changed": self.connection_info.changed,
                "snapshot_data": (
                    snapshot_data if isinstance(snapshot_data, dict) else None
                ),
                "msg": msg,
            }

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Snapshot Group operation ===")
            self.module.fail_json(msg=str(e))

        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Snapshot Group operation ===")
        self.module.exit_json(**resp)


def main(module=None):
    """Main function to execute the module."""
    obj_store = VSPHtiSnapshotGroupManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
