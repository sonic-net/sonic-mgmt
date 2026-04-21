#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
---
module: hv_vsp_one_snapshot
short_description: Manages snapshots on VSP E series and VSP One Block 20 series storage systems.
description:
  - This module enables creation, modification, and deletion of snapshots.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for snapshot management across VSP one B20 series and VSP E series models.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_snapshot.yml)
version_added: '4.4.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Specifies whether the module operates in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: Defines the snapshot operation type. Available options include C(present), C(absent),
      C(map), and C(restore).
    type: str
    required: false
    choices: ['present', 'absent', 'map', 'restore']
    default: 'present'
  spec:
    description: Configuration parameters for the snapshot operation.
    type: dict
    required: true
    suboptions:
      new_snapshots:
        description: List of new snapshots configurations. This is a mandatory field for create snapshot operation.
        type: list
        required: false
        elements: dict
        suboptions:
          master_volume_id:
            description: Specify the ID of the master volume from which snapshots are created. Decimal or hexadecimal value can be provided.
            type: str
            required: true
          pool_id:
            description: Specify the ID of the pool in which the differential data of the snapshot is stored as an integer in the range from 0 through 127.
            type: int
            required: true
          snapshot_group_name:
            description: Specify a snapshot group name of up to 32 characters.
            type: str
            required: true
          type:
            description: Snapshot type. The value can be either snapshot or mapped_snapshot, case insensitive.
            type: str
            required: true
      master_volume_id:
        description: Master volume ID of the snapshot. This is a mandatory field for map, restore, and delete snapshot operations.
          Decimal or hexadecimal value can be provided.
        type: str
        required: false
      snapshot_id:
        description: Snapshot ID. This is a mandatory field for map, restore, and delete snapshot operations.
        type: int
        required: false
      pool_id:
        description: Specify the ID of the pool in which the differential data of the snapshot is stored as
          an integer in the range from 0 through 127. This is a mandatory field for map snapshot operation.
        type: int
        required: false
      should_delete_svol:
        description: Deletes the SVOL if this field is set to true. The default value is false.
        type: bool
        required: false
        default: false
"""

EXAMPLES = """
- name: Create VSP one snapshot pairs
  # this is a test comment
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      new_snapshots:
        - master_volume_id: 1229
          pool_id: 0
          snapshot_group_name: "rd_snapshot_group_1"
          type: "snapshot"
        - master_volume_id: 28
          pool_id: 3
          snapshot_group_name: "rd_snapshot_group_4"
          type: "snapshot"

- name: Map VSP one snapshot pair
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
      state: "map"
      spec:
          master_volume_id: 27
          snapshot_id: 7
          pool_id: 3

- name: Restore VSP one snapshot pair
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    state: "restore"
    spec:
        master_volume_id: 27
        snapshot_id: 7

- name: Delete VSP one snapshot pair
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    state: "absent"
    spec:
        master_volume_id: 27
        snapshot_id: 7
"""

RETURN = """
snapshots:
  description: Snapshot information returned after operation. For map operation, it returns the information about the mapped volume.
  returned: always
  type: dict
  contains:
    id:
      description: Master volume ID of the snapshot and the snapshot ID, linked by a comma.
      type: str
      sample: "1445,4"
    is_volume_capacity_expanding:
      description: Master volume ID of the snapshot and the snapshot ID, linked by a comma.
      type: bool
      sample: false
    mapped_volume_id:
      description: ID of the volume to be created from the snapshots. This attribute is obtained
        only if the ID of the volume for which the snapshot was created is defined.
      type: int
      sample: 1445
    mapped_volume_id_hex:
      description: Mapped volume ID of the snapshot in hexadecimal.
      type: str
      sample: "00:05:A5"
    master_volume_id:
      description: Master volume ID of the snapshot.
      type: int
      sample: 1445
    master_volume_id_hex:
      description: Master volume ID of the snapshot in hexadecimal.
      type: str
      sample: "00:05:A5"
    pool_id:
      description: ID of the pool in which the differential data of the snapshots is stored.
      type: int
      sample: 1
    retention_period:
      description: Remaining Retention Time (hours) of the snapshot. If the snapshot data
        retention period is not set or the snapshot data retention period has expired, 0 is obtained.
      type: int
      sample: 0
    root_volume_id:
      description: ID of the root volume of the snapshots.
      type: int
      sample: 104
    snapshot_date:
      description: Date and time when the snapshot was created.
      type: str
      sample: "2025-08-28T18:12:39Z"
    snapshot_group_name:
      description: Snapshot group name.
      type: str
      sample: "test_sp_group"
    snapshot_id:
      description: Snapshot ID. The mirror unit number is obtained.
      type: int
      sample: 3
    status:
      description: Status of the snapshot.
      type: str
      sample: "Completed"
    type:
      description: Type of snapshot.
      type: str
      sample: "Snapshot"
    used_capacity__in_mb_per_root_volume:
      description: The amount of disk space (MiB) occupied by differential information and
        control information used by the snapshot group created from the same volume.
      type: int
      sample: 0
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_one_snapshot import (
    VspOneSnapshotReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPOneSnapshotArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPOneSnapshot:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPOneSnapshotArguments().get_vsp_one_snapshot_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_one_snapshot_spec()
            self.connection_info = params_manager.get_connection_info()
            self.state = params_manager.get_state()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One Snapshot Operation ===")
        snapshot = None
        registration_message = validate_ansible_product_registration()

        try:
            server_reconciler = VspOneSnapshotReconciler(self.connection_info)
            snapshot = server_reconciler.reconcile(self.state, self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP One Snapshot Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "comments": self.spec.comments if self.spec.comments else [],
            "errors": self.spec.errors if self.spec.errors else [],
        }
        if self.state == "map":
            response["mapped_volume"] = snapshot
        else:
            response["snapshots"] = snapshot
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One Snapshot Operation ===")
        self.module.exit_json(**response)


def main():
    obj_store = VSPOneSnapshot()
    obj_store.apply()


if __name__ == "__main__":
    main()
