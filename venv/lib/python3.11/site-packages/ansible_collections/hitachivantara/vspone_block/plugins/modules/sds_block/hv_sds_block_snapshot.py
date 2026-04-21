#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_snapshot
short_description: Manages snapshots on VSP One SDS Block and Cloud systems.
description:
  - This module allows you to create, prepare, and finalize snapshots on Hitachi SDS Block storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/snapshot.yml)
version_added: "4.1.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  state:
    description: The desired state of the snapshot.
    type: str
    required: false
    choices: ["present", "absent", "restore"]
    default: 'present'
  spec:
    description: Specification for the snapshot operation.
    type: dict
    required: true
    suboptions:
      name:
        description: The name of the snapshot. This is a valid field for create operation.
        type: str
        required: false
      master_volume_name:
        description: The name of the master volume. This field is valid for the create operation and is mandatory
          if the master_volume_id field is not provided.
        type: str
        required: false
      master_volume_id:
        description: The UUID of the master volume. This field is valid for the create operation and is mandatory
          if the master_volume_name field is not provided.
        type: str
        required: false
      snapshot_volume_name:
        description: The name of the snapshot volume. This field is valid for delete and restore operations and is mandatory
          if the snapshot_volume_id field is not provided.
        type: str
        required: false
      snapshot_volume_id:
        description: The UUID of the snapshot volume. This field is valid for delete and restore operations and is mandatory
          if the snapshot_volume_name field is not provided.
        type: str
        required: false
      operation_type:
        description: The type of snapshot operation. This field is valid for the create operation and is mandatory.
        type: str
        required: false
        choices: ["prepare_and_finalize", "prepare", "finalize"]
      vps_id:
        description: The UUID of the VPS.
        type: str
        required: false
      vps_name:
        description: The name of the VPS.
        type: str
        required: false
      qos:
        description: QoS settings for the snapshot. This field is valid for the create operation and is optional.
        type: dict
        required: false
        suboptions:
          upper_limit_for_iops:
            description: Upper limit for IOPS.
            type: int
            required: false
          upper_limit_for_transfer_rate:
            description: Upper limit for transfer rate.
            type: int
            required: false
          upper_alert_allowable_time:
            description: Upper alert allowable time.
            type: int
            required: false
"""

EXAMPLES = """
- name: Create a snapshot (present)
  hitachivantara.vspone_block.sds_block.hv_sds_block_snapshot:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      name: "snapshot1"
      master_volume_name: "volume1"
      operation_type: "prepare_and_finalize"

- name: Delete a snapshot (absent)
  hitachivantara.vspone_block.sds_block.hv_sds_block_snapshot:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "absent"
    spec:
      snapshot_volume_name: "snapshot1"

- name: Restore a snapshot (restore)
  hitachivantara.vspone_block.sds_block.hv_sds_block_snapshot:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "restore"
    spec:
      snapshot_volume_name: "snapshot1"
"""

RETURN = """
snapshot_info:
  description: Snapshot volume information retrieved from the storage system.
  returned: always
  type: dict
  contains:
    is_written_in_svol:
      description: Indicates whether data has been written to the secondary volume.
      type: bool
      sample: null
    qos_param:
      description: Quality of Service parameters for the snapshot.
      type: dict
      contains:
        upper_alert_allowable_time:
          description: Threshold time for upper alert in seconds.
          type: int
          sample: 30
        upper_alert_time:
          description: Current upper alert time setting.
          type: int
          sample: -1
        upper_limit_for_iops:
          description: Upper limit for IOPS.
          type: int
          sample: 120
        upper_limit_for_transfer_rate:
          description: Upper limit for data transfer rate (MB/s).
          type: int
          sample: 20
    snapshot_concordance_rate:
      description: The concordance rate of the snapshot in percentage.
      type: int
      sample: -1
    snapshot_progress_rate:
      description: Progress rate of the snapshot operation in percentage.
      type: int
      sample: -1
    snapshot_status:
      description: Current status of the snapshot.
      type: str
      sample: "Empty"
    snapshot_timestamp:
      description: Timestamp of the snapshot creation.
      type: str
      sample: ""
    snapshot_type:
      description: Type of the snapshot.
      type: str
      sample: "Snapshot"
    snapshot_volume_id:
      description: Unique identifier of the snapshot volume.
      type: str
      sample: "1ec0d4ea-2c47-47b2-b76b-22fa7714de43"
    snapshot_volume_name:
      description: Name of the snapshot volume.
      type: str
      sample: "testsnapshot12"
    snapshot_volume_nickname:
      description: Nickname of the snapshot volume.
      type: str
      sample: "SDSBolume12"
    status:
      description: Overall snapshot status.
      type: str
      sample: "Normal"
    status_summary:
      description: Summary of the snapshot status.
      type: str
      sample: "Normal"
    vps_id:
      description: VPS identifier associated with the snapshot.
      type: str
      sample: "(system)"
    vps_name:
      description: VPS name associated with the snapshot.
      type: str
      sample: "(system)"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_snapshot_reconciler import (
    SDSBSnapshotReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBSnapshotArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBSnapShotManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBSnapshotArguments().snapshot_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_sdsb_snapshot_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Snapshot Operation ===")
        storage_nodes = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBSnapshotReconciler(self.connection_info)
            storage_nodes, msg = sdsb_reconciler.snapshot_reconcile(
                self.state, self.spec
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Snapshot Operation ===")
            self.module.fail_json(msg=str(e))
        data = {
            "snapshot_info": storage_nodes,
            "changed": self.connection_info.changed,
            "message": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo("=== End of SDSB Snapshot Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBSnapShotManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
