#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_snapshot_facts
short_description: Retrieves information about snapshots.
description:
  - Gathers information (facts) about snapshots on VSP One SDS Block and Cloud systems.
  - Use this module to retrieve details about existing snapshots, including their names, associated volumes, and IDs.
  - For usage examples, see
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/snapshot.yml)
version_added: "4.1.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  spec:
    description: Parameters for filtering or identifying snapshots to gather facts about.
    type: dict
    required: true
    suboptions:
      master_volume_name:
        description: Name of the master volume associated with the snapshot.
        type: str
        required: false
      master_volume_id:
        description: ID of the master volume associated with the snapshot.
        type: str
        required: false
      snapshot_volume_name:
        description: Name of the snapshot volume.
        type: str
        required: false
      snapshot_volume_id:
        description: ID of the snapshot volume.
        type: str
        required: false
      vps_id:
        description: The ID of the VPS.
        type: str
        required: false
      vps_name:
        description: The name of the VPS.
        type: str
        required: false
"""

EXAMPLES = """
- name: Gather all snapshots using master volume name
  hitachivantara.vspone_block.sds_block.hv_sds_block_snapshot_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      master_volume_name: "snPvol"

- name: Gather all snapshots using master volume name and snapshot volume name
  hitachivantara.vspone_block.sds_block.hv_sds_block_snapshot_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      master_volume_name: "volume1"
      snapshot_volume_name: "snapshot1"
"""

RETURN = """
ansible_facts:
  description: Facts collected by the module.
  returned: always
  type: dict
  contains:
    snapshots_info:
      description: List of snapshot volume information retrieved from the storage system.
      returned: always
      type: list
      elements: dict
      contains:
        is_written_in_svol:
          description: Whether data has been written to the secondary volume.
          type: bool
        qos_param:
          description: Quality of Service parameters for the snapshot.
          type: dict
          contains:
            upper_alert_allowable_time:
              description: Threshold time for upper alert in seconds.
              type: int
            upper_alert_time:
              description: Current upper alert time setting.
              type: int
            upper_limit_for_iops:
              description: Upper limit for IOPS.
              type: int
            upper_limit_for_transfer_rate:
              description: Upper limit for data transfer rate (MB/s).
              type: int
        snapshot_concordance_rate:
          description: The concordance rate of the snapshot in percentage.
          type: int
        snapshot_progress_rate:
          description: Progress rate of the snapshot operation in percentage.
          type: int
        snapshot_status:
          description: Current status of the snapshot.
          type: str
        snapshot_timestamp:
          description: Timestamp of the snapshot creation.
          type: str
        snapshot_type:
          description: Type of the snapshot.
          type: str
        snapshot_volume_id:
          description: Unique identifier of the snapshot volume.
          type: str
        snapshot_volume_name:
          description: Name of the snapshot volume.
          type: str
        snapshot_volume_nickname:
          description: Nickname of the snapshot volume.
          type: str
        status:
          description: Overall snapshot status.
          type: str
        status_summary:
          description: Summary of the snapshot status.
          type: str
        vps_id:
          description: VPS identifier associated with the snapshot.
          type: str
        vps_name:
          description: VPS name associated with the snapshot.
          type: str
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


class SDSBSnapShotFactManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBSnapshotArguments().snapshot_facts_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_sdsb_snapshot_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Snapshot Facts ===")
        storage_nodes = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBSnapshotReconciler(self.connection_info)
            storage_nodes = sdsb_reconciler.snapshot_facts(self.spec)
        except Exception as e:
            self.module.fail_json(msg=str(e))
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Snapshot Facts ===")
        data = {
            "snapshots_info": storage_nodes,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo("=== End of SDSB Snapshot Facts  ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBSnapShotFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
