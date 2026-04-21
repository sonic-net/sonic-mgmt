#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_snapshot_facts
short_description: Retrieves snapshot information from Hitachi VSP storage systems.
description:
  - This module retrieves information about snapshots from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/snapshot_facts.yml)
version_added: '3.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_with_type
options:
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
    description:
      - Specification for the snapshot facts to be gathered.
    type: dict
    required: false
    suboptions:
      primary_volume_id:
        description: The primary volume identifier. If not provided, it will be omitted.
          Required for the Get snapshot pairs with the same P-VOL
          /Get one snapshot pair tasks.
        type: str
        required: false
      mirror_unit_id:
        description: The mirror unit identifier. If not provided, it will be omitted.
          Required for the Get one snapshot pair task.
        type: int
        required: false
"""

EXAMPLES = """
- name: Gather snapshot facts with primary volume and mirror unit ID
  hitachivantara.vspone_block.vsp.hv_snapshot_facts:
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      primary_volume_id: 525
      mirror_unit_id: 10

- name: Gather snapshot facts with only primary volume
  hitachivantara.vspone_block.vsp.hv_snapshot_facts:
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      primary_volume_id: 'volume1'

- name: Gather snapshot facts without specific volume or mirror unit ID
  hitachivantara.vspone_block.vsp.hv_snapshot_facts:
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the snapshots.
  returned: always
  type: dict
  contains:
    snapshots:
      description: A list of snapshots gathered from the storage system.
      type: list
      elements: dict
      contains:
        can_cascade:
          description: Indicates if the snapshot can cascade.
          type: bool
          sample: true
        concordance_rate:
          description: Concordance rate of the snapshot.
          type: int
          sample: -1
        copy_pace_track_size:
          description: Track size for copy pace.
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
          description: Indicates if the snapshot is cloned.
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
          description: Indicates if data is written in secondary volume.
          type: bool
          sample: false
        mirror_unit_id:
          description: Identifier of the mirror unit.
          type: int
          sample: 3
        pool_id:
          description: Identifier of the pool.
          type: int
          sample: 1
        primary_volume_id_hex:
          description: Hexadecimal identifier of the primary volume.
          type: str
          sample: "00:00:A8"
        primary_volume_id:
          description: Identifier of the primary volume.
          type: int
          sample: 168
        progress_rate:
          description: Progress rate of the snapshot.
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
        secondary_volume_id_hex:
          description: Hexadecimal identifier of the secondary volume.
          type: str
          sample: "00:00:CD"
        secondary_volume_id:
          description: Identifier of the secondary volume.
          type: int
          sample: 205
        snapshot_group_name:
          description: Name of the snapshot group.
          type: str
          sample: "snewar-tia-grp-02"
        snapshot_id:
          description: Identifier of the snapshot.
          type: str
          sample: "168,3"
        split_time:
          description: Split time of the snapshot.
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
class VSPHtiSnapshotFactManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPSnapshotArguments().get_snapshot_fact_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:

            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = self.params_manager.storage_system_info.serial
            self.spec = self.params_manager.get_snapshot_fact_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Snapshot Facts ===")
        snapshot_data = None
        registration_message = validate_ansible_product_registration()

        try:

            snapshot_data = self.get_snapshot_facts()

            if snapshot_data:
                for snapshot in snapshot_data:
                    if not isinstance(snapshot, dict):
                        break

                    snapshot["can_cascade"] = False
                    snapshot["is_cloned"] = ""
                    snapshot["is_data_reduction_force_copy"] = False
                    ttype = snapshot.get("type")
                    if ttype == "CASCADE":
                        snapshot["is_data_reduction_force_copy"] = True
                        snapshot["can_cascade"] = True
                        snapshot["is_cloned"] = False
                    elif ttype == "CLONE":
                        snapshot["is_data_reduction_force_copy"] = True
                        snapshot["can_cascade"] = True
                        snapshot["is_cloned"] = True

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Snapshot Facts ===")
            self.module.fail_json(msg=str(e))
        data = {
            "snapshots": snapshot_data,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Snapshot Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)

    def get_snapshot_facts(self):
        reconciler = VSPHtiSnapshotReconciler(
            self.connection_info,
            self.storage_serial_number,
        )

        result = reconciler.get_snapshot_facts(self.spec)
        return result


def main():

    obj_store = VSPHtiSnapshotFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
