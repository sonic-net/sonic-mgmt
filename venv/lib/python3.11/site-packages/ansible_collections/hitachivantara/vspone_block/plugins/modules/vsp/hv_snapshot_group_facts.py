#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_snapshot_group_facts
short_description: Retrieves snapshot information in units of snapshot groups from Hitachi VSP storage systems.
description:
  - This module retrieves information about snapshots in units of snapshot groups from Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/snapshot_group_facts.yml)
version_added: '3.2.0'
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
    description: Specification for the snapshot group facts to be gathered.
    type: dict
    required: false
    suboptions:
      snapshot_group_name:
        description: The name of the snapshot group.
          Required for the Get all snapshot pairs for a snapshot group task.
        type: str
        required: true
"""

EXAMPLES = """
- name: Gather snapshot facts with primary volume and mirror unit ID
  hitachivantara.vspone_block.vsp.hv_snapshot_group_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      snapshot_group_name: 'NewNameSPG'
"""


RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the snapshot groups.
  returned: always
  type: dict
  contains:
    snapshot_groups:
      description: Snapshot group information.
      type: dict
      contains:
        snapshot_group_id:
          description: Unique identifier for the snapshot group.
          type: str
          sample: "spc-snapshot"
        snapshot_group_name:
          description: Name of the snapshot group.
          type: str
          sample: "spc-snapshot"
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
            is_consistency_group:
              description: Indicates if it is a consistency group.
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
              description: ID of the mirror unit.
              type: int
              sample: 3
            pool_id:
              description: ID of the pool.
              type: int
              sample: 22
            primary_hex_volume_id:
              description: Hexadecimal ID of the primary volume.
              type: str
              sample: "00:03:4A"
            primary_volume_id:
              description: ID of the primary volume.
              type: int
              sample: 842
            progress_rate:
              description: Progress rate of the snapshot.
              type: int
              sample: -1
            pvol_host_groups:
              description: Host groups for the primary volume.
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
              description: Hexadecimal ID of the secondary volume.
              type: str
              sample: "00:06:36"
            secondary_volume_id:
              description: ID of the secondary volume.
              type: int
              sample: 1590
            snapshot_group_name:
              description: Name of the snapshot group.
              type: str
              sample: "spc-snapshot"
            snapshot_id:
              description: ID of the snapshot.
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
              description: Host groups for the secondary volume.
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
class VSPHtiSnapshotGrpFactManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPSnapshotArguments().snapshot_grp_fact_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:

            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = None
            self.spec = self.params_manager.snapshot_grp_fact_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Snapshot Group Facts ===")
        snapshot_data = None
        registration_message = validate_ansible_product_registration()

        try:
            snapshot_data = VSPHtiSnapshotReconciler(
                self.connection_info, self.storage_serial_number
            ).get_snapshot_facts(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Snapshot Group Facts ===")
            self.module.fail_json(msg=str(e))
        data = {
            "snapshot_groups": snapshot_data,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Snapshot Group Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    """Main function to execute the module."""
    obj_store = VSPHtiSnapshotGrpFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
