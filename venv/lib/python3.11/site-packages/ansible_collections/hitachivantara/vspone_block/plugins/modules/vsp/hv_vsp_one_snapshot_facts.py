#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_snapshot_facts
short_description: Retrieves snapshot information from VSP E series and VSP One Block 20 series storage systems.
description:
  - This module retrieves snapshot information from VSP E series and VSP One Block 20 series storage systems.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for snapshot facts retrieval across VSP one B20 series and VSP E series models.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_snapshot_facts.yml)
version_added: '4.4.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Specifies whether the module operates in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.connection_info
options:
  spec:
    description: Query parameters for retrieving snapshot information.
    type: dict
    required: false
    suboptions:
      master_volume_id:
        description: Master volume ID of the snapshot.
        type: str
        required: false
      snapshot_date_from:
        description: Information about snapshots created on and after the date and time specified for this parameter will be obtained.
          Specify the date and time from which snapshots will be obtained, in YYYY-MM-DDThh:mm:ssZ format.
        type: str
        required: false
      snapshot_date_to:
        description: Information about snapshots created on and before the date and time specified for this parameter will be obtained.
          Specify the date and time from which snapshots will be obtained, in YYYY-MM-DDThh:mm:ssZ format.
        type: str
        required: false
      snapshot_group_name:
        description: Snapshot group name. Information about the snapshot that is a perfect match with the specified value is obtained.
        type: str
        required: false
      start_id:
        description: Specify the first snapshot information to obtain, by specifying the master volume ID of the snapshot and the snapshot ID,
          linked by a comma. String in formation of 'master_volume_id,snapshot_id'. If this parameter is omitted, '0,0' is assumed.
        type: str
        required: false
      count:
        description: Specify the number of snapshots by using a value in the range from 1 through 1000. If this parameter is omitted,
          1000 is considered.
        type: int
        required: false
      snapshot_id:
        description: Snapshot ID.
        type: int
        required: false
"""

EXAMPLES = """
- name: Get snapshot pair with master_volume_id and snapshot_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      master_volume_id: 1445
      snapshot_id: 4

- name: Get all snapshot pairs
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"

- name: Get port information by protocol
  hitachivantara.vspone_block.vsp.hv_vsp_one_snapshot_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      protocol: "fc"
"""

RETURN = """
ansible_facts:
  description: Facts about snapshots retrieved from the storage system.
  returned: always
  type: dict
  contains:
    snapshots:
      description: List of snapshot information retrieved from the storage system.
      returned: always
      type: list
      elements: dict
      contains:
        id:
          description: Master volume ID of the snapshot and the snapshot ID, linked by a comma.
          type: str
          sample: "1445,4"
        is_volume_capacity_expanding:
          description: Indicates if the master volume capacity is expanding.
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
        root_volume_id_hex:
          description: ID of the root volume of the snapshots in hexadecimal.
          type: str
          sample: "00:00:68"
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
        used_capacity_in_mb_per_root_volume:
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


class VSPOneSnapshotFacts:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPOneSnapshotArguments().get_vsp_one_snapshot_facts_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_one_snapshot_facts_spec()
            self.connection_info = params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One Snapshot Facts Retrieval ===")
        snapshots = None
        registration_message = validate_ansible_product_registration()

        try:
            port_reconciler = VspOneSnapshotReconciler(self.connection_info)
            snapshots = port_reconciler.get_snapshot_facts(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP One Snapshot Facts Retrieval ===")
            self.module.fail_json(msg=str(e))

        response = {
            "snapshots": snapshots,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One Snapshot Facts Retrieval ===")
        self.module.exit_json(changed=False, ansible_facts=response)


def main():
    obj_store = VSPOneSnapshotFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
