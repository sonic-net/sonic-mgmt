#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_storagepool_facts
short_description: Retrieves storage pool information from Hitachi VSP storage systems.
description:
  - This module retrieves information about storage pools from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/storagepool_facts.yml)

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
notes:
  - The output parameters C(subscriber_id) and C(partner_id) were removed in version 3.4.0.
    They were also deprecated due to internal API simplification and are no longer supported.
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
    description: Specification for the storage pool facts to be gathered.
    type: dict
    required: false
    suboptions:
      pool_id:
        description: The pool number of the specific pool to retrieve.
          Required for the Get one storage pool task.
        type: int
        required: false
      pool_name:
        description: The name of the specific pool to retrieve.
          Required for the Get one storage pool using pool name task.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all pools
  hitachivantara.vspone_block.vsp.hv_storagepool_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"

- name: Get a specific pool
  hitachivantara.vspone_block.vsp.hv_storagepool_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      pool_id: 0

- name: Get a specific pool using pool name
  hitachivantara.vspone_block.vsp.hv_storagepool_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      pool_name: "PoolName"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the storage pools.
  returned: always
  type: dict
  contains:
    storage_pool:
      description: The storage pool information.
      type: list
      elements: dict
      contains:
        available_physical_volume_capacity_mb:
          description: The available physical volume capacity in MB.
          type: int
          sample: 14591094
        available_volume_capacity_mb:
          description: The available volume capacity in MB.
          type: int
          sample: 14591094
        blocking_mode:
          description: The blocking mode of the pool.
          type: str
          sample: "NB"
        capacities_excluding_system_data:
          description: Capacity information excluding system data.
          type: dict
          contains:
            compressed_capacity:
              description: The compressed capacity.
              type: int
              sample: 0
            deduped_capacity:
              description: The deduplicated capacity.
              type: int
              sample: 0
            pre_compressed_capacity:
              description: The pre-compressed capacity.
              type: int
              sample: 0
            pre_dedupred_capacity:
              description: The pre-deduplicated capacity.
              type: int
              sample: 0
            pre_used_capacity:
              description: The pre-used capacity.
              type: int
              sample: 0
            reclaimed_capacity:
              description: The reclaimed capacity.
              type: int
              sample: 0
            system_data_capacity:
              description: The system data capacity.
              type: int
              sample: 1118208
            used_virtual_volume_capacity:
              description: The used virtual volume capacity.
              type: int
              sample: 258048
        compression_rate:
          description: The compression rate.
          type: int
          sample: 0
        dat:
          description: The DAT information.
          type: str
          sample: ""
        data_reduction_accelerate_comp_capacity_mb:
          description: The data reduction accelerate compression capacity in MB.
          type: int
          sample: 0
        data_reduction_accelerate_comp_including_system_data:
          description: Data reduction accelerate compression including system data.
          type: dict
          contains:
            is_reduction_capacity_available:
              description: Whether reduction capacity is available.
              type: bool
              sample: false
            is_reduction_rate_available:
              description: Whether reduction rate is available.
              type: bool
              sample: false
            reduction_capacity:
              description: The reduction capacity.
              type: int
              sample: -1
            reduction_rate:
              description: The reduction rate.
              type: int
              sample: -1
        data_reduction_accelerate_comp_rate:
          description: The data reduction accelerate compression rate.
          type: int
          sample: 0
        data_reduction_before_capacity_mb:
          description: The data reduction before capacity in MB.
          type: int
          sample: 0
        data_reduction_capacity_mb:
          description: The data reduction capacity in MB.
          type: int
          sample: 0
        data_reduction_including_system_data:
          description: Data reduction including system data.
          type: dict
          contains:
            is_reduction_capacity_available:
              description: Whether reduction capacity is available.
              type: bool
              sample: false
            is_reduction_rate_available:
              description: Whether reduction rate is available.
              type: bool
              sample: false
            reduction_capacity:
              description: The reduction capacity.
              type: int
              sample: -1
            reduction_rate:
              description: The reduction rate.
              type: int
              sample: -1
        data_reduction_rate:
          description: The data reduction rate.
          type: int
          sample: 0
        depletion_threshold:
          description: The depletion threshold.
          type: int
          sample: 80
        duplication_ldev_ids:
          description: List of duplication LDEV IDs.
          type: list
          elements: int
          sample: [32731, 32730, 32729, 32728]
        duplication_ldev_ids_hex:
          description: List of duplication LDEV IDs in hexadecimal format.
          type: list
          elements: str
          sample: ["00:7F:DB", "00:7F:DA", "00:7F:D9", "00:7F:D8"]
        duplication_number:
          description: The number of duplications.
          type: int
          sample: 8
        duplication_rate:
          description: The duplication rate.
          type: int
          sample: 0
        effective_capacity_mb:
          description: The effective capacity in MB.
          type: int
          sample: 14591766
        first_ldev_id:
          description: The first LDEV ID.
          type: int
          sample: 32754
        has_blocked_pool_volume:
          description: Whether the pool has blocked pool volume.
          type: bool
          sample: null
        is_mainframe:
          description: Whether the pool is for mainframe.
          type: bool
          sample: false
        is_shrinking:
          description: Whether the pool is shrinking.
          type: bool
          sample: false
        located_volume_count:
          description: The count of located volumes.
          type: int
          sample: 29
        monitoring_mode:
          description: The monitoring mode.
          type: str
          sample: ""
        num_of_ldevs:
          description: The number of LDEVs.
          type: int
          sample: 12
        pool_action_mode:
          description: The pool action mode.
          type: str
          sample: ""
        pool_id:
          description: The pool ID.
          type: int
          sample: 0
        pool_name:
          description: The name of the pool.
          type: str
          sample: "test-ddp-pool_1"
        pool_status:
          description: The status of the pool.
          type: str
          sample: "NORMAL"
        pool_type:
          description: The type of the pool.
          type: str
          sample: "HDP"
        reserved_volume_count:
          description: The count of reserved volumes.
          type: int
          sample: 0
        snapshot_count:
          description: The count of snapshots.
          type: int
          sample: 1
        snapshot_used_capacity_mb:
          description: The snapshot used capacity in MB.
          type: int
          sample: 0
        suspend_snapshot:
          description: Whether snapshot is suspended.
          type: bool
          sample: true
        tier_operation_status:
          description: The tier operation status.
          type: str
          sample: ""
        tiers:
          description: List of tiers.
          type: list
          elements: dict
          sample: []
        total_located_capacity_mb:
          description: The total located capacity in MB.
          type: int
          sample: 33597984
        total_physical_capacity_mb:
          description: The total physical capacity in MB.
          type: int
          sample: 14591766
        total_pool_capacity_mb:
          description: The total pool capacity in MB.
          type: int
          sample: 14591766
        total_reserved_capacity_mb:
          description: The total reserved capacity in MB.
          type: int
          sample: 0
        used_capacity_rate:
          description: The used capacity rate.
          type: int
          sample: 1
        used_physical_capacity:
          description: The used physical capacity.
          type: int
          sample: -1
        used_physical_capacity_rate:
          description: The used physical capacity rate.
          type: int
          sample: 1
        virtual_volume_capacity_rate:
          description: The virtual volume capacity rate.
          type: int
          sample: -1
        warning_threshold:
          description: The warning threshold.
          type: int
          sample: 70
"""

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_storage_pool,
)
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPStoragePoolArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.message.module_msgs import (
    ModuleMessage,
)


class VspStoragePoolFactManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPStoragePoolArguments().storage_pool_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_pool_fact_spec()
            self.serial = self.params_manager.get_serial()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Storage Pool Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = vsp_storage_pool.VSPStoragePoolReconciler(
                self.params_manager.connection_info, self.serial
            ).storage_pool_facts(self.spec)
            if result is None:
                err_msg = ModuleMessage.STORAGE_POOL_NOT_FOUND.value
                self.logger.writeError(f"{err_msg}")
                self.logger.writeInfo("=== End of Storage Pool Facts ===")
                self.module.fail_json(msg=err_msg)

            data = {
                "storage_pool": result,
            }
            if registration_message:
                data["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{data}")
            self.logger.writeInfo("=== End of Storage Pool Facts ===")
            self.module.exit_json(changed=False, ansible_facts=data)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Storage Pool Facts ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VspStoragePoolFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
