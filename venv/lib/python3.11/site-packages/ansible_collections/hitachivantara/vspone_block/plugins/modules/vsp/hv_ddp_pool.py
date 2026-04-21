#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_ddp_pool
short_description: Manages DDP Pools on Hitachi VSP storage systems.
description: >
  - This module manages DDP Pools on Hitachi VSP storage systems.
  - It allows for the creation, deletion, and modification of DDP Pools.
  - This module supports only on VSP One storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/ddp_pool.yml)
version_added: '3.4.0'
author:
  - Hitachi Vantara, LTD. (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: The level of the Remote connection task. Choices are C(present), C(absent) C(expand).
    type: str
    required: false
    choices: ['present', 'absent', 'expand']
    default: 'present'
  spec:
    description: Specification for DDP pool tasks.
    type: dict
    required: true
    suboptions:
      pool_id:
        description: ID of the DDP Pool. Required for Update/Expand/Delete tasks.
        type: int
        required: false
      pool_name:
        description: Name of the DDP Pool. Required for Create/Update tasks.
        type: str
        required: false
      is_encryption_enabled:
        description: Whether encryption is enabled for the DDP Pool.
        type: bool
        required: false
      threshold_warning:
        description: Warning threshold for the DDP Pool.
        type: int
        required: false
      threshold_depletion:
        description: Depletion threshold for the DDP Pool.
        type: int
        required: false
      drives:
        description: List of drives to be added to the DDP Pool.
        type: list
        required: false
        elements: dict
        suboptions:
          drive_type_code:
            description: Specify a drive type code consisting of 12 characters. if not specified, the drive type code will be selected automatically.
            type: str
            required: false
          data_drive_count:
            description: Specify at least 9 for the number of data drives. if not specified, the number of data drives will be selected with recommend count.
            type: int
            required: false
"""

EXAMPLES = """
- name: Create a new DDP Pool
  hitachivantara.vspone_block.vsp.hv_ddp_pool:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      pool_name: "GK-21268"
      is_encryption_enabled: true
      threshold_warning: 70
      threshold_depletion: 80
      drives:
        - drive_type_code: "NM5C-R1R9NC"
          data_drive_count: 9

- name: Create a new DDP Pool with automatic drive type code and count
  hitachivantara.vspone_block.vsp.hv_ddp_pool:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      pool_name: "GK-21268"

- name: Update the DDP Pool Settings
  hitachivantara.vspone_block.vsp.hv_ddp_pool:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      pool_id: 12
      threshold_warning: 70
      threshold_depletion: 80
      pool_name: "GK-21268"

- name: Expand the DDP Pool size
  hitachivantara.vspone_block.vsp.hv_ddp_pool:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: expand
    spec:
      pool_id: 12
      drives:
        - drive_type_code: "NM5C-R1R9NC"
          data_drive_count: 9

- name: Delete a DDP Pool
  hitachivantara.vspone_block.vsp.hv_ddp_pool:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      pool_id: 12
"""

RETURN = """
DDP_Pool:
  description: Details of the managed DDP Pool.
  returned: success
  type: dict
  contains:
    capacity_manage:
      description: Capacity management details of the DDP Pool.
      type: dict
      contains:
        threshold_depletion:
          description: Depletion threshold for the pool.
          type: int
          sample: 80
        threshold_warning:
          description: Warning threshold for the pool.
          type: int
          sample: 70
        used_capacity_rate:
          description: Used capacity rate of the pool.
          type: int
          sample: 0
    config_status:
      description: Configuration status of the pool.
      type: list
      elements: str
    contains_capacity_saving_volume:
      description: Indicates if the pool contains capacity-saving volumes.
      type: bool
      sample: false
    drives:
      description: List of drives in the DDP Pool.
      type: list
      elements: dict
      contains:
        display_drive_capacity:
          description: Display capacity of the drive.
          type: str
          sample: "1.9 TB"
        drive_capacity:
          description: Capacity of the drive in GB.
          type: int
          sample: 1900
        drive_interface:
          description: Interface type of the drive.
          type: str
          sample: "NVMe"
        drive_rpm:
          description: RPM of the drive.
          type: str
          sample: "NUMBER_0"
        drive_type:
          description: Type of the drive.
          type: str
          sample: "SSD"
        locations:
          description: Physical locations of the drives.
          type: list
          elements: str
          sample: ["0-0", "0-1", "0-2", "0-3"]
        number_of_drives:
          description: Number of drives in the pool.
          type: int
          sample: 4
        parity_group_type:
          description: Parity group type of the drives.
          type: str
          sample: "DEFAULT"
        raid_level:
          description: RAID level of the drives.
          type: str
          sample: "RAID5"
        total_capacity:
          description: Total capacity of the drives in GB.
          type: int
          sample: 7600
    effective_capacity:
      description: Effective capacity of the pool in GB.
      type: int
      sample: 3990
    encryption:
      description: Encryption status of the pool.
      type: str
      sample: "DISABLED"
    free_capacity:
      description: Free capacity of the pool in GB.
      type: int
      sample: 3990
    id:
      description: ID of the DDP Pool.
      type: int
      sample: 15
    name:
      description: Name of the DDP Pool.
      type: str
      sample: "GK-21268"
    number_of_drive_types:
      description: Number of drive types in the pool.
      type: int
      sample: 1
    number_of_tiers:
      description: Number of tiers in the pool.
      type: int
      sample: 0
    number_of_volumes:
      description: Number of volumes in the pool.
      type: int
      sample: 13
    saving_effects:
      description: Data saving effects of the pool.
      type: dict
      contains:
        calculation_end_time:
          description: End time of the saving calculation.
          type: str
          sample: "2025-04-03T22:23:00Z"
        calculation_start_time:
          description: Start time of the saving calculation.
          type: str
          sample: "2025-04-03T22:21:19Z"
        data_reduction_without_system_data:
          description: Data reduction without system data.
          type: int
          sample: -1
        data_reduction_without_system_data_status:
          description: Status of data reduction without system data.
          type: str
          sample: "NoTargetData"
        efficiency_data_reduction:
          description: Efficiency of data reduction.
          type: int
          sample: -1
        efficiency_fmd_saving:
          description: Efficiency of FMD saving.
          type: int
          sample: -1
        is_total_efficiency_support:
          description: Indicates if total efficiency is supported.
          type: bool
          sample: true
        post_capacity_fmd_saving:
          description: Post-capacity FMD saving.
          type: int
          sample: 0
        pre_capacity_fmd_saving:
          description: Pre-capacity FMD saving.
          type: int
          sample: 0
        software_saving_without_system_data:
          description: Software saving without system data.
          type: int
          sample: -1
        software_saving_without_system_data_status:
          description: Status of software saving without system data.
          type: str
          sample: "NoTargetData"
        total_efficiency:
          description: Total efficiency of the pool.
          type: int
          sample: 9223372036854775807
        total_efficiency_status:
          description: Status of total efficiency.
          type: str
          sample: "Valid"
    status:
      description: Status of the DDP Pool.
      type: str
      sample: "Normal"
    subscription_limit:
      description: Subscription limit details of the pool.
      type: dict
      contains:
        current_rate:
          description: Current subscription rate.
          type: int
          sample: 396
        is_enabled:
          description: Indicates if subscription limit is enabled.
          type: bool
          sample: false
    tiers:
      description: List of tiers in the pool.
      type: list
      elements: dict
    total_capacity:
      description: Total capacity of the pool in GB.
      type: int
      sample: 3990
    used_capacity:
      description: Used capacity of the pool in GB.
      type: int
      sample: 0
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    operation_constants,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_dynamic_pool_reconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPDynamicPoolArgs,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPDynamicPool:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPDynamicPoolArgs().vsp_dynamic_pool_spec()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_dynamic_pool_spec()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of DDP Pool operation. ===")
        try:
            registration_message = validate_ansible_product_registration()
            result = vsp_dynamic_pool_reconciler.VspDynamicPoolReconciler(
                self.params_manager.connection_info,
            ).dynamic_pool_reconcile(self.state, self.spec)
            operation = operation_constants(self.module.params["state"])
            msg = (
                result
                if isinstance(result, str)
                else f"DDP Pool {operation} successfully."
            )
            result = result if not isinstance(result, str) else None
            response_dict = {
                "changed": self.connection_info.changed,
                "DDP_Pool": result,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of DDP Pool operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of DDP Pool operation. ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VSPDynamicPool()
    obj_store.apply()


if __name__ == "__main__":
    main()
