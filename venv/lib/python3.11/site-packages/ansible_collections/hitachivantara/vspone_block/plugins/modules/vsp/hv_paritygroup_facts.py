#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_paritygroup_facts
short_description: retrieves information about parity groups from Hitachi VSP storage systems.
description:
  - This module gathers facts about parity groups from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/paritygroup_facts.yml)
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
    description: Specification for the parity group facts to be gathered.
    type: dict
    required: false
    suboptions:
      parity_group_id:
        description: The parity group number of the parity group to retrieve.
          Required for the Get one parity group task.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get a specific parity group
  hitachivantara.vspone_block.vsp.hv_paritygroup_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      parity_group_id: 1-1

- name: Get all parity groups
  hitachivantara.vspone_block.vsp.hv_paritygroup_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the parity groups.
  returned: always
  type: dict
  contains:
    parity_groups:
      description: List of parity groups with their attributes.
      type: list
      elements: dict
      contains:
        clpr_id:
          description: CLPR (Cache Logical Partition) ID.
          type: int
          sample: 0
        copyback_mode:
          description: Indicates if copy back mode is enabled.
          type: bool
          sample: null
        drive_type:
          description: Type of drive.
          type: str
          sample: "SSD"
        free_capacity:
          description: Free capacity of the parity group.
          type: str
          sample: "0"
        free_capacity_mb:
          description: Free capacity in megabytes.
          type: bool
          sample: false
        is_accelerated_compression:
          description: Indicates if accelerated compression is enabled.
          type: bool
          sample: false
        is_encryption_enabled:
          description: Indicates if encryption is enabled.
          type: bool
          sample: null
        is_pool_array_group:
          description: Indicates if it is a pool array group.
          type: bool
          sample: null
        ldev_ids:
          description: List of LDEV IDs.
          type: list
          elements: int
          sample: [32732, 32733, 32734, 32743, 32752, 32753, 32754, 32755, 32756, 32757, 32758, 32759]
        parity_group_id:
          description: The parity group ID.
          type: str
          sample: "1-2"
        raid_level:
          description: RAID level of the parity group.
          type: str
          sample: "RAID5"
        resource_group_id:
          description: Resource group ID.
          type: int
          sample: -1
        total_capacity:
          description: Total capacity of the parity group.
          type: str
          sample: "15.46TB"
        total_capacity_mb:
          description: Total capacity in megabytes.
          type: float
          sample: 16210984.96
"""


from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParityGroupArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_parity_group,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    camel_array_to_snake_case,
    camel_dict_to_snake_case,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.message.module_msgs import (
    ModuleMessage,
)


class VspParityGroupFactManager:
    def __init__(self):
        # VSPStoragePoolArguments
        self.logger = Log()
        self.argument_spec = VSPParityGroupArguments().parity_group_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_parity_group_fact_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Parity Group Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            if self.spec.parity_group_id is not None:
                parity_group = self.direct_parity_group_read(self.spec.parity_group_id)
                parity_group_dict = parity_group.to_dict()
                parity_group_data_extracted = vsp_parity_group.VSPParityGroupCommonPropertiesExtractor().extract_parity_group(
                    parity_group_dict
                )
                snake_case_parity_group_data = camel_dict_to_snake_case(
                    parity_group_data_extracted
                )
                data = {"parity_groups": snake_case_parity_group_data}
                if registration_message:
                    data["user_consent_required"] = registration_message

                self.logger.writeInfo(f"{data}")
                self.logger.writeInfo("=== End of Parity Group Facts ===")
                self.module.exit_json(changed=False, ansible_facts=data)
            else:
                all_parity_groups = self.direct_all_parity_groups_read()
                parity_groups_list = all_parity_groups.data_to_list()
                parity_groups_data_extracted = vsp_parity_group.VSPParityGroupCommonPropertiesExtractor().extract_all_parity_groups(
                    parity_groups_list
                )
                snake_case_parity_groups_data = camel_array_to_snake_case(
                    parity_groups_data_extracted
                )
                data = {"parity_groups": snake_case_parity_groups_data}
                if registration_message:
                    data["user_consent_required"] = registration_message

                self.logger.writeInfo(f"{data}")
                self.logger.writeInfo("=== End of Parity Group Facts ===")
                self.module.exit_json(changed=False, ansible_facts=data)

        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Parity Group Facts ===")
            self.module.fail_json(msg=str(ex))

    def direct_all_parity_groups_read(self):
        result = vsp_parity_group.VSPParityGroupReconciler(
            self.params_manager.connection_info
        ).get_all_parity_groups()
        if result is None:
            raise ValueError(ModuleMessage.PARITY_GROUP_NOT_FOUND.value)
        return result

    def direct_parity_group_read(self, pg_id):
        result = vsp_parity_group.VSPParityGroupReconciler(
            self.params_manager.connection_info
        ).get_parity_group(pg_id)
        if result is None:
            raise ValueError(ModuleMessage.PARITY_GROUP_NOT_FOUND.value)
        return result


def main():
    obj_store = VspParityGroupFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
