#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_paritygroup
short_description: Create, delete parity group from Hitachi VSP storage systems.
description:
  - This module creates, delete parity group from Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/paritygroup.yml)
version_added: '3.2.0'
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
- hitachivantara.vspone_block.common.connection_with_type
options:
  state:
    description: The level of the HUR pairs task. Choices are C(present), C(absent), C(update), (assign_clpr_id).
    type: str
    required: false
    choices: ['present', 'absent', 'update', 'assign_clpr_id']
    default: 'present'
  spec:
    description: Specification for the parity group tasks.
    type: dict
    required: false
    suboptions:
      parity_group_id:
        description: The parity group number of the parity group to retrieve.
          Required for the Create parity group
          /Delete parity group
          /Update parity group
          /Assign CLPR ID to Parity Group tasks.
        type: str
        required: false
      drive_location_ids:
        description: Specify the locations of the drives to be used to create to the parity group.
          Required for the Create parity group task.
        type: list
        elements: str
        required: false
      raid_type:
        description: RAID type.
          Required for the Create parity group task.
        type: str
        required: false
      is_encryption_enabled:
        description: Specify whether to enable the encryption function for the parity group.
          Optional for the Create parity group task.
        type: bool
        required: false
      is_copy_back_mode_enabled:
        description: Specify whether to enable the encryption function for the parity group.
          Optional for the Create parity group task.
        type: bool
        required: false
      is_accelerated_compression_enabled:
        description: Specify whether to enable accelerated compression for the parity group.
          Optional for the Create parity group
          /Update parity group tasks.
        type: bool
        required: false
      clpr_id:
        description: Specify a CLPR number in the range from 0 to 31.
          Required for the Create parity group
          /Assign CLPR ID to Parity Group tasks.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create parity group
  hitachivantara.vspone_block.vsp.hv_paritygroup:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      parity_group_id: 1-10
      drive_location_ids: ["0-16", "0-17", "0-18", "0-19"]
      raid_type: 3D+1P
      is_encryption_enabled: true
      is_copy_back_mode_enabled: false
      is_accelerated_compression_enabled: true
      clpr_id: 1

- name: Delete parity group
  hitachivantara.vspone_block.vsp.hv_paritygroup:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "absent"
    spec:
      parity_group_id: 1-10

- name: Update parity group
  hitachivantara.vspone_block.vsp.hv_paritygroup:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "update"
    spec:
      parity_group_id: 1-10
      is_accelerated_compression_enabled: true

- name: Assign CLPR Id to parity group
  hitachivantara.vspone_block.vsp.hv_paritygroup:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "update"
    spec:
      parity_group_id: 1-10
      clpr_id: 0
"""

RETURN = """
parity_group:
  description: Parity group managed by the module.
  returned: success
  type: list
  elements: dict
  contains:
    clpr_id:
      description: CLPR number.
      type: int
      sample: 0
    copyback_mode:
      description: Indicates if copy back mode is enabled.
      type: bool
      sample: true
    drive_type:
      description: Type of drive.
      type: str
      sample: "SSD"
    free_capacity:
      description: Free capacity of the parity group (human readable).
      type: str
      sample: "0"
    free_capacity_mb:
      description: Free capacity of the parity group in MB.
      type: float
      sample: 0.0
    is_accelerated_compression:
      description: Indicates if accelerated compression is enabled.
      type: bool
      sample: false
    is_encryption_enabled:
      description: Indicates if encryption is enabled.
      type: bool
      sample: false
    is_pool_array_group:
      description: Indicates if it is a pool array group.
      type: bool
      sample: null
    ldev_ids:
      description: List of LDEV IDs.
      type: list
      elements: int
      sample:
        - 32732
    parity_group_id:
      description: Parity group ID.
      type: str
      sample: "1-2"
    raid_level:
      description: RAID level.
      type: str
      sample: "RAID5"
    resource_group_id:
      description: Resource group ID.
      type: int
      sample: -1
    resource_id:
      description: Resource ID.
      type: int
      sample: null
    status:
      description: Status of the parity group.
      type: str
      sample: null
    total_capacity:
      description: Total capacity of the parity group (human readable).
      type: str
      sample: "15.46TB"
    total_capacity_mb:
      description: Total capacity of the parity group in MB.
      type: float
      sample: 16210984.96
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_parity_group,
)

try:

    HAS_MESSAGE_ID = True
except ImportError:
    HAS_MESSAGE_ID = False

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPParityGroupArguments,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    camel_dict_to_snake_case,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPParityGroupManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPParityGroupArguments().parity_group()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
            # can be added mandotary , optional mandatory arguments
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_parity_group_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Parity Group operation ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = vsp_parity_group.VSPParityGroupReconciler(
                self.params_manager.connection_info, self.state
            ).parity_group_reconcile(self.state, self.spec)

            # if result is not None and result is not str:
            #   snake_case_parity_group_data = camel_dict_to_snake_case(result.to_dict())
            msg_state = ""
            if self.state == "present":
                msg_state = "Parity group created successfully."
            elif self.state == "update":
                msg_state = "Parity group updated successfully."
            msg = result if isinstance(result, str) else msg_state

            snake_case_parity_group_data = {}
            if not isinstance(result, str):
                parity_group_dict = result.to_dict()
                parity_group_data_extracted = vsp_parity_group.VSPParityGroupCommonPropertiesExtractor().extract_parity_group(
                    parity_group_dict
                )
                snake_case_parity_group_data = camel_dict_to_snake_case(
                    parity_group_data_extracted
                )

            response_dict = {
                "changed": self.connection_info.changed,
                "data": snake_case_parity_group_data,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message

            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of Parity Group operation ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Parity Group operation ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VSPParityGroupManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
