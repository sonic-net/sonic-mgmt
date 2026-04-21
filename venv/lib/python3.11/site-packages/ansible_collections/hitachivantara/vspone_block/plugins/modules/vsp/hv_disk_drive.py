#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_disk_drive
short_description: Changes disk drive settings from VSP block storage systems.
description:
    - This module changes disk drive settings from VSP block storage systems.
    - For examples go to URL
      U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/disk_drive.yml)
version_added: '3.2.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_info_basic
options:
  state:
    description: The level of the Disk Drives task.
    type: str
    required: false
    choices: ['present']
    default: 'present'
  spec:
    description: Specification for the hard drive tasks.
    type: dict
    required: false
    suboptions:
      drive_location_id:
        description: The drive location Id of the hard drive to retrieve. Optional for the Change drive settings task.
        type: str
        required: false
      is_spared_drive:
        description: Specify whether the disk drive is a spared drive. Required for the Change drive settings task.
        type: bool
        required: false
"""

EXAMPLES = """
- name: Change disk drive settings
  hitachivantara.vspone_block.vsp.hv_disk_drive:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      drive_location_id: "0-16"
      is_spared_drive: true
"""

RETURN = r"""
disk_drive:
  description: Disk drive managed by the module.
  returned: success
  type: dict
  contains:
    drive_location_id:
      description: The drive location identifier.
      type: str
      sample: "0-22"
    drive_type:
      description: Model identifier of the drive.
      type: str
      sample: "SNM5C-R1R9NC"
    drive_type_name:
      description: Human readable drive type name.
      type: str
      sample: "SSD"
    serial_number:
      description: Serial number of the drive.
      type: str
      sample: "C2YII03F"
    status:
      description: Status of the drive.
      type: str
      sample: "NML"
    total_capacity:
      description: Total capacity of the drive expressed as a string with units.
      type: str
      sample: "1900 GB"
    total_capacity_mb:
      description: Total capacity of the drive in megabytes.
      type: int
      sample: 1945600.0
    usage_type:
      description: Current usage type of the drive.
      type: str
      sample: "FREE"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_disk_drive,
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


class VSPDiskDriveManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPParityGroupArguments().drives()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
            # can be added mandotary , optional mandatory arguments
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_drives_fact_spec()
            self.serial = None
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Disk Drive operation. ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = vsp_disk_drive.VSPDiskDriveReconciler(
                self.params_manager.connection_info, self.state
            ).disk_drive_reconcile(self.state, self.spec)

            # if result is not None and result is not str:
            #   snake_case_parity_group_data = camel_dict_to_snake_case(result.to_dict())

            msg = (
                result
                if isinstance(result, str)
                else "Disk drive settings changed successfully."
            )
            result = (
                camel_dict_to_snake_case(result)
                if not isinstance(result, str)
                else None
            )
            response_dict = {
                "changed": self.connection_info.changed,
                "disk_drive": result,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message

            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of Disk Drive operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Disk Drive operation. ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VSPDiskDriveManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
