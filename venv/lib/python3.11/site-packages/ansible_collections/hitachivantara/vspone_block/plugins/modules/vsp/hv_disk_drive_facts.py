#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_disk_drive_facts
short_description: Retrieves information about hard drives from Hitachi VSP storage systems.
description:
    - This module gathers facts about hard drives from Hitachi VSP storage systems.
    - For examples go to URL
      U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/disk_drive_facts.yml)
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
- hitachivantara.vspone_block.common.connection_info_basic
options:
  storage_system_info:
    description: Information about the storage system.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false
  spec:
    description: Specification for the hard drive facts to be gathered.
    type: dict
    required: false
    suboptions:
      drive_location_id:
        description: The drive location Id of the hard drive to retrieve. Optional for the Get one disk drive task.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get a specific hard drive
  hitachivantara.vspone_block.hv_disk_drive_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      drive_location_id: 0-16

- name: Get all hard drives
  hitachivantara.vspone_block.hv_disk_drive_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the disk drives and
    additional module response fields.
  returned: always
  type: dict
  contains:
    disk_drives:
      description: Container for disk drive results.
      type: dict
      contains:
        data:
          description: List of disk drives with their attributes.
          type: list
          elements: dict
          contains:
            drive_location_id:
              description: Drive location identifier.
              type: str
              sample: "0-0"
            drive_type:
              description: Drive model identifier.
              type: str
              sample: "SNB5B-R1R9NC"
            drive_type_name:
              description: Human friendly drive type.
              type: str
              sample: "SSD"
            parity_group_id:
              description: ID of the parity group.
              type: str
              sample: "1-1"
            serial_number:
              description: Drive serial number.
              type: str
              sample: "DKN02C7E"
            status:
              description: Status code of the drive.
              type: str
              sample: "NML"
            total_capacity:
              description: Total capacity expressed as a human readable string.
              type: str
              sample: "1900 GB"
            total_capacity_mb:
              description: Total capacity in megabytes.
              type: float
              sample: 1945600.0
            usage_type:
              description: Usage type for the drive (e.g. DATA, CACHE).
              type: str
              sample: "DATA"
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParityGroupArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_parity_group,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    camel_dict_to_snake_case,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VspDiskDriveFactManager:
    def __init__(self):
        # VSPStoragePoolArguments
        self.logger = Log()
        self.argument_spec = VSPParityGroupArguments().drives_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_drives_fact_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        registration_message = validate_ansible_product_registration()

        try:
            self.logger.writeInfo("=== Start of Disk Drive Facts ===")
            result = vsp_parity_group.VSPParityGroupReconciler(
                self.params_manager.connection_info
            ).get_all_drives(self.spec)

            # if result is not None and result is not str:
            #   snake_case_parity_group_data = camel_dict_to_snake_case(result.to_dict())

            msg = (
                result
                if isinstance(result, str)
                else "Disk drives retrieved successfully."
            )
            result = (
                camel_dict_to_snake_case(result)
                if not isinstance(result, str)
                else None
            )
            response_dict = {
                "disk_drives": result,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message

            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of Disk Drive Facts ===")
            self.module.exit_json(changed=False, ansible_facts=response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Disk Drive Facts ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VspDiskDriveFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
