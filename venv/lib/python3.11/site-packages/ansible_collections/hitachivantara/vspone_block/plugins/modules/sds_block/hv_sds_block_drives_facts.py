#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_drives_facts
short_description: Retrieves information about storage drives.
description:
  - Get drives from storage system with various filtering options
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_drive_facts.yml)
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
    description: Specification for retrieving CHAP user information.
    type: dict
    required: false
    suboptions:
      id:
        description: Unique identifier for the drive.
        type: str
      status_summary:
        description: Filter drives by status summary
        choices: [ 'Normal', 'Warning', 'Error' ]
        type: str
      status:
          description: Filter drives by status
          choices: [ 'Offline', 'Normal', 'TemporaryBlockage', 'Blockage' ]
          type: str
      storage_node_id:
          description: Filter drives by storage node ID (UUID format)
          type: str
      locator_led_status:
          description: Filter drives by locator LED status
          choices: [ 'On', 'Off' ]
          type: str
"""

EXAMPLES = """
- name: Retrieve information about all drives
  hitachivantara.vspone_block.sds_block.hv_sds_block_drives_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about drives by specifying optional parameters
  hitachivantara.vspone_block.sds_block.hv_sds_block_drives_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      status_summary: Normal
      status: Normal
      storage_node_id: 086e0c50-4b8d-430e-be47-bd65da4ca229
      locator_led_status: "On"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the drives.
  returned: always
  type: dict
  contains:
    drives:
      description: List of drive entries.
      type: list
      elements: dict
      contains:
        id:
          description: Unique identifier for the drive.
          type: str
          sample: "f41a9fa2-180e-4776-bbc4-9c536870c247"
        wwid:
          description: World Wide Identifier of the drive.
          type: str
          sample: "naa.5000cca0a602a4f4"
        status_summary:
          description: Summary of the drive's status.
          type: str
          sample: "Normal"
        status:
          description: Current operational status of the drive.
          type: str
          sample: "TemporaryBlockage"
        type_code:
          description: Manufacturer-specific type code.
          type: str
          sample: "MO000800JWUFU"
        serial_number:
          description: Serial number of the drive.
          type: str
          sample: "V6V1G2LA"
        storage_node_id:
          description: UUID of the storage node associated with the drive.
          type: str
          sample: "152d2d10-4e18-44aa-86a4-fbd4f7e4cb08"
        device_file_name:
          description: Device file name as recognized by the OS.
          type: str
          sample: "sdh"
        vendor_name:
          description: Vendor or manufacturer name.
          type: str
          sample: "HP"
        firmware_revision:
          description: Firmware version of the drive.
          type: str
          sample: "HPD3"
        locator_led_status:
          description: Current status of the locator LED on the drive.
          type: str
          sample: "Off"
        drive_type:
          description: Type of the drive (e.g., SSD, HDD).
          type: str
          sample: "SSD"
        drive_capacity:
          description: Capacity of the drive in GB.
          type: int
          sample: 800
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBDrivesArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_drives_reconciler import (
    SDSBBlockDrivesReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockDrivesFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBDrivesArguments().drives_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_drives_fact_spec()
        self.logger.writeDebug(f"MOD:hv_sds_block_drives_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Drive Facts ===")
        block_drives = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBBlockDrivesReconciler(self.connection_info)
            block_drives = sdsb_reconciler.get_drives(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_drives_facts:block_drives= {block_drives}"
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Drive Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"drives": block_drives}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Drive Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockDrivesFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
