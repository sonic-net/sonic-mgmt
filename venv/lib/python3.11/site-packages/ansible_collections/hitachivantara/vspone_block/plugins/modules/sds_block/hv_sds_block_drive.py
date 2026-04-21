#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_drive
short_description: Turns ON and OFF the drive locator LED, removes a drive from VSP One SDS Block system cluster.
description:
  - This module allows to control on and off of the locator LED of a drive, and remove a drive on Hitachi SDS Block storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_drive.yml)
version_added: "4.2.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  state:
    description: The desired state of the storage pool.
    type: str
    required: false
    choices: ["present", "absent"]
    default: "present"
  spec:
    description: Specification for the drive.
    type: dict
    required: true
    suboptions:
      id:
        description: The ID of the drive.
        type: str
        required: true
      should_drive_locator_led_on:
        description: Whether to turn on the drive locator LED..
        type: bool
        required: false
        default: false
"""

EXAMPLES = """
- name: Turn on the locator LED of a drive
  hitachivantara.vspone_block.sds_block.hv_sds_block_drive:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      id: "ff27bc05-a181-4de2-b496-675fdc1ce869"
      should_drive_locator_led_on: true

- name: Turn off the locator LED of a drive
  hitachivantara.vspone_block.sds_block.hv_sds_block_drive:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      id: "ff27bc05-a181-4de2-b496-675fdc1ce869"

- name: Remove a drive
  hitachivantara.vspone_block.sds_block.hv_sds_block_drive:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "absent"
    spec:
      id: "ff27bc05-a181-4de2-b496-675fdc1ce869"
"""

RETURN = """
drive:
  description: Details of the drive.
  returned: always
  type: dict
  contains:
    id:
      description: Unique identifier for the drive.
      type: str
      sample: "f17d6b10-d0e4-4604-a0af-f9b3f0d32664"
    wwid:
      description: World Wide Identifier of the drive.
      type: str
      sample: "naa.5000cca0a602f64c"
    status_summary:
      description: Summary of the drive's status.
      type: str
      sample: "Normal"
    status:
      description: Current operational status of the drive.
      type: str
      sample: "Normal"
    type_code:
      description: Manufacturer-specific type code.
      type: str
      sample: "MO000800JWUFU"
    serial_number:
      description: Serial number of the drive.
      type: str
      sample: "V6V1MHJA"
    storage_node_id:
      description: UUID of the storage node associated with the drive.
      type: str
      sample: "db77407c-237d-4ae2-9efe-13332c2a71e8"
    device_file_name:
      description: Device file name as recognized by the OS.
      type: str
      sample: "sda"
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
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_drives_reconciler import (
    SDSBBlockDrivesReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBDrivesArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBDriveManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBDrivesArguments().drive()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_drive_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Drive Operation ===")
        drive = None
        msg = ""
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBBlockDrivesReconciler(self.connection_info)
            drive, msg = sdsb_reconciler.reconcile_drive(self.spec, self.state)
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Drive Operation ===")
            self.module.fail_json(msg=str(e))
        data = {
            "changed": self.connection_info.changed,
            "drive": drive,
            "message": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Drive Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBDriveManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
