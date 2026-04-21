#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_cmd_dev
short_description: Manages command devices for VSP block storage systems.
description:
    - This module allows to enable and to disable a command device on VSP block storage systems.
    - It also allows to modify the settings of the command device.
    - For examples go to URL
      U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/cmd_dev.yml)
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
- hitachivantara.vspone_block.common.connection_without_token
options:
  state:
    description: The level of the resource group task.
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
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
    description: Specification for the command device.
    type: dict
    required: false
    suboptions:
      ldev_id:
        description: The id of the LDEV. Required for Enable/Update/Disable tasks.
        type: str
        required: true
      is_security_enabled:
        description: Specify whether to enable the security settings for the command device.
        type: bool
        required: false
      is_user_authentication_enabled:
        description: Specify whether to enable the user authentication settings for the command device.
        type: bool
        required: false
      is_device_group_definition_enabled:
        description: Specify whether to enable the device group definition settings for the command device.
        type: bool
        required: false
"""

EXAMPLES = """
- name: Enable a Command Device
  hitachivantara.vspone_block.vsp.hv_cmd_dev:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      ldev_id: 98
      is_security_enabled: false
      is_user_authentication_enabled: false
      is_device_group_definition_enabled: false

- name: Update the settings of a Command Device
  hitachivantara.vspone_block.vsp.hv_cmd_dev:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      ldev_id: 98
      is_security_enabled: true
      is_user_authentication_enabled: true
      is_device_group_definition_enabled: true

- name: Disable a Command Device
  hitachivantara.vspone_block.vsp.hv_cmd_dev:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: absent
    spec:
      ldev_id: 98
      is_security_enabled: false
      is_user_authentication_enabled: false
      is_device_group_definition_enabled: false
"""

RETURN = """
command_device:
    description: The command device information.
    returned: always except when state is absent
    type: dict
    contains:
        canonical_name:
            description: Unique identifier for the command device.
            type: str
            sample: "naa.60060e80282742005080274200000078"
        clpr_id:
            description: CLPR identifier.
            type: int
            sample: 0
        compression_acceleration_status:
            description: Compression acceleration status.
            type: str
            sample: ""
        data_reduction_process_mode:
            description: Data reduction process mode.
            type: str
            sample: ""
        dedup_compression_progress:
            description: Progress percentage of deduplication and compression.
            type: int
            sample: -1
        dedup_compression_status:
            description: Status of deduplication and compression.
            type: str
            sample: "DISABLED"
        deduplication_compression_mode:
            description: Mode of deduplication and compression.
            type: str
            sample: "disabled"
        emulation_type:
            description: Emulation type of the command device.
            type: str
            sample: "OPEN-V-CVS-CM"
        hostgroups:
            description: List of host groups associated with the command device.
            type: list
            elements: dict
        is_alua:
            description: Indicates if ALUA is enabled.
            type: bool
            sample: false
        is_command_device:
            description: Indicates if it is a command device.
            type: bool
            sample: true
        is_compression_acceleration_enabled:
            description: Indicates if compression acceleration is enabled.
            type: bool
            sample: null
        is_data_reduction_share_enabled:
            description: Indicates if data reduction share is enabled.
            type: bool
            sample: false
        is_device_group_definition_enabled:
            description: Indicates if device group definition is enabled.
            type: bool
            sample: null
        is_encryption_enabled:
            description: Indicates if encryption is enabled.
            type: bool
            sample: false
        is_full_allocation_enabled:
            description: Indicates if full allocation is enabled.
            type: bool
            sample: false
        is_relocation_enabled:
            description: Indicates if relocation is enabled.
            type: bool
            sample: null
        is_security_enabled:
            description: Indicates if security is enabled.
            type: bool
            sample: null
        is_user_authentication_enabled:
            description: Indicates if user authentication is enabled.
            type: bool
            sample: null
        is_write_protected:
            description: Indicates if the command device is write-protected.
            type: bool
            sample: null
        is_write_protected_by_key:
            description: Indicates if the command device is write-protected by key.
            type: bool
            sample: null
        iscsi_targets:
            description: List of iSCSI targets associated with the command device.
            type: list
            elements: dict
        ldev_id:
            description: The ID of the LDEV.
            type: int
            sample: 120
        ldev_id_hex:
            description: Logical unit ID in hexadecimal format.
            type: str
            sample: "00:00:78"
        mp_blade_id:
            description: Management processor blade id.
            type: int
            sample: 1
        name:
            description: Name of the command device.
            type: str
            sample: "smrha-120"
        num_of_ports:
            description: Number of ports associated with the command device.
            type: int
            sample: -1
        nvm_subsystems:
            description: List of NVM subsystems associated with the command device.
            type: list
            elements: dict
        parity_group_id:
            description: ID of the parity group.
            type: str
            sample: ""
        path_count:
            description: Number of paths associated with the command device.
            type: int
            sample: -1
        pool_id:
            description: ID of the pool.
            type: int
            sample: 10
        provision_type:
            description: Provision type of the command device.
            type: str
            sample: "CMD,CVS,HDP"
        qos_settings:
            description: Quality of Service settings for the command device.
            type: dict
            sample: null
        resource_group_id:
            description: ID of the resource group.
            type: int
            sample: 0
        snapshots:
            description: List of snapshots associated with the command device.
            type: list
            elements: dict
        status:
            description: Status of the command device.
            type: str
            sample: "NML"
        storage_serial_number:
            description: Serial number of the storage system.
            type: str
            sample: "810050"
        tiering_policy:
            description: Tiering policy details.
            type: dict
            sample: {}
        total_capacity:
            description: Total capacity of the command device.
            type: str
            sample: "1.00GB"
        total_capacity_in_mb:
            description: Total capacity in megabytes.
            type: float
            sample: 1024.0
        used_capacity:
            description: Used capacity of the command device.
            type: str
            sample: "0.00B"
        used_capacity_in_mb:
            description: Used capacity in megabytes.
            type: float
            sample: 0.0
        virtual_ldev_id:
            description: ID of the virtual LDEV.
            type: int
            sample: -1
        virtual_ldev_id_hex:
            description: Virtual LDEV ID in hex format.
            type: str
            sample: ""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_cmd_dev import (
    VSPCmdDevReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPCmdDevArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPCmdDevManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPCmdDevArguments().cmd_dev()
        # self.logger.writeDebug(f"MOD:hv_cmd_dev:argument_spec= {self.argument_spec}")
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
            # can be added mandotary , optional mandatory arguments
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = None
            self.spec = self.parameter_manager.get_cmd_dev_spec()
            self.state = self.parameter_manager.get_state()

        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of Command Device operation. ===")
        registration_message = validate_ansible_product_registration()

        cmd_dev = None
        comment = None
        try:
            reconciler = VSPCmdDevReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            cmd_dev, comment = reconciler.reconcile_cmd_dev(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Command Device operation. ===")
            self.module.fail_json(msg=str(e))

        resp = {
            "changed": self.connection_info.changed,
        }
        if cmd_dev:
            resp["command_device"] = cmd_dev
        if comment:
            resp["comment"] = comment
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Command Device operation. ===")
        self.module.exit_json(**resp)


def main(module=None):
    obj_store = VSPCmdDevManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
