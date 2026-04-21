#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_external_path_group
short_description: Manages External Path Groups in the Hitachi VSP storage systems.
description:
  - This module adds and removes external paths to the external path group in the Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/external_path_group.yml)
version_added: '3.5.0'
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
    description: The level of the External Path Group task.
    type: str
    required: false
    choices: ['present', 'add_external_path', 'remove_external_path']
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
    description: Specification for the External Path Group management.
    type: dict
    required: false
    suboptions:
      external_path_group_id:
        description: External path group number. Required for the Add/Remove tasks.
        type: int
        required: true
      external_fc_paths:
        description: List of external FC path objects. Required for the Add/Remove tasks.
        type: list
        elements: dict
        required: false
        suboptions:
          port:
            description: Number of the port on the local storage system. Required for the Add/Remove tasks.
            type: str
            required: true
          external_wwn:
            description: WWN of the external storage system. Required for the Add/Remove tasks.
            type: str
            required: true
      external_iscsi_target_paths:
        description: List of external iSCSI target path objects. Required for the Add/Remove tasks.
        type: list
        elements: dict
        required: false
        suboptions:
          port:
            description: Number of the port on the local storage system. Required for the Add/Remove tasks.
            type: str
            required: true
          external_iscsi_ip_address:
            description: IP address of the iSCSI target on the external storage system. Required for the Add/Remove tasks.
            type: str
            required: true
          external_iscsi_name:
            description: iSCSI name of the iSCSI target on the external storage system. Required for the Add/Remove tasks.
            type: str
            required: true
"""

EXAMPLES = """
- name: Add external paths to an external path group
  hitachivantara.vspone_block.vsp.hv_external_path_group:
    connection_info:
      address: storage1.company.com
      username: 'username'
      password: 'password'
    state: "add_external_path"
    spec:
      external_path_group_id: 1
      external_fc_paths:
        - port: "CL6-A"
          external_wwn: "50060e8012277d61"
      external_iscsi_target_paths:
        - port: "CL1-C"
          external_iscsi_ip_address: "172.25.59.214"
          external_iscsi_name: "iqn.1994-04.jp.co.hitachi:rsd.has.t.10045.1c020"

- name: Add external paths to an external path group
  hitachivantara.vspone_block.vsp.hv_external_path_group:
    connection_info:
      address: storage1.company.com
      username: 'username'
      password: 'password'
    state: "remove_external_path"
    spec:
      external_path_group_id: 1
      external_fc_paths:
        - port: "CL6-A"
          external_wwn: "50060e8012277d61"
      external_iscsi_target_paths:
        - port: "CL1-C"
          external_iscsi_ip_address: "172.25.59.214"
          external_iscsi_name: "iqn.1994-04.jp.co.hitachi:rsd.has.t.10045.1c020"
"""

RETURN = """
external_path_group:
  description: The External Path Group managed by the module.
  returned: success
  type: list
  elements: dict
  contains:
    external_path_group_id:
      description: External path group number.
      type: int
      sample: 1
    external_serial_number:
      description: Serial number of the external storage system.
      type: str
      sample: "410109"
    storage_serial_number:
      description: Serial number of the storage system.
      type: str
      sample: "410109"
    external_parity_groups:
      description: The list of external parity groups.
      type: list
      elements: dict
      contains:
        cache_mode:
          description: Cache mode.
          type: str
          sample: "E"
        external_parity_group_id:
          description: External parity group ID.
          type: str
          sample: "1-3"
        external_parity_group_status:
          description: Status of the external parity group.
          type: str
          sample: "NML"
        is_data_direct_mapping:
          description: Whether the data direct mapping attribute is enabled.
          type: bool
          sample: false
        is_inflow_control_enabled:
          description: Inflow cache control.
          type: bool
          sample: false
        load_balance_mode:
          description: The load balancing method for I/O operations for the external storage system.
          type: str
          sample: "N"
        mp_blade_id:
          description: Inflow cache control.
          type: int
          sample: 0
        path_mode:
          description: Path mode of the external storage system.
          type: str
          sample: "M"
        external_luns:
          description: List of LUNs of the external storage system.
          type: list
          elements: dict
          contains:
            external_lun:
              description: LUN within the ports of the external storage system.
              type: int
              sample: 2
            external_wwn:
              description: WWN of the external storage system.
              type: str
              sample: "50060e8012277d71"
            path_status:
              description: Status of the external path.
              type: str
              sample: "NML"
            port_id:
              description: Port number.
              type: str
              sample: "CL6-B"
            priority:
              description: Priority within the external path group.
              type: int
              sample: 1
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_external_path_group import (
    VSPExternalPathGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPExternalPathGroupArguments,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class ModuleManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPExternalPathGroupArguments().external_path_group()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_external_path_group_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of External Path Group operation ===")
        try:
            registration_message = validate_ansible_product_registration()
            result = VSPExternalPathGroupReconciler(
                self.params_manager.connection_info, self.serial
            ).external_path_group_reconcile(self.state, self.spec)

            self.connection_info.changed = False
            msg = self.get_message()

            if result is None:
                result = []

            response_dict = {
                "changed": self.connection_info.changed,
                "external_path_group": result,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of External Path Group operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of External Path Group operation. ===")
            self.module.fail_json(msg=str(ex))

    def get_message(self):

        if self.state == "present":
            return "Create external path group is not supported."
        elif self.state == "remove_external_path":
            self.connection_info.changed = True
            return "External paths removed from the external path group successfully."
        elif self.state == "add_external_path":
            self.connection_info.changed = True
            return "External paths added to the external path group successfully."
        else:
            return "Unknown state provided."


def main(module=None):
    obj_store = ModuleManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
