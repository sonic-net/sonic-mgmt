#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_external_paritygroup
short_description: Manages assignment of MP blade and CLPR to an External Parity Group from Hitachi VSP storage systems.
description:
  - This module retrieves information about External Volume from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/external_parity_group_facts.yml)
version_added: '4.0.0'
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
options:
  state:
    description: The level of the External Path Group task.
    type: str
    required: false
    choices: ['present', 'assign_external_parity_group', 'change_mp_blade', 'disconnect', 'absent']
    default: 'present'
  connection_info:
    description: Information required to establish a connection to the storage system.
    type: dict
    required: true
    suboptions:
      address:
        description: IP address or hostname of the storage system.
        type: str
        required: true
      username:
        description: Username for authentication. This is a required field if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication. This is a required field if api_token is not provided.
        type: str
        required: false
      connection_type:
        description: Type of connection to the storage system.
        type: str
        required: false
        choices: ['direct']
        default: 'direct'
      api_token:
        description: This field is used to pass the value of the lock token to operate on locked resources.
        type: str
        required: false
  spec:
    description: Specification for External Parity Group.
    type: dict
    required: false
    suboptions:
      external_parity_group_id:
        description: The external parity group ID. This is a required field for all the operations.
        type: str
        required: true
      external_path_group_id:
        description: External path group ID. This is a required field for the create operation.
        type: int
        required: false
      port_id:
        description: Number of the port on the local storage system. This is a required field for the create operation.
        type: str
        required: false
      external_wwn:
        description: WWN of the external storage system. This is a required field for create operation.
        type: str
        required: false
      lun_id:
        description: LUN of the port on the external storage system. This is a required field for the create operation.
        type: int
        required: false
      emulation_type:
        description: Emulation type. This is an optional field for create operation.
        type: str
        required: false
        choices: [
            "OPEN-3", "OPEN-8", "OPEN-9", "OPEN-E", "OPEN-K",
            "OPEN-L", "OPEN-V", "3380-3", "3380-3A", "3380-3B",
            "3380-3C", "3390-1", "3390-2", "3390-3", "3390-A",
            "3390-3A", "3390-3B", "3390-3C", "3390-3R", "3390-9",
            "3390-9A", "3390-9B", "3390-9C", "3390-L", "3390-LA",
            "3390-LB", "3390-LC", "3390-M", "3390-MA", "3390-MB",
            "3390-MC", "3390-V", "6586-G", "6586-J", "6586-K",
            "6586-KA", "6586-KB", "6586-KC", "6588-1", "6588-3",
            "6588-9", "6588-A", "6588-3A", "6588-3B", "6588-3C",
            "6588-9A", "6588-9B", "6588-9C", "6588-L", "6588-LA",
            "6588-LB", "6588-LC"
          ]
        default: "OPEN-V"
      is_external_attribute_migration:
        description: Whether to set the nondisruptive migration attribute for the external volume group. This is an optional field for
          the create operation. If this attribute is omitted, false is set.
        type: bool
        required: false
      command_device_ldev_id:
        description: LDEV number of the remote command device. This is an optional field for the create operation.
          The specified LDEV number is assigned to the remote command device.
        type: int
        required: false
      mp_blade_id:
        description: The blade number of the MP blade to be assigned to the external volume group.
        type: int
        required: false
      clpr_id:
        description: CLPR number to be used by the external volume group. This is an optional field for the create operation.
          Specify a decimal (base 10) number in the range from 0 to 31. If this attribute is omitted for the create, 0 is set.
        type: int
        required: false
      force:
        description: Specify whether to forcibly unmap the external volume without destaging it. This is an optional field for
          the delete operation. If this attribute is omitted, false is set. Specify true to unmap the volume on the external
          storage system without destaging it.
        type: bool
        required: false
"""

EXAMPLES = """
- name: Change the MP blade assigned to an external parity group
  hitachivantara.vspone_block.vsp.hv_external_path_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"
    state: "change_mp_blade"
    spec:
      external_parity_group_id: "1-5"
      mp_blade_id: 0

- name: Assign external parity group to a CLPR
  hitachivantara.vspone_block.vsp.hv_external_path_group_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"
    state: "assign_external_parity_group"
    spec:
      external_parity_group_id: "1-5"
      clpr_id: 1

- name: Create external parity group
  hitachivantara.vspone_block.vsp.hv_external_paritygroup:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"
    state: "present"
    spec:
      external_parity_group_id: "1-17"
      external_path_group_id: 4
      port_id: "CL6-B"
      external_wwn: "50060e8012277d71"
      lun_id: 20

- name: Disconnect from a volume on the external storage system
  hitachivantara.vspone_block.vsp.hv_external_paritygroup:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"
    state: "disconnect"
    spec:
      external_parity_group_id: "1-17"

- name: Delete external parity group
  hitachivantara.vspone_block.vsp.hv_external_paritygroup:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"
    state: "disconnect"
    spec:
      external_parity_group_id: "1-17"
      force: true
"""

RETURN = """
external_parity_groups:
  description: >
    List of discovered external parity groups.
  returned: always
  type: list
  elements: dict
  contains:
    external_parity_group_id:
      description: External parity group ID.
      type: str
      sample: "1-17"
    available_volume_capacity:
      description: Available capacity (GB).
      type: int
      sample: 20
    available_volume_capacity_in_kb:
      description: Available capacity (KB).
      type: int
      sample: 20971520
    used_capacity_rate:
      description: Usage rate of the external parity group.
      type: int
      sample: 0
    clpr_id:
      description: CLPR number assigned to the external parity group.
      type: int
      sample: 0
    emulation_type:
      description: Emulation type.
      type: str
      sample: "OPEN-V"
    external_product_id:
      description: External product identifier.
      type: str
      sample: "OPEN-V"
    num_of_ldevs:
      description: Number of LDEVs in the external parity group.
      type: int
      sample: 0
    storage_serial_number:
      description: Storage serial number.
      type: str
      sample: "810045"
    spaces:
      description: Free space and LDEV information for the external parity group.
      type: list
      elements: dict
      contains:
        lba_size:
          description: Size of the partition in the external parity group (hex string, multiple of 512 bytes).
          type: str
          sample: "0x000002800000"
        ldev_id:
          description: LDEV number or false if not defined.
          type: raw
          sample: 1351
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_external_parity_group import (
    VSPExternalParityGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPExternalParityGroupArguments,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class Manager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPExternalParityGroupArguments().external_parity_group()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.spec = self.params_manager.get_external_parity_group_spec()
            self.serial = self.params_manager.get_serial()
            self.logger.writeDebug("20250228 serial={}", self.serial)
            self.state = self.params_manager.get_state()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of External Parity Group operation ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = []
            result, msg = VSPExternalParityGroupReconciler(
                self.connection_info, self.serial
            ).external_parity_group_reconcile(self.state, self.spec)

        except Exception as ex:

            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of External Parity Group operation ===")
            self.module.fail_json(msg=str(ex))
        data = {
            "changed": self.connection_info.changed,
            "external_parity_groups": result,
            "msg": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        # self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of External Parity Group operation ===")
        self.module.exit_json(**data)


def main(module=None):
    obj_store = Manager()
    obj_store.apply()


if __name__ == "__main__":
    main()
