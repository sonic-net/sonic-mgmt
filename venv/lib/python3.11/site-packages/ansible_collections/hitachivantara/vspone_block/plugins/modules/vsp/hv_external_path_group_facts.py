#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_external_path_group_facts
short_description: Retrieves information about External Path Group from Hitachi VSP storage systems.
description:
  - This module retrieves information about External Volume from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/external_path_group_facts.yml)
version_added: '3.5.0'
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
- hitachivantara.vspone_block.common.connection_without_token
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
    description: Specification for retrieving External Path Group information.
    type: dict
    required: false
    suboptions:
      external_path_group_id:
        description: The external path group ID. Required for the Get a specific external path group task.
        type: int
        required: false

"""

EXAMPLES = """
- name: Retrieve information about all External Path Groups
  hitachivantara.vspone_block.vsp.hv_external_path_group_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"

- name: Retrieve information about a specific External Path Groups
  hitachivantara.vspone_block.vsp.hv_external_path_group_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"
    spec:
      external_path_group_id: 1
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the external path groups.
  returned: always
  type: list
  elements: dict
  contains:
    external_path_group_id:
      description: External path group ID.
      type: int
      sample: 1
    external_product_id:
      description: External product ID.
      type: str
      sample: "VSP Gx00"
    external_serial_number:
      description: External serial number.
      type: str
      sample: "410109"
    storage_serial_number:
      description: Storage serial number.
      type: str
      sample: "810050"
    external_paths:
      description: The list of external paths.
      type: list
      elements: dict
      contains:
        port_id:
          description: Port ID.
          type: str
          sample: "CL6-B"
        external_wwn:
          description: External WWN.
          type: str
          sample: "50060e8012277d61"
        q_depth:
          description: Queue depth.
          type: str
          sample: "32"
        io_time_out:
          description: IO timeout.
          type: int
          sample: 30
        blocked_path_monitoring:
          description: Blocked path monitoring.
          type: int
          sample: 0
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
          description: External Parity Group Status.
          type: str
          sample: "NML"
        is_data_direct_mapping:
          description: Data direct mapping.
          type: bool
          sample: false
        load_balance_mode:
          description: Load balance mode.
          type: str
          sample: "N"
        mp_blade_id:
          description: Load balance mode.
          type: int
          sample: 0
        path_mode:
          description: Load balance mode.
          type: str
          sample: "M"
        external_luns:
          description: External lun IDs.
          type: list
          elements: dict
          contains:
            external_lun:
              description: External lun.
              type: int
              sample: 2
            external_wwn:
              description: External WWN.
              type: str
              sample: "50060e8012277d61"
            path_status:
              description: Path status.
              type: str
              sample: "NML"
            port_id:
              description: Path status.
              type: str
              sample: "CL6-B"
            priority:
              description: External lun.
              type: int
              sample: 2
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


class FactManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPExternalPathGroupArguments().external_path_group_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_external_path_group_fact_spec()
            self.serial = self.params_manager.get_serial()
            self.logger.writeDebug("20250228 serial={}", self.serial)
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of External Path Group Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = []
            result = VSPExternalPathGroupReconciler(
                self.params_manager.connection_info, self.serial
            ).external_path_group_facts(self.spec)

        except Exception as ex:

            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of External Path Group Facts ===")
            self.module.fail_json(msg=str(ex))
        data = {
            "external_path_groups": result,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        # self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of External  Path Group Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = FactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
