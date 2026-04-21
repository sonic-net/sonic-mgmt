#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_iscsi_target_facts
short_description: Retrieves information about iscsi targets from Hitachi VSP storage systems.
description:
  - This module retrieves information about iscsi targets from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/iscsi_target_facts.yml)
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
notes:
  - The output parameters C(subscriber_id) and C(partner_id) were removed in version 3.4.0.
    They were also deprecated due to internal API simplification and are no longer supported.
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
    description: Specification for retrieving iscsi target information.
    type: dict
    required: true
    suboptions:
      ports:
        description: List of ports of the iscsi target.
          Required for the Get iSCSI targets by ports
          /Get iSCSI targets by ports and name tasks.
        required: false
        type: list
        elements: str
      name:
        description: Name of the iscsi target.
          Required for the Get iSCSI targets by ports and name task.
        required: false
        type: str
      iscsi_id:
        description: ID of the iscsi target.
          Required for the Get iSCSI targets by iSCSI ID task.
        required: false
        type: int
"""

EXAMPLES = """
- name: Get all iscsi targets
  hitachivantara.vspone_block.vsp.hv_iscsi_target_facts:
    connection_info:
      address: storage1.example.com
      username: "dummy_username"
      password: "dummy_password"

- name: Get iscsi targets by ports
  hitachivantara.vspone_block.vsp.hv_iscsi_target_facts:
    connection_info:
      address: storage1.example.com
      username: "dummy_username"
      password: "dummy_password"
    spec:
      ports: ['CL4-C']

- name: Get iscsi targets by ports and name
  hitachivantara.vspone_block.vsp.hv_iscsi_target_facts:
    connection_info:
      address: storage1.example.com
      username: "dummy_username"
      password: "dummy_password"
    spec:
      name: 'iscsi-target-server-1'
      ports: ['CL4-C']

- name: Get iscsi targets by iscsi_id
  hitachivantara.vspone_block.vsp.hv_iscsi_target_facts:
    connection_info:
      address: storage1.example.com
      username: "dummy_username"
      password: "dummy_password"
    spec:
      iscsi_id: 10
"""

RETURN = """
ansible_facts:
  description: Dictionary containing the discovered properties of the iSCSI targets.
  returned: always
  type: dict
  contains:
    iscsi_targets:
      description: List of iSCSI targets with their attributes.
      type: list
      elements: dict
      contains:
        auth_param:
          description: Authentication parameters for the iSCSI target.
          type: dict
          contains:
            authentication_mode:
              description: Mode of authentication.
              type: str
              sample: "NONE"
            is_chap_enabled:
              description: Indicates if CHAP is enabled.
              type: bool
              sample: false
            is_chap_required:
              description: Indicates if CHAP is required.
              type: bool
              sample: false
            is_mutual_auth:
              description: Indicates if mutual authentication is enabled.
              type: bool
              sample: false
        chap_users:
          description: List of CHAP users.
          type: list
          elements: str
          sample: []
        host_mode:
          description: Host mode settings.
          type: dict
          contains:
            host_mode:
              description: Host mode.
              type: str
              sample: "WINDOWS_EXTENSION"
            host_mode_options:
              description: List of host mode options.
              type: list
              elements: dict
              contains:
                raid_option:
                  description: RAID option.
                  type: str
                  sample: "EXPANDED_PERSISTENT_RESERVE_KEY"
                raid_option_number:
                  description: RAID option number.
                  type: int
                  sample: 61
              sample:
                - raid_option: "EXPANDED_PERSISTENT_RESERVE_KEY"
                  raid_option_number: 61
                - raid_option: "WS2012"
                  raid_option_number: 73
        iqn:
          description: IQN of the iSCSI target.
          type: str
          sample: "iqn.1994-04.jp.co.hitachi:rsd.has.t.10045.1c008"
        iqn_initiators:
          description: List of IQN initiators.
          type: list
          elements: str
          sample: []
        iscsi_id:
          description: ID of the iSCSI target.
          type: int
          sample: 8
        iscsi_name:
          description: Name of the iSCSI target.
          type: str
          sample: "test-vinod-20-5"
        logical_units:
          description: List of logical units.
          type: list
          elements: dict
          contains:
            host_lun_id:
              description: Host LUN ID.
              type: int
              sample: 0
            logical_unit_id:
              description: Logical unit ID.
              type: int
              sample: 1
          sample: []
        port_id:
          description: Port ID.
          type: str
          sample: "CL1-C"
        resource_group_id:
          description: Resource group ID.
          type: int
          sample: 0
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_iscsi_target import (
    VSPIscsiTargetReconciler,
    VSPIscsiTargetCommonPropertiesExtractor,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPIscsiTargetArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPIscsiTargetFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPIscsiTargetArguments().iscsi_target_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameterManager = VSPParametersManager(self.module.params)
        self.connection_info = parameterManager.get_connection_info()
        self.spec = parameterManager.get_iscsi_target_fact_spec()
        self.serial_number = parameterManager.get_serial()

    def apply(self):
        self.logger.writeInfo("=== Start of iSCSI Target Facts ===")
        iscsi_target_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            vsp_reconciler = VSPIscsiTargetReconciler(
                self.connection_info, self.serial_number
            )
            iscsi_targets = vsp_reconciler.get_iscsi_targets(self.spec)
            self.logger.writeDebug("iscsi_targets = {}", iscsi_targets)
            output_list = iscsi_targets.data_to_list()
            self.logger.writeDebug("output_list = {}", output_list)
            iscsi_target_data_extracted = (
                VSPIscsiTargetCommonPropertiesExtractor().extract(output_list)
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of iSCSI Target Facts ===")
            self.module.fail_json(msg=str(e))
        data = {
            "iscsi_targets": iscsi_target_data_extracted,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of iSCSI Target Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = VSPIscsiTargetFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
