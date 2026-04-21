#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_hg_facts
short_description: Retrieves host group information from a specified Hitachi VSP storage system.
description:
  - This module fetches detailed information about host groups configured within a given Hitachi VSP storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/hostgroup_facts.yml)
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
  - The output parameters C(entitlement_status), C(subscriber_id) and C(partner_id) were removed in version 3.4.0.
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
    description: Specification for retrieving Host Group information.
    type: dict
    required: false
    suboptions:
      name:
        description: If specified, filters the results to include only the host groups with this name.
          Required for the Get host groups of specific ports with the same host group name
          /Get hostgroup details using hostgroup name tasks.
        type: str
        required: false
      ports:
        description: Filters the host groups to those associated with the specified Storage FC ports.
          Required for the Get host groups of specific ports/Get host groups of specific ports with the same host group name
          /Get host groups of specific ports, including WWNs and LDEVs/Get hostgroup details using hostgroup number
          /Get hostgroup details using hostgroup name/Get hostgroup details with specific LUN number tasks.
        type: list
        required: false
        elements: str
      query:
        description: Determines what information to return about the host groups.
          Can specify 'wwns' for HBA WWNs, 'ldevs' for mapped LDEVs, or both.
          Required for the Get host groups of specific ports, including WWNs and LDEVs task.
        type: list
        elements: str
        required: false
        choices: ['wwns', 'ldevs']
        default: []
      lun:
        description: Filters the host groups to those associated with the specified LUN.
          Required for the Get hostgroup details with specific LUN number task.
        type: int
        required: false
      host_group_number:
        description: Filters the host groups to those associated with the specified host group number.
          Required for the Get hostgroup details using hostgroup number task.
        type: int
        required: false
"""

EXAMPLES = """
- name: Get all host groups
  hitachivantara.vspone_block.vsp.hv_hg_facts:
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"

- name: Get Host Groups of specific ports
  hitachivantara.vspone_block.vsp.hv_hg_facts:
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      ports: ['CL1-A', 'CL2-B']
"""

RETURN = """
ansible_facts:
  description: The collected host group facts.
  returned: always
  type: dict
  contains:
    hostGroups:
      description: List of host groups retrieved from the storage system.
      returned: always
      type: list
      elements: dict
      contains:
        host_group_id:
          description: ID of the host group.
          type: int
          sample: 33
        host_group_name:
          description: Name of the host group.
          type: str
          sample: "AutoAnsibleHurPri01"
        host_mode:
          description: Host mode of the host group.
          type: str
          sample: "LINUX"
        host_mode_options:
          description: List of host mode options.
          type: list
          elements: dict
          contains:
            host_mode_option:
              description: Host mode option.
              type: str
              sample: "EXTENDED_COPY"
            host_mode_option_number:
              description: Host mode option number.
              type: int
              sample: 54
        lun_paths:
          description: List of LUN paths.
          type: list
          elements: dict
          contains:
            asymmetric_access_state:
              description: Asymmetric access state.
              type: str
              sample: "Active/Optimized"
            host_group_number:
              description: Host group number.
              type: int
              sample: 33
            host_mode:
              description: Host mode for the LUN path.
              type: str
              sample: "LINUX/IRIX"
            host_mode_options:
              description: List of host mode options for the LUN path.
              type: list
              elements: dict
            is_alua_enabled:
              description: Whether ALUA is enabled.
              type: bool
              sample: false
            is_command_device:
              description: Whether this is a command device.
              type: bool
              sample: false
            ldev_id:
              description: LDEV ID.
              type: int
              sample: 3694
            ldev_id_hex:
              description: LDEV ID in hexadecimal format.
              type: str
              sample: "00:0E:6E"
            lu_host_reserve:
              description: LU host reserve information.
              type: dict
              contains:
                aca_reserve:
                  description: ACA reserve status.
                  type: bool
                  sample: false
                mainframe:
                  description: Mainframe reserve status.
                  type: bool
                  sample: false
                open_system:
                  description: Open system reserve status.
                  type: bool
                  sample: false
                persistent:
                  description: Persistent reserve status.
                  type: bool
                  sample: false
                pgr_key:
                  description: PGR key status.
                  type: bool
                  sample: false
            lun:
              description: LUN number.
              type: int
              sample: 17
            lun_id:
              description: LUN ID.
              type: str
              sample: "CL4-B,33,17"
            port_id:
              description: Port ID for the LUN path.
              type: str
              sample: "CL4-B"
        port_id:
          description: Port associated with the host group.
          type: str
          sample: "CL4-B"
        resource_group_id:
          description: Resource group ID.
          type: int
          sample: 0
        wwns:
          description: List of WWNs.
          type: list
          elements: dict
          contains:
            id:
              description: WWN ID.
              type: str
              sample: "1212121212121212"
            name:
              description: Name associated with the WWN.
              type: str
              sample: ""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPHostGroupArguments,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_host_group,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.message.module_msgs import (
    ModuleMessage,
)


class VSPHostGroupFactsManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPHostGroupArguments().host_group_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        try:
            self.params = VSPParametersManager(self.module.params)
            self.serial_number = self.params.storage_system_info.serial
            self.spec = self.params.get_host_group_spec()
            self.connection_info = self.params.get_connection_info()

        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Host Group Facts ===")
        registration_message = validate_ansible_product_registration()
        host_group_data = None
        host_group_data_extracted = {}
        try:
            host_group_data = self.direct_host_group_read()
            self.logger.writeDebug(f"host_group_data= {host_group_data}")
            # host_group_data_result = (
            #     vsp_host_group.VSPHostGroupCommonPropertiesExtractor(
            #         self.serial_number
            #     ).extract(host_group_data)
            # )
            host_group_data_extracted = {"hostGroups": host_group_data}

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Host Group Facts ===")
            self.module.fail_json(msg=str(e))
        if registration_message:
            host_group_data_extracted["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{host_group_data_extracted}")
        self.logger.writeInfo("=== End of Host Group Facts ===")
        self.module.exit_json(changed=False, ansible_facts=host_group_data_extracted)

    def direct_host_group_read(self):
        result = vsp_host_group.VSPHostGroupReconciler(
            self.connection_info, self.serial_number
        ).get_host_groups(self.spec)
        if result is None:
            raise ValueError(ModuleMessage.HOST_GROUP_NOT_FOUND.value)
        return result.data_to_snake_case_list()


def main():
    obj_store = VSPHostGroupFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
