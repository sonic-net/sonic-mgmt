#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_gad_facts
short_description: Retrieves GAD pairs information from Hitachi VSP storage systems.
description:
  - This module allows to fetch GAD pairs on Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/gad_pair_facts.yml)
version_added: '3.1.0'
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
  - The output parameters C(entitlement_status) and C(partner_id) were removed in version 3.4.0.
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
  secondary_connection_info:
    description: Information required to establish a connection to the secondary storage system.
    required: false
    type: dict
    suboptions:
      address:
        description: IP address or hostname of the secondary storage.
        type: str
        required: true
      username:
        description: Username for authentication. This field is required for secondary storage connection if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication. This field is required for secondary storage connection api_token is not provided.
        type: str
        required: false
      api_token:
        description: Value of the lock token to operate on locked resources. Provide this only when operation is on locked resources.
        type: str
        required: false
  spec:
    description: Specification for the GAD pairs task.
    type: dict
    required: true
    suboptions:
      primary_volume_id:
        description: Primary Volume Id. Required for the Get GAD pair using primary volume ID task.
        type: str
        required: false
      copy_group_name:
          description: Copy Group Name.
          type: str
          required: False
      secondary_storage_serial_number:
          description: Secondary Storage Serial Number.
          type: int
          required: False
      secondary_volume_id:
          description: Secondary Volume Id. Required for the Get GAD pair using secondary volume ID task.
          type: str
          required: False
      copy_pair_name:
          description: Copy Pair Name.
          type: str
          required: False
      local_device_group_name:
          description: Local Device Group Name.
          type: str
          required: False
      remote_device_group_name:
          description: Remote Device Group Name.
          type: str
          required: False
"""

EXAMPLES = """
- name: Get all GAD pairs
  hitachivantara.vspone_block.vsp.hv_gad_facts:
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the GAD pairs.
  returned: success
  type: dict
  contains:
    gad_pair:
      description: List of GAD pairs with their attributes.
      type: list
      elements: dict
      contains:
        consistency_group_id:
          description: Consistency group ID.
          type: int
          sample: -1
        copy_group_name:
          description: Copy group name.
          type: str
          sample: "cp_group_840"
        copy_pace_track_size:
          description: Copy pace track size.
          type: str
          sample: ""
        copy_pair_name:
          description: Pair name.
          type: str
          sample: "gad_pair_840"
        copy_rate:
          description: Copy rate.
          type: str
          sample: ""
        is_alua_enabled:
          description: Whether ALUA is enabled or not.
          type: bool
          sample: false
        local_device_group_name:
          description: Local device group name.
          type: str
          sample: "cp_group_840S_"
        mirror_unit_id:
          description: Mirror unit ID.
          type: int
          sample: 0
        primary_virtual_serial_number:
          description: Primary virtual serial number.
          type: int
          sample: -1
        primary_virtual_volume_id:
          description: Primary virtual volume id.
          type: int
          sample: -1
        primary_volume_id:
          description: Primary volume ID.
          type: int
          sample: 840
        primary_volume_id_hex:
          description: Primary volume ID in hexadecimal format.
          type: str
          sample: "00:03:48"
        primary_volume_status:
          description: Status of the GAD pair.
          type: str
          sample: "PSUE"
        primary_volume_storage_id:
          description: Primary volume storage ID.
          type: str
          sample: "810050"
        primary_vsm_resource_group_name:
          description: Primary VSM resource group name.
          type: str
          sample: ""
        quorum_disk_id:
          description: Quorum disk ID.
          type: int
          sample: 21
        remote_device_group_name:
          description: Remote device group name.
          type: str
          sample: "cp_group_840P_"
        remote_mirror_copy_pair_id:
          description: Remote mirror copy pair ID.
          type: str
          sample: "A34000810050,cp_group_840,cp_group_840S_,cp_group_840P_,gad_pair_840"
        secondary_virtual_serial_number:
          description: Secondary virtual storage ID.
          type: int
          sample: -1
        secondary_virtual_volume_id:
          description: Secondary virtual volume ID.
          type: int
          sample: -1
        secondary_volume_id:
          description: Secondary volume ID.
          type: int
          sample: 831
        secondary_volume_id_hex:
          description: Secondary volume ID in hexadecimal format.
          type: str
          sample: "00:03:3F"
        secondary_volume_status:
          description: Status of the GAD pair.
          type: str
          sample: "PSUE"
        secondary_volume_storage_id:
          description: Secondary volume storage ID.
          type: str
          sample: "810045"
        secondary_vsm_resource_group_name:
          description: Secondary VSM resource group name.
          type: str
          sample: ""
"""

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_gad_pair,
)
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPGADArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPGADPairManagerFact:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPGADArguments().gad_pair_fact_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.gad_pair_fact_spec()
            self.serial = self.params_manager.get_serial()
            self.connection_info = self.params_manager.get_connection_info()
            self.secondary_connection_info = (
                self.params_manager.get_secondary_connection_info()
            )

            # sng20241115 for the remote_connection_manager
            self.spec.secondary_connection_info = self.secondary_connection_info
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of GAD Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            reconciler = vsp_gad_pair.VSPGadPairReconciler(
                self.connection_info, self.secondary_connection_info, self.serial
            )
            response = reconciler.gad_pair_facts(self.spec)

            result = response if not isinstance(response, str) else None
            response_dict = {
                "gad_pair": result,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of GAD Facts ===")
            self.module.exit_json(changed=False, ansible_facts=response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of GAD Facts ===")
            self.module.fail_json(msg=str(ex))


def main(module=None):
    obj_store = VSPGADPairManagerFact()
    obj_store.apply()


if __name__ == "__main__":
    main()
