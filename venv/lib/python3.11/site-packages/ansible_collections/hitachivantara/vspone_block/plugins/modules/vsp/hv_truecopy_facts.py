#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_truecopy_facts
short_description: Retrieves TrueCopy pairs information from Hitachi VSP storage systems.
description:
  - This module retrieves the TrueCopy pairs information from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/truecopy_facts.yml)
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
    description: >
      Information required to establish a connection to the secondary storage system.
    required: false
    type: dict
    suboptions:
      address:
        description: IP address or hostname of the Hitachi storage system.
        type: str
        required: true
      username:
        description: Username for authentication. This field is a required field if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication. This field is a required field if api_token is not provided.
        type: str
        required: false
      api_token:
        description: This field is used to pass the value of the lock token of the secondary storage to operate on locked resources.
        type: str
        required: false
  spec:
    description:
      - Specification for retrieving TrueCopy pair information.
    type: dict
    required: false
    suboptions:
      primary_volume_id:
        description:
          - ID of the primary volume to retrieve TrueCopy pair information for.
        type: str
        required: false
      secondary_volume_id:
        description:
          - ID of the secondary volume to retrieve TrueCopy pair information for.
        type: str
        required: false
      copy_group_name:
        description:
          - Name of the copy group to retrieve TrueCopy pair information for.
        type: str
        required: false
      copy_pair_name:
        description:
          - Name of the copy pair to retrieve TrueCopy pair information for.
        type: str
        required: false
      local_device_group_name:
        description:
          - Name of the local device group to retrieve TrueCopy pair information for.
        type: str
        required: false
      remote_device_group_name:
        description:
          - Name of the remote device group to retrieve TrueCopy pair information for.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all TrueCopy pairs
  hitachivantara.vspone_block.vsp.hv_truecopy_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"

- name: Retrieve TrueCopy pair information for a specific volume
  hitachivantara.vspone_block.vsp.hv_truecopy_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      primary_volume_id: 123
"""

RETURN = """
ansible_facts:
  description: Dictionary containing the discovered properties of the TrueCopy pairs.
  returned: always
  type: dict
  contains:
    truecopy_pairs:
      description: A list of TrueCopy pairs information.
      type: list
      elements: dict
      contains:
        consistency_group_id:
          description: Consistency Group ID.
          type: str
          sample: ""
        copy_group_name:
          description: Name of the copy group.
          type: str
          sample: "cp_group_840"
        copy_pair_name:
          description: Name of the copy pair.
          type: str
          sample: "gad_pair_840"
        copy_progress_rate:
          description: Copy progress rate.
          type: int
          sample: -1
        fence_level:
          description: Fence level.
          type: str
          sample: "NEVER"
        primary_volume_id:
          description: Primary volume ID.
          type: int
          sample: 840
        primary_volume_id_hex:
          description: Primary volume ID in hexadecimal format.
          type: str
          sample: "00:03:48"
        pvol_status:
          description: PVOL status.
          type: str
          sample: "PSUE"
        pvol_storage_device_id:
          description: PVOL storage device ID.
          type: str
          sample: "A34000810050"
        remote_mirror_copy_pair_id:
          description: Remote mirror copy pair ID.
          type: str
          sample: "A34000810050,cp_group_840,cp_group_840S_,cp_group_840P_,gad_pair_840"
        replication_type:
          description: Type of replication.
          type: str
          sample: "GAD"
        secondary_volume_id:
          description: Secondary volume ID.
          type: int
          sample: 831
        secondary_volume_id_hex:
          description: Secondary volume ID in hexadecimal format.
          type: str
          sample: "00:03:3F"
        storage_serial_number:
          description: Storage serial number.
          type: str
          sample: "810045"
        svol_status:
          description: SVOL status.
          type: str
          sample: "PSUE"
        svol_storage_device_id:
          description: SVOL storage device ID.
          type: str
          sample: "A34000810045"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_true_copy import (
    VSPTrueCopyReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPTrueCopyArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPTrueCopyFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPTrueCopyArguments().true_copy_facts()
        self.logger.writeDebug(
            f"MOD:hv_truecopy_facts:argument_spec= {self.argument_spec}"
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        self.parameter_manager = VSPParametersManager(self.module.params)
        self.connection_info = self.parameter_manager.get_connection_info()
        self.storage_serial_number = self.parameter_manager.storage_system_info.serial
        self.spec = self.parameter_manager.get_true_copy_fact_spec()
        self.state = self.parameter_manager.get_state()
        self.secondary_connection_info = (
            self.parameter_manager.get_secondary_connection_info()
        )

        self.spec.secondary_connection_info = self.secondary_connection_info
        # self.logger.writeDebug(f"MOD:hv_truecopy_facts:spec= {self.spec}")

    def apply(self):

        self.logger.writeInfo("=== Start of TrueCopy Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            reconciler = VSPTrueCopyReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            tc_pairs = reconciler.get_true_copy_facts(self.spec)
            self.logger.writeDebug(f"MOD:hv_truecopy_facts:tc_pairs= {tc_pairs}")

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of TrueCopy Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "truecopy_pairs": tc_pairs,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of TrueCopy Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = VSPTrueCopyFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
