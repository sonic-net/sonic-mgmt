#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_storage_node_bmc_connection_facts
short_description: Get storage node BMC access settings from the storage system.
description:
  - Get storage node BMC access settings from the storage system.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/storage_node_bmc_access_setting_facts.yml)
version_added: '4.2.0'
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
    description: Specification for retrieving storage node BMC access settings information.
      This operation is valid only for bare metal.
    type: dict
    required: false
    suboptions:
      id:
        description: Filter storage node BMC access settings by storage node ID.
        type: str
        required: true
"""

EXAMPLES = """
- name: Retrieve information about all storage_node_bmc_connection_information
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_bmc_connection_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about storage_node_bmc_connection_information by specifying id
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_bmc_connection_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "126f360e-c79e-4e75-8f7c-7d91bfd2f0b8"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the internode_port.
  returned: always
  type: dict
  contains:
    storage_node_bmc_connection_information:
      description: A list of BMC connection information about storage nodes.
      type: list
      elements: dict
      contains:
        id:
          description: Storage node ID.
          type: str
          sample: "44f1d113-405e-448f-ad77-fd5554971c36"
        bmc_name:
          description: The host name or IP address (IPv4) of the BMC. An empty string "" is output if nothing is set.
          type: str
          sample: "10.164.118.96"
        bmc_user:
          description: The username for BMC connection. An empty string "" is output if nothing is set.
          type: str
          sample: "administrator@local,10.164.118.96-ptfm-endo_SN01"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBStotagrNodeBmcAccessSettingArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_bmc_settings import (
    SDSBBmcSettingsReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockStorageNodeBmcAccessSettingFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            SDSBStotagrNodeBmcAccessSettingArguments().storage_node_bmc_access_setting_facts()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_storage_node_bmc_access_setting_fact_spec()
        self.logger.writeDebug(
            f"MOD:storage_node_bmc_connection_information:spec= {self.spec}"
        )

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Storage Node BMC Connection Setting Facts ==="
        )
        response = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBBmcSettingsReconciler(self.connection_info)
            response = sdsb_reconciler.get_storage_node_bmc_settings(self.spec)

            self.logger.writeDebug(
                f"MOD:storage_node_bmc_connection_information:storage_node_network_settings= {response}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Storage Node BMC Connection Setting Facts ==="
            )
            self.module.fail_json(msg=str(e))

        data = {"storage_node_bmc_connection_information": response}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(
            "=== End of SDSB Storage Node BMC Connection Setting Facts ==="
        )
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockStorageNodeBmcAccessSettingFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
