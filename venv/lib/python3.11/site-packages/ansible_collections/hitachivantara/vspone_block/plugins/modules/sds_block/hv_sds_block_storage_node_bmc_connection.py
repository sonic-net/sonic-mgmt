#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_storage_node_bmc_connection
short_description: Manages BMC connection settings for a storage node on VSP One SDS Block and Cloud systems.
description:
  - This module allows to update the BMC connection settings of a storage node.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/storage_node_bmc_connection.yml)
version_added: "4.3.0"
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
    choices: ['present']
    default: 'present'
  spec:
    description: Specification for the BMC connection settings.
    type: dict
    required: true
    suboptions:
      name:
        description: The name of the storage node.
        type: str
        required: false
      id:
        description: The UUID of the storage node.
        type: str
        required: false
      bmc_name:
        description: The host name or IP address (IPv4) of the BMC.
        type: str
        required: false
      bmc_user:
        description: The username for BMC connection.
        type: str
        required: false
      bmc_password:
        description: The password for BMC connection.
        type: str
        required: false
"""

EXAMPLES = """
- name: Update BMC connection information for one storage node by id
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_bmc_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      id: "72ecacd0-1d4c-431c-80e8-80924a1b8f28"
      bmc_name: "10.76.45.222"
      bmc_user: "admin"
      bmc_password: "CHANGE_ME_SET_YOUR_PASSWORD"

- name: Update BMC connection information for one storage node by name
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_bmc_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "SN01"
      bmc_name: "10.76.45.222"
      bmc_user: "admin"
      bmc_password: "CHANGE_ME_SET_YOUR_PASSWORD"
"""

RETURN = """
storage_node_bmc_connection_information:
  description: BMC connection information of the storage node.
  type: dict
  returned: always
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
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_bmc_settings import (
    SDSBBmcSettingsReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBStotagrNodeBmcAccessSettingArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBStorageNodeManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = (
            SDSBStotagrNodeBmcAccessSettingArguments().storage_node_bmc_access_setting()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            parameter_manager = SDSBParametersManager(self.module.params)
            self.connection_info = parameter_manager.get_connection_info()
            self.spec = parameter_manager.get_storage_node_bmc_access_setting_spec()
            self.state = parameter_manager.get_state()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Storage Node BMC Connection Setting Operation ==="
        )
        storage_nodes = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBBmcSettingsReconciler(self.connection_info)
            storage_node_bmc_connection_information = (
                sdsb_reconciler.reconcile_storage_node_bmc_settings(
                    self.spec, self.state
                )
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Storage Node BMC Connection Setting Operation ==="
            )
            self.module.fail_json(msg=str(e))
        data = {
            "changed": self.connection_info.changed,
            "storage_node_bmc_connection_information": storage_node_bmc_connection_information,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo(
            "=== End of SDSB Storage Node BMC Connection Setting Operation ==="
        )
        self.module.exit_json(**data)


def main():
    obj_store = SDSBStorageNodeManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
