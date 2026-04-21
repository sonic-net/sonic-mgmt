#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_capacity_management_settings_facts
short_description: Retrieves capacity management settings from VSP One SDS Block and Cloud system cluster.
description:
  - Get capacity management settings from storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/capacity_management_settings_facts.yml)
version_added: "4.2.0"
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
    description: Parameters for filtering or identifying capacity management settings to gather facts about.
    type: dict
    required: false
    suboptions:
      storage_controller_id:
        description: Filter capacity management settings by storage_controller ID.
        required: false
        type: str
"""

EXAMPLES = """
- name: Retrieve capacity management settings for the cluster and for all storage controllers
  hitachivantara.vspone_block.sds_block.hv_sds_block_capacity_management_settings_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve capacity management settings for the cluster and for a specific storage controller
  hitachivantara.vspone_block.sds_block.hv_sds_block_capacity_management_settings_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      storage_controller_id: "126f360e-c79e-4e75-8f7c-7d91bfd2f0b8"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the capacity management settings.
  returned: always
  type: dict
  contains:
    capacity_management_settings:
      description: Dictionary of capacity_management_settings.
      type: dict
      contains:
        is_storage_cluster_capacity_balancing_enabled:
          description: Capacity balancing settings of the storage cluster.
          type: bool
          sample: true
        storage_controllers_capacity_balancing_settings:
          description: A list of storage controller capacity balancing output objects.
          type: list
          elements: dict
          contains:
            id:
              description: Storage controller ID.
              type: str
              sample: "25244614-4af4-4922-839a-8528c9e4fd7f"
            is_enabled:
              description: Specify whether to enable or disable capacity balancing of a storage controller. If this is enabled,
                capacity balancing applies to this storage controller. If this is disabled, capacity balancing does not apply to this storage controller.
              type: bool
              sample: true
            status:
              description: Capacity balancing status of a storage controller. Either Enabled or Disabled.
              type: str
              sample: "Enabled"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBCapacityManagementSettingsArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_capacity_management_settings import (
    SDSBCapacityManagementSettingsReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockCapacityManagementSettingsFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            SDSBCapacityManagementSettingsArguments().capacity_management_settings_facts()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_capacity_management_settings_fact_spec()
        self.logger.writeDebug(
            f"MOD:hv_sds_block_capacity_management_settings_facts:spec= {self.spec}"
        )

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Capacity Management Settings Facts ==="
        )
        capacity_settings = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBCapacityManagementSettingsReconciler(
                self.connection_info
            )
            capacity_settings = sdsb_reconciler.get_capacity_management_settings(
                self.spec
            )

            self.logger.writeDebug(
                f"MOD:hv_sds_block_capacity_management_settings_facts:capacity_management_settings= {capacity_settings}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Capacity Management Settings Facts ==="
            )
            self.module.fail_json(msg=str(e))

        data = {"capacity_management_settings": capacity_settings}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Capacity Management Settings Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockCapacityManagementSettingsFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
