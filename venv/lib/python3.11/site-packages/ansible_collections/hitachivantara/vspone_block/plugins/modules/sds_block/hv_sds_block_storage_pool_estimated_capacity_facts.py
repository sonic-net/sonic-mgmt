#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_storage_pool_estimated_capacity_facts
short_description: Obtains the preliminary calculation results of the storage pool logical capacity (unit TiB).
description:
  - Obtains the preliminary calculation results of the storage pool logical capacity (unit TiB)  in the specified configuration
    and when adding resources or changing resources to the current configuration.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/estimated_capacity_facts.yml)
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
    description: Parameters for getting estimated capacity for specified configuration or updated configuration.
      This feature is available only with a Floating base license and for the AWS cloud model.
    type: dict
    required: true
    suboptions:
      id:
        description: The ID of the storage pool.
        required: false
        type: str
      name:
        description: The name of the storage pool.
        required: false
        type: str
      number_of_storage_nodes:
        description: The number of storage nodes.
        required: true
        type: int
      number_of_drives:
        description: The number of drives for each storage node.
        required: true
        type: int
      number_of_tolerable_drive_failures:
        description: The number of drive failures that can be allowed.
        required: true
        type: int
      query:
        description: Whether the estimates is for current configuration or updated configuration.
        required: true
        type: str
        choices: ["specified_configuration",  "updated_configuration"]
"""

EXAMPLES = """
- name: Retrieve storage pool estimated capacity for specified configuration
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_pool_estimated_capacity_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "5b2d757a-ffec-42f0-979c-4d5d7b8af05e"
      number_of_storage_nodes: 2
      number_of_drives: 6
      number_of_tolerable_drive_failures: 0
      query: "specified_configuration"

- name: Retrieve storage pool estimated capacity for updated configuration
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_pool_estimated_capacity_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "5b2d757a-ffec-42f0-979c-4d5d7b8af05e"
      number_of_storage_nodes: 2
      number_of_drives: 6
      number_of_tolerable_drive_failures: 0
      query: "updated_configuration"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the storage pool estinated capacity.
  returned: always
  type: dict
  contains:
    estimated_capacity:
      description: Dictionary of estimated_capacity.
      type: dict
      contains:
        estimated_pool_capacit_in_tb:
          description: Estimated pool capacity in TiB.
          type: int
          sample: 3
        difference_capacit_in_tb:
          description: Difference pool capacity in TiB.
          type: int
          sample: 3
        number_of_storage_nodes:
          description: The number of storage nodes.
          type: int
          sample: 2
        number_of_drives:
          description: The number of drives for each storage node.
          type: int
          sample: 6
        number_of_tolerable_drive_failures:
          description: The number of drive failures that can be allowed.
          type: int
          sample: 0
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBEstimatedCapacityArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_estimated_capacity import (
    SDSBEstimatedCapacityReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockEstimatedCapacityFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBEstimatedCapacityArguments().estimated_capacity_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            parameter_manager = SDSBParametersManager(self.module.params)
            self.connection_info = parameter_manager.get_connection_info()
            self.spec = parameter_manager.get_estimated_capacity_fact_spec()
            self.logger.writeDebug(
                f"MOD:hv_sds_block_storage_pool_estimated_capacity_facts:spec= {self.spec}"
            )
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Estimated Capacity Facts ===")
        estimated_capacity = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBEstimatedCapacityReconciler(self.connection_info)
            estimated_capacity = sdsb_reconciler.get_estimated_capacity(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_storage_pool_estimated_capacity_facts:capacity_management_settings= {estimated_capacity}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Estimated Capacity Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"estimated_capacity": estimated_capacity}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Estimated Capacity Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockEstimatedCapacityFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
