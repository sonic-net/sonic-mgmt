#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_storage_system_facts
short_description: Retrieves information about a specific VSP One SDS Block and Cloud system.
description:
  - This module gathers facts about a specific storage system.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/storagesystem_facts.yml)
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
  - hitachivantara.vspone_block.common.sdsb_connection_info
"""

EXAMPLES = """
- name: Get Storage System
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_system_facts:
      connection_info:
          address: sdsb.company.com
          username: "admin"
          password: "secret"
"""


RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the storage system.
  returned: always
  type: dict
  contains:
    storage_system:
      description: The storage system information.
      type: dict
      contains:
        api_version:
          description: API version.
          type: str
          sample: "01.18.02.40"
        cluster_id:
          description: Cluster UUID.
          type: str
          sample: "2f8576d7-2d24-4e73-9550-696434fcfe81"
        cluster_name:
          description: Cluster name.
          type: str
          sample: "SC01"
        efficiency_data_reduction:
          description: Efficiency data reduction percentage.
          type: int
          sample: -1
        free_pool_capacity_in_mb:
          description: Free pool capacity in megabytes.
          type: int
          sample: 24801000
        health_statuses:
          description: List of health statuses.
          type: list
          elements: dict
          contains:
            protection_domain_id:
              description: Protection domain identifier.
              type: str
              sample: ""
            status:
              description: Health status.
              type: str
              sample: "Normal"
            type:
              description: Type of health status.
              type: str
              sample: "License"
        number_of_compute_ports:
          description: Number of compute ports.
          type: int
          sample: 5
        number_of_drives:
          description: Number of drives.
          type: int
          sample: 60
        number_of_fault_domains:
          description: Number of fault domains.
          type: int
          sample: 1
        number_of_storage_pools:
          description: Number of storage pools.
          type: int
          sample: 1
        number_of_total_servers:
          description: Number of total servers.
          type: int
          sample: 8
        number_of_total_storage_nodes:
          description: Number of total storage nodes.
          type: int
          sample: 5
        number_of_total_volumes:
          description: Number of total volumes.
          type: int
          sample: 10
        product_name:
          description: API name.
          type: str
          sample: "Hitachi Virtual Storage Software Block REST API"
        total_efficiency:
          description: Total efficiency percentage.
          type: int
          sample: -1
        total_pool_capacity_in_mb:
          description: Total pool capacity in megabytes.
          type: int
          sample: 24801000
        used_pool_capacity_in_mb:
          description: Used pool capacity in megabytes.
          type: int
          sample: 0
        write_back_mode_with_cache_protection:
          description: Write-back mode with cache protection status.
          type: str
          sample: "Enabled"
"""


from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBStorageSystemArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    sdsb_storage_system,
)
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    camel_dict_to_snake_case,
)
from dataclasses import asdict
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBStorageSystemFactManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBStorageSystemArguments().storage_system_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = SDSBParametersManager(self.module.params)
        except Exception as e:
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Storage System Facts ===")
        sdsb_storage_system_data = None

        registration_message = validate_ansible_product_registration()
        try:
            sdsb_storage_system_data = asdict(self.direct_sdsb_storage_system_read())
            snake_case_storage_system_data = camel_dict_to_snake_case(
                sdsb_storage_system_data
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Storage System Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"storage_system": snake_case_storage_system_data}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Storage System Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)

    def direct_sdsb_storage_system_read(self):
        result = sdsb_storage_system.SDSBStorageSystemReconciler(
            self.params_manager.connection_info
        ).sdsb_get_storage_system()
        if result is None:
            self.module.fail_json("Couldn't read storage system.")
        return result


def main():
    obj_store = SDSBStorageSystemFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
