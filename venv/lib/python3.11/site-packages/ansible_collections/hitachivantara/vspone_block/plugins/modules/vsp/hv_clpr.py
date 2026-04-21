#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2023, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_clpr
short_description: Manages CLPRs on Hitachi VSP storage systems.
description:
  - This module manages Cache Logical Partitions (CLPRs) on Hitachi VSP storage systems.
  - Supports creating, updating, deleting CLPRs.
version_added: '3.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.gateway_note
  - hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: The desired state of the CLPR.
    type: str
    required: false
    choices: ['present', 'absent', 'update']
    default: 'present'
  spec:
    description: Specification for the CLPR operation.
    type: dict
    required: true
    suboptions:
      clpr_id:
        description: ID of the CLPR. Required for Update and Delete tasks.
        type: int
        required: false
      clpr_name:
        description: Name of the CLPR. Required for Create and Update tasks.
        type: str
        required: false
      cache_memory_capacity_mb:
        description:
          - Cache memory capacity in MB. Required for Create and Update tasks.
          - For VSP 5000 series storage systems, specify a multiple of 4096.
          - For other storage systems, specify a multiple of 2048.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create CLPR
  hitachivantara.vspone_block.vsp.hv_clpr:
    connection_info:
      address: "{{ storage_address }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: present
    spec:
      clpr_name: "CLPRDEV"
      cache_memory_capacity_mb: 12288

- name: Update CLPR cache capacity
  hitachivantara.vspone_block.vsp.hv_clpr:
    connection_info:
      address: "{{ storage_address }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: update
    spec:
      clpr_id: 1
      cache_memory_capacity_mb: 24576

- name: Delete CLPR
  hitachivantara.vspone_block.vsp.hv_clpr:
    connection_info:
      address: "{{ storage_address }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: absent
    spec:
      clpr_id: 1
"""

RETURN = """
clpr_info:
  description: Details of the CLPR operation
  type: dict
  returned: on success
  contains:
    clpr_id:
      description: CLPR ID
      type: int
      sample: 3
    clpr_name:
      description: CLPR name
      type: str
      sample: "CLPRDEV34"
    cache_memory_capacity_in_gb:
      description: Cache memory capacity in GB
      type: float
      sample: 12.0
    cache_memory_capacity_in_mb:
      description: Cache memory capacity in MB
      type: int
      sample: 12288
    cache_memory_used_capacity_in_gb:
      description: Used cache memory in GB
      type: float
      sample: 0.0
    cache_memory_used_capacity_in_mb:
      description: Used cache memory in MB
      type: int
      sample: 0
    cache_usage_rate:
      description: Cache usage rate percentage
      type: int
      sample: 0
    side_files_capacity_in_gb:
      description: Side files capacity in GB
      type: float
      sample: 0.0
    side_files_capacity_in_mb:
      description: Side files capacity in MB
      type: int
      sample: 0
    side_files_usage_rate:
      description: Side files usage rate percentage
      type: int
      sample: 0
    write_pending_data_capacity_in_gb:
      description: Write pending data capacity in GB
      type: float
      sample: 0.0
    write_pending_data_capacity_in_mb:
      description: Write pending data capacity in MB
      type: int
      sample: 0
    write_pending_data_rate:
      description: Write pending data rate percentage
      type: int
      sample: 0
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_clpr_reconciler import (
    VSPClprReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPClprManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = {
            "state": {
                "type": "str",
                "choices": ["present", "absent", "update"],
                "default": "present",
            },
            "connection_info": {"required": True, "type": "dict"},
            "spec": {"required": True, "type": "dict"},
        }

        self.module = AnsibleModule(
            argument_spec=self.argument_spec, supports_check_mode=False
        )

        self.params_manager = VSPParametersManager(self.module.params)
        self.connection_info = self.params_manager.connection_info
        self.spec = self.params_manager.set_clpr_spec()
        self.state = self.module.params["state"]

    def apply(self):
        self.logger.writeInfo("=== Start of CLPR operation ===")
        registration_message = validate_ansible_product_registration()

        try:
            reconciler = VSPClprReconciler(self.connection_info)
            result = reconciler.clpr_reconcile_direct(self.state, self.spec)

            response = {
                "changed": self.connection_info.changed,
                "clpr_info": result,
                "msg": self._get_message(),
            }

            if registration_message:
                response["user_consent_required"] = registration_message

            self.logger.writeInfo("=== End of CLPR operation ===")
            self.module.exit_json(**response)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of CLPR operation ===")
            self.module.fail_json(msg=str(e))

    def _get_message(self):
        messages = {
            "present": "CLPR created successfully.",
            "update": "CLPR updated successfully.",
            "absent": "CLPR deleted successfully.",
        }
        return messages.get(self.state, "Operation completed successfully.")


def main():
    VSPClprManager().apply()


if __name__ == "__main__":
    main()
