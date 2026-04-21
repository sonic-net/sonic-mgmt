#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_volume_facts
short_description: Retrieves facts about VSP E series and VSP One Block 20 series storage systems.
description:
  - This module gathers information about volumes in VSP E series and VSP One Block 20 series storage systems.
  - It supports filtering by pool, server, volume nickname, capacity, and volume ID.
  - For usage examples, see
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_volume_facts.yml)
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
  - hitachivantara.vspone_block.common.connection_info
notes:
- With each request, you can obtain information about a maximum of 500 volumes.
- To obtain information about additional volumes, execute the ansible task multiple times by using a combination of the count and start_volume_id parameters.
- By specifying the count parameter, you can also filter the volume information you require.
options:
  spec:
    description: Specification for the volume task.
    type: dict
    required: false
    suboptions:
      pool_id:
        description: ID of the pool.
        required: false
        type: int
      pool_name:
        description: Name of the pool. if both pool_id is present, it will ignore this parameter.
        required: false
        type: str
      server_id:
        description: ID of the server.
        required: false
        type: int
      server_nickname:
        description: Nickname of the server. if both server_id is present, it will ignore this parameter.
        required: false
        type: str
      nickname:
        description: Nickname of the volume.
        required: false
        type: str
      min_total_capacity:
        description: Minimum total capacity.
        required: false
        type: str
      max_total_capacity:
        description: Maximum total capacity.
        required: false
        type: str
      min_used_capacity:
        description: Minimum used capacity.
        required: false
        type: str
      max_used_capacity:
        description: Maximum used capacity.
        required: false
        type: str
      start_volume_id:
        description: Starting volume ID.
        required: false
        type: str
      count:
        description: Number of volumes.
        required: false
        type: int
      volume_id:
        description: ID of the volume.
        required: false
        type: str
"""

EXAMPLES = """
- name: Get facts for volumes in a specific pool by pool_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      pool_id: 1

- name: Get facts for volumes in a specific pool by pool_name
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      pool_name: "SP01"

- name: Get facts for volumes attached to a server by server_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 2001

- name: Get facts for volumes attached to a server by server_nickname
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_nickname: "ComputeNode-1"

- name: Get facts for a volume by nickname
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nickname: "RD-volume-0004"

- name: Get facts for volumes with capacity filters
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      min_total_capacity: 100
      max_total_capacity: 500
      min_used_capacity: 50
      max_used_capacity: 400

- name: Get facts for a range of volumes by start_volume_id and count
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      start_volume_id: 1000
      count: 10

- name: Get facts for a specific volume by volume_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      volume_id: 12345
"""

RETURN = """
ansible_facts:
  description: Facts about the requested volumes.
  returned: always
  type: dict
  contains:
    volumes:
      description: List of volume information objects.
      type: list
      elements: dict
      contains:
        id:
          description: ID of the volume.
          type: int
        id_hex:
          description: ID of the volume in hexadecimal.
          type: str
        nickname:
          description: Nickname of the volume.
          type: str
        pool_id:
          description: ID of the pool.
          type: int
        pool_name:
          description: Name of the pool.
          type: str
        total_capacity:
          description: Total capacity of the volume.
          type: int
        total_capacity_in_mb:
          description: Total capacity in MB.
          type: int
        used_capacity:
          description: Used capacity of the volume.
          type: int
        used_capacity_in_mb:
          description: Used capacity in MB.
          type: int
        free_capacity:
          description: Free capacity of the volume.
          type: int
        free_capacity_in_mb:
          description: Free capacity in MB.
          type: int
        reserved_capacity:
          description: Reserved capacity of the volume.
          type: int
        capacity_saving:
          description: Capacity saving setting (e.g., DEDUPLICATION_AND_COMPRESSION).
          type: str
        capacity_saving_progress:
          description: Capacity saving progress.
          type: int
        capacity_saving_status:
          description: Capacity saving status.
          type: str
        compression_acceleration:
          description: Whether compression acceleration is enabled.
          type: bool
        compression_acceleration_status:
          description: Compression acceleration status.
          type: str
        is_data_reduction_share_enabled:
          description: Whether data reduction share is enabled.
          type: bool
        luns:
          description: List of LUNs associated with the volume.
          type: list
          elements: dict
        number_of_connecting_servers:
          description: Number of servers connected to the volume.
          type: int
        number_of_snapshots:
          description: Number of snapshots for the volume.
          type: int
        parent_volume_id:
          description: ID of the parent volume.
          type: int
        parent_volume_id_hex:
          description: ID of the parent volume in hexadecimal.
          type: str
        qos_settings:
          description: QoS settings for the volume.
          type: dict
        volume_types:
          description: List of volume types.
          type: list
          elements: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_volume_simple_api_reconciler import (
    VSPVolumeSimpleAPIReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPVolumeSimpleAPIArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPSimpleVolumeFacts:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            VSPVolumeSimpleAPIArguments().get_volume_simple_api_facts_args()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_volume_simple_api_facts_spec()
            self.connection_info = params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP Volume Facts Operation ===")
        volume = None
        registration_message = validate_ansible_product_registration()

        try:
            volume_reconciler = VSPVolumeSimpleAPIReconciler(self.connection_info)
            volume = volume_reconciler.volume_facts_reconcile(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP Volume Facts Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "volumes": volume,
            "comments": self.spec.comments if self.spec.comments else [],
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP Volume Facts Operation ===")
        self.module.exit_json(changed=False, ansible_facts=response)


def main():
    obj_store = VSPSimpleVolumeFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
