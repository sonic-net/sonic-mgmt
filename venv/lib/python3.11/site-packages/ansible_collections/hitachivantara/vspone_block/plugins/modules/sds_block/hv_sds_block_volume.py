#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_volume
short_description: Manages VSP One SDS Block and Cloud systems volumes.
description:
  - This module allows the creation, update and deletion of volume, adding and removing compute code.
  - It supports various volume operations based on the specified state.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/volume.yml)
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
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  state:
    description: The level of the volume task. Choices are C(present) and C(absent).
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the volume task.
    type: dict
    required: true
    suboptions:
      id:
        description: The id of the volume.
        type: str
        required: false
      name:
        description: The name of the volume.
        type: str
        required: false
      nickname:
        description: The nickname of the volume.
        type: str
        required: false
      capacity:
        description: The capacity of the volume.
        type: str
        required: false
      capacity_saving:
        description: Settings of the data reduction function. C(Disabled) or  C(Compression).
        type: str
        required: false
      pool_name:
        description: The name of the storage pool where the volume will be created.
        type: str
        required: false
      vps_id:
        description: The ID of the VPS where the volume will be created/deleted. vps_id and pool_name are mutually exclusive.
        type: str
        required: false
      vps_name:
        description: The name of the VPS where the volume will be created/deleted. vps_name and pool_name are mutually exclusive.
        type: str
        required: false
      state:
        description: The state of the volume task.
        type: str
        required: false
        choices: ['add_compute_node', 'remove_compute_node']
      compute_nodes:
        description: The array of name of compute nodes to which the volume is attached.
        type: list
        required: false
        elements: str
      qos_param:
        description: The quality of service parameters for the volume.
        type: dict
        required: false
        suboptions:
          upper_limit_for_iops:
            description: The upper limit for IOPS.
            type: int
            required: false
          upper_limit_for_transfer_rate_mb_per_sec:
            description: The upper limit for transfer rate (MB per Sec).
            type: int
            required: false
          upper_alert_allowable_time_in_sec:
            description: The upper alert allowable time(In seconds).
            type: int
            required: false

"""

EXAMPLES = """
- name: Create volume
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      pool_name: "SP01"
      name: "RD-volume-4"
      capacity: 99
      compute_nodes: ["CAPI123678", "ComputeNode-1"]

- name: Create volume with QoS parameters
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      pool_name: "SP01"
      name: "RD-volume-4"
      capacity: 99
      qos_param:
        upper_limit_for_iops: 100
        upper_limit_for_transfer_rate_mb_per_sec: 100
        upper_alert_allowable_time_in_sec: 100
      compute_nodes: ["CAPI123678", "ComputeNode-1"]

- name: Delete volume by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: absent
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "df63a5d9-32ea-4ae1-879a-7c23fbc574db"

- name: Delete volume by name
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: absent
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "RD-volume-4"

- name: Expand volume
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "RD-volume-4"
      capacity: 202

- name: Update volume nickname
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "RD-volume-4"
      nickname: "RD-volume-0004"

- name: Update volume QoS parameters
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "RD-volume-4"
      qos_param:
        upper_limit_for_iops: 100
        upper_limit_for_transfer_rate_mb_per_sec: 100
        upper_alert_allowable_time_in_sec: 100

- name: Update volume name
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "aba5c900-b04c-4beb-8ca4-ed53537afb09"
      name: "RD-volume-0004"
      nickname: "RD-volume-0004"

- name: Remove compute node
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      state: "remove_compute_node"
      id: "aba5c900-b04c-4beb-8ca4-ed53537afb09"
      compute_nodes: ["ComputeNode-1"]

- name: Add compute node
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      state: "add_compute_node"
      id: "aba5c900-b04c-4beb-8ca4-ed53537afb09"
      compute_nodes: ["ComputeNode-1"]
"""

RETURN = """
volumes:
  description: The volume information.
  returned: always
  type: dict
  contains:
    capacity_saving:
      description: Capacity saving status.
      type: str
      sample: "Disabled"
    compute_nodes_info:
      description: List of compute nodes to which the volume is attached.
      type: list
      elements: dict
      sample: []
    data_reduction_effects:
      description: Data reduction effects on the volume.
      type: dict
      sample: {}
    data_reduction_progress_rate:
      description: Data reduction progress rate.
      type: str
      sample: ""
    data_reduction_status:
      description: Data reduction status.
      type: str
      sample: "Disabled"
    full_allocated:
      description: Whether the volume is fully allocated.
      type: bool
      sample: false
    id:
      description: Unique identifier for the volume.
      type: str
      sample: "355a9259-96e7-479d-8586-29b2aa74e106"
    naa_id:
      description: NAA identifier for the volume.
      type: str
      sample: "60060e810274f000600274f00000271c"
    name:
      description: Name of the volume.
      type: str
      sample: "SDSBolume12"
    nickname:
      description: Nickname of the volume.
      type: str
      sample: "SDSBolume12"
    number_of_connecting_servers:
      description: Number of servers connected to the volume.
      type: int
      sample: 0
    number_of_snapshots:
      description: Number of snapshots of the volume.
      type: int
      sample: 0
    pool_id:
      description: Pool identifier where the volume is created.
      type: str
      sample: "80d306ea-d224-4fb1-a746-5ed41994e708"
    pool_name:
      description: Name of the storage pool.
      type: str
      sample: "SP01"
    protection_domain_id:
      description: Protection domain identifier.
      type: str
      sample: "66449f50-caa4-4070-ade1-e81f29614741"
    qos_param:
      description: Quality of service parameters for the volume.
      type: dict
      contains:
        upper_alert_allowable_time_in_sec:
          description: Upper alert allowable time in seconds.
          type: int
          sample: 100
        upper_alert_time:
          description: Upper alert time.
          type: bool
          sample: false
        upper_limit_for_iops:
          description: Upper limit for IOPS.
          type: int
          sample: 100
        upper_limit_for_transfer_rate_mb_per_sec:
          description: Upper limit for transfer rate (MB per sec).
          type: int
          sample: 100
    saving_mode:
      description: Saving mode.
      type: str
      sample: ""
    snapshot_attribute:
      description: Snapshot attribute.
      type: str
      sample: "-"
    snapshot_status:
      description: Snapshot status.
      type: str
      sample: ""
    status:
      description: Status of the volume.
      type: str
      sample: "Normal"
    status_summary:
      description: Summary of the volume status.
      type: str
      sample: "Normal"
    storage_controller_id:
      description: Storage controller identifier.
      type: str
      sample: "970e253e-b023-4ce5-b538-c9f8b9ebfa56"
    total_capacity_mb:
      description: Total capacity of the volume in MB.
      type: int
      sample: 100
    used_capacity:
      description: Used capacity of the volume.
      type: int
      sample: -1
    volume_number:
      description: Volume number.
      type: int
      sample: 10012
    volume_type:
      description: Type of the volume.
      type: str
      sample: "Normal"
    vps_id:
      description: VPS identifier.
      type: str
      sample: "(system)"
    vps_name:
      description: VPS name.
      type: str
      sample: "(system)"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_constants import (
    StateValue,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_volume import (
    SDSBVolumeReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_properties_extractor import (
    VolumePropertiesExtractor,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBVolumeArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBVolumeManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBVolumeArguments().volume()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            params_manager = SDSBParametersManager(self.module.params)
            self.state = params_manager.get_state()
            self.connection_info = params_manager.get_connection_info()
            self.spec = params_manager.get_volume_spec()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Volume Operation ===")
        volumes = None
        volumes_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBVolumeReconciler(self.connection_info)
            volumes = sdsb_reconciler.reconcile_volume(self.state, self.spec)

            self.logger.writeDebug(f"MOD:hv_sds_block_volume:volumes= {volumes}")
            if self.state.lower() == StateValue.ABSENT:
                volumes_data_extracted = volumes
            else:
                output_dict = volumes.to_dict()
                volumes_data_extracted = VolumePropertiesExtractor().extract_dict(
                    output_dict
                )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Volume Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "volumes": volumes_data_extracted,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Volume Operation ===")
        self.module.exit_json(**response)


def main(module=None):
    obj_store = SDSBVolumeManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
