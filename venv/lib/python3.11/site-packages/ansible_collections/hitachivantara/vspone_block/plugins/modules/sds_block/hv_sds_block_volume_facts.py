#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_volume_facts
short_description: Retrieves information about VSP One SDS Block and Cloud systems volumes.
description:
  - This module retrieves information about storage volumes.
  - It provides details about a storage volume such as name, type and other details.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/volume_facts.yml)
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
options:
  spec:
    description: Specification for retrieving volume information.
    type: dict
    required: false
    suboptions:
      count:
        type: int
        description: The maximum number of obtained volume information items. Default is 500.
        required: false
        default: 500
      names:
        type: list
        description: The names of the volumes.
        required: false
        elements: str
      nicknames:
        type: list
        description: The nickname of the volume.
        required: false
        elements: str
      capacity_saving:
        type: str
        description: Settings of the data reduction function for volumes.
        required: false
        choices: ['Disabled', 'Compression']
      vps_id:
        description: The ID of the VPS.
        type: str
        required: false
      vps_name:
        description: The name of the VPS.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get volumes by default count
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Get volumes by count
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      count: 200

- name: Get volumes by names
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      names: ['test-volume1', 'test-volume2']

- name: Get volumes by other filters
  hitachivantara.vspone_block.sds_block.hv_sds_block_volume_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      count: 200
      capacity_saving: 'Disabled'
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the storage volumes.
  returned: always
  type: dict
  contains:
    volumes:
      description: List of storage volumes with their attributes.
      type: list
      elements: dict
      contains:
        capacity_saving:
          description: Capacity saving status.
          type: str
          sample: "Disabled"
        compute_nodes_info:
          description: Information about the compute nodes connected to the volume.
          type: list
          elements: dict
          contains:
            id:
              description: Unique identifier for the compute node.
              type: str
              sample: "4f9041aa-ab2f-4789-af2e-df4a0178a4d3"
            name:
              description: Name of the compute node.
              type: str
              sample: "hitachitest"
        data_reduction_effects:
          description: Effects of data reduction on the volume.
          type: dict
          contains:
            post_capacity_data_reduction:
              description: Capacity after data reduction.
              type: int
              sample: 0
            pre_capacity_data_reduction_without_system_data:
              description: Capacity before data reduction without system data.
              type: int
              sample: 0
            system_data_capacity:
              description: Capacity of system data.
              type: int
              sample: 0
        data_reduction_progress_rate:
          description: Progress rate of data reduction.
          type: str
          sample: ""
        data_reduction_status:
          description: Status of data reduction.
          type: str
          sample: "Disabled"
        full_allocated:
          description: Whether the volume is fully allocated.
          type: bool
          sample: false
        id:
          description: Unique identifier for the volume.
          type: str
          sample: "ef69d5c6-ed7c-4302-959f-b8b8a7382f3b"
        naa_id:
          description: NAA identifier for the volume.
          type: str
          sample: "60060e810a85a000600a85a000000017"
        name:
          description: Name of the volume.
          type: str
          sample: "vol010"
        nickname:
          description: Nickname of the volume.
          type: str
          sample: "vol010"
        number_of_connecting_servers:
          description: Number of servers connected to the volume.
          type: int
          sample: 1
        number_of_snapshots:
          description: Number of snapshots of the volume.
          type: int
          sample: 0
        pool_id:
          description: Identifier of the pool to which the volume belongs.
          type: str
          sample: "cb9f7ecf-ceba-4d8e-808b-9c7bc3e59c03"
        pool_name:
          description: Name of the pool to which the volume belongs.
          type: str
          sample: "SP01"
        protection_domain_id:
          description: Identifier of the protection domain.
          type: str
          sample: "645c36b6-da9e-44bb-b711-430e06c7ad2b"
        qos_param:
          description: Quality of Service parameters for the volume.
          type: dict
          contains:
            upper_alert_allowable_time_in_sec:
              description: Upper alert allowable time in seconds.
              type: int
              sample: 100
            upper_alert_time:
              description: Upper alert time flag.
              type: bool
              sample: false
            upper_limit_for_iops:
              description: Upper limit for IOPS.
              type: int
              sample: 100
            upper_limit_for_transfer_rate_mb_per_sec:
              description: Upper limit for transfer rate in MB/s.
              type: int
              sample: 100
        saving_mode:
          description: Saving mode setting.
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
          description: Identifier of the storage controller.
          type: str
          sample: "fc22f6d3-2bd3-4df5-b5db-8a728e301af9"
        total_capacity_mb:
          description: Total capacity of the volume in MB.
          type: int
          sample: 120
        used_capacity_mb:
          description: Used capacity of the volume in MB.
          type: int
          sample: 0
        volume_number:
          description: Volume number.
          type: int
          sample: 23
        volume_type:
          description: Type of the volume.
          type: str
          sample: "Normal"
        vps_id:
          description: Identifier of the VPS.
          type: str
          sample: "(system)"
        vps_name:
          description: Name of the VPS.
          type: str
          sample: "(system)"
"""

from ansible.module_utils.basic import AnsibleModule
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


class SDSBVolumeFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBVolumeArguments().volume_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_volume_fact_spec()
        self.logger.writeDebug(f"MOD:hv_sds_volume_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Volume Facts ===")
        volumes = None
        volumes_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBVolumeReconciler(self.connection_info)
            volumes = sdsb_reconciler.get_volumes(self.spec)

            self.logger.writeDebug(f"MOD:hv_sds_volume_facts:volumes= {volumes}")
            output_dict = volumes.data_to_list()
            volumes_data_extracted = VolumePropertiesExtractor().extract(output_dict)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Volume Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"volumes": volumes_data_extracted}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Volume Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBVolumeFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
