#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_compute_node_facts
short_description: Retrieves information about compute nodes.
description:
  - This module retrieves information about compute nodes.
  - It provides details about a compute node such as ID, volume and other details.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/compute_node_facts.yml)
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
    description: Specification for retrieving compute node information.
    type: dict
    required: false
    suboptions:
      names:
        description: The names of the compute nodes.
        type: list
        required: false
        elements: str
      hba_name:
        description: A WWN or an iSCSI name.
        type: str
        required: false
      vps_name:
        description: VPS name.
        type: str
        required: false
      vps_id:
        description: VPS ID.
        type: str
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all compute nodes
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about compute nodes by hba_name
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      hba_name: 'iqn.1991-05.com.hitachi:test-iscsi-iqn1'

- name: Retrieve information about compute nodes by names
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      names: ['computenode1', 'computenode2']
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the compute nodes.
  returned: always
  type: dict
  contains:
    compute_nodes:
      description: A list of compute nodes.
      type: list
      elements: dict
      contains:
        compute_node_info:
          description: Information about the compute node.
          type: dict
          contains:
            id:
              description: Unique identifier for the compute node.
              type: str
              sample: "ca1beba6-4392-4d21-a161-3e3e94fb45e2"
            lun:
              description: Logical Unit Number.
              type: int
              sample: -1
            nickname:
              description: Nickname of the compute node.
              type: str
              sample: "spc-iqn.1994-05.com.redhat:5475aab33df5"
            number_of_paths:
              description: Number of paths.
              type: int
              sample: -1
            number_of_volumes:
              description: Number of volumes.
              type: int
              sample: 2
            os_type:
              description: Operating system type.
              type: str
              sample: "Linux"
            paths:
              description: List of paths.
              type: list
              elements: dict
              contains:
                hba_name:
                  description: HBA name.
                  type: str
                  sample: "iqn.1994-05.com.redhat:5475aab33df5"
                port_ids:
                  description: List of port IDs.
                  type: list
                  elements: str
                  sample: [
                    "932962b5-ab61-429f-ba06-cd976e1a8f97",
                    "181d4ed3-ae8a-418d-9deb-72a4eb1e2204",
                    "0f13e320-53e7-4088-aa11-418636b58376"
                  ]
            total_capacity_mb:
              description: Total capacity in MB.
              type: int
              sample: 90112
            used_capacity_mb:
              description: Used capacity in MB.
              type: int
              sample: 4998
            vps_id:
              description: VPS ID.
              type: str
              sample: "(system)"
            vps_name:
              description: VPS name.
              type: str
              sample: "(system)"
        volume_info:
          description: Information about the volumes.
          type: list
          elements: dict
          contains:
            id:
              description: Unique identifier for the volume.
              type: str
              sample: "3ac02c92-05f0-4eba-9c00-3503afc18290"
            name:
              description: Name of the volume.
              type: str
              sample: "spc-a879277ec4"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_compute_node import (
    SDSBComputeNodeReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_properties_extractor import (
    ComputeNodeAndVolumePropertiesExtractor,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBComputeNodeArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBComputeNodeFactsManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBComputeNodeArguments().compute_node_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        # self.logger.writeDebug(f"MOD:hv_sds_block_compute_node_facts:argument_spec= {self.connection_info}")
        self.spec = parameter_manager.get_compute_node_fact_spec()
        self.logger.writeDebug(f"MOD:hv_sds_block_compute_node_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Compute Node Facts ===")
        compute_nodes = None
        compute_node_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBComputeNodeReconciler(self.connection_info)
            compute_nodes = sdsb_reconciler.get_compute_nodes(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_compute_node_facts:compute_nodes= {compute_nodes}"
            )
            output_dict = compute_nodes.data_to_list()
            compute_node_data_extracted = (
                ComputeNodeAndVolumePropertiesExtractor().extract(output_dict)
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Compute Node Facts ===")
            self.module.fail_json(msg=str(e))
        data = {
            "compute_nodes": compute_node_data_extracted,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Compute Node Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBComputeNodeFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
