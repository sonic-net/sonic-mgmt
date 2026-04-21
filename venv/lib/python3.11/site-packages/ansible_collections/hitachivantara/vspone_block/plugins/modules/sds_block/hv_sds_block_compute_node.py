#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_compute_node
short_description: Manages compute nodes in VSP One SDS Block and Cloud systems.
description:
  - This module allows for the creation, update and deletion of compute node,
    adding iqn initiators to compute node, remove iqn initiators from compute node,
    attach volumes to compute node, detach volumes from compute node.
  - It supports various compute node operations based on the specified task level.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/compute_node.yml)
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
    description: The level of the compute node task. Choices are C(present) and C(absent).
    type: str
    required: false
    choices:
      - present
      - absent
    default: present
  spec:
    description: Specification for the compute node task.
    type: dict
    required: true
    suboptions:
      id:
        description: ID of the compute node.
        type: str
        required: false
      name:
        description: Name of the compute node.
        type: str
        required: false
      os_type:
        description: The OS type of the compute node.
        type: str
        required: false
      state:
        description: The state of the compute node task.
        type: str
        required: false
        choices:
          - add_iscsi_initiator
          - remove_iscsi_initiator
          - attach_volume
          - detach_volume
          - add_host_nqn
          - remove_host_nqn
      iscsi_initiators:
        description: The array of iSCSI Initiators.
        type: list
        required: false
        elements: str
      host_nqns:
        description: The array of NQN Initiators.
        type: list
        required: false
        elements: str
      volumes:
        description: The array of name of volumes.
        type: list
        required: false
        elements: str
      should_delete_all_volumes:
        description: Will delete the volumes that are not attached to any compute node.
        type: bool
        required: false
      vps_id:
        description: The ID of the VPS where the compute node will be created.
        type: str
        required: false
      vps_name:
        description: The name of the VPS where the compute node will be created.
        type: str
        required: false
"""

EXAMPLES = """
- name: Create compute node
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "computenode1"
      os_type: "VMWARE"
      iscsi_initiators: ["iqn.1991-05.com.hitachi:test-iscsi-iqn1", "iqn.1991-05.com.hitachi:test-iscsi-iqn2"]
      volumes: ["test-volume1", "test-volume2"]

- name: Delete compute node by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "3d971bb3-40fd-4cb5-bf68-2010b30aa74d"

- name: Delete compute node by name
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "computenode1"
      should_delete_all_volumes: true

- name: Update compute node name
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "3d971bb3-40fd-4cb5-bf68-2010b30aa74d"
      name: "computenode1a"
      os_type: "LINUX"

- name: Add iqn initiators to compute node
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      state: "add_iscsi_initiator"
      name: "computenode1"
      os_type: "VMWARE"
      iscsi_initiators: ["iqn.1991-05.com.hitachi:test-iscsi-iqn3", "iqn.1991-05.com.hitachi:test-iscsi-iqn4"]

- name: Remove iqn initiators from compute node
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      state: "remove_iscsi_initiator"
      name: "computenode1"
      os_type: "VMWARE"
      iscsi_initiators: ["iqn.1991-05.com.hitachi:test-iscsi-iqn3", "iqn.1991-05.com.hitachi:test-iscsi-iqn4"]

- name: Attach volumes to compute node
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      state: "attach_volume"
      name: "computenode1"
      volumes: ["test-volume3", "test-volume4"]

- name: Detach volumes from compute node
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_node:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      state: "detach_volume"
      name: "computenode1"
      volumes: ["test-volume3", "test-volume4"]
"""

RETURN = """
compute_nodes:
  description: Dictionary containing the discovered properties of the compute nodes.
  type: list
  returned: success
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
              sample:
                - "932962b5-ab61-429f-ba06-cd976e1a8f97"
                - "181d4ed3-ae8a-418d-9deb-72a4eb1e2204"
                - "0f13e320-53e7-4088-aa11-418636b58376"
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
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_constants import (
    StateValue,
)
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


class SDSBComputeNodeManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBComputeNodeArguments().compute_node()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        params_manager = SDSBParametersManager(self.module.params)
        self.state = params_manager.get_state()

        self.connection_info = params_manager.get_connection_info()
        self.spec = params_manager.get_compute_node_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Compute Node Operation ===")
        compute_node = None
        compute_node_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBComputeNodeReconciler(self.connection_info)
            compute_node = sdsb_reconciler.reconcile_compute_node(self.state, self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_compute_node:compute_nodes= {compute_node}"
            )

            if self.state.lower() == StateValue.ABSENT:
                compute_node_data_extracted = compute_node
            else:
                output_dict = compute_node.to_dict()
                self.logger.writeDebug(
                    f"MOD:hv_sds_block_compute_node:output_dict= {output_dict}"
                )
                compute_node_data_extracted = (
                    ComputeNodeAndVolumePropertiesExtractor().extract_dict(output_dict)
                )
                self.logger.writeDebug(
                    f"MOD:hv_sds_block_compute_node:compute_node_data_extracted= {compute_node_data_extracted}"
                )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Compute Node Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "compute_nodes": compute_node_data_extracted,
        }
        if registration_message:
            response["user_consent_required"] = registration_message

        self.logger.writeInfo("=== End of SDSB Compute Node Operation ===")
        self.module.exit_json(**response)


def main(module=None):
    obj_store = SDSBComputeNodeManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
