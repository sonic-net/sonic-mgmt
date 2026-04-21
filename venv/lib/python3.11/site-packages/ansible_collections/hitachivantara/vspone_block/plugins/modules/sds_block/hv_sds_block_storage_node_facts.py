#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_storage_node_facts
short_description: Retrieves information about VSP One SDS Block and Cloud systems storage nodes.
description:
  - This module retrieves information about storage nodes.
  - It provides details about a storage node such as ID, name and other details.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/storage_node_facts.yml)
version_added: '4.1.0'
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
    description: Specification for retrieving storage node information.
    type: dict
    required: false
    suboptions:
      fault_domain_id:
        description: The ID of a fault domain to which the volume belongs.
        type: str
        required: false
      id:
        description: Storage node ID.
        type: str
        required: false
      name:
        description: Storage node name.
        type: str
        required: false
      cluster_role:
        description: The role of a storage node in a storage cluster.
        type: str
        required: false
        choices: ['Master', 'Worker']
      protection_domain_id:
        description: The ID of the protection domain to which the volume is belonging.
        type: str
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all storage nodes
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about storage node by name
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "vssbesxi1"

- name: Retrieve information about storage nodes by fault domain ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      fault_domain_id: "c0b833cd-1fee-417d-bbf2-d25aac767ad4"

- name: Retrieve information about storage nodes by protection domain ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      protection_domain_id: "4090c412-edf2-4368-8175-1f60507afbb8"

- name: Retrieve information about storage nodes by cluster role
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      cluster_role: "Master"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the storage nodes.
  returned: always
  type: dict
  contains:
    storage_nodes:
      description: A list of storage nodes.
      type: list
      elements: dict
      contains:
        storage_node_info:
          description: Information about the storage node.
          type: dict
          contains:
            bios_uuid:
              description: The storage node UUID registered in SMBIOS.
              type: str
              sample: "37383638-3430-4d32-3239-343030355153"
            cluster_role:
              description: The role of the storage node in the storage cluster.
              type: str
              sample: "Worker"
            control_port_ipv4_address:
              description: The IPv4 address of the control port.
              type: str
              sample: "10.76.34.105"
            drive_data_relocation_status:
              description: Status of drive data relocation.
              type: str
              sample: "Stopped"
            fault_domain_id:
              description: The ID of the fault domain.
              type: str
              sample: "05c3b302-9d43-448d-b0fa-3bbc64d0666d"
            fault_domain_name:
              description: Name of the fault domain.
              type: str
              sample: "SC01-PD01-FD01"
            id:
              description: Storage node ID.
              type: str
              sample: "e6f3c56b-dcac-4cd5-8524-112ff1273c89"
            insufficient_resources_for_rebuild_capacity:
              description: Insufficient resources for rebuild capacity.
              type: dict
              contains:
                capacity_of_drive:
                  description: Lacking drive capacity for rebuild.
                  type: int
                  sample: 0
                number_of_drives:
                  description: Number of lacking drives for rebuild.
                  type: int
                  sample: 0
            internode_port_ipv4_address:
              description: The IPv4 address of the internode port.
              type: str
              sample: "192.168.210.105"
            is_capacity_balancing_enabled:
              description: Whether capacity balancing is enabled.
              type: bool
              sample: true
            is_storage_master_node_primary:
              description: Whether the storage master node is primary.
              type: bool
              sample: false
            memory_mb:
              description: Memory size in MB.
              type: int
              sample: 196608
            model_name:
              description: Model name of the server running the storage node.
              type: str
              sample: "Hitachi Advanced Server HA820"
            name:
              description: Storage node name.
              type: str
              sample: "SDS-NODE5"
            protection_domain_id:
              description: The ID of the protection domain.
              type: str
              sample: "66449f50-caa4-4070-ade1-e81f29614741"
            rebuildable_resources:
              description: Resources for which rebuild is possible.
              type: dict
              contains:
                number_of_drives:
                  description: Number of drive failures that can be tolerated.
                  type: int
                  sample: 1
            serial_number:
              description: Serial number of the server running the storage node.
              type: str
              sample: "2M294005QS"
            software_version:
              description: Storage software version.
              type: str
              sample: "01.18.02.40"
            status:
              description: The status of the storage node.
              type: str
              sample: "Ready"
            status_summary:
              description: Summary of the storage node status.
              type: str
              sample: "Normal"
            storage_node_attributes:
              description: Storage node attributes (empty list if none).
              type: list
              elements: str
              sample: []
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_storage_node import (
    SDSBStorageNodeReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBStorageNodeArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBStorageNodeFactsManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBStorageNodeArguments().storage_node_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_storage_node_fact_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Storage Node Facts ===")
        storage_nodes = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBStorageNodeReconciler(self.connection_info)
            storage_nodes = sdsb_reconciler.get_storage_nodes(self.spec)
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Storage Node Facts ===")
            self.module.fail_json(msg=str(e))
        data = {
            "storage_nodes": storage_nodes,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Storage Node Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBStorageNodeFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
