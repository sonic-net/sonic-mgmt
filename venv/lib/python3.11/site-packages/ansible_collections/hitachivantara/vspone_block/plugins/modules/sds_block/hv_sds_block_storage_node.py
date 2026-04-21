#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_storage_node
short_description: Manages storage node on VSP One SDS Block and Cloud systems.
description:
  - This module allows block storage node for maintenance,
    and restore storage node from blocked state on VSP One SDS Block and Cloud systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/storage_node.yml)
version_added: "4.1.0"
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
    description: The desired state of the storage pool.
    type: str
    required: false
    choices: ['present', 'maintenance', 'restore']
    default: 'present'
  spec:
    description: Specification for the storage node.
    type: dict
    required: true
    suboptions:
      name:
        description: The name of the storage node.
        type: str
        required: false
      id:
        description: The UUID of the storage node.
        type: str
        required: false
      is_capacity_balancing_enabled:
        description: Enables or disables the capacity balancing. If true, capacity balancing applies to the storage node.
          If false, capacity balancing does not apply to the storage node.
        type: bool
        required: false
"""

EXAMPLES = """
- name: Block storage node for maintenance
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "maintenance"
    spec:
      id: "3d0997ce-7065-4e4a-9095-4dc62b36f300"

- name: Restore storage node from maintenance
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "restore"
    spec:
      id: "3d0997ce-7065-4e4a-9095-4dc62b36f300"
"""

RETURN = """
storage_nodes:
  description: List of storage nodes.
  returned: always
  type: list
  elements: dict
  contains:
    bios_uuid:
      description: The storage node UUID, which is registered in the SMBIOS.
      type: str
      sample: "422c2bdc-fdcf-8d33-63b9-377776cee60d"
    cluster_role:
      description: The role of the storage node in the storage cluster.
      type: str
      sample: "Master"
    control_port_ipv4_address:
      description: The IP address (IPv4) of the control port.
      type: str
      sample: "172.25.58.141"
    drive_data_relocation_status:
      description: Status of drive data relocation.
      type: str
      sample: "Stopped"
    fault_domain_id:
      description: The ID of a fault domain to which the volume belongs.
      type: str
      sample: "c0b833cd-1fee-417d-bbf2-d25aac767ad4"
    fault_domain_name:
      description: Name of a fault domain to which the volume belongs.
      type: str
      sample: "SC14-PD01-FD01"
    id:
      description: Storage node ID.
      type: str
      sample: "f3dbcbcc-9cfd-426d-8696-4d23fc9a5dee"
    insufficient_resources_for_rebuild_capacity:
      description: Insufficient resources for rebuild capacity (may be empty).
      type: dict
      contains:
        capacity_of_drive:
          description: Lacking drive capacity of rebuild capacity.
          type: int
          sample: 0
        number_of_drives:
          description: The number of lacking drives of rebuild capacity.
          type: int
          sample: 0
    internode_port_ipv4_address:
      description: The IP address (IPv4) of the internode port.
      type: str
      sample: "192.168.101.141"
    memory_mb:
      description: Memory size in megabytes.
      type: int
      sample: 118784
    model_name:
      description: Model name of the server on which the storage node is running.
      type: str
      sample: "Advanced System HA810"
    name:
      description: Storage node name.
      type: str
      sample: "vssbesxi1"
    protection_domain_id:
      description: The ID of the protection domain to which the volume is belonging.
      type: str
      sample: "4090c412-edf2-4368-8175-1f60507afbb8"
    rebuildable_resources:
      description: Resource for which Rebuild is possible (may be empty).
      type: dict
      contains:
        number_of_drives:
          description: The number of drive failures that can be tolerated.
          type: int
          sample: 1
    serial_number:
      description: Serial number of the server on which the storage node is running.
      type: str
      sample: "MXQ941046B"
    software_version:
      description: The version of storage software.
      type: str
      sample: "01.14.00.00"
    status:
      description: The status of the storage node.
      type: str
      sample: "Ready"
    status_summary:
      description: The summary of the storage node status.
      type: str
      sample: "Normal"
    storage_node_attributes:
      description: Storage node attribute. An empty array ([]) means a storage node which has no attribute.
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


class SDSBStorageNodeManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBStorageNodeArguments().storage_node()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_storage_node_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Storage Node Operation ===")
        storage_nodes = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBStorageNodeReconciler(
                self.connection_info, self.state
            )
            storage_nodes = sdsb_reconciler.reconcile_storage_node(self.spec)
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Storage Node Operation ===")
            self.module.fail_json(msg=str(e))
        data = {
            "changed": self.connection_info.changed,
            "storage_nodes": storage_nodes,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Storage Node Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBStorageNodeManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
