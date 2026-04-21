#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: hv_resource_group
short_description: Manages resource groups on Hitachi VSP storage systems.
description:
  - This module allows the creation and deletion of resource groups on Hitachi
    VSP storage systems.
  - It also enables adding or removing various types of resources to/from the
    resource group.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/resource_group.yml)
version_added: 3.2.0
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
  - hitachivantara.vspone_block.common.connection_with_type
options:
  state:
    description: The desired state of the resource group task.
    type: str
    required: false
    choices:
      - present
      - absent
    default: present

  storage_system_info:
    description: Information about the storage system. This field is optional.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false

  spec:
    description: Specification for the resource group.
    type: dict
    required: true
    suboptions:
      name:
        description: >
          The name of the resource group.
          Required for the following tasks:
          - Create a Resource Group without any resources
          - Create a Resource Group with virtual storage serial number of VSM
          - Create a Resource Group with LDEVs
          - Create a Resource Group with the following resources: LDEVs, parity groups, ports, host groups, NVM subsystem IDs
          - Create a Resource Group with storage pool IDs and parity groups
          - Add the following resources to an existing Resource Group by Name: LDEVs, ports, host groups, iSCSI targets
          - Remove the following resources from an existing Resource Group by Name: LDEVs, ports, host groups, iSCSI targets
          - Delete a Resource Group by Name
        type: str
        required: false

      id:
        description: >
          The ID of the resource group.
          Optional for the following tasks:
          - Add the following resources to an existing Resource Group by ID: LDEVs, ports, host groups, NVM subsystem IDs
          - Remove the following resources from an existing Resource Group by ID: LDEVs, ports, host groups, NVM subsystem IDs
          - Delete a Resource Group by ID
          - Delete a Resource Group by ID forcefully
          Required for the following tasks:
          - Add LDEVs using LDEV range to an existing Resource Group by ID
          - Remove LDEVs using LDEV range from an existing Resource Group by ID
        type: int
        required: false

      virtual_storage_serial:
        description: >
          Virtual storage serial number associated with the resource group.
          Required for the Create a Resource Group with virtual storage serial number of VSM task.
        type: str
        required: false

      virtual_storage_model:
        description: >
          Virtual storage model name associated with the resource group.
          Required for the Create a Resource Group with virtual storage serial number of VSM task.
        type: str
        required: false
        choices:
          - VSP_5100H
          - VSP_5200H
          - VSP_5500H
          - VSP_5600H
          - VSP_5100
          - VSP_5200
          - VSP_5500
          - VSP_5600
          - VSP_E1090
          - VSP_E590
          - VSP_E790
          - VSP_E990
          - VSP_F350
          - VSP_F370
          - VSP_F400
          - VSP_F600
          - VSP_F700
          - VSP_F800
          - VSP_F900
          - VSP_G130
          - VSP_G150
          - VSP_G200
          - VSP_G350
          - VSP_G370
          - VSP_G400
          - VSP_G600
          - VSP_G700
          - VSP_G800
          - VSP_G900
          - VSP_ONE_B28
          - VSP_ONE_B26
          - VSP_ONE_B24
          - VSP_E790H
          - VSP_E590H
          - VSP_G1000
          - VSP_G1500
          - VSP_F1500
          - VSP_E1090H

      ldevs:
        description: >
          List of LDEVs to be added or removed from the resource group.
          Optional for the Create a Resource Group with LDEVs or with the following resources:
          LDEVs, parity groups, ports, host groups, NVM subsystem IDs.
          Also used for add/remove operations by ID or Name.
        type: list
        required: false
        elements: str

      start_ldev:
        description: >
          First LDEV number. If you specify this attribute, you must also specify end_ldev.
          If you specify ldevs, you cannot specify this attribute.
          Required for add/remove LDEVs using LDEV range by ID.
        type: str
        required: false

      end_ldev:
        description: >
          Last LDEV number. If you specify this attribute, you must also specify start_ldev.
          If you specify ldevs, you cannot specify this attribute.
          Required for add/remove LDEVs using LDEV range by ID.
        type: str
        required: false

      ports:
        description: >
          List of ports to be added or removed from the resource group.
          Optional for Create or Add/Remove operations by ID or Name.
        type: list
        required: false
        elements: str

      parity_groups:
        description: >
          List of parity groups to be added or removed from the resource group.
          Optional for the Create a Resource Group with LDEVs, parity groups, ports,
          host groups, NVM subsystem IDs, or with storage pool IDs.
        type: list
        required: false
        elements: str

      external_parity_groups:
        description: >
          List of external parity groups to be added or removed from the resource group.
        type: list
        required: false
        elements: str

      host_groups:
        description: >
          List of host groups to be added or removed from the resource group.
          Required for Create, Add, or Remove operations involving host groups.
        type: list
        required: false
        elements: dict
        suboptions:
          name:
            description: >
              Name of the host group.
              Required for create/add/remove operations involving host groups.
            type: str
            required: true
          port:
            description: >
              Port name associated with the host group.
              Required for create/add/remove operations involving host groups.
            type: str
            required: true

      iscsi_targets:
        description: >
          List of iSCSI targets to be added or removed from the resource group.
          Optional for add/remove operations by Name.
        type: list
        required: false
        elements: dict
        suboptions:
          name:
            description: >
              Name of the iSCSI target.
              Required for add/remove operations by Name.
            type: str
            required: true
          port:
            description: >
              Port name associated with the iSCSI target.
              Required for add/remove operations by Name.
            type: str
            required: true

      nvm_subsystem_ids:
        description: >
          List of NVM subsystem IDs to be added or removed from the resource group.
          Optional for Create or Add/Remove operations by ID.
        type: list
        required: false
        elements: int

      storage_pool_ids:
        description: >
          Pool volumes to be added or removed from the resource group.
          Optional for Create a Resource Group with storage pool IDs and parity groups.
        type: list
        required: false
        elements: int

      state:
        description: >
          - Operation to be performed on the resources in the resource group.
          - add_resource- To add resources to the resource group.
          - remove_resource - To remove resources from the resource group.
        type: str
        required: false
        choices:
          - add_resource
          - remove_resource
        default: add_resource

      force:
        description: >
          For delete operations, specifies if the operation should be forced.
          Optional for Delete a Resource Group by ID forcefully.
        type: bool
        required: false
        default: false

      add_resource_time_out_in_sec:
        description: >
          Timeout for an add resource operation. The default timeout is 300 seconds.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create a Resource Group with virtual storage serial number of VSM
  hitachivantara.vspone_block.vsp.hv_resource_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "my_resource_group_1"
      virtual_storage_serial: "69200"
      virtual_storage_model: "VSP G370"

- name: Get Resource Group by name
  hitachivantara.vspone_block.vsp.hv_resource_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "my_resource_group"

- name: Create a Resource Group with LDEVs, parity groups, ports, and host groups
  hitachivantara.vspone_block.vsp.hv_resource_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      ldevs: [1, 2, 3]
      parity_groups: ["PG1", "PG2"]
      ports: ["CL1-A", "CL1-C"]
      host_groups:
        - port: "CL1-A"
          name: "my_host_group_1"
        - port: "CL1-A"
          name: "my_host_group_2"

- name: Add resources to an existing Resource Group by ID
  hitachivantara.vspone_block.vsp.hv_resource_group:
    connection_info:
    address: storage1.company.com
    username: "admin"
    password: "secret"
    spec:
    state: add_resource
    id: 4
    ldevs: [3, 4]
    host_groups:
      - port: "CL1-A"
        name: "my_host_group_3"
    iscsi_targets:
      - port: "CL1-C"
        name: "my_iscsi_target_2"

- name: Remove resources from an existing Resource Group by ID
  hitachivantara.vspone_block.vsp.hv_resource_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      id: 4
      state: remove_resource
      ldevs: [3, 4]
      host_groups:
        - port: "CL1-A"
          name: "my_host_group_3"
      iscsi_targets:
        - port: "CL1-C"
          name: "my_iscsi_target_2"

- name: Delete a Resource Group by ID forcefully
  hitachivantara.vspone_block.vsp.hv_resource_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: absent
    spec:
      id: 4
      force: true
"""

RETURN = """
resource_groups:
    description: The resource group information.
    returned: always
    type: list
    elements: dict
    contains:
        id:
            description: The ID of the resource group.
            type: int
            sample: 4
        name:
            description: The name of the resource group.
            type: str
            sample: "my_resource_group"
        lock_status:
            description: The lock status of the resource group.
            type: str
            sample: "Unlocked"
        host_groups:
            description: List of host groups in the resource group.
            type: list
            elements: dict
            contains:
              id:
                description: The ID of the host group.
                type: int
                sample: 1
              name:
                description: The name of the host group.
                type: str
                sample: "my_host_group_1"
              port:
                description: The port name associated with the host group.
                type: str
                sample: "CL1-A"
        iscsi_targets:
            description: List of iSCSI targets in the resource group.
            type: list
            elements: dict
            contains:
              id:
                description: The ID of the iSCSI target.
                type: int
                sample: 1
              name:
                description: The name of the iSCSI target.
                type: str
                sample: "my_iscsi_target_1"
              port:
                description: The port name associated with the iSCSI target.
                type: str
                sample: "CL1-C"
        ldevs:
            description: List of LDEVs in the resource group.
            type: list
            elements: int
            sample: [1, 2, 3]
        ldevs_hex:
            description: List of LDEVs in hexadecimal format in the resource group.
            type: list
            elements: str
            sample: ["0x1", "0x2", "0x3"]
        parity_groups:
            description: List of parity groups in the resource group.
            type: list
            elements: str
            sample: ["PG1", "PG2"]
        ports:
            description: List of ports in the resource group.
            type: list
            elements: str
            sample: ["CL1-A", "CL1-C"]
        virtual_storage_id:
            description: The virtual storage ID associated with the resource group.
            type: int
            sample: 200
        virtual_storage_serial:
            description: The virtual storage serial number associated with the resource group.
            type: str
            sample: "69200"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPResourceGroupArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_resource_group import (
    VSPResourceGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPResourceGroupManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPResourceGroupArguments().resource_group()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = (
                self.parameter_manager.storage_system_info.serial
            )
            self.spec = self.parameter_manager.get_resource_group_spec()
            self.state = self.parameter_manager.get_state()
            self.logger.writeDebug(
                f"MOD:hv_resource_group:spec= {self.spec} ss = {self.storage_serial_number}"
            )
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Resource Group operation ===")
        registration_message = validate_ansible_product_registration()

        rg = None
        try:
            reconciler = VSPResourceGroupReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            rg, comment = reconciler.reconcile_resource_group(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Resource Group operation ===")
            self.module.fail_json(msg=str(e))

        resp = {
            "changed": self.connection_info.changed,
            # "resource_groups": rg,
        }
        if rg:
            resp["resource_groups"] = rg
        if comment:
            resp["comment"] = comment
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Resource Group operation ===")
        self.module.exit_json(**resp)


def main(module=None):
    obj_store = VSPResourceGroupManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
