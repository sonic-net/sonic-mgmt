#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_nvm_subsystems
short_description: Manages NVM subsystems on Hitachi VSP storage systems.
description:
  - This module allows creation, deletion, and other operations on NVM subsystems on Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/nvm_subsystems.yml)
version_added: '3.2.0'
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
  storage_system_info:
    description: Information about the storage system. This field is an optional field.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false
  state:
    description: The desired state of the NVM subsystem.
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the NVM subsystems to be used.
    type: dict
    required: true
    suboptions:
      name:
        description: The name of the NVM subsystem.If not given, it assigns the name of the NVM subsystem to "smrha-<10 digit random number>".
          Optional for the Create an NVM Subsystem with a specific ID
          /Create an NVM Subsystem with a free ID tasks.
          Required for the Add host NQNs to an NVM Subsystem with a specific Name
          /Add namespaces and namespace paths to an NVM Subsystem with a specific name
          /Add ports to an NVM Subsystem with a specific Name
          /Remove ports from an NVM Subsystem with a specific Name or ID
          /Remove namespace from an NVM Subsystem with specific Id or Name
          /Remove namespace from an NVM Subsystem with specific Id or Name using force
          /Remove host NQNs from an NVM Subsystem with a specific Id or Name
          /Remove host NQNs from an NVM Subsystem with a specific Id or Name using force
          /Update host NQNs nickname of an NVM Subsystem with a specific Id or Name
          /Update namespace nicknames of an NVM Subsystem with a specific Id or Name
          /Delete an NVM Subsystem with a specific name
          /Delete an NVM Subsystem with a specific name forcefully tasks.
        type: str
        required: false
      id:
        description: The ID of the NVM subsystem.
          Required for the Create an NVM Subsystem with a specific ID
          /Add host NQNs to an NVM Subsystem with a specific ID
          /Add namespaces and namespace paths to an NVM Subsystem with a specific ID
          /Add ports to an NVM Subsystem with a specific ID
          /Remove ports from an NVM Subsystem with a specific Name or ID
          /Remove namespace paths from an NVM Subsystem with specific Id or Name
          /Remove namespace from an NVM Subsystem with specific Id or Name
          /Remove namespace from an NVM Subsystem with specific Id or Name using force
          /Remove host NQNs from an NVM Subsystem with a specific Id or Name
          /Remove host NQNs from an NVM Subsystem with a specific Id or Name using force
          /Update host NQNs nickname of an NVM Subsystem with a specific Id or Name
          /Update namespace nicknames of an NVM Subsystem with a specific Id or Name
          /Delete an NVM Subsystem with a specific Id
          /Delete an NVM Subsystem with a specific Id forcefully tasks.
        type: int
        required: false
      host_mode:
        description: The host mode of the NVM subsystem.
          Required for the Create an NVM Subsystem with a specific ID
          /Create an NVM Subsystem with a free ID tasks.
        type: str
        required: false
      enable_namespace_security:
        description: Namespace security settings.
          Required for the Create an NVM Subsystem with a specific ID task.
          Optional for the Create an NVM Subsystem with a free ID task.
        type: bool
        required: false
        default: true
      ports:
        description: The ports of the NVM subsystem.
          Required for the Create an NVM Subsystem with a specific ID
          /Create an NVM Subsystem with a free ID
          /Add ports to an NVM Subsystem with a specific ID
          /Add ports to an NVM Subsystem with a specific Name
          /Remove ports from an NVM Subsystem with a specific Name or ID tasks.
        type: list
        elements: str
        required: false
      host_nqns:
        description: The host NQNs of the NVM subsystem.
          Required for the Create an NVM Subsystem with a specific ID
          /Add host NQNs to an NVM Subsystem with a specific ID
          /Add host NQNs to an NVM Subsystem with a specific Name
          /Remove host NQNs from an NVM Subsystem with a specific Id or Name
          /Remove host NQNs from an NVM Subsystem with a specific Id or Name using force
          /Update host NQNs nickname of an NVM Subsystem with a specific Id or Name tasks.
          Optional for the Create an NVM Subsystem with a free ID task.
        type: list
        elements: dict
        required: false
      namespaces:
        description: The namespaces of the NVM subsystem.
          Required for the Create an NVM Subsystem with a specific ID
          /Add namespaces and namespace paths to an NVM Subsystem with a specific ID
          /Add namespaces and namespace paths to an NVM Subsystem with a specific name
          /Remove namespace paths from an NVM Subsystem with specific Id or Name
          /Remove namespace from an NVM Subsystem with specific Id or Name
          /Remove namespace from an NVM Subsystem with specific Id or Name using force
          /Update namespace nicknames of an NVM Subsystem with a specific Id or Name tasks.
          Optional for the Create an NVM Subsystem with a free ID task.
        type: list
        elements: dict
        required: false
        suboptions:
          ldev_id:
            description: The LDEV ID of the namespace.
              Required for the Create an NVM Subsystem with a specific ID
              /Create an NVM Subsystem with a free ID
              /Add namespaces and namespace paths to an NVM Subsystem with a specific ID
              /Add namespaces and namespace paths to an NVM Subsystem with a specific name
              /Remove namespace paths from an NVM Subsystem with specific Id or Name
              /Remove namespace from an NVM Subsystem with specific Id or Name
              /Remove namespace from an NVM Subsystem with specific Id or Name using force
              /Update namespace nicknames of an NVM Subsystem with a specific Id or Name tasks.
            type: str
            required: true
          nickname:
            description: The nickname of the namespace.
              Required for the Create an NVM Subsystem with a specific ID
              /Create an NVM Subsystem with a free ID
              /Add namespaces and namespace paths to an NVM Subsystem with a specific ID
              /Add namespaces and namespace paths to an NVM Subsystem with a specific name
              /Remove namespace paths from an NVM Subsystem with specific Id or Name
              /Remove namespace from an NVM Subsystem with specific Id or Name
              /Remove namespace from an NVM Subsystem with specific Id or Name using force
              /Update namespace nicknames of an NVM Subsystem with a specific Id or Name tasks.
            type: str
            required: false
          paths:
            description: The paths of the namespace.
              Required for the Create an NVM Subsystem with a specific ID
              /Create an NVM Subsystem with a free ID
              /Add namespaces and namespace paths to an NVM Subsystem with a specific ID
              /Add namespaces and namespace paths to an NVM Subsystem with a specific name
              /Remove namespace paths from an NVM Subsystem with specific Id or Name
              /Remove namespace from an NVM Subsystem with specific Id or Name
              /Remove namespace from an NVM Subsystem with specific Id or Name using force
              /Update namespace nicknames of an NVM Subsystem with a specific Id or Name tasks.
            type: list
            elements: str
            required: false
      force:
        description: This flag is used to force the operation.
          Required for the Remove namespace from an NVM Subsystem with specific Id or Name using force
          /Remove host NQNs from an NVM Subsystem with a specific Id or Name using force
          /Delete an NVM Subsystem with a specific Id forcefully
          /Delete an NVM Subsystem with a specific name forcefully tasks.
        type: bool
        required: false
        default: false
      state:
        description:
          - The specific operation to perform on the NVM subsystem.
          - C(add_port) - Add ports to the NVM subsystem.
          - C(remove_port) - Remove ports from the NVM subsystem.
          - C(add_host_nqn) - Add host NQNs to the NVM subsystem.
          - C(remove_host_nqn) - Remove host NQNs from the NVM subsystem.
          - C(add_namespace) - Add namespaces to the NVM subsystem.
          - C(remove_namespace) - Remove namespaces from the NVM subsystem.
          - C(add_namespace_path) - Add paths to the namespace.
          - C(remove_namespace_path) - Remove paths from the namespace.
        type: str
        required: false
        choices: ['add_port', 'remove_port', 'add_host_nqn', 'remove_host_nqn', 'add_namespace',
                  'remove_namespace', 'add_namespace_path', 'remove_namespace_path']
"""

EXAMPLES = """
- name: Create an NVM Subsystem
  hitachivantara.vspone_block.vsp.hv_nvm_subsystems:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      name: "nvm_tcp_01"
      id: 1000
      host_mode: "VMWARE_EX"
      enable_namespace_security: true
      ports: ["CL1-D"]
      host_nqns:
        - nqn: "nqn.2014-08.org.example:uuid:4b73e622-ddc1-449a-99f7-412c0d3baa40"
          nickname: "my_host_nqn_40"
      namespaces:
        - ldev_id: 11101
          nickname: "nickname"
          paths: ["nqn.2014-08.org.example:uuid:4b73e622-ddc1-449a-99f7-412c0d3baa40"]

- name: Add host NQNs to an NVM Subsystem with a specific ID
  hitachivantara.vspone_block.vsp.hv_nvm_subsystems:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      id: 1000
      state: "add_host_nqn"
      host_nqns:
        - nqn: "nqn.2014-08.org.example:uuid:4b73e622-ddc1-449a-99f7-412c0d3baa41"
          nickname: "my_host_nqn_41"

- name: Remove host NQNs from an NVM Subsystem with a specific ID
  hitachivantara.vspone_block.vsp.hv_nvm_subsystems:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      id: 1000
      state: "remove_host_nqn"
      host_nqns:
        - nqn: "nqn.2014-08.org.example:uuid:4b73e622-ddc1-449a-99f7-412c0d3baa41"
          nickname: "my_host_nqn_41"

- name: Delete an NVM Subsystem with a specific Id forcefully
  hitachivantara.vspone_block.vsp.hv_nvm_subsystems:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "absent"
    spec:
      id: "nvm_subsystems_id_18"
      force: true
"""

RETURN = """
nvm_subsystems:
  description: The NVM subsystem information.
  type: list
  elements: dict
  returned: success
  contains:
    storage_serial_number:
      description: The serial number of the storage system.
      type: str
      sample: "810045"
    host_nqn_info:
      description: List of host NQN information.
      type: list
      elements: dict
      contains:
        host_nqn:
          description: Host NQN.
          type: str
          sample: "nqn.2014-08.com.ucpa-sc-hv:nvme:scpodl-esxi235"
        host_nqn_nickname:
          description: Nickname for the host NQN.
          type: str
          sample: ""
    namespace_paths_info:
      description: List of namespace paths information.
      type: list
      elements: dict
      contains:
        host_nqn:
          description: Host NQN.
          type: str
          sample: "nqn.2014-08.com.ucpa-sc-hv:nvme:scpodl-esxi235"
        ldev_id:
          description: Logical device ID.
          type: int
          sample: 5555
        ldev_id_hex:
          description: Logical device hex ID.
          type: str
          sample: "00:15:B3"
        namespace_id:
          description: Namespace ID.
          type: int
          sample: 3
    namespaces_info:
      description: List of namespaces information.
      type: list
      elements: dict
      contains:
        block_capacity:
          description: Block capacity of the namespace.
          type: int
          sample: 20971520
        capacity_in_mb:
          description: Capacity in MB.
          type: float
          sample: 10240.0
        capacity_in_unit:
          description: Capacity in human-readable unit.
          type: str
          sample: "10.00GB"
        ldev_id:
          description: Logical device ID.
          type: int
          sample: 2000
        ldev_id_hex:
          description: Logical device hex ID.
          type: str
          sample: "00:07:D0"
        namespace_id:
          description: Namespace ID.
          type: int
          sample: 2
        namespace_nickname:
          description: Nickname for the namespace.
          type: str
          sample: ""
    nvm_subsystem_info:
      description: Information about the NVM subsystem.
      type: dict
      contains:
        host_mode:
          description: Host mode.
          type: str
          sample: "VMWARE_EX"
        namespace_security_setting:
          description: Namespace security setting.
          type: str
          sample: "Enable"
        nvm_subsystem_id:
          description: NVM subsystem ID.
          type: int
          sample: 1
        nvm_subsystem_name:
          description: NVM subsystem name.
          type: str
          sample: "NVME-TCP-CL1-D-01"
        resource_group_id:
          description: Resource group ID.
          type: int
          sample: 8
        t10pi_mode:
          description: T10PI mode.
          type: str
          sample: "Disable"
    port_info:
      description: List of port information.
      type: list
      elements: dict
      contains:
        port_id:
          description: Port ID.
          type: str
          sample: "CL1-D"
        port_type:
          description: Port type.
          type: str
          sample: "NVME_TCP"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_nvme import (
    VSPNvmeReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPNvmeSubsystemArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPNvmSubsystemManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPNvmeSubsystemArguments().nvme_subsystem()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = None
            self.spec = self.parameter_manager.get_nvme_subsystem_spec()
            self.state = self.parameter_manager.get_state()

        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of NVM Subsystem operation ===")
        registration_message = validate_ansible_product_registration()

        nvm_subsystems = None
        try:
            reconciler = VSPNvmeReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            nvm_subsystems = reconciler.reconcile_nvm_subsystem(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of NVM Subsystem operation ===")
            self.module.fail_json(msg=str(e))

        resp = {
            "changed": self.connection_info.changed,
            "nvm_subsystems": nvm_subsystems,
        }
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of NVM Subsystem operation ===")
        self.module.exit_json(**resp)


def main(module=None):
    obj_store = VSPNvmSubsystemManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
