#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
---
module: hv_sds_block_spare_node
short_description: Manages spare nodes on VSP One SDS Block and Cloud systems.
description:
  - This module manages spare node configuration including node identification, fault domain assignment,
    network configuration, and BMC settings on Hitachi SDS Block storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/spare_node.yml)
version_added: "4.4.0"
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
    description: The desired state of the spare node.
    type: str
    required: false
    choices: ["present", "absent"]
    default: "present"
  spec:
    description: Configuration specifications for spare node management.
    required: true
    type: dict
    suboptions:
      id:
        description: Unique identifier for the spare node.
        required: false
        type: str
      fault_domain_id:
        description: Identifier for the fault domain where the spare node belongs.
        required: false
        type: str
      control_port_ipv4_address:
        description: IPv4 address for the control port of the spare node.
        required: false
        type: str
      setup_user_password:
        description: Password for the setup user account.
        required: false
        type: str
      bmc_name:
        description: Name of the Baseboard Management Controller (BMC).
        required: false
        type: str
      bmc_user:
        description: Username for BMC authentication.
        required: false
        type: str
      bmc_password:
        description: Password for BMC authentication.
        required: false
        type: str
"""

EXAMPLES = r"""
- name: Add a spare node to the SDS Block storage system
  hitachivantara.vspone_block.hv_sds_block_spare_node:
    connection_info:
      address: "{{ storage_system_ip }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: present
    spec:
      id: "spare-node-01"
      fault_domain_id: "fd-001"
      control_port_ipv4_address: "192.168.1.100"
      setup_user_password: "{{ setup_password }}"
      bmc_name: "spare-bmc-01"
      bmc_user: "admin"
      bmc_password: "{{ bmc_password }}"

- name: Remove a spare node from the SDS Block storage system
  hitachivantara.vspone_block.hv_sds_block_spare_node:
    connection_info:
      address: "{{ storage_system_ip }}"
      username: "{{ username }}"
      password: "{{ password }}"
    state: absent
    spec:
      id: "spare-node-01"

- name: Configure spare node with minimal settings
  hitachivantara.vspone_block.hv_sds_block_spare_node:
    connection_info:
      address: "{{ storage_system_ip }}"
      username: "{{ username }}"
      password: "{{ password }}"
    spec:
      id: "spare-node-02"
      fault_domain_id: "fd-002"
      control_port_ipv4_address: "192.168.1.101"
"""

RETURN = r"""
spare_node:
  description: The spare node configuration.
  returned: always
  type: dict
  contains:
    id:
      description: Unique identifier for the spare node.
      type: str
      sample: "spare-node-01"
    name:
      description: Name of the spare node.
      type: str
      sample: "spare-node-01"
    fault_domain_id:
      description: Identifier for the fault domain where the spare node belongs.
      type: str
      sample: "fd-001"
    fault_domain_name:
      description: Name of the fault domain where the spare node belongs.
      type: str
      sample: "fault-domain-001"
    control_port_ipv4_address:
      description: IPv4 address for the control port of the spare node.
      type: str
      sample: "192.168.1.100"
    software_version:
      description: Software version of the spare node.
      type: str
      sample: "1.0.0"
    bios_uuid:
      description: BIOS UUID of the spare node.
      type: str
      sample: "12345678-1234-1234-1234-123456789abc"
    model_name:
      description: Model name of the spare node.
      type: str
      sample: "HV-SDSB-001"
    serial_number:
      description: Serial number of the spare node.
      type: str
      sample: "SN123456789"
    bmc_name:
      description: Name of the Baseboard Management Controller (BMC).
      type: str
      sample: "spare-bmc-01"
    bmc_user:
      description: Username for BMC authentication.
      type: str
      sample: "admin"
"""

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_storage_cluster_mgmt_reconciler import (
    SDSBStorageControllerReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SpareNodeArgs,
    SDSBParametersManager,
)
from ansible.module_utils.basic import AnsibleModule


class SDSBSpareNodeManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SpareNodeArgs().spare_node()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.spare_node_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Spare Node Configuration Operation ==="
        )
        spare_node_settings = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBStorageControllerReconciler(self.connection_info)
            spare_node_settings = sdsb_reconciler.spare_node_reconcile(
                self.state, self.spec
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Spare Node Configuration Operation ==="
            )
            self.module.fail_json(msg=str(e))

        data = {
            "changed": self.connection_info.changed,
            "spare_node": spare_node_settings,
            "message": (
                self.spec.comment
                if self.spec.comment
                else "Successfully updated spare node settings."
            ),
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Spare Node Configuration Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBSpareNodeManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
