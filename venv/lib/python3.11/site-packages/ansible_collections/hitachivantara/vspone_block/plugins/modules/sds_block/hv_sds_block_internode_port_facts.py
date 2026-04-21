#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_internode_port_facts
short_description: Get internode port from VSP One SDS Block and Cloud systems.
description:
  - Get internode port from storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_internode_port_facts.yml)
version_added: "4.1.0"
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
    description: Specification for retrieving CHAP user information.
    type: dict
    required: false
    suboptions:
      id:
        description: Filter internode port by ID (UUID format).
        type: str
"""

EXAMPLES = """
- name: Retrieve information about all internode_port
  hitachivantara.vspone_block.sds_block.hv_sds_block_internode_port_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about internode_port by specifying id
  hitachivantara.vspone_block.sds_block.hv_sds_block_internode_port_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "126f360e-c79e-4e75-8f7c-7d91bfd2f0b8"
"""

RETURN = r"""
ansible_facts:
  description: Dictionary containing discovered internode port information.
  returned: always
  type: dict
  contains:
    internode_ports:
      description: List of internode port entries.
      type: list
      elements: dict
      contains:
        id:
          description: Unique identifier for the internode port.
          type: str
          sample: "8caf0b3a-043d-4833-ab7c-3f3d1d6d30db"
        storage_node_id:
          description: UUID of the storage node associated with this internode port.
          type: str
          sample: "72ecacd0-1d4c-431c-80e8-80924a1b8f28"
        mac_address:
          description: MAC address of the network interface.
          type: str
          sample: "b4:96:91:c9:ef:ea"
        mtu_size:
          description: Maximum Transmission Unit size.
          type: int
          sample: 9000
        interface_name:
          description: Interface name of the network device.
          type: str
          sample: "eth1"
        device_name:
          description: Name of the physical device.
          type: str
          sample: "Ethernet Controller E810-XXV for SFP (Ethernet Network Adapter E810-XXV-2)"
        configured_port_speed:
          description: Configured speed setting of the port.
          type: str
          sample: "Auto"
        port_speed_duplex:
          description: Actual speed and duplex setting of the port.
          type: str
          sample: "25Gbps Full"
        is_teaming_enabled:
          description: Whether NIC teaming is enabled.
          type: bool
          sample: true
        ipv4_information:
          description: IPv4 network configuration.
          type: dict
          contains:
            address:
              description: IPv4 address.
              type: str
              sample: "192.168.110.51"
            subnet_mask:
              description: Subnet mask.
              type: str
              sample: "255.255.255.0"
        teaming:
          description: Teaming configuration details, if present.
          type: dict
          contains:
            active_port:
              description: Which port is active in the team.
              type: str
              sample: "primary"
            auto_fail_back_enabled:
              description: Whether automatic fail-back is enabled.
              type: bool
              sample: true
            mode:
              description: Teaming mode.
              type: str
              sample: "active-standby"
            primary_configured_port_speed:
              description: Configured speed of the primary port in the team.
              type: str
              sample: "Auto"
            primary_device_name:
              description: Device name of the primary port in the team.
              type: str
              sample: "Ethernet Controller E810-XXV for SFP (Ethernet Network Adapter E810-XXV-2)"
            primary_interface_name:
              description: Interface name of the primary port in the team.
              type: str
              sample: "port2"
            primary_mac_address:
              description: MAC address of the primary port in the team.
              type: str
              sample: "b4:96:91:c9:ef:ea"
            primary_port_speed_duplex:
              description: Actual speed and duplex setting of the primary port.
              type: str
              sample: "25Gbps Full"
            secondary_configured_port_speed:
              description: Configured speed of the secondary port in the team.
              type: str
              sample: "Auto"
            secondary_device_name:
              description: Device name of the secondary port in the team.
              type: str
              sample: "Ethernet Controller E810-XXV for SFP (Ethernet Network Adapter E810-XXV-2)"
            secondary_interface_name:
              description: Interface name of the secondary port in the team.
              type: str
              sample: "port3"
            secondary_mac_address:
              description: MAC address of the secondary port in the team.
              type: str
              sample: "b4:96:91:c9:ef:eb"
            secondary_port_speed_duplex:
              description: Actual speed and duplex setting of the secondary port.
              type: str
              sample: "25Gbps Full"
        redundancy:
          description: Redundancy level for the port (e.g., 0 for none).
          type: int
          sample: 1
        status:
          description: Current operational status of the internode port.
          type: str
          sample: "Normal"
        status_summary:
          description: Summary of the port's status.
          type: str
          sample: "Normal"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBControlPortArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_control_port_reconciler import (
    SDSBControlPortReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockInterNodePortFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBControlPortArguments().control_port_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_control_port_fact_spec()
        self.logger.writeDebug(f"MOD:hv_sds_block_control_port_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Inter Node Port Facts ===")
        control_port = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBControlPortReconciler(self.connection_info)
            control_port = sdsb_reconciler.get_internode_ports(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_control_port_facts:control_port= {control_port}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Inter Node Port Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"internode_ports": control_port}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Inter Node Port Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockInterNodePortFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
