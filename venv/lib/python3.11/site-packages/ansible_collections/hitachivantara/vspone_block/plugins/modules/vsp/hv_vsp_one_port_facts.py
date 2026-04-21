#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_port_facts
short_description: Retrieves port information from VSP E series and VSP One Block 20 series storage systems.
description:
  - This module retrieves port information from  VSP E series and VSP One Block 20 series storage systems.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for port facts retrieval across VSP one B20 series and VSP E series models.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_port_facts.yml)
version_added: '4.3.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Specifies whether the module operates in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.connection_info
options:
  spec:
    description: Query parameters for retrieving port information.
    type: dict
    required: false
    suboptions:
      port_id:
        description: Port identifier to filter ports.
        type: str
        required: false
      protocol:
        description: Protocol type to filter ports. Valid values are  like C(NVME_TCP), C(FC), and C(iSCSI). This is case insensitive.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get port information by port ID
  hitachivantara.vspone_block.hv_vsp_one_port_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      port_id: "CL1-C"

- name: Get all port information
  hitachivantara.vspone_block.hv_vsp_one_port_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
- name: Get port information by protocol
  hitachivantara.vspone_block.hv_vsp_one_port_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      protocol: "fc"
"""

RETURN = """
ansible_facts:
  description: Facts about ports retrieved from the storage system.
  returned: always
  type: dict
  contains:
    port:
      description: Port information retrieved from the storage system.
      returned: always
      type: dict
      contains:
        actual_port_speed:
          description: Current actual speed of the port.
          type: str
          sample: "LINK_DOWN"
        fc_information:
          description: Fibre Channel information for the port.
          type: dict
          contains:
            al_pa:
              description: Arbitrated Loop Physical Address.
              type: str
              sample: "EF"
            fabric_switch_setting:
              description: Whether fabric switch setting is enabled.
              type: bool
              sample: false
            connection_type:
              description: Fibre Channel connection type.
              type: str
              sample: "FC_AL"
            sfp_data_transfer_rate:
              description: SFP data transfer rate.
              type: str
              sample: "NUMBER_16"
            port_mode:
              description: Port mode setting.
              type: str
              sample: "SCSI"
        id:
          description: Port identifier.
          type: str
          sample: "CL4-D"
        iscsi_information:
          description: iSCSI information for the port.
          type: dict
          contains:
            delayed_ack:
              description: Delayed ACK setting.
              type: bool
              sample: true
            ip_mode:
              description: IP mode (ipv4 or ipv6).
              type: str
              sample: "ipv4"
            ipv4_information:
              description: IPv4 configuration details.
              type: dict
              contains:
                address:
                  description: IPv4 address.
                  type: str
                  sample: "192.168.0.74"
                default_gateway:
                  description: Default gateway address.
                  type: str
                  sample: "0.0.0.0"
                subnet_mask:
                  description: Subnet mask.
                  type: str
                  sample: "255.255.255.0"
            ipv6_information:
              description: IPv6 configuration details.
              type: dict
              contains:
                default_gateway:
                  description: Default gateway for IPv6.
                  type: str
                  sample: "::"
                global:
                  description: Global IPv6 configuration mode.
                  type: str
                  sample: "Auto"
                global_address:
                  description: Global IPv6 address.
                  type: str
                  sample: "::"
                global_address_status:
                  description: Status of global IPv6 address.
                  type: str
                  sample: "INVALID"
                linklocal:
                  description: Link-local IPv6 configuration mode.
                  type: str
                  sample: "Auto"
                linklocal_address:
                  description: Link-local IPv6 address.
                  type: str
                  sample: "fe80::"
                linklocal_address_status:
                  description: Status of link-local IPv6 address.
                  type: str
                  sample: "INVALID"
            is_ipv6_updating:
              description: Whether IPv6 is currently updating.
              type: bool
              sample: false
            isns_server_ip_address:
              description: iSNS server IP address.
              type: str
              sample: "0.0.0.0"
            isns_server_mode:
              description: Whether iSNS server mode is enabled.
              type: bool
              sample: false
            isns_server_port:
              description: iSNS server port number.
              type: int
              sample: 3205
            keep_alive_timer:
              description: Keep alive timer value in seconds.
              type: int
              sample: 60
            link_mtu_size:
              description: Link MTU size.
              type: str
              sample: "NUMBER_1500"
            mtu_size:
              description: MTU size.
              type: str
              sample: "NUMBER_1500"
            selective_ack:
              description: Selective ACK setting.
              type: bool
              sample: true
            tcp_port:
              description: TCP port number.
              type: int
              sample: 3260
            virtual_port_enabled:
              description: Whether virtual port is enabled.
              type: bool
              sample: false
            vlan_use:
              description: Whether VLAN is in use.
              type: bool
              sample: false
            window_size:
              description: TCP window size.
              type: str
              sample: "NUMBER_64K"
        nvme_tcp_information:
          description: NVMe over TCP information for the port.
          type: dict
          contains:
            delayed_ack:
              description: Delayed ACK setting.
              type: bool
              sample: true
            ip_mode:
              description: IP mode (ipv4 or ipv6).
              type: str
              sample: "ipv4"
            ipv4_information:
              description: IPv4 configuration details.
              type: dict
              contains:
                address:
                  description: IPv4 address.
                  type: str
                  sample: "192.168.0.78"
                default_gateway:
                  description: Default gateway address.
                  type: str
                  sample: "0.0.0.0"
                subnet_mask:
                  description: Subnet mask.
                  type: str
                  sample: "255.255.255.0"
            ipv6_information:
              description: IPv6 configuration details.
              type: dict
            is_ipv6_updating:
              description: Whether IPv6 is currently updating.
              type: bool
              sample: false
            link_mtu_size:
              description: Link MTU size.
              type: str
              sample: "NUMBER_1500"
            mtu_size:
              description: MTU size.
              type: str
              sample: "NUMBER_1500"
            tcp_port:
              description: TCP port number.
              type: int
              sample: 4420
            virtual_port_enabled:
              description: Whether virtual port is enabled.
              type: bool
              sample: false
        port_iscsi_name:
          description: iSCSI name for the port.
          type: str
          sample: ""
        port_security:
          description: Whether port security is enabled.
          type: bool
          sample: false
        port_speed:
          description: Configured port speed.
          type: str
          sample: "NUMBER_100"
        port_wwn:
          description: Port WWN address.
          type: str
          sample: ""
        protocol:
          description: Protocol used by the port.
          type: str
          sample: "NVME_TCP"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_one_port_reconciler import (
    VSPOnePortSimpleAPIReconciler,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPOnePortArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPOnePortFacts:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPOnePortArguments().get_vsp_one_port_facts_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_one_port_facts_spec()
            self.connection_info = params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One Port Facts Retrieval ===")
        ports = None
        registration_message = validate_ansible_product_registration()

        try:
            port_reconciler = VSPOnePortSimpleAPIReconciler(self.connection_info)
            ports = port_reconciler.port_facts_reconcile(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP One Port Facts Retrieval ===")
            self.module.fail_json(msg=str(e))

        response = {
            "port": ports,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One Port Facts Retrieval ===")
        self.module.exit_json(changed=False, ansible_facts=response)


def main():
    obj_store = VSPOnePortFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
