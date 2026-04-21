#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_port
short_description: Manages ports on VSP E series and VSP One Block 20 series storage systems.
description:
  - This module manages port configuration on VSP E series and VSP One Block 20 series storage systems.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for port management across VSP one B20 series and VSP E series models.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_port.yml)
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
    description: Configuration parameters for managing port settings.
    type: dict
    required: true
    suboptions:
      port_id:
        description: Port identifier to configure.
        type: str
        required: true
      port_speed_in_gbps:
        description: Port speed in Gbps.
        type: int
        choices: [0, 1, 4, 8, 10, 16, 25, 32, 64, 100]
        required: false
      enable_port_security:
        description: Whether to enable port security.
        type: bool
        required: false
      fc_settings:
        description: Fibre Channel specific settings.
        type: dict
        required: false
        suboptions:
          al_pa:
            description: Arbitrated Loop Physical Address.
            type: str
            required: false
          should_enable_fabric_switch_setting:
            description: Whether to enable fabric switch setting.
            type: bool
            required: false
          connection_type:
            description: FC connection type choices are C(Point_To_Point) and C(FC_AL) and case insensitive.
            type: str
            required: false
      iscsi_settings:
        description: iSCSI specific settings.
        type: dict
        required: false
        suboptions:
          enable_vlan_use:
            description: Whether to enable VLAN use.
            type: bool
            required: false
          add_vlan_id:
            description: VLAN ID to add.
            type: int
            required: false
          delete_vlan_id:
            description: VLAN ID to delete.
            type: int
            required: false
          ip_mode:
            description: IP mode configuration. Choices are C(ipv4) and C(ipv4v6) and case insensitive.
            type: str
            required: false
          ipv4_configuration:
            description: IPv4 configuration settings.
            type: dict
            required: false
            suboptions:
              address:
                description: IPv4 address.
                type: str
                required: false
              subnet_mask:
                description: IPv4 subnet mask.
                type: str
                required: false
              default_gateway:
                description: IPv4 default gateway.
                type: str
                required: false
          ipv6_configuration:
            description: IPv6 configuration settings.
            type: dict
            required: false
            suboptions:
              linklocal:
                description: IPv6 link-local address.
                type: str
                required: false
              global:
                description: IPv6 global address.
                type: str
                required: false
              default_gateway:
                description: IPv6 default gateway.
                type: str
                required: false
          tcp_port:
            description: TCP port number.
            type: int
            required: false
          enable_selective_ack:
            description: Whether to enable selective ACK.
            type: bool
            required: false
          enable_delayed_ack:
            description: Whether to enable delayed ACK.
            type: bool
            required: false
          window_size:
            description: TCP window size. Choices are C(NUMBER_16K), C(NUMBER_32K), C(NUMBER_64K), C(NUMBER_128K), C(NUMBER_256K), C(NUMBER_512K),
                        C(NUMBER_1024K) and case insensitive.
            type: str
            required: false
          mtu_size:
            description: MTU size. Choices are C(NUMBER_1500), C(NUMBER_4500), C(NUMBER_9000) and case insensitive.
            type: str
            required: false
          keep_alive_timer:
            description: Keep alive timer value.
            type: int
            required: false
          enable_isns_server_mode:
            description: Whether to enable iSNS server mode.
            type: bool
            required: false
          isns_server_ip_address:
            description: iSNS server IP address.
            type: str
            required: false
          isns_server_port:
            description: iSNS server port.
            type: int
            required: false
          enable_virtual_port:
            description: Whether to enable virtual port.
            type: bool
            required: false
      nvme_tcp_settings:
        description: NVMe over TCP specific settings.
        type: dict
        required: false
        suboptions:
          enable_vlan_use:
            description: Whether to enable VLAN use.
            type: bool
            required: false
          add_vlan_id:
            description: VLAN ID to add.
            type: int
            required: false
          delete_vlan_id:
            description: VLAN ID to delete.
            type: int
            required: false
          ip_mode:
            description: IP mode configuration. Choices are C(ipv4) and C(ipv4v6) and case insensitive.
            type: str
            required: false
          ipv4_configuration:
            description: IPv4 settings.
            type: dict
            required: false
            suboptions:
              address:
                description: IPv4 address.
                type: str
                required: false
              subnet_mask:
                description: IPv4 subnet mask.
                type: str
                required: false
              default_gateway:
                description: IPv4 default gateway.
                type: str
                required: false
          ipv6_configuration:
            description: IPv6 settings.
            type: dict
            required: false
            suboptions:
              linklocal:
                description: IPv6 link-local address.
                type: str
                required: false
              global_:
                description: IPv6 global address.
                type: str
                required: false
              default_gateway:
                description: IPv6 default gateway.
                type: str
                required: false
          tcp_port:
            description: TCP port number.
            type: int
            required: false
          discovery_tcp_port:
            description: Discovery TCP port number.
            type: int
            required: false
          enable_selective_ack:
            description: Whether to enable selective ACK.
            type: bool
            required: false
          enable_delayed_ack:
            description: Whether to enable delayed ACK.
            type: bool
            required: false
          window_size:
            description: TCP window size. Choices are C(NUMBER_64K), C(NUMBER_128K), C(NUMBER_256K), C(NUMBER_512K), C(NUMBER_1024K) and case insensitive.
            type: str
            required: false
          mtu_size:
            description: MTU size. Choices are C(NUMBER_1500), C(NUMBER_4500), C(NUMBER_9000) and case insensitive.
            type: str
            required: false
"""

EXAMPLES = """
- name: Configure basic port settings (port security and speed)
  hitachivantara.vspone_block.vsp.hv_vsp_one_port:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      port_id: "CL1-C"
      port_speed_in_gbps: 32
      enable_port_security: true

- name: Configure FC port with all settings
  hitachivantara.vspone_block.vsp.hv_vsp_one_port:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      port_id: "CL2-A"
      port_speed_in_gbps: 16
      enable_port_security: false
      fc_settings:
        al_pa: "0x01"
        should_enable_fabric_switch_setting: true
        connection_type: "Point_To_Point"

- name: Configure iSCSI port with comprehensive settings
  hitachivantara.vspone_block.vsp.hv_vsp_one_port:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      port_id: "CL3-B"
      port_speed_in_gbps: 25
      enable_port_security: true
      iscsi_settings:
        enable_vlan_use: true
        add_vlan_id: 100
        ip_mode: "ipv4v6"
        ipv4_configuration:
          address: "192.168.1.100"
          subnet_mask: "255.255.255.0"
          default_gateway: "192.168.1.1"
        ipv6_configuration:
          linklocal: "fe80::1"
          global: "2001:db8::100"
          default_gateway: "2001:db8::1"
        tcp_port: 3260
        enable_selective_ack: true
        enable_delayed_ack: false
        window_size: "NUMBER_256K"
        mtu_size: "NUMBER_9000"
        keep_alive_timer: 300
        enable_isns_server_mode: true
        isns_server_ip_address: "192.168.1.200"
        isns_server_port: 3205
        enable_virtual_port: false

- name: Configure NVMe over TCP port with all parameters
  hitachivantara.vspone_block.vsp.hv_vsp_one_port:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      port_id: "CL4-D"
      port_speed_in_gbps: 100
      enable_port_security: false
      nvme_tcp_settings:
        enable_vlan_use: true
        add_vlan_id: 200
        ip_mode: "ipv4"
        ipv4_settings:
          address: "10.0.1.50"
          subnet_mask: "255.255.255.0"
          default_gateway: "10.0.1.1"
        ipv6_settings:
          linklocal: "fe80::2"
          global_: "2001:db8:1::50"
          default_gateway: "2001:db8:1::1"
        tcp_port: 4420
        discovery_tcp_port: 8009
        enable_selective_ack: false
        enable_delayed_ack: true
        window_size: "NUMBER_512K"
        mtu_size: "NUMBER_4500"

- name: Remove VLAN from iSCSI port
  hitachivantara.vspone_block.vsp.hv_vsp_one_port:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      port_id: "CL3-B"
      iscsi_settings:
        delete_vlan_id: 100

- name: Configure port with minimal settings
  hitachivantara.vspone_block.vsp.hv_vsp_one_port:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      port_id: "CL1-A"
      port_speed_in_gbps: 0  # Auto speed
"""

RETURN = """
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
        self.argument_spec = VSPOnePortArguments().get_vsp_one_port_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_one_port_spec()
            self.connection_info = params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One Port Module ===")
        ports = None
        registration_message = validate_ansible_product_registration()

        try:
            port_reconciler = VSPOnePortSimpleAPIReconciler(self.connection_info)
            port = port_reconciler.reconcile(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP One Port Module ===")
            self.module.fail_json(msg=str(e))

        response = {
            "port": port,
            "comment": self.spec.comment,
            "changed": self.connection_info.changed,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One Port Module ===")
        self.module.exit_json(**response)


def main():
    obj_store = VSPOnePortFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
