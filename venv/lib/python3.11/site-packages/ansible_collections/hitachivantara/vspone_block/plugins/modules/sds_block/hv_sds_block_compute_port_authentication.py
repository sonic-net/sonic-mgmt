#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_compute_port_authentication
short_description: Manages compute port authentication mode settings.
description:
  - This module manages compute port authentication mode settings.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/port_auth.yml)
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
    description: The level of the compute port authentication task. Choices are C(present) and C(absent).
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the compute port authentication task.
    type: dict
    required: true
    suboptions:
      port_name:
        description: Port name.
        type: str
        required: false
      state:
        description: The state of the port authorization task.
        type: str
        required: false
        choices: ['add_chap_user', 'remove_chap_user']
      authentication_mode:
        description: Authentication mode.
        type: str
        required: false
        choices: ['CHAP', 'CHAP_complying_with_initiator_setting', 'None']
      is_discovery_chap_authentication:
        description: When true is specified, CHAP authentication at the time of discovery is enabled.
        type: bool
        required: false
      target_chap_users:
        description: List of target CHAP user name.
        type: list
        required: false
        elements: str
"""

EXAMPLES = """
- name: Set port authentication mode
  hitachivantara.vspone_block.sds_block.hv_sds_block_compute_port_authentication:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      port_name: "iqn.1994-04.jp.co.hitachi:rsd.sph.t.0a85a.000"
      authentication_mode: "CHAP"
      target_chap_users: ["chapuser1"]
"""

RETURN = """
compute_port_authorizations:
  description: The compute port information.
  returned: always
  type: dict
  contains:
    chap_users_info:
      description: List of CHAP users information.
      type: list
      elements: dict
      contains:
        id:
          description: Unique identifier for the CHAP user.
          type: str
          sample: "a083ca8f-e925-474a-b63b-d9b06b2d02ad"
        initiator_chap_user_name:
          description: Initiator CHAP user name.
          type: str
          sample: ""
        target_chap_user_name:
          description: Target CHAP user name.
          type: str
          sample: "RD-chap-user-1"
    port_auth_info:
      description: Port authentication information.
      type: dict
      contains:
        auth_mode:
          description: Authentication mode.
          type: str
          sample: "CHAP"
        id:
          description: Unique identifier for the port authentication.
          type: str
          sample: "0f13e320-53e7-4088-aa11-418636b58376"
        is_discovery_chap_auth:
          description: Indicates if discovery CHAP authentication is enabled.
          type: bool
          sample: false
        is_mutual_chap_auth:
          description: Indicates if mutual CHAP authentication is enabled.
          type: bool
          sample: true
    port_info:
      description: Port information.
      type: dict
      contains:
        configured_port_speed:
          description: Configured port speed.
          type: str
          sample: "Auto"
        fc_information:
          description: Fibre Channel information.
          type: dict
          sample: null
        id:
          description: Unique identifier for the port.
          type: str
          sample: "0f13e320-53e7-4088-aa11-418636b58376"
        interface_name:
          description: Interface name.
          type: str
          sample: "eth2"
        iscsi_information:
          description: iSCSI information.
          type: dict
          contains:
            delayed_ack:
              description: Indicates if delayed ACK is enabled.
              type: bool
              sample: true
            ip_mode:
              description: IP mode.
              type: str
              sample: "ipv4"
            ipv4_information:
              description: IPv4 information.
              type: dict
              contains:
                address:
                  description: IPv4 address.
                  type: str
                  sample: "10.76.34.52"
                default_gateway:
                  description: Default gateway.
                  type: str
                  sample: "10.76.34.1"
                subnet_mask:
                  description: Subnet mask.
                  type: str
                  sample: "255.255.255.0"
            ipv6_information:
              description: IPv6 information.
              type: dict
              contains:
                default_gateway:
                  description: Default gateway.
                  type: str
                  sample: ""
                global_address1:
                  description: Global address 1.
                  type: str
                  sample: ""
                global_address_mode:
                  description: Global address mode.
                  type: str
                  sample: "Manual"
                linklocal_address:
                  description: Link-local address.
                  type: str
                  sample: ""
                linklocal_address_mode:
                  description: Link-local address mode.
                  type: str
                  sample: "Auto"
                subnet_prefix_length1:
                  description: Subnet prefix length.
                  type: int
                  sample: 0
            is_isns_client_enabled:
              description: Indicates if iSNS client is enabled.
              type: bool
              sample: false
            isns_servers:
              description: List of iSNS servers.
              type: list
              elements: dict
              contains:
                index:
                  description: Index of the iSNS server.
                  type: int
                  sample: 1
                port:
                  description: Port of the iSNS server.
                  type: int
                  sample: 3205
                server_name:
                  description: Name of the iSNS server.
                  type: str
                  sample: ""
            mac_address:
              description: MAC address.
              type: str
              sample: "b4:96:91:c8:76:0c"
            mtu_size:
              description: MTU size.
              type: int
              sample: 9000
        name:
          description: Port name.
          type: str
          sample: "iqn.1994-04.jp.co.hitachi:rsd.sph.t.0a85a.001"
        nickname:
          description: Port nickname.
          type: str
          sample: "001-iSCSI-001"
        nvme_tcp_information:
          description: NVMe over TCP information.
          type: dict
          sample: null
        port_speed:
          description: Port speed.
          type: str
          sample: "25G"
        port_speed_duplex:
          description: Port speed duplex.
          type: str
          sample: "25Gbps Full"
        protection_domain_id:
          description: Protection domain ID.
          type: str
          sample: "645c36b6-da9e-44bb-b711-430e06c7ad2b"
        protocol:
          description: Protocol.
          type: str
          sample: "iSCSI"
        status:
          description: Port status.
          type: str
          sample: "Normal"
        status_summary:
          description: Port status summary.
          type: str
          sample: "Normal"
        storage_node_id:
          description: Storage node ID.
          type: str
          sample: "c3be292d-fe72-48c9-8780-3a0cbb5fbff6"
        type:
          description: Port type.
          type: str
          sample: "Universal"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_constants import (
    StateValue,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_port_auth import (
    SDSBPortAuthReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_properties_extractor import (
    PortDetailPropertiesExtractor,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBPortAuthArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBPortAuthManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBPortAuthArguments().port_auth()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.state = parameter_manager.get_state()
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_port_auth_spec()
        self.logger.writeDebug(
            f"MOD:hv_sds_block_port_authentication:spec= {self.spec}"
        )

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Compute Port Authentication Operation ==="
        )
        port_auth = None
        port_auth_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBPortAuthReconciler(self.connection_info)
            self.logger.writeDebug(
                f"MOD:hv_sds_block_port_authentication:apply:spec= {self.spec}"
            )
            port_auth = sdsb_reconciler.reconcile_port_auth(self.state, self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_port_authentication:port_auth= {port_auth}"
            )
            if self.state.lower() == StateValue.PRESENT:
                # output_dict = port_auth.data_to_list()
                output_dict = port_auth.to_dict()
                port_auth_data_extracted = PortDetailPropertiesExtractor().extract_dict(
                    output_dict
                )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Compute Port Authentication Operation ==="
            )
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "compute_port_authorizations": port_auth_data_extracted,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo(
            "=== End of SDSB Compute Port Authentication Operation ==="
        )
        self.module.exit_json(**response)


def main(module=None):
    obj_store = SDSBPortAuthManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
