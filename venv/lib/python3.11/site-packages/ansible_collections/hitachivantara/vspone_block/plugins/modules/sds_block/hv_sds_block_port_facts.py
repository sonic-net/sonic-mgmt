#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_port_facts
short_description: Retrieves information about compute ports.
description:
  - This module retrieves information about compute ports.
  - It provides details about a compute port such as ID, lun and other details.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/compute_port_facts.yml)
version_added: '3.0.0'
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
    description: Specification for retrieving compute port information.
    type: dict
    required: true
    suboptions:
      names:
        description: The names of the compute ports.
        type: list
        required: false
        elements: str
      nicknames:
        description: The nicknames of the compute ports.
        type: list
        required: false
        elements: str
"""

EXAMPLES = """
- name: Retrieve information about all compute ports
  hitachivantara.vspone_block.sds_block.hv_sds_block_port_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about compute ports by compute node name
  hitachivantara.vspone_block.sds_block.hv_sds_block_port_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      nicknames: ["000-iSCSI-000"]

- name: Retrieve information about compute ports by names
  hitachivantara.vspone_block.sds_block.hv_sds_block_port_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      names: ["p1-compute-node", "RD-compute-node-111"]
"""

RETURN = """
ansible_facts:
  description: Dictionary of returned facts.
  returned: always
  type: dict
  contains:
    ports:
      description: A list of compute ports.
      returned: always
      type: list
      elements: dict
      contains:
        chap_users_info:
          description: List of CHAP users information.
          type: list
          elements: dict
          contains:
            id:
              description: Unique identifier for the CHAP user.
              type: str
              sample: "464e1fd1-9892-4134-866c-6964ce786676"
            initiator_chap_user_name:
              description: Initiator CHAP user name.
              type: str
              sample: ""
            target_chap_user_name:
              description: Target CHAP user name.
              type: str
              sample: "test"
        port_auth_info:
          description: Port authentication information.
          type: dict
          contains:
            auth_mode:
              description: Authentication mode.
              type: str
              sample: "CHAP"
            id:
              description: Unique identifier for the port authentication info.
              type: str
              sample: "932962b5-ab61-429f-ba06-cd976e1a8f97"
            is_discovery_chap_auth:
              description: Indicates if discovery CHAP authentication is enabled.
              type: bool
              sample: false
            is_mutual_chap_auth:
              description: Indicates if mutual CHAP authentication is enabled.
              type: bool
              sample: true
        port_info:
          description: Detailed information about the port.
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
              sample: "932962b5-ab61-429f-ba06-cd976e1a8f97"
            interface_name:
              description: Name of the interface.
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
                      sample: "10.76.34.51"
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
                      description: Subnet prefix length 1.
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
                  sample: "b4:96:91:c8:75:bc"
                mtu_size:
                  description: MTU size.
                  type: int
                  sample: 9000
            name:
              description: Name of the port.
              type: str
              sample: "iqn.1994-04.jp.co.hitachi:rsd.sph.t.0a85a.000"
            nickname:
              description: Nickname of the port.
              type: str
              sample: "000-iSCSI-000"
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
              description: Protocol used by the port.
              type: str
              sample: "iSCSI"
            status:
              description: Status of the port.
              type: str
              sample: "Normal"
            status_summary:
              description: Summary of the port status.
              type: str
              sample: "Normal"
            storage_node_id:
              description: Storage node ID.
              type: str
              sample: "01f598b8-dc1c-45fc-b821-5ea108d42593"
            type:
              description: Type of the port.
              type: str
              sample: "Universal"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_port import (
    SDSBPortReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_properties_extractor import (
    PortDetailPropertiesExtractor,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBPortArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBPortFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBPortArguments().port_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        self.logger.writeDebug(f"spec = {self.argument_spec}")
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_compute_port_fact_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Compute Port Facts ===")
        ports = None
        ports_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBPortReconciler(self.connection_info)
            ports = sdsb_reconciler.get_compute_ports(self.spec)

            self.logger.writeDebug(f"MOD:hv_sds_block_port_facts:ports= {ports}")
            output_dict = ports.data_to_list()
            ports_data_extracted = PortDetailPropertiesExtractor().extract(output_dict)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Compute Port Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "ports": ports_data_extracted,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Compute Port Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = SDSBPortFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
