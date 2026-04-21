#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_compute_port
short_description: Manages compute ports in VSP One SDS Block and Cloud systems.
description:
  - This module allows to change the settings and protocol of the compute port on Hitachi SDS Block storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/compute_port.yml)
version_added: "4.3.0"
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
    description: The desired state of the compute port.
    type: str
    required: false
    choices: ['present']
    default: 'present'
  spec:
    description: Specification for the compute port.
    type: dict
    required: true
    suboptions:
      id:
        description: The ID of the compute port.
        type: str
        required: false
      name:
        description: The name of the compute port.
        type: str
        required: false
      nick_name:
        description: The nickname of the compute port.
        type: str
        required: false
      protocol:
        description: The protocol of the compute port.
        type: str
        required: false
        choices: ["iscsi", "nvme_tcp"]
"""

EXAMPLES = """
- name: Expand storage pool by pool name
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_pool:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "expand"
    spec:
      name: "SP01"
      drive_ids: ["6a14d3cb-264f-41b1-81c0-cdbfab73d358"]

- name: Edit compute port settings
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_pool:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "expand"
    spec:
      id: "3f9bcecc-9ac5-4c21-abed-5b03e682e7b4"
      drive_ids: ["6a14d3cb-264f-41b1-81c0-cdbfab73d358"]
"""

RETURN = """
compute_ports:
  description: Detailed information about the port.
  returned: always
  type: dict
  contains:
    configured_port_speed:
      description: Configured port speed.
      type: str
      sample: "Auto"
    fc_information:
      description: Fibre Channel information.
      type: dict
      sample: ""
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


class SDSBComputePortManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBPortArguments().compute_port()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_compute_port_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Compute Port Operation ===")
        compute_ports = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBPortReconciler(self.connection_info)
            compute_ports = sdsb_reconciler.reconcile_compute_port(self.spec)
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Storage Pool Operation ===")
            self.module.fail_json(msg=str(e))
        msg = ""
        if compute_ports:
            msg = self.get_message()
        data = {
            "changed": self.connection_info.changed,
            "compute_ports": compute_ports if compute_ports else "",
            "message": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Compute Port Operation ===")
        self.module.exit_json(**data)

    def get_message(self):
        msg = ""
        if self.state == "present":
            msg = "Successfully completed the compute port operation."
            if self.connection_info.changed and self.spec.protocol:
                msg = (
                    msg
                    + " You must also carry out operations, including restarting the storage cluster, to apply the protocol setting change. "
                )

        return msg


def main():
    obj_store = SDSBComputePortManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
