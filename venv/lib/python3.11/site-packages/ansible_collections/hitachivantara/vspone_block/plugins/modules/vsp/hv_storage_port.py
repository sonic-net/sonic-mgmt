#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_storage_port
short_description: Change the storage port settings in the Hitachi VSP storage systems.
description:
  - This module change the storage port settings information in the Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/storage_port.yml)
version_added: '3.1.0'
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
    description: The level of the port tasks. Choices are C(present), C(login_test), C(register_external_iscsi_target), C(unregister_external_iscsi_target).
    type: str
    required: false
    choices: ['present', 'login_test', 'register_external_iscsi_target', 'unregister_external_iscsi_target']
    default: 'present'
  storage_system_info:
    description: Information about the storage system. This field is an optional field.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false
  spec:
    description: Specification for the storage port tasks.
    type: dict
    required: false
    suboptions:
      port:
        description: The port id of the specific port to retrieve.
        type: str
        required: true
      port_attribute:
        description: Specify the port attribute of the port. The specifiable values are 'TAR' or 'ALL'. Use 'TAR' for Fibre Target port,
          use 'ALL' for Bidirectional port. This attribute cannot be specified at the same time as any other attribute.
        type: str
        required: false
      port_mode:
        description: Specify the operating mode of the port. The specifiable values are 'FC-NVMe' or 'FCP-SCSI'.
          This attribute cannot be specified at the same time as any other attribute.
        type: str
        required: false
      port_speed:
        description: Specify the transfer speed of the port. The specifiable values are 'AUT' or 'nG', where n is a number and G can be omitted.
        type: str
        required: false
      fabric_mode:
        description: Fabric mode of the port. Set when this value is true. Not set when this value is false.
          When specifying this attribute, be sure to also specify the port_connection attribute.
        type: bool
        required: false
      port_connection:
        description: Topology setting for the port. The specifiable values are 'FCAL', 'P2P' or 'PtoP'.
          When specifying this attribute, be sure to also specify the fabric_mode attribute.
        type: str
        required: false
      enable_port_security:
        description: Specify whether to enable the lun security setting for the port.
        type: bool
        required: false
      external_iscsi_targets:
        description: Information about the iSCSI target of the external storage system.
        type: list
        required: false
        elements: dict
        suboptions:
          ip_address:
            description: IP address of the iSCSI target of the external storage system.
            type: str
            required: true
          name:
            description: ISCSI name of the iSCSI target of the external storage system.
            type: str
            required: true
          tcp_port:
            description: TCP port number of the iSCSI target of the external storage system.
            type: int
            required: false
      host_ip_address:
        description: >
                Sending the ping command from a specified iSCSI port or NVMe/TCP port on the storage system to the host,
                It will return ping results when this is provided by ignoring other parameter.
        type: str
        required: false
"""

EXAMPLES = """
- name: Change attribute setting of the storage port by port id
  hitachivantara.vspone_block.vsp.hv_storage_port:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      port: "CL8-B"
      port_attribute: "TAR"  # Options: "TAR", "ALL"

- name: Change port mode setting of the storage port by port id
  hitachivantara.vspone_block.vsp.hv_storage_port:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      port: "CL8-B"
      port_mode: "FC-NVMe"  # Options: "FC-NVMe", "FCP-SCSI"

- name: Change port security setting of the storage port by port id
  hitachivantara.vspone_block.vsp.hv_storage_port:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      port: "CL1-A"
      enable_port_security: true

- name: Perform a login test
  hitachivantara.vspone_block.vsp.hv_storage_port:
    connection_info: "{{ connection_info }}"
    state: "login_test"
    spec:
      port: "CL1-C"
      external_iscsi_target:
        ip_address: "172.25.59.213"
        name: "iqn.1994-04.jp.co.hitachi:rsd.has.t.10045.1c019"

- name: Sending the ping command to a specified host
  hitachivantara.vspone_block.vsp.hv_storage_port:
    connection_info: "{{ connection_info }}"
    state: "login_test"
    spec:
      port: "CL1-C"
      host_ip_address: "172.25.59.213"
"""

RETURN = """
storagePort:
  description: The storage port information.
  returned: always
  type: list
  elements: dict
  contains:
    fabric_mode:
      description: Indicates if the port is in fabric mode.
      type: bool
      sample: true
    ipv4_address:
      description: IPv4 address of the port.
      type: str
      sample: ""
    ipv4_gateway_address:
      description: IPv4 gateway address of the port.
      type: str
      sample: ""
    ipv4_subnetmask:
      description: IPv4 subnet mask of the port.
      type: str
      sample: ""
    iscsi_window_size:
      description: iSCSI window size.
      type: str
      sample: ""
    keep_alive_timer:
      description: Keep alive timer value.
      type: int
      sample: -1
    loop_id:
      description: Loop ID of the port.
      type: str
      sample: "CE"
    lun_security_setting:
      description: Indicates if LUN security setting is enabled.
      type: bool
      sample: false
    mac_address:
      description: MAC address of the port.
      type: str
      sample: ""
    port_attributes:
      description: List of port attributes.
      type: list
      elements: str
      sample: ["TAR", "MCU", "RCU", "ELUN"]
    port_connection:
      description: Type of port connection.
      type: str
      sample: "PtoP"
    port_id:
      description: Port ID.
      type: str
      sample: "CL8-B"
    port_mode:
      description: Operating mode of the port.
      type: str
      sample: "FCP-SCSI"
    port_speed:
      description: Speed of the port.
      type: str
      sample: "AUT"
    port_type:
      description: Type of the port.
      type: str
      sample: "FIBRE"
    storage_serial_number:
      description: Serial number of the storage system.
      type: str
      sample: "715035"
    tcp_port:
      description: TCP port number.
      type: str
      sample: ""
    wwn:
      description: World Wide Name of the port.
      type: str
      sample: "50060e8028274271"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPStoragePortArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_storage_port import (
    VSPStoragePortReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log_decorator import (
    LogDecorator,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


@LogDecorator.debug_methods
class VSPStoragePortManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPStoragePortArguments().storage_port()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:

            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = self.params_manager.storage_system_info.serial
            self.spec = self.params_manager.port_module_spec()
            self.state = self.params_manager.get_state()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Storage Port operation. ===")
        port_data = None
        resp = {}
        registration_message = validate_ansible_product_registration()
        try:

            port_data = self.storage_port_module()

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Storage Port operation. ===")
            self.module.fail_json(msg=str(e))
        if self.spec.host_ip_address:

            resp["ping_result"] = port_data
        else:
            resp = {
                "changed": self.connection_info.changed,
                "port_info": port_data,
                "msg": "Storage port updated successfully",
            }
        if self.state and self.state == "login_test":
            resp["msg"] = "Login test performed successfully"
        if registration_message:
            resp["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Storage Port operation. ===")
        self.module.exit_json(**resp)

    def storage_port_module(self):
        reconciler = VSPStoragePortReconciler(
            self.connection_info,
            self.storage_serial_number,
            self.state,
        )
        result = reconciler.vsp_storage_port_reconcile(self.spec)
        return result


def main(module=None):
    """
    :return: None
    """
    obj_store = VSPStoragePortManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
