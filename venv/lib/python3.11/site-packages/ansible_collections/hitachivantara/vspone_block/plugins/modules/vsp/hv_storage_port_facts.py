#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_storage_port_facts
short_description: Retrieves storage port information from Hitachi VSP storage systems.
description:
  - This module retrieves information about storage ports from Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/storage_port_facts.yml)
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
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_with_type
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
  spec:
    description: Specification for the storage port facts to be gathered.
    type: dict
    required: false
    suboptions:
      ports:
        description: The id of the specific ports to retrieve.
        type: list
        required: false
        elements: str
      query:
        description: This field allows to query for getting information about a port on an external storage system.
          query parameter is one of C(external_iscsi_targets), C(registered_external_iscsi_targets), C(external_storage_ports), C(external_luns).
        type: list
        required: false
        elements: str
      external_iscsi_ip_address:
        description:  IP address of the iSCSI target on the external storage system.
        type: str
        required: false
      external_tcp_port:
        description: TCP port number of the iSCSI target on the external storage system. If this attribute is omitted,
          the TCP port number of the port on the local storage system is assumed.
        type: int
        required: false
      external_iscsi_name:
        description: iSCSI name of the target on the external storage system.
        type: str
        required: false
      external_wwn:
        description: This field is used to pass the value of the external WWN to operate on external storage systems.
          This field is used to query for getting information about a port on an external storage system.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all ports
  hitachivantara.vspone_block.vsp.hv_storage_port_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"

- name: Get information about specific ports
  hitachivantara.vspone_block.vsp.hv_storage_port_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      ports: ["CLA-1", "CLA-2"]
"""


RETURN = """
ansible_facts:
    description: >
        Dictionary containing the discovered properties of the storage ports.
    returned: always
    type: dict
    contains:
        port_data:
            description: The storage port information.
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
                    description: iSCSI window size of the port.
                    type: str
                    sample: ""
                keep_alive_timer:
                    description: Keep alive timer value of the port.
                    type: int
                    sample: -1
                loop_id:
                    description: Loop ID of the port.
                    type: str
                    sample: "CE"
                lun_security_setting:
                    description: Indicates if LUN security is enabled.
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
                    sample:
                        - "TAR"
                        - "MCU"
                        - "RCU"
                        - "ELUN"
                port_connection:
                    description: Connection type of the port.
                    type: str
                    sample: "PtoP"
                port_id:
                    description: ID of the port.
                    type: str
                    sample: "CL8-B"
                port_mode:
                    description: Mode of the port.
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
class VSPStoragePortFactManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPStoragePortArguments().storage_port_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:

            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = self.params_manager.storage_system_info.serial
            self.spec = self.params_manager.get_port_fact_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Storage Port Facts ===")
        port_data = None
        registration_message = validate_ansible_product_registration()

        try:

            port_data = self.get_storage_port_facts()

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of Storage Port Facts ===")
            self.module.fail_json(msg=str(e))
        if self.spec.query:
            lower_case_query = [key.lower() for key in self.spec.query]
            if "external_luns" in lower_case_query:
                if self.spec.external_wwn:
                    data = {
                        "fc_luns": port_data,
                    }
                else:
                    data = {
                        "iscsi_luns": port_data,
                    }
            else:
                data = {
                    "port_data": port_data,
                }
        else:
            data = {
                "port_data": port_data,
            }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Storage Port Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)

    def get_storage_port_facts(self):
        reconciler = VSPStoragePortReconciler(
            self.connection_info,
            self.storage_serial_number,
        )

        result = reconciler.vsp_storage_port_facts(self.spec)
        return result


def main():
    """
    :return: None
    """
    obj_store = VSPStoragePortFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
