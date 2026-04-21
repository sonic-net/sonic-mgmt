#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_snmp_settings
short_description: Manage SNMP settings on Hitachi Vantara storage systems.
description:
  - This module allows you to configure SNMP (Simple Network Management Protocol) settings on Hitachi Vantara storage systems,
    including agent enablement, SNMP versions, trap destinations, authentication, and system group information.
  - For example usage, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/snmp_settings.yml)
version_added: "4.0.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.8
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.gateway_note
  - hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: Desired state of the SNMP settings.
    type: str
    required: false
    default: present
    choices: ["present", "test"]
  spec:
    description: SNMP settings specification.
    type: dict
    required: false
    suboptions:
      is_snmp_agent_enabled:
        description: Whether SNMP agent is enabled.
          Required for the Specifying the SNMP error notification destinations with v2c version
          /Specifying the SNMP error notification destinations with v3 version
          /Disable the SNMP agent tasks.
        type: bool
        required: true
      snmp_version:
        description: SNMP version to use.
          Required for the Specifying the SNMP error notification destinations with v2c version
          /Specifying the SNMP error notification destinations with v3 version
          /Disable the SNMP agent tasks.
        type: str
        required: true
        choices: ["v1", "v2c", "v3"]

      snmp_v1v2c_trap_destination_settings:
        description: SNMP v1/v2c trap destination settings.
          Required for the Specifying the SNMP error notification destinations with v2c version task.
        type: list
        elements: dict
        required: false
        suboptions:
          community:
            description: SNMP community string.
              Required for the Specifying the SNMP error notification destinations with v2c version task.
            type: str
            required: true
          send_trap_to:
            description: List of trap destination addresses.
              Required for the Specifying the SNMP error notification destinations with v2c version task.
            type: list
            elements: str
            required: true

      snmp_v3_trap_destination_settings:
        description: SNMP v3 trap destination settings.
          Required for the Specifying the SNMP error notification destinations with v3 version task.
        type: list
        elements: dict
        required: false
        suboptions:
          user_name:
            description: SNMP v3 user name.
              Required for the Specifying the SNMP error notification destinations with v3 version task.
            type: str
            required: true
          send_trap_to:
            description: Trap destination address.
              Required for the Specifying the SNMP error notification destinations with v3 version task.
            type: str
            required: true
          authentication:
            description: Authentication settings for SNMP v3.
              Optional for the Specifying the SNMP error notification destinations with v3 version task.
            type: dict
            required: false
            suboptions:
              protocol:
                description: Authentication protocol.
                  Optional for the Specifying the SNMP error notification destinations with v3 version task.
                type: str
                required: false
                choices: ["MD5", "SHA"]
              password:
                description: Authentication password.
                  Optional for the Specifying the SNMP error notification destinations with v3 version task.
                type: str
                required: false
              encryption:
                description: Encryption settings.
                  Optional for the Specifying the SNMP error notification destinations with v3 version task.
                type: dict
                required: false
                suboptions:
                  protocol:
                    description: Encryption protocol.
                      Optional for the Specifying the SNMP error notification destinations with v3 version task.
                    type: str
                    required: false
                    choices: ["AES", "DES"]
                  key:
                    description: Encryption key.
                      Optional for the Specifying the SNMP error notification destinations with v3 version task.
                    type: str
                    required: false

      snmp_v1v2c_authentication_settings:
        description: SNMP v1/v2c authentication settings.
          Required for the Specifying the SNMP error notification destinations with v2c version task.
        type: list
        elements: dict
        required: false
        suboptions:
          community:
            description: SNMP community string.
              Required for the Specifying the SNMP error notification destinations with v2c version task.
            type: str
            required: true
          requests_permitted:
            description: List of permitted requests.
              Required for the Specifying the SNMP error notification destinations with v2c version task.
            type: list
            elements: str
            required: true

      snmp_v3_authentication_settings:
        description: SNMP v3 authentication settings.
          Required for the Specifying the SNMP error notification destinations with v3 version task.
        type: list
        elements: dict
        required: false
        suboptions:
          user_name:
            description: SNMP v3 user name.
              Required for the Specifying the SNMP error notification destinations with v3 version task.
            type: str
            required: true
          authentication:
            description: Authentication settings for SNMP v3.
              Optional for the Specifying the SNMP error notification destinations with v3 version task.
            type: dict
            required: false
            suboptions:
              protocol:
                description: Authentication protocol.
                  Optional for the Specifying the SNMP error notification destinations with v3 version task.
                type: str
                required: false
                choices: ["MD5", "SHA"]
              password:
                description: Authentication password.
                  Optional for the Specifying the SNMP error notification destinations with v3 version task.
                type: str
                required: false
              encryption:
                description: Encryption settings.
                  Optional for the Specifying the SNMP error notification destinations with v3 version task.
                type: dict
                required: false
                suboptions:
                  protocol:
                    description: Encryption protocol.
                      Optional for the Specifying the SNMP error notification destinations with v3 version task.
                    type: str
                    required: false
                    choices: ["AES", "DES"]
                  key:
                    description: Encryption key.
                      Optional for the Specifying the SNMP error notification destinations with v3 version task.
                    type: str
                    required: false
      system_group_information:
        description: System group information.
          Required for the Specifying the SNMP error notification destinations with v2c version
          /Specifying the SNMP error notification destinations with v3 version
          /Disable the SNMP agent tasks.
        type: dict
        required: true
        suboptions:
          storage_system_name:
            description: Name of the storage system.
              Required for the Specifying the SNMP error notification destinations with v2c version
              /Specifying the SNMP error notification destinations with v3 version
              /Disable the SNMP agent tasks.
            type: str
            required: true
          contact:
            description: Contact information.
              Required for the Specifying the SNMP error notification destinations with v2c version
              /Specifying the SNMP error notification destinations with v3 version
              /Disable the SNMP agent tasks.
            type: str
            required: true
          location:
            description: Location information.
              Required for the Specifying the SNMP error notification destinations with v2c version
              /Specifying the SNMP error notification destinations with v3 version
              /Disable the SNMP agent tasks.
            type: str
            required: true
"""


EXAMPLES = """
- name: Configure SNMP settings on Hitachi Vantara storage system
  hitachivantara.vspone_block.vsp.hv_snmp_settings:
    connection_info:
      address: 192.0.2.10
      username: admin
      password: secret
    spec:
      is_snmp_agent_enabled: true
      snmp_version: "v2c"
      snmp_v1v2c_trap_destination_settings:
        - community: "public"
          send_trap_to:
            - "203.0.113.1"
            - "203.0.113.2"
      snmp_v1v2c_authentication_settings:
        - community: "public"
          requests_permitted:
            - "get"
            - "set"
      system_group_information:
        storage_system_name: "VSP-Block-01"
        contact: "admin@datacenter.com"
        location: "Data Center 1"
"""

RETURN = """
snmp_settings:
  description: SNMP configuration details.
  returned: always
  type: dict
  contains:
    is_snmp_agent_enabled:
      description: Whether SNMP agent is enabled on the storage system.
      type: bool
      sample: true
    snmp_version:
      description: SNMP version configured on the system.
      type: str
      sample: "v2c"
    snmp_engine_id:
      description: SNMP engine ID of the storage system.
      type: str
      sample: "0x80001f88043636326431396163"
    request_authentication_setting:
      description: SNMP request authentication settings.
      type: dict
      contains:
        snmpv3_settings:
          description: SNMPv3 authentication settings.
          type: list
          elements: dict
          contains:
            user_name:
              description: SNMPv3 username.
              type: str
              sample: "snmpv3user"
            send_trap_to:
              description: IP address to send traps to.
              type: str
              sample: "192.168.1.100"
            authentication:
              description: Authentication configuration.
              type: dict
              contains:
                protocol:
                  description: Authentication protocol.
                  type: str
                  sample: "SHA"
                password:
                  description: Authentication password.
                  type: str
                  sample: "CHANGE_ME_SET_YOUR_PASSWORD"
                encryption:
                  description: Encryption settings.
                  type: dict
                  contains:
                    protocol:
                      description: Encryption protocol.
                      type: str
                      sample: "AES"
                    key:
                      description: Encryption key.
                      type: str
                      sample: "encryptionKey456"
        snmpv1v2c_settings:
          description: SNMPv1/v2c authentication settings.
          type: list
          elements: dict
          contains:
            community:
              description: SNMP community string.
              type: str
              sample: "public"
            requests_permitted:
              description: List of permitted IP addresses for requests.
              type: list
              elements: str
              sample: ["192.168.1.0/24", "10.0.0.0/8"]
    sending_trap_setting:
      description: SNMP trap configuration settings.
      type: dict
      contains:
        snmpv1v2c_settings:
          description: SNMPv1/v2c trap settings.
          type: list
          elements: dict
          contains:
            community:
              description: SNMP community string.
              type: str
              sample: "public"
            send_trap_to:
              description: List of IP addresses to send traps to.
              type: list
              elements: str
              sample: ["172.25.37.79", "203.0.113.21"]
        snmpv3_settings:
          description: SNMPv3 trap settings.
          type: list
          elements: dict
          contains:
            user_name:
              description: SNMPv3 username.
              type: str
              sample: "trapuser"
            send_trap_to:
              description: IP address to send traps to.
              type: str
              sample: "192.168.1.200"
            authentication:
              description: Authentication configuration.
              type: dict
              contains:
                protocol:
                  description: Authentication protocol.
                  type: str
                  sample: "SHA"
                password:
                  description: Authentication password.
                  type: str
                  sample: "CHANGE_ME_SET_YOUR_PASSWORD"
                encryption:
                  description: Encryption settings.
                  type: dict
                  contains:
                    protocol:
                      description: Encryption protocol.
                      type: str
                      sample: "AES"
                    key:
                      description: Encryption key.
                      type: str
                      sample: "trapEncKey321"
    system_group_information:
      description: System group information for SNMP.
      type: dict
      contains:
        storage_system_name:
          description: Name of the storage system.
          type: str
          sample: "VSP-Block-45-102"
        contact:
          description: Contact information for the system.
          type: str
          sample: "admin@hitachivantara.com"
        location:
          description: Physical location of the system.
          type: str
          sample: "SC Data Center 1"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_initial_system_config_reconciler import (
    InitialSystemConfigReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPSNMPArguments,
    VSPParametersManager,
)


class AuditLogModule:
    """
    Class representing Audit log Module.
    """

    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPSNMPArguments().snmp_args()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.spec = self.parameter_manager.get_snmp_settings_spec()
            self.state = self.parameter_manager.get_state()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of SNMP Settings Module ===")
        registration_message = validate_ansible_product_registration()

        try:
            response, msg = InitialSystemConfigReconciler(
                self.parameter_manager.connection_info
            ).snmp_reconcile(self.state, self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of SNMP Settings Module ===")
            self.module.fail_json(msg=str(e))

        data = {
            "snmp_settings": response,
            "changed": self.parameter_manager.connection_info.changed,
            "message": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SNMP Settings Module ===")
        self.module.exit_json(**data)


def main():
    obj_store = AuditLogModule()
    obj_store.apply()


if __name__ == "__main__":
    main()
