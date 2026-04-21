#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: hv_snmp_settings_facts
short_description: Retrieves SNMP configuration from Hitachi VSP storage systems.
description:
  - This module retrieves SNMP settings (v1, v2c, v3) from Hitachi VSP storage systems.
  - For example usage, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/snmp.yml)
version_added: '4.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.8
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.gateway_note
  - hitachivantara.vspone_block.common.connection_info
"""

EXAMPLES = """
- name: Enable SNMP agent and configure SNMPv2c with trap destinations
  hitachivantara.vspone_block.vsp.hv_snmp_settings_facts:
    connection_info:
      address: 192.0.2.10
      username: admin
      password: secret
"""
RETURN = """
ansible_facts:
  description: SNMP settings and related information retrieved from the storage system.
  returned: always
  type: dict
  contains:
    snmp_settings:
      description: SNMP configuration details.
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
from ansible.module_utils.basic import AnsibleModule


class SNMPSettingsFacts:
    """
    Class representing SNMPv3 settings.
    """

    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPSNMPArguments().snmp_facts()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of SNMP Settings Facts ===")
        registration_message = validate_ansible_product_registration()

        try:
            response = InitialSystemConfigReconciler(
                self.parameter_manager.connection_info
            ).snmp_facts()

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of SNMP Settings Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "snmp_settings": response,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SNMP Settings Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SNMPSettingsFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
