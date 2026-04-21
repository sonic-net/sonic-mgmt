#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_snmp_settings
short_description: Manages SNMP settings on VSP One SDS Block and Cloud systems.
description:
  - This module manages SNMP settings including agent enablement, version configuration,
    trap settings, authentication settings, and system group information on Hitachi SDS Block storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_snmp.yml)
version_added: "4.4.0"
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
  spec:
    description: Specification for the SNMP settings.
    type: dict
    required: true
    suboptions:
      is_snmp_agent_enabled:
        description: Enable or disable the SNMP agent.
        type: bool
        required: false
      snmp_version:
        description: The SNMP version to use.
        type: str
        required: false
        choices: ["v2c"]
        default: "v2c"
      sending_trap_setting:
        description: Configuration for sending SNMP traps.
        type: dict
        required: false
        suboptions:
          snmpv2c_settings:
            description: SNMPv2c trap settings list.
            type: list
            elements: dict
            required: false
            suboptions:
              community:
                description: SNMP community string for traps.
                type: str
                required: false
                default: null
              send_trap_to:
                description: List of IP addresses or host names to send traps to.
                type: list
                elements: str
                required: false
      request_authentication_setting:
        description: Configuration for SNMP request authentication.
        type: dict
        required: false
        suboptions:
          snmpv2c_settings:
            description: SNMPv2c authentication settings list.
            type: list
            elements: dict
            required: false
            suboptions:
              community:
                description: SNMP community string for requests.
                type: str
                required: false
                default: null
              requests_permitted:
                description: List of IP addresses or host names permitted to make requests.
                type: list
                elements: str
                required: false
      system_group_information:
        description: System group information settings.
        type: dict
        required: false
        suboptions:
          storage_system_name:
            description: Name of the storage system.
            type: str
            required: false
          contact:
            description: Contact information for the system administrator.
            type: str
            required: false
          location:
            description: Physical location of the storage system.
            type: str
            required: false
"""

EXAMPLES = """
- name: Enable SNMP agent with basic configuration
  hitachivantara.vspone_block.sds_block.hv_sds_block_snmp_settings:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      is_snmp_agent_enabled: true
      snmp_version: "v2c"

- name: Configure SNMP with trap settings
  hitachivantara.vspone_block.sds_block.hv_sds_block_snmp_settings:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      is_snmp_agent_enabled: true
      snmp_version: "v2c"
      sending_trap_setting:
        snmpv2c_settings:
          - community: "public"
            send_trap_to:
              - "192.168.1.100"
              - "monitoring.company.com"
          - community: "private"
            send_trap_to:
              - "192.168.1.101"

- name: Configure SNMP with authentication settings
  hitachivantara.vspone_block.sds_block.hv_sds_block_snmp_settings:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      is_snmp_agent_enabled: true
      request_authentication_setting:
        snmpv2c_settings:
          - community: "readonly"
            requests_permitted:
              - "192.168.1.50"
              - "nms.company.com"
          - community: "readwrite"
            requests_permitted:
              - "192.168.1.51"

- name: Configure complete SNMP settings with system information
  hitachivantara.vspone_block.sds_block.hv_sds_block_snmp_settings:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      is_snmp_agent_enabled: true
      snmp_version: "v2c"
      sending_trap_setting:
        snmpv2c_settings:
          - community: "public"
            send_trap_to:
              - "192.168.1.100"
      request_authentication_setting:
        snmpv2c_settings:
          - community: "readonly"
            requests_permitted:
              - "192.168.1.50"
      system_group_information:
        storage_system_name: "Production-SDS-Block-01"
        contact: "admin@company.com"
        location: "Data Center Room A1"

- name: Disable SNMP agent
  hitachivantara.vspone_block.sds_block.hv_sds_block_snmp_settings:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      is_snmp_agent_enabled: false
"""

RETURN = """
snmp_settings:
  description: The SNMP settings configuration.
  returned: always
  type: dict
  contains:
    is_snmp_agent_enabled:
      description: Whether the SNMP agent is enabled.
      type: bool
      sample: true
    snmp_version:
      description: The SNMP version in use.
      type: str
      sample: "v2c"
    sending_trap_setting:
      description: SNMP trap configuration settings.
      type: dict
      contains:
        snmpv2c_settings:
          description: List of SNMPv2c trap configurations.
          type: list
          elements: dict
          contains:
            community:
              description: SNMP community string for traps.
              type: str
              sample: "public"
            send_trap_to:
              description: List of destinations for SNMP traps.
              type: list
              elements: str
              sample: ["192.168.1.100", "monitoring.company.com"]
    request_authentication_setting:
      description: SNMP request authentication settings.
      type: dict
      contains:
        snmpv2c_settings:
          description: List of SNMPv2c authentication configurations.
          type: list
          elements: dict
          contains:
            community:
              description: SNMP community string for requests.
              type: str
              sample: "readonly"
            requests_permitted:
              description: List of hosts permitted to make SNMP requests.
              type: list
              elements: str
              sample: ["192.168.1.50", "nms.company.com"]
    system_group_information:
      description: System group information.
      type: dict
      contains:
        storage_system_name:
          description: Name of the storage system.
          type: str
          sample: "Production-SDS-Block-01"
        contact:
          description: Contact information for the system administrator.
          type: str
          sample: "admin@company.com"
        location:
          description: Physical location of the storage system.
          type: str
          sample: "Data Center Room A1"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_storage_cluster_mgmt_reconciler import (
    SDSBStorageControllerReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBStorageSNMPSettingsArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBSnmpManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBStorageSNMPSettingsArguments().storage_snmp_settings()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_snmp_settings_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB SNMP Configuration Operation ===")
        snmp_settings = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBStorageControllerReconciler(self.connection_info)
            snmp_settings = sdsb_reconciler.snmp_reconcile(self.spec)
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB SNMP Configuration Operation ===")
            self.module.fail_json(msg=str(e))

        msg = ""
        if snmp_settings and self.connection_info.changed is True:
            msg = "Successfully updated SNMP settings."

        data = {
            "changed": self.connection_info.changed,
            "snmp_settings": snmp_settings,
            "message": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB SNMP Configuration Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBSnmpManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
