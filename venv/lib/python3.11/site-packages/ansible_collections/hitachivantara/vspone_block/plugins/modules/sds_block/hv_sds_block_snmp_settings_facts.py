#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_snmp_settings_facts
short_description: Get SNMP settings from VSP One SDS Block and Cloud systems.
description:
  - This module retrieves SNMP settings including agent status, version configuration,
    trap settings, authentication settings, and system group information from Hitachi SDS Block storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_snmp_settings_facts.yml)
version_added: "4.4.0"
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
"""

EXAMPLES = """
- name: Retrieve all SNMP settings information
  hitachivantara.vspone_block.sds_block.hv_sds_block_snmp_settings_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the SNMP settings.
  returned: always
  type: dict
  contains:
    snmp_settings:
      description: SNMP configuration settings.
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
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
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
from ansible.module_utils.basic import AnsibleModule


class SDSBBlockSnmpSettingsFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            SDSBStorageSNMPSettingsArguments().storage_snmp_settings_facts()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB SNMP Settings Facts ===")
        snmp_settings = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBStorageControllerReconciler(self.connection_info)
            snmp_settings = sdsb_reconciler.snmp_facts_reconcile()

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB SNMP Settings Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"snmp_settings": snmp_settings}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB SNMP Settings Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockSnmpSettingsFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
