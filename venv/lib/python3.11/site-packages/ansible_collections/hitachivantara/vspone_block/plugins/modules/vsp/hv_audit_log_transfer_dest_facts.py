#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_audit_log_transfer_dest_facts
short_description: Retrieves about the settings related to the transfer of audit log files to the syslog servers.
description:
  - This module retrieves about the settings related to the transfer of audit log files to the syslog servers..
  - For example usage, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/audit_log_transfer_dest_facts.yml)
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
- name: Get about the settings related to the transfer of audit log files to the syslog servers.
  hitachivantara.vspone_block.vsp.hv_audit_log_transfer_dest_facts:
    connection_info:
      address: 192.0.2.10
      username: admin
      password: secret
"""

RETURN = """
ansible_facts:
  description: Audit Logs and related information retrieved from the storage system.
  returned: always
  type: dict
  contains:
    audit_log_transfer_dest_info:
      description: Details about the audit log transfer settings.
      type: dict
      contains:
        is_detailed:
          description: Whether detailed audit logs are enabled.
          type: bool
          returned: always
        location_name:
          description: Name of the location or identifier.
          type: str
          returned: always
        primary_syslog_server:
          description: Primary syslog server configuration.
          type: dict
          contains:
            ip_address:
              description: IP address of the primary syslog server.
              type: str
              returned: always
            is_enabled:
              description: Whether the primary syslog server is enabled.
              type: bool
              returned: always
            port:
              description: Port used by the primary syslog server.
              type: int
              returned: always
        retries:
          description: Whether retries for syslog transfer are enabled.
          type: bool
          returned: always
        retry_interval:
          description: Interval between retries (seconds).
          type: int
          returned: always
        secondary_syslog_server:
          description: Secondary syslog server configuration.
          type: dict
          contains:
            ip_address:
              description: IP address of the secondary syslog server.
              type: str
              returned: always
            is_enabled:
              description: Whether the secondary syslog server is enabled.
              type: bool
              returned: always
            port:
              description: Port used by the secondary syslog server.
              type: int
              returned: always
        transfer_protocol:
          description: Protocol used for transferring audit logs.
          type: str
          returned: always
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPAuditLogArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_initial_system_config_reconciler import (
    InitialSystemConfigReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class AuditLogFacts:
    """
    Class representing Audit log facts.
    """

    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPAuditLogArguments().audit_log_facts()

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

        self.logger.writeInfo("=== Start of Audit Logs Facts ===")
        registration_message = validate_ansible_product_registration()

        try:
            response = InitialSystemConfigReconciler(
                self.parameter_manager.connection_info
            ).audit_log_facts()

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Audit Logs Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "audit_log_transfer_dest_info": response,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Audit Logs Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = AuditLogFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
