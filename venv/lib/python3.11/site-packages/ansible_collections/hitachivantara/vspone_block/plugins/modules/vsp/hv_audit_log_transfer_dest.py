#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_audit_log_transfer_dest
short_description: This module specifies settings related to the transfer of audit log files from a storage system to the syslog servers.
description:
  - The module specifies settings related to the transfer of audit log files from a storage system to the syslog servers.
  - For example usage, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/audit_log_transfer_dest.yml)
version_added: '4.0.0'
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
    description: The state of the audit log transfer destination configuration.
    type: str
    choices: [present, test]
    default: present
    required: false
  spec:
    description: Settings related to audit log transfer and syslog servers.
    type: dict
    required: False
    suboptions:
      transfer_protocol:
        description: Protocol used for transferring audit logs. Required for Setting the transfer
          destination tasks.
        type: str
        required: true
        choices: [TLS, UDP]
      location_name:
        description: Name of the location or identifier. Required for Setting the transfer
          destination tasks.
        type: str
        required: true
      retries:
        description: Number of retries for syslog transfer.
        type: bool
        required: false
      retry_interval:
        description: Interval between retries.
        type: int
        required: false
      is_detailed:
        description: Whether detailed audit logs are enabled.
        type: bool
        required: false
      primary_syslog_server:
        description: Primary syslog server configuration.
        type: dict
        required: false
        suboptions:
          is_enabled:
            description: Whether the primary syslog server is enabled. Required for Setting the
              transfer destination tasks.
            type: bool
            required: true
          ip_address:
            description: IP address of the primary syslog server. Optional for Setting the transfer
              destination tasks.
            type: str
            required: false
          port:
            description: Port used by the primary syslog server. Optional for Setting the transfer
              destination tasks.
            type: int
            required: false
          client_cert_file_name:
            description: Client certificate file name.
            type: str
            required: false
          client_cert_file_password:
            description: Password for the client certificate file.
            type: str
            required: false
          root_cert_file_name:
            description: Root certificate file name.
            type: str
            required: false
      secondary_syslog_server:
        description: Secondary syslog server configuration.
        type: dict
        required: false
        suboptions:
          is_enabled:
            description: Whether the secondary syslog server is enabled. Required for Setting the transfer
              destination tasks.
            type: bool
            required: true
          ip_address:
            description: IP address of the secondary syslog server. Optional for Setting the transfer
              destination tasks.
            type: str
            required: false
          port:
            description: Port used by the secondary syslog server. Optional for Setting the transfer destination
              tasks.
            type: int
            required: false
          client_cert_file_name:
            description: Client certificate file name.
            type: str
            required: false
          client_cert_file_password:
            description: Password for the client certificate file.
            type: str
            required: false
          root_cert_file_name:
            description: Root certificate file name.
            type: str
            required: false
"""

EXAMPLES = """
- name: Configure audit log transfer settings and syslog servers
  hitachivantara.vspone_block.vsp.hv_audit_log_transfer_dest:
    connection_info:
      address: 192.0.2.10
      username: admin
      password: secret
    spec:
      transfer_protocol: "TLS"
      location_name: "datacenter1"
      retries: 3
      retry_interval: 60
      is_detailed: true
      primary_syslog_server:
        is_enabled: true
        ip_address: "203.0.113.1"
        port: 514
        client_cert_file_name: "client-cert.pem"
        client_cert_file_password: "CHANGE_ME_SET_YOUR_PASSWORD"
        root_cert_file_name: "root-cert.pem"
      secondary_syslog_server:
        is_enabled: false
        ip_address: "203.0.113.2"
        port: 514
        client_cert_file_name: "client-cert2.pem"
        client_cert_file_password: "CHANGE_ME_SET_YOUR_PASSWORD"
        root_cert_file_name: "root-cert2.pem"
"""

RETURN = """
ansible_facts:
  description: Audit Logs and related information retrieved from the storage system.
  returned: always
  type: dict
  contains:
    audit_log_info:
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
          description: Number of retries for syslog transfer.
          type: int
          returned: when supported
        retry_interval:
          description: Interval between retries.
          type: int
          returned: when supported
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


class AuditLogModule:
    """
    Class representing Audit log Module.
    """

    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPAuditLogArguments().audit_log()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.spec = self.parameter_manager.get_audit_log_spec()
            self.state = self.parameter_manager.get_state()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of Audit Logs Module ===")
        registration_message = validate_ansible_product_registration()

        try:
            response, msg = InitialSystemConfigReconciler(
                self.parameter_manager.connection_info
            ).audit_log_reconcile(self.state, self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Audit Logs Module ===")
            self.module.fail_json(msg=str(e))

        data = {
            "audit_log_transfer_dest_info": response,
            "changed": self.parameter_manager.connection_info.changed,
            "message": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Audit Logs Module ===")
        self.module.exit_json(**data)


def main():
    obj_store = AuditLogModule()
    obj_store.apply()


if __name__ == "__main__":
    main()
