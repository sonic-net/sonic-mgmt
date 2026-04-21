#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_web_server
short_description: Manages the web server access setting for VSP One SDS Block and Cloud systems.
description:
  - Manages the web server access setting for VSP One SDS Block and Cloud systems.
  - This module allows you to configure client address allowlists and import server certificates.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_web_server.yml)
version_added: "4.5.0"
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
  state:
    description: Desired state of the web server settings.
    type: str
    choices: ['present', 'import_certificate']
    default: 'present'
  spec:
    description: Specification for the web server settings.
    type: dict
    required: true
    suboptions:
      enable_client_address_allowlist:
        description: Enable or disable the client address allowlist.
        type: bool
        required: false
      client_address_allowlist:
        description: List of client addresses for the allowlist.
        type: list
        elements: str
        required: false
      server_certificate_file_path:
        description: Path to the server certificate file(Required when state is 'import_certificate').
        type: str
        required: false
      server_certificate_secret_key_file_path:
        description: Path to the server certificate secret key file (Required when state is 'import_certificate').
        type: str
        required: false
"""

EXAMPLES = """
- name: Configure web server client address allowlist
  hitachivantara.vspone_block.sds_block.hv_sds_block_web_server:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      enable_client_address_allowlist: true
      client_address_allowlist:
        - "192.168.1.0/24"
        - "10.0.0.100"

- name: Import server certificate
  hitachivantara.vspone_block.sds_block.hv_sds_block_web_server:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: import_certificate
    spec:
      server_certificate_file_path: "/path/to/server.crt"
      server_certificate_secret_key_file_path: "/path/to/server.key"

- name: Disable client address allowlist
  hitachivantara.vspone_block.sds_block.hv_sds_block_web_server:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      enable_client_address_allowlist: false
"""


RETURN = r"""
web_server_setting:
  description: Web server access settings
  type: dict
  returned: always
  contains:
    allowlist_setting:
      description: Allowlist configuration settings
      type: dict
      returned: always
      contains:
        client_names:
          description: List of client IP addresses or host names in the allowlist
          type: list
          elements: str
          returned: always
        is_enabled:
          description: Whether the allowlist is enabled
          type: bool
          returned: always
    whitelist_setting:
      description: Whitelist configuration settings
      type: dict
      returned: always
      contains:
        client_names:
          description: List of client IP addresses or host names in the whitelist
          type: list
          elements: str
          returned: always
        is_enabled:
          description: Whether the whitelist is enabled
          type: bool
          returned: always
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    WebServerAccessSettingsArgs,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_web_server_settings_reconciler import (
    SDSBWebServerSettingsReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockWebServerSettingsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = WebServerAccessSettingsArgs().web_server_access_settings()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.state = parameter_manager.get_state()
        self.spec = parameter_manager.web_server_settings_spec()
        self.connection_info = parameter_manager.get_connection_info()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Web Server Facts ===")
        web_server_settings = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBWebServerSettingsReconciler(self.connection_info)
            web_server_settings = sdsb_reconciler.reconcile_web_server_settings(
                self.state, self.spec
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Web Server Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "web_server_setting": web_server_settings,
            "comment": self.spec.comment,
            "changed": self.connection_info.changed,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Web Server Facts ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBBlockWebServerSettingsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
