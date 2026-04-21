#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_upload_file
short_description: This uploads the files required to set the transfer destination of audit log files
description:
  - This module uploads files required to set the transfer destination of audit log files.
  - For example usage, visit
    https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/upload_file.yml
version_added: "4.0.0"
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
options:
  spec:
    description: Specification to upload file.
    type: dict
    required: true
    suboptions:
      file_path:
        description: Path to the file to be uploaded.
        type: str
        required: true
      file_type:
        description: Type of the file to be uploaded.
        type: str
        required: true
        choices:
          - primary_client
          - primary_root
          - secondary_client
          - secondary_root

"""

EXAMPLES = """
- name: Enable SNMP agent and configure SNMPv2c with trap destinations
  hitachivantara.vspone_block.vsp.hv_upload_file:
    connection_info:
      address: 192.0.2.10
      username: admin
      password: secret
    spec:
      file_path: /path/to/audit_log_file.pem
      file_type: primary_client
"""
RETURN = """
---
result:
  description: Dictionary containing the outcome of the module execution.
  returned: always
  type: dict
  contains:
    changed:
      description: Indicates whether any change was made.
      type: bool
      returned: always
      sample: false
    failed:
      description: Indicates whether the module execution failed.
      type: bool
      returned: always
      sample: false
    message:
      description: Human-readable message(s) about the operation result.
      type: list
      elements: str
      returned: always
      sample:
        - ""
        - "Transfer destination for audit log file specified successfully."
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    UploadCertFileArgs,
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


class UploadFile:
    """
    Class representing UploadFile.
    """

    def __init__(self):

        self.logger = Log()
        self.argument_spec = UploadCertFileArgs().upload_cert_file_args()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.spec = self.parameter_manager.get_upload_file_spec()
            self.connection_info = self.parameter_manager.connection_info
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of Upload File Module ===")
        registration_message = validate_ansible_product_registration()

        try:
            response = InitialSystemConfigReconciler(
                self.parameter_manager.connection_info
            ).upload_file_reconcile(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Upload File Module ===")
            self.module.fail_json(msg=str(e))

        data = {
            "message": response,
            "changed": self.connection_info.changed,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Upload File Module ===")
        self.module.exit_json(**data)


def main():
    obj_store = UploadFile()
    obj_store.apply()


if __name__ == "__main__":
    main()
