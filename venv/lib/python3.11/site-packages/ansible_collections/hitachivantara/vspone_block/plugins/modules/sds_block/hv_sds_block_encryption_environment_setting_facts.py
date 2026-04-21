#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_encryption_environment_setting_facts
short_description: Retrieves encryption environment settings from VSP One SDS Block and Cloud systems.
description:
  - This module retrieves encryption environment configuration settings from Hitachi SDS Block storage systems.
  - Provides information about encryption enablement status, key management server usage, and warning thresholds.
  - Utilizes the Hitachi Vantara SDS Block API for encryption environment facts retrieval.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/encryption_environment_settings.yml)
version_added: '4.5.0'
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
- name: Get encryption environment settings
  hitachivantara.vspone_block.sds_block.hv_sds_block_encryption_environment_setting_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the encryption environment settings.
  returned: always
  type: dict
  contains:
    encryption_environment_settings:
      description: Information about encryption environment settings.
      type: dict
      contains:
        is_enabled:
          description: Indicates whether the encryption environment settings are enabled or disabled.
          type: bool
          sample: true
        is_encryption_key_management_server_in_use:
          description: Indicates whether to use an encryption key management server.
          type: bool
          sample: false
        free_keys_warning_threshold:
          description: The warning threshold for the number of encryption keys not allocated to encryption targets.
          type: int
          sample: 2000
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBEncryptionKeyArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_encryption_key_reconciler import (
    SDSBEncryptionKeyReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBEncryptionEnvironmentSettingFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            SDSBEncryptionKeyArguments().encryption_environment_setting_facts()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Encryption Environment Setting Facts ==="
        )
        response = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBEncryptionKeyReconciler(self.connection_info)
            response = sdsb_reconciler.get_encryption_environment_settings()

            self.logger.writeDebug(
                f"MOD:encryption_environment_setting_facts:settings= {response}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Encryption Environment Setting Facts ==="
            )
            self.module.fail_json(msg=str(e))

        data = {"encryption_environment_settings": response}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(
            "=== End of SDSB Encryption Environment Setting Facts ==="
        )
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBEncryptionEnvironmentSettingFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
