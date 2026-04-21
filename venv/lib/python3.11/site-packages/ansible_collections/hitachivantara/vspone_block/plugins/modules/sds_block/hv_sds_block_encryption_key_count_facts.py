#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_encryption_key_count_facts
short_description: Get encryption key count information from VSP One SDS Block and Cloud systems.
description:
  - Get information about the number of encryption keys from storage system.
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
- name: Get encryption key count
  hitachivantara.vspone_block.sds_block.hv_sds_block_encryption_key_count_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the encryption key count information.
  returned: always
  type: dict
  contains:
    encryption_key_count:
      description: Information about encryption key counts.
      type: dict
      contains:
        total_allocated_encryption_targets:
          description: Number of encryption keys allocated to encryption targets.
          type: int
          sample: 0
        total_unallocated_encryption_targets:
          description: Number of encryption keys not yet allocated to encryption targets.
          type: int
          sample: 4096
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


class SDSBEncryptionKeyCountFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBEncryptionKeyArguments().encryption_key_count_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Encryption Key Count Facts ===")
        response = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBEncryptionKeyReconciler(self.connection_info)
            response = sdsb_reconciler.get_encryption_key_count()

            self.logger.writeDebug(f"MOD:encryption_key_count_facts:count= {response}")

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Encryption Key Count Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"encryption_key_count": response}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Encryption Key Count Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBEncryptionKeyCountFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
