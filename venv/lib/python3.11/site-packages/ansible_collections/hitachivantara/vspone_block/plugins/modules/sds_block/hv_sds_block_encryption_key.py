#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_encryption_key
short_description: Manage encryption keys on VSP One SDS Block and Cloud systems.
description:
  - Create and delete encryption keys on storage system.
version_added: '4.5.0'
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
  state:
    description: State of the encryption key.
    type: str
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for encryption key management.
    type: dict
    required: true
    suboptions:
      number_of_keys:
        description: Number of encryption keys to be created (1-4096).
        type: int
        required: false
      id:
        description: ID of the encryption key (required for deletion).
        type: str
        required: false
"""

EXAMPLES = """
- name: Create encryption keys
  hitachivantara.vspone_block.sds_block.hv_sds_block_encryption_key:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      number_of_keys: 5

- name: Delete encryption key
  hitachivantara.vspone_block.sds_block.hv_sds_block_encryption_key:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      id: "07a76cb8-6ad6-475e-a515-4c5f4ac70e09"
"""

RETURN = r"""
encryption_keys:
  description: List of created encryption keys.
  returned: when state is present
  type: list
  elements: dict
  contains:
    id:
      description: Unique identifier for the encryption key.
      type: str
      sample: "1762b15c-0656-48d6-a9f2-3104092b28b9"
    created_time:
      description: Time when the encryption key was created.
      type: str
      sample: "2023-07-09T04:59:17Z"
    key_type:
      description: Type of the encryption key.
      type: str
      sample: "Free"
    target_information:
      description: Target information for the encryption key.
      type: str
      sample: "00000000-0000-0000-0000-000000000000"
    key_generated_location:
      description: Location where the key was generated.
      type: str
      sample: "Internal"
    number_of_backups:
      description: Number of backups for the encryption key.
      type: int
      sample: 0
    target_name:
      description: Name of the target.
      type: str
      sample: ""
encryption_key:
  description: Deletion result message.
  returned: when state is absent
  type: str
  sample: "Encryption key 07a76cb8-6ad6-475e-a515-4c5f4ac70e09 is deleted successfully."
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


class SDSBEncryptionKeyManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBEncryptionKeyArguments().encryption_key()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.state = parameter_manager.get_state()
        self.spec = parameter_manager.get_encryption_key_spec()
        self.logger.writeDebug(
            f"MOD:encryption_key:state={self.state}, spec={self.spec}"
        )

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Encryption Key Management ===")

        response = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBEncryptionKeyReconciler(self.connection_info)
            response = sdsb_reconciler.reconcile(self.state, self.spec)

            self.logger.writeDebug(f"MOD:encryption_key:response={response}")

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Encryption Key Management ===")
            self.module.fail_json(msg=str(e))

        if self.state == "present":
            result_data = {"encryption_keys": response}
        else:
            result_data = {"encryption_key": response}

        response_data = {
            "changed": self.connection_info.changed,
            "comments": (
                self.spec.comments
                if hasattr(self.spec, "comments") and self.spec.comments
                else []
            ),
            "errors": (
                self.spec.errors
                if hasattr(self.spec, "errors") and self.spec.errors
                else []
            ),
        }
        response_data.update(result_data)

        if registration_message:
            response_data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Encryption Key Management ===")
        self.module.exit_json(**response_data)


def main():
    obj_store = SDSBEncryptionKeyManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
