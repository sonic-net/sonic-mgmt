#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_encryption_key_facts
short_description: Retrieves encryption key information from VSP One SDS Block and Cloud systems.
description:
  - This module retrieves detailed information about encryption keys from Hitachi SDS Block storage systems.
  - Supports filtering by key ID, type, target resource, creation time, and other criteria.
  - Utilizes the Hitachi Vantara SDS Block API for encryption key facts retrieval.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/encryption_key_facts.yml)
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
options:
  spec:
    description: Specification for retrieving encryption key information.
    type: dict
    required: false
    suboptions:
      key_id:
        description: Filter encryption keys by key ID.
        type: str
        required: false
      id:
        description: Filter encryption keys by ID.
        type: str
        required: false
      count:
        description: Limit the number of encryption keys returned.
        type: int
        required: false
      key_type:
        description: Filter encryption keys by type.
        type: str
        required: false
      target_resource_id:
        description: Filter encryption keys by target resource ID.
        type: str
        required: false
      target_resource_name:
        description: Filter encryption keys by target resource name.
        type: str
        required: false
      start_creation_time:
        description: Filter encryption keys created after this time.
        type: str
        required: false
      end_creation_time:
        description: Filter encryption keys created before this time.
        type: str
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all encryption keys
  hitachivantara.vspone_block.sds_block.hv_sds_block_encryption_key_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about specific encryption key by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_encryption_key_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "1762b15c-0656-48d6-a9f2-3104092b28b9"

- name: Retrieve limited number of encryption keys
  hitachivantara.vspone_block.sds_block.hv_sds_block_encryption_key_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      count: 5
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the encryption keys.
  returned: always
  type: dict
  contains:
    encryption_keys:
      description: A list of encryption key information.
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


class SDSBEncryptionKeyFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBEncryptionKeyArguments().encryption_key_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_encryption_key_fact_spec()
        self.logger.writeDebug(f"MOD:encryption_key_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Encryption Key Facts ===")
        response = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBEncryptionKeyReconciler(self.connection_info)

            response = sdsb_reconciler.get_encryption_keys_facts(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Encryption Key Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"encryption_keys": response}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Encryption Key Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBEncryptionKeyFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
