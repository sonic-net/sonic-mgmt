#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_chap_user_facts
short_description: Retrieves information about VSP One SDS Block and Cloud system CHAP users.
description:
  - This module retrieves information about CHAP users.
  - It provides details about a CHAP user such as initiator CHAP user name, target CHAP user name and ID.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/chap_user_facts.yml)
version_added: '3.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: "full"
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  spec:
    description: Specification for retrieving CHAP user information.
    type: dict
    required: false
    suboptions:
      id:
        description: ID of the CHAP user to retrieve information for.
        type: str
        required: false
      target_chap_user_name:
        description: Target CHAP user name to retrieve information for.
        type: str
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all CHAP users
  hitachivantara.vspone_block.sds_block.hv_sds_block_chap_user_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about a specific CHAP user by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_chap_user_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "464e1fd1-9892-4134-866c-6964ce786676"

- name: Retrieve information about a specific CHAP user by name
  hitachivantara.vspone_block.sds_block.hv_sds_block_chap_user_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      target_chap_user_name: "chapuser1"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the CHAP users.
  returned: always
  type: dict
  contains:
    chap_users:
      description: List of CHAP users with their attributes.
      type: list
      elements: dict
      contains:
        id:
          description: Unique identifier for the CHAP user.
          type: str
          sample: "464e1fd1-9892-4134-866c-6964ce786676"
        initiator_chap_user_name:
          description: Initiator CHAP user name.
          type: str
          sample: "chapuser1"
        target_chap_user_name:
          description: Target CHAP user name.
          type: str
          sample: "newchapuser2"
"""
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBChapUserArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_properties_extractor import (
    ChapUserPropertiesExtractor,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_chap_users import (
    SDSBChapUserReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBChapUserFactsManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBChapUserArguments().chap_user_facts()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_chap_user_fact_spec()
        self.logger.writeDebug(f"MOD:hv_sds_block_chap_user_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB CHAP User Facts ===")
        chap_users = None
        chap_users_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBChapUserReconciler(self.connection_info)
            chap_users = sdsb_reconciler.get_chap_users(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_chap_user_facts:chap_users= {chap_users}"
            )
            output_dict = chap_users.data_to_list()
            chap_users_data_extracted = ChapUserPropertiesExtractor().extract(
                output_dict
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB CHAP User Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"chap_users": chap_users_data_extracted}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB CHAP User Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBChapUserFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
