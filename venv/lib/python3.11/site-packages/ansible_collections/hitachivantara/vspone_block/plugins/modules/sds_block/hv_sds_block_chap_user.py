#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_chap_user
short_description: Manages VSP One SDS Block and Cloud system CHAP users.
description:
  - This module allows for the creation, deletion and updating of CHAP users.
  - It supports various CHAP user operations based on the specified task level.
  - For examples go to URL U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/chap_user.yml)
version_added: '3.0.0'
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
    description: The level of the CHAP user task. Choices are C(present) and C(absent).
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the CHAP user task.
    type: dict
    required: true
    suboptions:
      id:
        description: ID of the CHAP user.
        type: str
        required: false
      target_chap_user_name:
        description: Target CHAP user name.
        type: str
        required: false
      target_chap_secret:
        description: Target CHAP user secret.
        type: str
        required: false
      initiator_chap_user_name:
        description: Initiator CHAP user name.
        type: str
        required: false
      initiator_chap_secret:
        description: Initiator CHAP user secret.
        type: str
        required: false
"""

EXAMPLES = """
- name: Create a CHAP user
  hitachivantara.vspone_block.sds_block.hv_sds_block_chap_user:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      target_chap_user_name: "chapuser2"
      target_chap_user_secret: "CHANGE_ME_SET_YOUR_PASSWORD"
      initiator_chap_user_name: "chapuser1"
      initiator_chap_secret: "CHANGE_ME_SET_YOUR_PASSWORD"

- name: Delete a CHAP user
  hitachivantara.vspone_block.sds_block.hv_sds_block_chap_user:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "464e1fd1-9892-4134-866c-6964ce786676"

- name: Update chap user name
  hitachivantara.vspone_block.sds_block.hv_sds_block_chap_user:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "464e1fd1-9892-4134-866c-6964ce786676"
      target_chap_user_name: "newchapuser2"

- name: Update chap user secret
  hitachivantara.vspone_block.sds_block.hv_sds_block_chap_user:
    state: present
    connection_info:
      username: "admin"
      password: "password"
    spec:
      id: "464e1fd1-9892-4134-866c-6964ce786676"
      target_chap_user_name: "chapuser2"
      target_chap_user_secret: "CHANGE_ME_SET_YOUR_PASSWORD"
"""

RETURN = r"""
chap_users:
  description: List of CHAP users with their attributes.
  returned: always
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
      sample: "example_initiator_user"
    target_chap_user_name:
      description: Target CHAP user name.
      type: str
      sample: "example_target_user"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_constants import (
    StateValue,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_chap_users import (
    SDSBChapUserReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_properties_extractor import (
    ChapUserPropertiesExtractor,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBChapUserArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBChapUserManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBChapUserArguments().chap_user()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.state = parameter_manager.get_state()
        self.connection_info = parameter_manager.get_connection_info()
        # self.logger.writeDebug(f"MOD:hv_sds_block_chap_user_facts:argument_spec= {self.connection_info}")
        self.spec = parameter_manager.get_chap_user_spec()
        # self.logger.writeDebug(f"MOD:hv_sds_block_chap_user_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB CHAP User Operation ===")
        chap_users = None
        chap_user_data_extracted = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBChapUserReconciler(self.connection_info)
            chap_users = sdsb_reconciler.reconcile_chap_user(self.state, self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_chap_user_facts:chap_users= {chap_users}"
            )
            if self.state.lower() == StateValue.ABSENT:
                chap_user_data_extracted = chap_users
            else:
                output_dict = chap_users.to_dict()
                chap_user_data_extracted = ChapUserPropertiesExtractor().extract_dict(
                    output_dict
                )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB CHAP User Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "chap_users": chap_user_data_extracted,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB CHAP User Operation ===")
        self.module.exit_json(**response)


def main():
    obj_store = SDSBChapUserManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
