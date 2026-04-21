#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_user_facts
short_description: Retrieves user information from Hitachi VSP storage systems.
description:
  - This module retrieves information about users from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/user_facts.yml)
version_added: "3.3.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.gateway_note
  - hitachivantara.vspone_block.common.connection_info
options:
  spec:
    description: Specification for the user facts to be gathered.
    type: dict
    required: false
    suboptions:
      name:
        description: The name of the specific user to retrieve.
        type: str
        required: false
      id:
        description: The id of the specific user to retrieve.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all users for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"

- name: Get user by name for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "user1"
"""

RETURN = """
ansible_facts:
  description: Dictionary containing the discovered properties of the user groups.
  returned: always
  type: dict
  contains:
    users:
        description: The user information.
        type: list
        elements: dict
        contains:
            authentication:
                description: Authentication type - local or external.
                type: str
                sample: "local"
            user_group_names:
                description: User group names.
                type: list
                elements: str
                sample: ["Administrator User Group"]
            id:
                description: The ID of the user.
                type: str
                sample: "ucpa"
            is_account_status:
                description: The account status of the user.
                type: bool
                sample: true
            is_built_in:
                description: Indicates whether the user is built-in or not.
                type: bool
                sample: false
            name:
                description: The name of the user.
                type: str
                sample: "ucpa"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_user import (
    VSPUserReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPUserArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPUserFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPUserArguments().user_facts()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = None
            self.spec = self.parameter_manager.get_user_fact_spec()
            self.state = self.parameter_manager.get_state()

        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of User Facts ===")
        registration_message = validate_ansible_product_registration()

        try:
            reconciler = VSPUserReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )

            users = reconciler.get_user_facts(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of User Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "users": users,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of User Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = VSPUserFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
