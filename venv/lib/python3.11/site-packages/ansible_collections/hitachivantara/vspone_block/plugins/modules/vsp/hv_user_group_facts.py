#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_user_group_facts
short_description: Retrieves user group information from Hitachi VSP storage systems.
description:
  - This module retrieves information about user groups from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/user_group_facts.yml)
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
    description: Specification for the user group facts to be gathered.
    type: dict
    required: false
    suboptions:
      name:
        description: The name of the specific user group to retrieve.
        type: str
        required: false
      id:
        description: The id of the specific user group to retrieve.
        type: str
        required: false
"""

EXAMPLES = r"""
- name: Get all user groups for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_group_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"

- name: Get user group by name for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_group_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "my_user_group"
"""

RETURN = """
ansible_facts:
  description: Dictionary containing the discovered properties of the users.
  returned: always
  type: dict
  contains:
    user_groups:
        description: The user group information.
        type: list
        elements: dict
        contains:
            has_all_resource_group:
                description: Indicates whether the user group has all resource groups.
                type: bool
                sample: false
            id:
                description: The ID of the user group.
                type: str
                sample: "devGroup8"
            is_built_in:
                description: Indicates whether the user group is built-in.
                type: bool
                sample: false
            name:
                description: The name of the user group.
                type: str
                sample: "devGroup8"
            resource_group_ids:
                description: The resource group IDs.
                type: list
                elements: int
                sample: [0, 8, 9, 1023]
            role_names:
                description: The role names.
                type: list
                elements: str
                sample: ["Storage Administrator (Performance Management)", "Storage Administrator (Provisioning)"]
            users:
                description: The list of users belong to this user group.
                type: list
                elements: str
                sample: ["oracle_sap", "RD-QA-User-14U-1"]
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_user_group import (
    VSPUserGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPUserGroupArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPUserGroupFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPUserGroupArguments().user_group_facts()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = None
            # self.logger.writeDebug(
            #     f"MOD:hv_user_group_facts:serial= {self.storage_serial_number}"
            # )
            self.spec = self.parameter_manager.get_user_group_fact_spec()
            self.state = self.parameter_manager.get_state()

        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of User Group Facts ===")
        registration_message = validate_ansible_product_registration()

        try:
            reconciler = VSPUserGroupReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )

            user_groups = reconciler.get_user_group_facts(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of User Group Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "user_groups": user_groups,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of User Group Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = VSPUserGroupFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
