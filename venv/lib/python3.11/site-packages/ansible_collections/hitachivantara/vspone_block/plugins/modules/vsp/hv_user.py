#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_user
short_description: Manages users on Hitachi VSP storage systems.
description:
  - This module allows the creation and deletion of users on Hitachi VSP storage systems.
  - It also enables add/remove user to/from the user groups.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/user.yml)
version_added: "3.3.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.gateway_note
  - hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: The desired state of the user task.
    type: str
    required: false
    default: "present"
    choices: ["present", "absent"]
  spec:
    description: Specification for the user.
    type: dict
    required: true
    suboptions:
      authentication:
        description: The authentication method for the user. Required for user creation.
        type: str
        required: false
        choices: ["local", "external"]
        default: "local"
      password:
        description: The password of the user.
        type: str
        required: false
      name:
        description: The name of the user.
        type: str
        required: false
      id:
        description: The ID of the user.
        type: str
        required: false
      group_names:
        description: User group name. You can specify up to 8 group names.
        type: list
        required: false
        elements: str
      state:
        description:
          - Operation to be performed on the user.
          - C(add_user_group) - To add the user to the user groups.
          - C(remove_user_group) - To remove the user from the user groups.
        type: str
        required: false
        choices: ["add_user_group", "remove_user_group"]
        default: null
"""

EXAMPLES = """
- name: Create a User
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "devUser"
      authentication: "local"
      password: "CHANGE_ME_SET_YOUR_PASSWORD"
      group_names: [
        "Audit Log Administrator (View Only) User Group",
        "Storage Administrator (View & Modify) User Group"]

- name: Change User Password by User Name
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "devUser"
      password: "CHANGE_ME_SET_YOUR_PASSWORD"

- name: Add Resource Groups to a User Group
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      state: add_user_group
      id: "devUser"
      group_names: ["devGroup3_new_4"]

- name: Remove User from  User Groups by User ID
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      state: remove_user_group
      id: "devUser"
      group_names: ["devGroup3_new_4"]

- name: Delete a User Group by ID
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: absent
    spec:
      id: "devUser"
"""

RETURN = """
users:
  description: The user information.
  returned: always
  type: dict
  contains:
    authentication:
      description: The authentication method.
      type: str
      sample: "local"
    user_group_names:
      description: The user group names.
      type: list
      elements: str
      sample: ["Audit Log Administrator (View Only) User Group", "Storage Administrator (View & Modify) User Group"]
    id:
      description: The ID of the user.
      type: str
      sample: "devUser"
    is_account_status:
      description: The account status of the user.
      type: bool
      sample: true
    is_built_in:
      description: The user is built-in or not.
      type: bool
      sample: false
    name:
      description: The name of the user.
      type: str
      sample: "devUser"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPUserArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_user import (
    VSPUserReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPUserManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPUserArguments().user()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = None
            #     self.parameter_manager.storage_system_info.serial
            # )
            self.spec = self.parameter_manager.get_user_spec()
            self.state = self.parameter_manager.get_state()
            # self.logger.writeDebug(
            #     f"MOD:hv_user:spec= {self.spec} ss = {self.storage_serial_number}"
            # )
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of User operation ===")
        registration_message = validate_ansible_product_registration()

        user = None
        try:
            reconciler = VSPUserReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            user, comment = reconciler.reconcile_user(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of User operation ===")
            self.module.fail_json(msg=str(e))

        resp = {
            "changed": self.connection_info.changed,
        }
        if user:
            resp["users"] = user
        if comment:
            resp["comment"] = comment
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of User operation ===")
        self.module.exit_json(**resp)


def main(module=None):
    obj_store = VSPUserManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
