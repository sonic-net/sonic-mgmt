#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_user_group
short_description: Manages user groups on Hitachi VSP storage systems.
description:
  - This module allows the creation and deletion of user groups on Hitachi VSP storage systems.
  - It also enables adding or removing resource groups to/from the user group.
  - This module is supported for C(direct) connection types.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/user_group.yml)
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
    description: The desired state of the user group task.
    type: str
    required: false
    default: "present"
    choices: ["present", "absent"]
  spec:
    description: Specification for the user  group.
    type: dict
    required: true
    suboptions:
      name:
        description: The name of the user group.
        type: str
        required: false
      id:
        description: The ID of the user group.
        type: str
        required: false
      role_names:
        description:
          - The role name. Specify one or more of the following role names.
          - "AUDIT_LOG_ADMIN_VIEW_N_MODIFY"
          - "AUDIT_LOG_ADMIN_VIEW_ONLY"
          - "SECURITY_ADMIN_VIEW_N_MODIFY"
          - "SECURITY_ADMIN_VIEW_ONLY"
          - "STORAGE_ADMIN_INIT_CONFIG"
          - "STORAGE_ADMIN_LOCAL_COPY"
          - "STORAGE_ADMIN_PERF_MGMT"
          - "STORAGE_ADMIN_PROVISION"
          - "STORAGE_ADMIN_REMOTE_COPY"
          - "STORAGE_ADMIN_SYS_RESOURCE_MGMT"
          - "STORAGE_ADMIN_VIEW_ONLY"
          - "SUPPORT_PERSONNEL"
          - "USER_MAINTENANCE"
        type: list
        required: false
        elements: str
      resource_group_ids:
        description:
          - List of resource group IDs to be added or removed from the user group.
          - The following six role names has access to all the resource groups, so this field will be ignored
            if you specify any one of them in the role_names field.
          - AUDIT_LOG_ADMIN_VIEW_N_MODIFY
          - AUDIT_LOG_ADMIN_VIEW_ONLY
          - SECURITY_ADMIN_VIEW_N_MODIFY
          - SECURITY_ADMIN_VIEW_ONLY
          - SUPPORT_PERSONNEL
          - USER_MAINTENANCE
        type: list
        required: false
        elements: int
      state:
        description:
          - Operation to be performed on the resource groups in the user group.
          - C(add_resource_group) -  To add resource groups to the user group.
          - C(remove_resource_group) - To remove resource groups from the user group.
          - C(add_role) - To add roles to the user group.
          - C(remove_role) - To remove roles from the user group.
        type: str
        required: false
        choices:
          [
            "add_resource_group",
            "remove_resource_group",
            "add_role",
            "remove_role",
          ]
        default: null
"""

EXAMPLES = """
- name: Create a User Group for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      name: "devGroup"
      role_names: ["STORAGE_ADMIN_PERF_MGMT", "STORAGE_ADMIN_PROVISION"]
      resource_group_ids: [8, 9]

- name: Change User Group Name for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      id: "devGroup3_new_3"
      name: "devGroup3_new_4"

- name: Add Resource Groups to a User Group for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      state: add_resource_group
      id: "devGroup3"
      resource_group_ids: [1, 2]

- name: Remove Resource Groups from a User Group for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      state: remove_resource_group
      id: "devGroup3"
      resource_group_ids: [1, 2]

- name: Delete a User Group by ID for direct connection type
  hitachivantara.vspone_block.vsp.hv_user_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: absent
    spec:
      id: "devGroup3"
"""

RETURN = """
user_groups:
  description: The user group information.
  returned: always
  type: dict
  contains:
    has_all_resource_group:
        description: Indicates whether the user group has access to all resource groups.
        type: bool
        sample: false
    id:
        description: The ID of the user group.
        type: str
        sample: "devGroup8"
    is_built_in:
        description: Indicates whether the user group is a built-in user group.
        type: bool
        sample: false
    name:
        description: The name of the user group.
        type: str
        sample: "devGroup8"
    resource_group_ids:
        description: The list of resource group IDs.
        type: list
        elements: int
        sample: [0, 8, 9, 1023]
    role_names:
        description: The list of role names.
        type: list
        elements: str
        sample: ["Storage Administrator (Performance Management)", "Storage Administrator (Provisioning)"]
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPUserGroupArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_user_group import (
    VSPUserGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPUserManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPUserGroupArguments().user_group()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = None
            self.spec = self.parameter_manager.get_user_group_spec()
            self.state = self.parameter_manager.get_state()

        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of User Group operation ===")
        registration_message = validate_ansible_product_registration()

        user_group = None
        try:
            reconciler = VSPUserGroupReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            user_group, comment = reconciler.reconcile_user_group(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of User Group operation ===")
            self.module.fail_json(msg=str(e))

        resp = {
            "changed": self.connection_info.changed,
        }
        if user_group:
            resp["user_groups"] = user_group
        if comment:
            resp["comment"] = comment
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of User  Group operation ===")
        self.module.exit_json(**resp)


def main(module=None):
    obj_store = VSPUserManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
