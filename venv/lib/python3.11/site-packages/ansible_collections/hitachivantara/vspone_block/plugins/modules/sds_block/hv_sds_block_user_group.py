#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_user_group
short_description: Create and update user groups on the storage system.
description:
  - Create and update user groups on the storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_user_groups.yml)
version_added: "4.5.0"
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
  state:
    description: The level of the user group task.
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the user group task.
    type: dict
    required: false
    suboptions:
      id:
        description: The user group ID.
        type: str
        required: false
      role_names:
        description: Role of the user group. At least one role must be specified. This is a required field to create user group.
        type: list
        elements: str
        required: false
      external_group_name:
        description: Name of the group registered with an external authorization server when the external authorization server is linked.
        type: str
        required: false
      vps_id:
        description: The ID of the virtual private storage (VPS) that the user group belongs to.
        type: str
        required: false
      scope:
        description: An array of the IDs of virtual private storages (VPSs) that the user group can access.
        type: list
        elements: str
        required: false
      vps_name:
        description: The name of the virtual private storage (VPS) that the user group belongs to.
        type: str
        required: false
"""

EXAMPLES = """
- name: Create a new user group
  hitachivantara.vspone_block.sds_block.hv_sds_block_user_group:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      id: "vps_admin_4"
      role_names:
        - "Security"
        - "Storage"
        - "Monitor"
      vps_id: "system"
      scope:
        - "system"
        - "3ffcf3c6-5696-477e-bd0c-6a8d6ab4a0af"

- name: Update an existing user group
  hitachivantara.vspone_block.sds_block.hv_sds_block_user_group:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      id: "admin-vps02"
      role_names:
        - "Security"
        - "Storage"
        - "Monitor"
      scope:
        - "system"
        - "2a843522-a819-47ab-a208-69d190809604"
        - "ae0f247c-dc56-491c-9cb9-4b2b6d33b345"

- name: Delete a user group
  hitachivantara.vspone_block.sds_block.hv_sds_block_user_group:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      id: "admin-vps02"
"""

RETURN = r"""
user_groups:
  description: Information about a specific user group configured on the system.
  returned: success
  type: dict
  contains:
    external_group_name:
      description: Name of the external directory group (LDAP/AD) associated with this user group; empty for local groups.
      type: str
      sample: ""
    is_built_in:
      description: Whether the group is built-in (system-defined) or user-created.
      type: bool
      sample: false
    member_users:
      description: List of users that belong to this user group.
      type: list
      elements: str
      sample: []
    role_names:
      description: List of roles assigned to the user group.
      type: list
      elements: str
      sample:
        - Security
        - Storage
        - Monitor
        - Service
        - Audit
    scope:
      description: Operational scopes where the roles apply (e.g., 'system' or VPS IDs).
      type: list
      elements: str
      sample:
        - system
    user_group_id:
      description: Unique identifier of the user group.
      type: str
      sample: testG
    user_group_object_id:
      description: Object ID representing the user group in the management system.
      type: str
      sample: testG
    vps_id:
      description: Identifier of the VPS or system context associated with the user group.
      type: str
      sample: "(system)"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBUserGroupsArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_user_group import (
    SDSBUserGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockUserGroupManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBUserGroupsArguments().user_groups()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        try:
            parameter_manager = SDSBParametersManager(self.module.params)
            self.connection_info = parameter_manager.get_connection_info()
            self.spec = parameter_manager.get_user_group_spec()
            self.state = parameter_manager.get_state()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))
        self.logger.writeDebug(f"MOD:hv_sds_user:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB User Group Operation ===")
        user_groups = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBUserGroupReconciler(self.connection_info)
            user_groups = sdsb_reconciler.reconcile_user_group(self.spec, self.state)

            self.logger.writeDebug(f"MOD:hv_sds_users_facts:user_groups= {user_groups}")

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB User Group Operation ===")
            self.module.fail_json(msg=str(e))

        msg = self.spec.comments
        data = {
            "changed": self.connection_info.changed,
            "user_groups": user_groups if user_groups else [],
            "comments": msg if msg else "",
        }
        # if self.state == "present":
        #     msg = "User group created successfully."
        # elif self.state == "absent":
        #     msg = self.spec.comments
        # data["msg"] = msg if msg else ""
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB User Group Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBBlockUserGroupManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
