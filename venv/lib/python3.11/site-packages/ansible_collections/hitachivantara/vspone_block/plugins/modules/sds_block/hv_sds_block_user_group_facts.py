#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_user_group_facts
short_description: Get user groups from the storage system.
description:
  - Get users from the storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_user_group_facts.yml)
version_added: "4.4.0"
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
    description: Specification for retrieving user group information.
    type: dict
    required: false
    suboptions:
      id:
        description: Filter user groups by ID (UUID format).
        type: str
      vps_name:
        description: Filter user groups by VPS name.
        type: str
      vps_id:
        description: Filter user groups by VPS ID.
        type: str
"""

EXAMPLES = """
- name: Retrieve information about all user groups
  hitachivantara.vspone_block.sds_block.hv_sds_block_user_group_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about user group by specifying id
  hitachivantara.vspone_block.sds_block.hv_sds_block_user_group_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin_group"
      password: "password"
    spec:
      id: "1"
"""

RETURN = r"""
---
ansible_facts:
  description: Facts containing details of user groups configured in the system.
  returned: always
  type: dict
  contains:
    user_groups:
      description: User group details.
      type: dict
      contains:
        user_group_id:
          description: Unique identifier of the user group.
          type: str
          sample: testG
        user_group_object_id:
          description: Object ID of the user group.
          type: str
          sample: testG
        external_group_name:
          description: Name of the external directory group, if applicable.
          type: str
          sample: ""
        is_built_in:
          description: Indicates whether the user group is a built-in system group.
          type: bool
          sample: false
        member_users:
          description: List of users who are members of the group.
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
          description: List of scopes where the group roles are applicable.
          type: list
          elements: str
          sample:
            - system
        vps_id:
          description: Virtual Partition System (VPS) identifier associated with the group.
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


class SDSBBlockFaultDomainFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBUserGroupsArguments().user_group_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_user_group_facts_spec()
        self.logger.writeDebug(f"MOD:hv_sds_users_group_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB User Group Facts ===")
        user_groups = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBUserGroupReconciler(self.connection_info)
            user_groups = sdsb_reconciler.get_user_groups(self.spec)

            self.logger.writeDebug(f"MOD:hv_sds_users_facts:user_groups= {user_groups}")

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB User Group Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"user_groups": user_groups}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB User Group Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockFaultDomainFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
