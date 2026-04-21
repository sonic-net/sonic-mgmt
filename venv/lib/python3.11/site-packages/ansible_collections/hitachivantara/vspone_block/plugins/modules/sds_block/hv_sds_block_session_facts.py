#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_session_facts
short_description: Retrieves information about sessions on VSP One SDS Block and Cloud systems.
description:
  - This module retrieves information about sessions.
  - It provides details about a session.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_session_facts.yml)
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
    description: Specification for retrieving session information.
    type: dict
    required: false
    suboptions:
      id:
        description: ID of the session to retrieve information for.
        type: str
        required: false
      vps_id:
        description: The ID of the virtual private storage (VPS) that the acquisition-target resource belongs to.
        type: str
        required: false
      user_id:
        description: User ID.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all Sessions
  hitachivantara.vspone_block.sds_block.hv_sds_block_session_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Get Session by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_session_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "464e1fd1-9892-4134-866c-6964ce786676"
"""

RETURN = """
ansible_facts:
  description: Contains facts collected from the system, including session information.
  returned: always
  type: dict
  contains:
    sessions:
      description: List of active user sessions on the system.
      returned: always
      type: list
      elements: dict
      contains:
        created_time:
          description: The UTC time when the session was created.
          returned: always
          type: str
          sample: "2025-11-05T22:58:40Z"
        expiration_time:
          description: The UTC time when the session will expire.
          returned: always
          type: str
          sample: "2025-11-06T22:58:40Z"
        last_access_time:
          description: The UTC time when the session was last accessed.
          returned: always
          type: str
          sample: "2025-11-05T22:58:41Z"
        privileges:
          description: List of privileges assigned to the session.
          returned: always
          type: list
          elements: dict
          contains:
            role_names:
              description: List of role names associated with the session privileges.
              returned: always
              type: list
              elements: str
              sample: ["Audit", "Security", "Storage", "Monitor", "Service", "Resource", "RemoteCopy"]
            scope:
              description: Scope of the privileges.
              returned: always
              type: str
              sample: "system"
        role_names:
          description: List of roles assigned to the user in this session.
          returned: always
          type: list
          elements: str
          sample: ["Audit", "Security", "Storage", "Monitor", "Service", "Resource", "RemoteCopy"]
        session_id:
          description: Unique identifier for the session.
          returned: always
          type: str
          sample: "d62a9719-f1fd-40f6-8c18-5a04794c74a0"
        user_id:
          description: ID of the user who owns the session.
          returned: always
          type: str
          sample: "admin"
        user_object_id:
          description: Object identifier of the user associated with the session.
          returned: always
          type: str
          sample: "admin"
        vps_id:
          description: The ID of the virtual private storage (VPS) instance associated with the session.
          returned: always
          type: str
          sample: "(system)"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_session import (
    SDSBSessionReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBSessionArguments,
    SDSBParametersManager,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBSessionFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBSessionArguments().session_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_session_fact_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Session Facts ===")
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBSessionReconciler(self.connection_info)
            sessions = sdsb_reconciler.get_session_facts(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_session_facts:session= {sessions}"
            )

        except Exception as e:
            self.logger.writeInfo("=== End of SDSB Session Facts ===")
            self.module.fail_json(msg=str(e))
        data = {"sessions": sessions}

        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Session Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = SDSBSessionFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
