#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_session
short_description: Manages sessions on VSP One SDS Block and Cloud systems.
description:
  - This module allows to generate and discard session.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_session.yml)
version_added: '4.5.0'
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
    description: State of the session.
    required: false
    type: str
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for Session.
    required: false
    type: dict
    suboptions:
      id:
        description: Session ID. UUID format. Required for delete operation.
        type: str
        required: false
      alive_time:
        description: The idle time in seconds after which a session times out. Valid for create session operation.
          If omitted, 300 is applied. If specified value must be between 1 and 300.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create a session
  hitachivantara.vspone_block.sds_block.hv_sds_block_session:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      alive_time: 100

- name: Delete a session
  hitachivantara.vspone_block.sds_block.hv_sds_block_session:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
      state: "absent"
      spec:
        id: "ae0f247c-dc56-491c-9cb9-4b2b6d33b345"
"""

RETURN = """
session:
  description: Information about the user session.
  type: dict
  returned: always
  contains:
    createdTime:
      description: Timestamp when the session was created.
      type: str
      sample: "2025-11-06T19:22:13Z"
    expirationTime:
      description: Timestamp when the session will expire.
      type: str
      sample: "2025-11-07T19:22:13Z"
    lastAccessTime:
      description: Timestamp of the last access using this session.
      type: str
      sample: "2025-11-06T19:22:13Z"
    privileges:
      description: List of privilege objects associated with the session.
      type: list
      elements: dict
      contains:
        roleNames:
          description: List of role names granted in this privilege.
          type: list
          elements: str
          sample: ["Audit", "Security", "Storage", "Monitor", "Service", "Resource", "RemoteCopy"]
        scope:
          description: Scope of the privilege.
          type: str
          sample: "system"
    roleNames:
      description: List of roles assigned to the session.
      type: list
      elements: str
      sample: ["Audit", "Security", "Storage", "Monitor", "Service", "Resource", "RemoteCopy"]
    sessionId:
      description: Unique identifier for the session.
      type: str
      sample: "0ba72e6d-b109-4638-bbea-9452ed8401b8"
    token:
      description: Session token used for authentication.
      type: str
      sample: "gAAAAABpDPVlhsNMvLyM5vBrb5oMpKDuChy1vT-HtowicWzZnEHtfLKPvj95U5rzOxdhw3p95ipuREgrkZRTgM2RDTHM3nWQDQD82qxwd50v74XqXTheuztB2506bRqHtLXgUQ..."
    userId:
      description: ID of the user who owns the session.
      type: str
      sample: "admin"
    userObjectId:
      description: Object ID of the user.
      type: str
      sample: "admin"
    vpsId:
      description: Identifier for the Virtual Private Storage (VPS) or system context.
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
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)


class SDSBSessionManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBSessionArguments().session()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.state = parameter_manager.get_state()
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_session_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Session Operation ===")
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBSessionReconciler(self.connection_info)
            session = sdsb_reconciler.reconcile_session(self.state, self.spec)

            self.logger.writeDebug(f"MOD:hv_sds_block_session:session= {session}")

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Session Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "session": session,
        }

        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Session Operation ===")
        self.module.exit_json(**response)


def main(module=None):
    obj_store = SDSBSessionManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
