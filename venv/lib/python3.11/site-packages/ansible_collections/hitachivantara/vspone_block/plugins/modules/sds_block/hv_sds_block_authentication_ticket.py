#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_authentication_ticket
short_description: Manages authentication tickets for VSP One SDS Block and Cloud systems.
description:
  - This module allows for the creation, deletion and updating of authentication tickets.
  - It supports various authentication ticket operations based on the specified task level.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/authentication_ticket.yml)
version_added: '4.1.0'
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
    description: The level of the authentication ticket task. Choices are C(present) and C(absent).
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the authentication ticket task.
    type: dict
    required: false
    suboptions:
      max_age_days:
        description: >
          Supported range: 1 to 365. If omitted, the ticket expiration date and time
          are the same as that for the password of the user who issued the ticket.
          However, if the user's password does not have an expiration time,
          the ticket will be valid for 365 days.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create a authentication ticket
  hitachivantara.vspone_block.sds_block.hv_sds_block_authentication_ticket:
    state: present
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      max_age_days: 15

- name: Discard all authentication tickets
  hitachivantara.vspone_block.sds_block.hv_sds_block_authentication_ticket:
    state: absent
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
"""

RETURN = r"""
ticket_info:
  description: >
    Dictionary containing the authentication ticket details.
  returned: always
  type: dict
  contains:
    expiration_time:
      description: Expiration time of the authentication ticket in ISO 8601 format.
      type: str
      sample: "2025-07-15T05:18:28Z"
    ticket:
      description: The authentication ticket string.
      type: str
      sample: "2025-07-15T05_"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsd_authentication_ticket_reconciler import (
    SDSBTicketManagementReconciler,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBTicketManagementArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBTicketManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBTicketManagementArguments().ticket_management()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.state = parameter_manager.get_state()
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_ticket_mgmt_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Ticket Authentication ===")
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBTicketManagementReconciler(self.connection_info)
            task_response = sdsb_reconciler.ticket_management_reconcile(
                self.state, self.spec
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Ticket Authentication ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "ticket_info": task_response,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Ticket Authentication ===")
        self.module.exit_json(**response)


def main():
    obj_store = SDSBTicketManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
