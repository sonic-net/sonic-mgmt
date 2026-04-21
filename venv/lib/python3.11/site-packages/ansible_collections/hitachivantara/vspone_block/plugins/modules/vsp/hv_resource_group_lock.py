#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_resource_group_lock
short_description: Allows the locking and unlocking of resource groups on Hitachi VSP storage systems.
description:
    - This module allows the locking and unlocking of resource groups on Hitachi VSP storage systems.
    - For examples, go to URL
      U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/resource_management_with_lock/vsp_direct)
version_added: '3.2.0'
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
- hitachivantara.vspone_block.common.connection_with_type
notes:
  - The input parameters C(id) and C(name) were removed in version 3.4.0.
    They were deprecated due to internal API simplification and are no longer supported.
  - The output parameters C(entitlement_status), C(subscriber_id), and C(partner_id) were removed in version 3.4.0.
    They were also deprecated due to internal API simplification and are no longer supported.
options:
  state:
    description:
      - Set state to C(present) for locking resource group.
      - Set state to C(absent) for unlocking resource group.
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  storage_system_info:
    description: Information about the storage system. This field is an optional field.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false
  secondary_connection_info:
    description: Information required to establish a connection to the remote storage system.
    type: dict
    required: false
    suboptions:
      address:
        description: IP address or hostname of the storage system.
        type: str
        required: true
      username:
        description: Username for authentication for secondary storage. This is a required field if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication for secondary storage. This is a required field if api_token is not provided.
        type: str
        required: false
      api_token:
        description: This token is required while working on locked resources. Provide the lock_token value returned
          by lock resource group task for secondary storage system.
        type: str
        required: false
  spec:
    description: Specification for the resource group lock.
    type: dict
    required: false
    suboptions:
      lock_timeout_sec:
        description: The time that elapses before a lock timeout (in seconds). Specify a value from 0 to 7200.
          Default is 0.
          Required for the Lock Resource Groups task.
        type: int
        required: false
"""

EXAMPLES = """
- name: Lock resource groups
  hitachivantara.vspone_block.vsp.hv_resource_group_lock:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      lock_timeout_sec: 300

- name: Unlock the Resource Groups that were locked
  hitachivantara.vspone_block.vsp.hv_resource_group_lock:
    connection_info:
      address: storage1.company.com
      api_token: lock_token_value
    state: absent
"""

RETURN = """
response:
  description: Information of the locked resource group. When secondary_connection_info is provided,
    remote_lock_session_id, remote_lock_token, and remote_locked_resource_groups are populated in the output.
  returned: always
  type: dict
  contains:
    lock_session_id:
      description: ID of the session that locked the local resources.
      type: int
      sample: 26945
    lock_token:
      description: Token that should be used to do operations on local resources.
      type: str
      sample: "62316257-5362-458a-8a9a-8922beaf7460"
    locked_resource_groups:
      description: List of local resource groups that are locked.
      type: list
      elements: dict
      contains:
        id:
          description: The ID of the resource group.
          type: int
          sample: 1
        name:
          description: Name of the resource group.
          type: str
          sample: "test-rg-1"
    remote_lock_session_id:
      description: ID of the session that locked the remote resources.
      type: int
      sample: 16945
    remote_lock_token:
      description: Token that should be used to do operations on remote resources.
      type: str
      sample: "72316257-5362-458a-8a9a-8922beaf7460"
    remote_locked_resource_groups:
      description: List of remote resource groups that are locked.
      type: list
      elements: dict
      contains:
        id:
          description: The ID of the resource group.
          type: int
          sample: 2
        name:
          description: Name of the resource group.
          type: str
          sample: "test-rg-2"
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_rg_lock_reconciler import (
    VSPResourceGroupLockReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPResourceGroupLockArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPResourceGroupLockManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPResourceGroupLockArguments().rg_lock()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
            # can be added mandotary , optional mandatory arguments
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.parameter_manager.get_connection_info()
            self.storage_serial_number = (
                self.parameter_manager.storage_system_info.serial
            )
            self.spec = self.parameter_manager.get_rg_lock_spec()
            self.state = self.parameter_manager.get_state()
            self.secondary_connection_info = (
                self.parameter_manager.get_secondary_connection_info()
            )
            if self.secondary_connection_info:
                self.spec.secondary_connection_info = self.secondary_connection_info

        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Resource Group Lock operation ===")
        registration_message = validate_ansible_product_registration()

        response = None
        comment = None
        try:
            reconciler = VSPResourceGroupLockReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            response = reconciler.reconcile_rg_lock(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Resource Group Lock operation ===")
            self.module.fail_json(msg=str(e))

        resp = {
            "changed": self.connection_info.changed,
        }
        comment = None
        if self.state == "absent":
            if response is None:
                comment = "Resource Groups unlocked successfully."
            else:
                comment = response
        else:
            if response:
                comment = "Resource Groups locked successfully."
                resp["locked_resource_groups"] = response
        if comment:
            resp["comment"] = comment
        if registration_message:
            resp["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Resource Group Lock operation ===")
        self.module.exit_json(**resp)


def main(module=None):
    obj_store = VSPResourceGroupLockManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
