#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_remote_connection
short_description: Manages Remote connections on Hitachi VSP storage systems.
description: >
  - This module allows settings of remote connections used for remote copy operations.
  - Remote connections are used to connect storage systems used in remote copy operations for TrueCopy, Universal Replicator, and global-active device.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/remote_connection.yml)
version_added: '3.3.0'
author:
  - Hitachi Vantara, LTD. (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_without_token
options:
  state:
    description: The level of the Remote connection task. Choices are C(present), C(absent).
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the Create/update Remote connection task.
    type: dict
    required: true
    suboptions:
      path_group_id:
        description: Path group ID.
          Required for the Create a new remote connection
          /Update the remote path of an existing remote connection
          /Update remote connection settings
          /Delete a remote connection tasks.
        type: int
        required: true
      remote_storage_serial_number:
        description: Serial number of the remote storage system.
          Required for the Create a new remote connection
          /Update the remote path of an existing remote connection
          /Update remote connection settings
          /Delete a remote connection tasks.
        type: str
        required: true
      remote_paths:
        description: List of remote paths, For new remote connection, at least one remote path is required.
          Required for the Create a new remote connection
          /Update the remote path of an existing remote connection tasks.
        type: list
        required: false
        elements: dict
        suboptions:
            local_port:
                description: Port number of the local storage system
                  Required for the Create a new remote connection
                  /Update the remote path of an existing remote connection tasks.
                type: str
                required: true
            remote_port:
                description: Port number of the remote storage system
                  Required for the Create a new remote connection
                  /Update the remote path of an existing remote connection tasks.
                type: str
                required: true
      min_remote_paths:
        description: Minimum number of remote paths, Specify a value that is no more than the number of remote paths registered in the remote connection.
          Optional for the Create a new remote connection
          /Update remote connection settings tasks.
        type: int
        required: false
      remote_io_timeout_in_sec:
        description: Remote IO timeout in seconds.
          Optional for the Create a new remote connection
          /Update remote connection settings tasks.
        type: int
        required: false
      round_trip_in_msec:
        description: Round trip time in milliseconds.
          Optional for the Create a new remote connection
          /Update remote connection settings tasks.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create a new remote connection
  hitachivantara.vspone_block.vsp.hv_remote_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      path_group_id: 101
      remote_storage_serial_number: "40014"
      remote_paths:
        - local_port: "CL7-C"
          remote_port: "CL7-C"
        - local_port: "CL7-D"
          remote_port: "CL7-D"
      min_remote_paths: 1
      remote_io_timeout_in_sec: 15
      round_trip_in_msec: 1

- name: update remote path of a existing remote connection
  hitachivantara.vspone_block.vsp.hv_remote_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      path_group_id: 101
      remote_storage_serial_number: "40014"
      remote_paths:
        - local_port: "CL7-C"
          remote_port: "CL7-C"
        - local_port: "CL7-D"
          remote_port: "CL7-D"

- name: update remote connection settings
  hitachivantara.vspone_block.vsp.hv_remote_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      path_group_id: 101
      remote_storage_serial_number: "40014"
      remote_io_timeout_in_sec: 15
      round_trip_in_msec: 1
      min_remote_paths: 1

- name: Delete a remote connection
  hitachivantara.vspone_block.vsp.hv_remote_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      path_group_id: 101
      remote_storage_serial_number: "40014"
"""

RETURN = """
remote_connection:
    description: Newly created remote connection object.
    returned: success
    type: dict
    contains:
        cu_status:
            description: CU status.
            type: str
            sample: "NML"
        cu_type:
            description: CU type.
            type: str
            sample: "REMOTE"
        min_num_of_paths:
            description: Minimum number of paths.
            type: int
            sample: 1
        num_of_paths:
            description: Number of paths.
            type: int
            sample: 1
        path_group_id:
            description: Path group ID.
            type: int
            sample: 101
        port_type:
            description: Port type.
            type: str
            sample: "FIBRE"
        remote_paths:
            description: List of remote paths.
            type: list
            elements: dict
            contains:
                cu_type:
                    description: CU type.
                    type: str
                    sample: "REMOTE"
                local_port_id:
                    description: Local port ID.
                    type: str
                    sample: "CL7-C"
                path_number:
                    description: Path number.
                    type: int
                    sample: 0
                path_status:
                    description: Path status.
                    type: str
                    sample: "NML_01"
                port_type:
                    description: Port type.
                    type: str
                    sample: "FIBRE"
                remote_port_id:
                    description: Remote port ID.
                    type: str
                    sample: "CL7-C"
        remote_serial_number:
            description: Remote serial number.
            type: str
            sample: "40014"
        remote_storage_device_id:
            description: Remote storage device ID.
            type: str
            sample: "900000040014"
        remote_storage_model:
            description: Remote storage model.
            type: str
            sample: "VSP 5600H"
        remote_storage_type_id:
            description: Remote storage type ID.
            type: str
            sample: "R9"
        remotepath_group_id:
            description: Remote path group ID.
            type: str
            sample: "40014,R9,101"
        round_trip_time_in_milli_seconds:
            description: Round trip time in milliseconds.
            type: int
            sample: 1
        timeout_value_for_remote_io_in_seconds:
            description: Timeout value for remote IO in seconds.
            type: int
            sample: 15
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_remote_connection_reconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPRemoteConnectionArgs,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPRemoteConnection:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPRemoteConnectionArgs().remote_connection_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_remote_connection_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Remote Connection operation. ===")
        try:
            registration_message = validate_ansible_product_registration()
            result = vsp_remote_connection_reconciler.VSPRemoteConnectionReconciler(
                self.params_manager.connection_info, self.serial
            ).remote_connection_reconcile(self.state, self.spec)

            msg = result if isinstance(result, str) else self.get_message()
            result = result if not isinstance(result, str) else None
            response_dict = {
                "changed": self.connection_info.changed,
                "remote_connection": result,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of Remote Connection operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Remote Connection operation. ===")
            self.module.fail_json(msg=str(ex))

    def get_message(self):

        if self.state == "present":
            return "Remote connection created/updated successfully."
        elif self.state == "absent":
            return "Remote connection deleted successfully."


def main(module=None):
    obj_store = VSPRemoteConnection()
    obj_store.apply()


if __name__ == "__main__":
    main()
