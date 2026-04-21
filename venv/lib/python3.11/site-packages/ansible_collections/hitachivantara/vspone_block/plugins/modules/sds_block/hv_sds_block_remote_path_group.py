#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_remote_path_group
short_description: Manages remote path groups on VSP One SDS Block and Cloud systems.
description:
  - This module allows create a remote path group, add remote path to a remote path group,
    remove remote path from remote path group, and delete remote path group  on Hitachi SDS Block storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/remote_path_group.yml)
version_added: "4.5.0"
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
    description: The desired state of the remote path group.
    type: str
    required: false
    choices: ['present', 'absent', 'add_remote_path', 'remove_remote_path']
    default: 'present'
  spec:
    description: Specification for the remote path group.
    type: dict
    required: false
    suboptions:
      id:
        description: The ID of the remote path group. Required for update and delete operation.
        type: str
        required: false
      local_port:
        description: Port number of the local storage system in CLx-y format. Required for create operation.
        type: str
        required: false
      remote_serial:
        description: Serial number of the remote storage system. Required for create operation.
        type: str
        required: false
      remote_storage_system_type:
        description: ID indicating the remote storage system model. Required for create operation.
        type: str
        required: false
        choices: ['R9', 'M8']
      remote_port:
        description: Port number of the remote storage system in CLx-y format. Required for create operation.
        type: str
        required: false
      path_group_id:
        description: Path group ID. Required for create operation. Value must be between 1 and 255.
        type: int
        required: false
      remote_io_timeout_in_sec:
        description: Timeout setting value for the RIO (remote IO) between the local storage system and remote
          storage system in seconds. Optional for create operation. Value must be between 10 and 80.
          Default value is 15.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create a remote path group
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_path_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      remote_serial: "810045"
      remote_storage_system_type: "M8"
      local_port: "CL1-C"
      remote_port: "CL2-C"
      path_group_id: 20
      remote_io_timeout_in_sec: 200

- name: Delete a remote path group
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_path_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "restore"
    spec:
      id: "3d0997ce-7065-4e4a-9095-4dc62b36f300"
"""

RETURN = """
remote_path_groups:
  description: Details of the remote path group configuration.
  type: dict
  returned: always
  contains:
    cu_status:
      description: Connection unit status of the remote path group.
      type: str
      sample: "Error"
    cu_type:
      description: Type of the connection unit.
      type: str
      sample: "Remote"
    id:
      description: Unique identifier of the remote path group.
      type: str
      sample: "72b765af-5159-405d-9d60-a899ad8f751c"
    local_storage_controller_id:
      description: Identifier of the local storage controller associated with the path group.
      type: str
      sample: "3c65e322-ac62-4966-9489-072dbccdf430"
    number_of_paths:
      description: Number of paths in the remote path group.
      type: int
      sample: 1
    path_group_id:
      description: Identifier of the remote path group.
      type: int
      sample: 25
    protocol:
      description: Communication protocol used for the remote connection.
      type: str
      sample: "iSCSI"
    remote_serial_number:
      description: Serial number of the remote storage system.
      type: str
      sample: "810050"
    remote_storage_type_id:
      description: Model or type identifier of the remote storage system.
      type: str
      sample: "M8"
    timeout_value_for_remote_io_in_seconds:
      description: Timeout value (in seconds) for remote I/O operations.
      type: int
      sample: 15
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_remote_path_group import (
    SDSBRemotePathGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBRemotePathGroupArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockRemoteIscsiPortManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBRemotePathGroupArguments().remote_path_group()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            parameter_manager = SDSBParametersManager(self.module.params)
            self.connection_info = parameter_manager.get_connection_info()
            self.spec = parameter_manager.get_remote_path_group_spec()
            self.state = parameter_manager.get_state()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Remote Path Group Operation ===")
        remote_path_groups = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBRemotePathGroupReconciler(self.connection_info)
            remote_path_groups = sdsb_reconciler.reconcile_remote_path_group(
                self.spec, self.state
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Remote Path Group Operation ===")
            self.module.fail_json(msg=str(e))

        data = {
            "changed": self.connection_info.changed,
            "remote_path_groups": remote_path_groups if remote_path_groups else [],
        }
        if self.spec.comments:
            data["message"] = self.spec.comments

        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Remote Path Group Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBBlockRemoteIscsiPortManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
