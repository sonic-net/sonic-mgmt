#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_remote_path_group_facts
short_description: Get information about remote path groups from VSP One SDS Block and Cloud systems.
description:
  - Get information about remote path groups from storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/remote_path_group_facts.yml)
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
  spec:
    description: Parameters for filtering or identifying remote path groups to
      gather facts about.
    type: dict
    required: false
    suboptions:
      id:
        description: The ID of a remote path group.
        type: str
        required: false
      local_storage_controller_id:
        description: The ID of a local storage system controller. UUID format.
        type: str
        required: false
      remote_serial:
        description: Serial number of the remote storage system.
        type: str
        required: false
      remote_storage_system_type:
        description: ID indicating the remote storage system model.
        type: str
        required: false
        choices:
          - R9
          - M8
      path_group_id:
        description: Path group ID.
        type: int
        required: false
"""

EXAMPLES = """
- name: Get all remote path groups
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_path_group_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Get remote path group by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_path_group_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "da87655a-3958-4921-b4c0-437986397d11"
"""

RETURN = r"""
ansible_facts:
  description: Collected facts containing details about remote path groups.
  type: dict
  returned: always
  contains:
    remote_path_groups:
      description: List of remote path group details.
      type: list
      elements: dict
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
          sample: "20be7610-9e5e-4713-bff2-e9d993d1f6d4"
        local_storage_controller_id:
          description: Identifier of the local storage controller.
          type: str
          sample: "3c65e322-ac62-4966-9489-072dbccdf430"
        number_of_paths:
          description: Number of paths in the remote path group.
          type: int
          sample: 1
        path_group_id:
          description: Identifier of the remote path group.
          type: int
          sample: 15
        protocol:
          description: Communication protocol used for the remote connection.
          type: str
          sample: "iSCSI"
        remote_serial_number:
          description: Serial number of the remote storage system.
          type: str
          sample: "810045"
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

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBRemotePathGroupArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_remote_path_group import (
    SDSBRemotePathGroupReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBRemotePathGroupFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBRemotePathGroupArguments().remote_path_group_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_remote_path_group_fact_spec()
        self.logger.writeDebug(
            f"MOD:hv_sds_block_remote_path_group_facts:spec= {self.spec}"
        )

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Remote Path Group Facts ===")
        remote_path_groups = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBRemotePathGroupReconciler(self.connection_info)
            remote_path_groups = sdsb_reconciler.get_remote_path_group_facts(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_remote_path_group_facts:remote_path_groups= {remote_path_groups}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Remote Path Group Facts ===")
            self.module.fail_json(msg=str(e))

        if remote_path_groups is None:
            remote_path_groups = []

        data = {"remote_path_groups": remote_path_groups}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Remote Path Group Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBRemotePathGroupFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
