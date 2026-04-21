#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_remote_connection_facts
short_description: Retrieves Remote connection details from Hitachi VSP storage systems.
description: >
  - This module retrieves information about remote connections from Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/remote_connection_facts.yml)
version_added: '3.3.0'
author:
  - Hitachi Vantara, LTD. (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_without_token
options:
  spec:
    description: Specification for remote connection facts.
    type: dict
    required: false
    suboptions:
      path_group_id:
        description: Path group ID.
            Required for the Get remote connection information using path group id task.
        type: int
        required: false
"""

EXAMPLES = """
- name: Get all remote connection details
  hitachivantara.vspone_block.vsp.hv_remote_connection_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"

- name: Get remote connection details using path group id
  hitachivantara.vspone_block.vsp.hv_remote_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    spec:
      path_group_id: 101
"""

RETURN = """
ansible_facts:
    description: Facts about the remote connections.
    returned: success
    type: dict
    contains:
      remote_connections:
        description: Newly created remote connection object.
        returned: success
        type: list
        elements: dict
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


class VSPRemoteConnectionFacts:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPRemoteConnectionArgs().remote_connection_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_remote_connection_facts_spec()
            self.serial = self.params_manager.get_serial()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Remote Connection facts operation. ===")
        try:
            registration_message = validate_ansible_product_registration()
            result = vsp_remote_connection_reconciler.VSPRemoteConnectionReconciler(
                self.params_manager.connection_info, self.serial
            ).remote_connection_facts(self.spec)

            result = result if not isinstance(result, str) else None
            response_dict = {
                "remote_connections": result,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of Remote Connection facts operation. ===")
            self.module.exit_json(changed=False, ansible_facts=response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Remote Connection facts operation. ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VSPRemoteConnectionFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
