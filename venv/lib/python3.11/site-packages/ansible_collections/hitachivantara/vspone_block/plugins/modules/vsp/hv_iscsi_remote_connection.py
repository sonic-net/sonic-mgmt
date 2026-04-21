#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_iscsi_remote_connection
short_description: Manages Remote connections through iSCSI ports on Hitachi VSP storage systems.
description: >
  - This module allows settings of remote connections through iSCSI ports used for remote copy operations.
  - Remote connections are used to connect storage systems used in remote copy operations for TrueCopy, Universal Replicator, and global-active device.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/remote_iscsi_connection.yml)
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
    description: Specification for iSCSI remote connection tasks.
    type: dict
    required: true
    suboptions:
      remote_storage_serial_number:
        description: Serial number of the remote storage system.
            Required for the Create a new remote connection using iSCSI ports
            /Delete an iSCSI-based remote connection tasks.
        type: str
        required: true
      local_port:
          description: Port number of the local storage system
            Required for the Create a new remote connection using iSCSI ports
            /Delete an iSCSI-based remote connection tasks.
          type: str
          required: true
      remote_port:
          description: Port number of the remote storage system
            Required for the Create a new remote connection using iSCSI ports
            /Delete an iSCSI-based remote connection tasks.
          type: str
          required: true
      remote_storage_ip_address:
        description: IP address of the remote storage system.
            Required for the Create a new remote connection using iSCSI ports task.
        type: str
        required: false
      remote_tcp_port:
        description: TCP port of the remote storage system.
            Optional for the Create a new remote connection using iSCSI ports task.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create a new remote connection through iSCSI ports
  hitachivantara.vspone_block.vsp.hv_remote_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: present
    spec:
      remote_storage_serial_number: "40014"
      local_port: "CL7-D"
      remote_port: "CL7-D"
      remote_storage_ip_address: "10.120.10.120"
      remote_tcp_port: 3260

- name: Delete a iSCSI remote connection
  hitachivantara.vspone_block.vsp.hv_remote_connection:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      remote_storage_serial_number: "40014"
      local_port: "CL7-D"
      remote_port: "CL7-D"
"""

RETURN = """
remote_connection:
    description: Newly created remote connection object.
    returned: success
    type: dict
    contains:
        local_port_id:
            description: Local port ID.
            type: str
            sample: "CL1-C"
        remote_ip_address:
            description: Remote IP address.
            type: str
            sample: "10.12.10.120"
        remote_iscsi_port_id:
            description: Remote iSCSI port ID.
            type: str
            sample: "CL1-C,810045,M8,CL1-C"
        remote_port_id:
            description: Remote port ID.
            type: str
            sample: "CL1-C"
        remote_serial_number:
            description: Remote serial number.
            type: str
            sample: "810045"
        remote_storage_device_id:
            description: Remote storage device ID.
            type: str
            sample: "A34000810045"
        remote_storage_model:
            description: Remote storage model.
            type: str
            sample: "VSP One B26"
        remote_storage_type_id:
            description: Remote storage type ID.
            type: str
            sample: "M8"
        remote_tcp_port:
            description: Remote TCP port.
            type: int
            sample: 3260
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_iscsi_remote_connection_reconciler,
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

        self.argument_spec = VSPRemoteConnectionArgs().iscsi_remote_connection_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_iscsi_remote_connection_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of iSCSI Remote Connection operation. ===")
        try:
            registration_message = validate_ansible_product_registration()
            result = vsp_iscsi_remote_connection_reconciler.VSPRemoteIscsiConnectionReconciler(
                self.params_manager.connection_info, self.serial
            ).remote_iscsi_connection_reconcile(
                self.state, self.spec
            )

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
            self.logger.writeInfo("=== End of iSCSI Remote Connection operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of iSCSI Remote Connection operation. ===")
            self.module.fail_json(msg=str(ex))

    def get_message(self):

        if self.state == "present":
            return "Remote connection created successfully."
        elif self.state == "absent":
            return "Remote connection deleted successfully."


def main(module=None):
    obj_store = VSPRemoteConnection()
    obj_store.apply()


if __name__ == "__main__":
    main()
