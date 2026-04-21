#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_remote_storage_registration
short_description: Manages remote storage registration and unregistration on Hitachi VSP storage systems.
description:
  - This module manages remote storage registration and unregistration on Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/remote_storage_registration.yml)
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
- hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: The desired state of the task.
    type: str
    required: false
    choices: ['present', 'absent']
    default: present
  secondary_connection_info:
    description: Information required to establish a connection to the secondary storage system.
    required: true
    type: dict
    suboptions:
      address:
        description: IP address or hostname of storage system.
        type: str
        required: true
      username:
        description: Username for authentication to the secondary storage system. This is a required field if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication to the secondary storage system. This is a required field if api_token is not provided.
        type: str
        required: false
      api_token:
        description: This field is used to pass the value of the lock token to operate on locked resources.
        type: str
        required: false
  spec:
    description: Specification for the remote storage registration and unregistration.
    type: dict
    required: false
    suboptions:
      is_mutual_discovery:
        description: Specify whether to perform a mutual registration operation. true means perform a mutual registration operation.
          Required for the Register Remote Storage task.
        type: bool
        required: false
      is_mutual_deletion:
        description: Specify whether to perform a mutual deletion operation during unregistration. true means perform a mutual deletion operation.
          Required for the Unregister Remote Storage task.
        type: bool
        required: false
      rest_server_ip:
        description: IP address of the rest server of the remote storage system.
            If not provided, secondary_connection_info.address will be used for rest_server_ip.
              Required for the Register Remote Storage task.
        type: str
        required: false
      rest_server_port:
        description: Port number of the rest server of the remote storage system. If not provided, 443 will be used for rest_server_port.
        type: int
        required: false
"""

EXAMPLES = """
- name: Register Remote Storage
  hitachivantara.vspone_block.vsp.hv_remote_storage_registration:
    connection_info:
      address: 172.0.0.2
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: 172.0.0.3
      username: "admin"
      password: "password"
    state: present
    spec:
      is_mutual_discovery: true
      rest_server_ip: 172.0.0.1

- name: Unregister Remote Storage
  hitachivantara.vspone_block.vsp.hv_remote_storage_registration:
    connection_info:
      address: 172.0.0.2
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: 172.0.0.3
      username: "admin"
      password: "password"
    state: absent
    spec:
      is_mutual_deletion: true
"""

RETURN = """
remote_storage:
  description: >
    A list of information about the storage systems registered on the REST API server.
  returned: always
  type: list
  elements: dict
  contains:
    storages_registered_in_local:
      description: List of storage systems registered locally.
      type: list
      elements: dict
      contains:
        communication_modes:
          description: List of communication modes.
          type: list
          elements: dict
          contains:
            communicationMode:
              description: Mode of communication.
              type: str
              sample: "lanConnectionMode"
        ctl1_ip:
          description: IP address of controller 1.
          type: str
          sample: "172.0.0.127"
        ctl2_ip:
          description: IP address of controller 2.
          type: str
          sample: "172.0.0.128"
        dkc_type:
          description: Type of DKC (Local or Remote).
          type: str
          sample: "Local"
        model:
          description: Model of the storage system.
          type: str
          sample: "VSP E1090H"
        rest_server_ip:
          description: IP address of the REST server.
          type: str
          sample: "172.0.0.2"
        rest_server_port:
          description: Port number of the REST server.
          type: int
          sample: 443
        serial_number:
          description: Serial number of the storage system.
          type: str
          sample: "710036"
        storage_device_id:
          description: Storage device ID.
          type: str
          sample: "938000710036"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_remote_storage_registration import (
    VSPRemoteStorageRegistrationReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPRemoteStorageRegistrationArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPRemoteStorageRegistrationManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            VSPRemoteStorageRegistrationArguments().remote_storage_registration()
        )

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
            self.spec = self.parameter_manager.get_remote_storage_registration_spec()
            self.state = self.parameter_manager.get_state()
            self.secondary_connection_info = (
                self.parameter_manager.get_secondary_connection_info()
            )
            self.spec.secondary_connection_info = self.secondary_connection_info
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of Remote Storage Registration operation. ===")
        registration_message = validate_ansible_product_registration()

        remote_storage = None
        comment = None
        try:
            reconciler = VSPRemoteStorageRegistrationReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )
            remote_storage = reconciler.reconcile_remote_storage_registration(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo(
                "=== End of Remote Storage Registration operation ==="
            )
            self.module.fail_json(msg=str(e))
        resp = {
            "changed": self.connection_info.changed,
        }
        comment = None
        if remote_storage is None and self.state == "absent":
            comment = "Remote storage is unregistered successfully."

        if remote_storage:
            if isinstance(remote_storage, str):
                comment = remote_storage
            else:
                resp["remote_storage"] = remote_storage
                comment = "Remote storage is registered successfully."
        if comment:
            resp["comment"] = comment
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Remote Storage Registration operation ===")
        self.module.exit_json(**resp)


def main(module=None):
    obj_store = VSPRemoteStorageRegistrationManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
