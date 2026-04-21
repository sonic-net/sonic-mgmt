#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_remote_storage_registration_facts
short_description: Retrieves remote storage registration information from Hitachi VSP storage systems.
description:
  - This module retrieves remote storage registration information from Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/remote_storage_registration_facts.yml)
version_added: '3.2.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_info
options:
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
        description: Username for authentication.
        type: str
        required: false
      password:
        description: Password for authentication.
        type: str
        required: false
      api_token:
        description: Value of the lock token to operate on locked resources.
        type: str
        required: false
"""

EXAMPLES = """
- name: Remote Storage Registration Facts
  hitachivantara.vspone_block.vsp.hv_remote_storage_registration_facts:
    connection_info:
      address: 172.0.0.2
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: 172.0.0.3
      username: "admin"
      password: "password"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the remote storage registration.
  returned: always
  type: dict
  contains:
    remote_storages:
      description: A list of information about the storage systems registered on the REST API server.
      type: list
      elements: dict
      contains:
        storages_registered_in_local:
          description: List of storage systems registered in the local storage system.
          type: list
          elements: dict
          contains:
            communication_modes:
              description: List of communication modes for the storage system.
              type: list
              elements: dict
              contains:
                communicationMode:
                  description: Mode of communication.
                  type: str
                  sample: "lanConnectionMode"
            ctl1_ip:
              description: IP address of controller 1, or false if not available.
              type: str
              sample: "172.25.44.104"
            ctl2_ip:
              description: IP address of controller 2, or false if not available.
              type: str
              sample: "172.25.44.105"
            dkc_type:
              description: Type of the storage system.
              type: str
              sample: "Remote"
            model:
              description: Model of the storage system.
              type: str
              sample: "VSP E590"
            rest_server_ip:
              description: IP address of the REST API server.
              type: str
              sample: "172.25.44.104"
            rest_server_port:
              description: Port of the REST API server.
              type: int
              sample: 443
            serial_number:
              description: Serial number of the storage system.
              type: int
              sample: 611032
            storage_device_id:
              description: Unique identifier for the storage device.
              type: str
              sample: "934000611032"
        storages_registered_in_remote:
          description: List of storage systems registered in the remote storage system.
          type: list
          elements: dict
          contains:
            communication_modes:
              description: List of communication modes for the storage system.
              type: list
              elements: dict
              contains:
                communicationMode:
                  description: Mode of communication.
                  type: str
                  sample: "lanConnectionMode"
            ctl1_ip:
              description: IP address of controller 1, or false if not available.
              type: str
              sample: "172.25.44.21"
            ctl2_ip:
              description: IP address of controller 2, or false if not available.
              type: str
              sample: "172.25.44.22"
            dkc_type:
              description: Type of the storage system.
              type: str
              sample: "Remote"
            model:
              description: Model of the storage system.
              type: str
              sample: "VSP E990"
            rest_server_ip:
              description: IP address of the REST API server.
              type: str
              sample: "172.25.44.21"
            rest_server_port:
              description: Port of the REST API server.
              type: int
              sample: 443
            serial_number:
              description: Serial number of the storage system.
              type: int
              sample: 446039
            storage_device_id:
              description: Unique identifier for the storage device.
              type: str
              sample: "936000446039"
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


class VSPRemoteStorageRegistrationFactsManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = (
            VSPRemoteStorageRegistrationArguments().remote_storage_registration_facts()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        self.parameter_manager = VSPParametersManager(self.module.params)
        self.connection_info = self.parameter_manager.get_connection_info()
        self.storage_serial_number = self.parameter_manager.get_serial()
        self.spec = self.parameter_manager.get_remote_storage_registration_fact_spec()
        self.state = self.parameter_manager.get_state()
        self.secondary_connection_info = (
            self.parameter_manager.get_secondary_connection_info()
        )
        self.spec.secondary_connection_info = self.secondary_connection_info

    def apply(self):
        self.logger.writeInfo("=== Start of Remote Storage Registration Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            reconciler = VSPRemoteStorageRegistrationReconciler(
                self.connection_info,
                self.storage_serial_number,
                self.state,
                # self.secondary_connection_info,
            )

            remote_storages = reconciler.get_remote_storage_registration_facts(
                self.spec
            )
            self.logger.writeDebug(
                f"MOD:hv_copy_group_facts:copy_groups= {remote_storages}"
            )

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Remote Storage Registration Facts ===")
            self.module.fail_json(msg=str(e))

        data = {
            "remote_storages": remote_storages,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Remote Storage Registration Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = VSPRemoteStorageRegistrationFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
