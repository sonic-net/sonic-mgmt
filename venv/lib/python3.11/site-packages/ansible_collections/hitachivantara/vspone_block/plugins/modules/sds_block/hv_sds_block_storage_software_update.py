#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_storage_software_update
short_description: Manages software update and downgrade on VSP One SDS Block and Cloud systems.
description:
  - This module allows software update and downgrade on VSP One SDS Block and Cloud systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/software_update.yml)
version_added: "4.3.0"
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
    description: The desired state of the storage pool.
    type: str
    required: false
    choices: ['present', 'software_update_file_present']
    default: 'present'
  spec:
    description: Specification for the storage software update.
    type: dict
    required: false
    suboptions:
      should_stop_software_update:
        description: Should stop storage software update.
        type: bool
        required: false
        default: false
      is_software_downgrade:
        description: Whether to perform storage software downgrade.
        type: bool
        required: false
        default: false
      software_update_file:
        description: The update file of the storage software to be transferred to the storage cluster.
        type: str
        required: false
"""

EXAMPLES = """
- name: Update the storage software
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_software_update:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"

- name: Downgrade the storage software
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_software_update:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      should_stop_software_update: true

- name: Upload the storage software update file
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_software_update:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      software_update_file: "/root/sdsb_sw_update/hsds-update-01170140-0007.tar"

- name: Downgrade the storage software
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_software_update:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      is_software_downgrade: true
"""

RETURN = """
message:
  description: Success or failure message for the storage software update.
  type: dict
  returned: always
  sample: "Successfully downgraded software. ID for this job = 822bd1fa-c5ee-4bea-a47d-f178146248cb."
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_software_update import (
    SDSBSoftwareUpdateReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBSoftwareUpdateArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBStorageSoftwareUpdateManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBSoftwareUpdateArguments().software_update()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_software_update_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Storage Software Update Operation ===")
        software_update = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBSoftwareUpdateReconciler(self.connection_info)
            software_update = sdsb_reconciler.reconcile_software_update(
                self.spec, self.state
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Storage Software Update Operation ==="
            )
            self.module.fail_json(msg=str(e))

        data = {
            "changed": self.connection_info.changed,
            "message": software_update,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Storage Software Update Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBStorageSoftwareUpdateManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
