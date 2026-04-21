#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_software_update_file_facts
short_description: Get information about the update file of the storage software that performed transfer (upload) in the storage cluster.
description:
  - Get the information of the update file of the storage software which performed transfer (upload) in the storage cluster.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/software_update_file_facts)
version_added: "4.3.0"
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
"""

EXAMPLES = """
- name: Get BMC connection for all storage nodes
  hitachivantara.vspone_block.sds_block.hv_sds_block_software_update_file_facts:
    connection_info: "{{ connection_info }}"
  register: result
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the storage_controllers.
  returned: always
  type: dict
  contains:
    software_update_file:
      description: Software update file information.
      type: dict
      contains:
        version:
          description: The version of the update file of the storage software.
          type: str
          sample: "01.10.02.00"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBSoftwareUpdateArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_software_update import (
    SDSBSoftwareUpdateReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockStorageControllerFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBSoftwareUpdateArguments().software_update_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        # self.spec = parameter_manager.get_storage_controller_fact_spec()
        # self.logger.writeDebug(
        #     f"MOD:hv_sds_block_storage_controller_facts:spec= {self.spec}"
        # )

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Software Update File Facts ===")
        software_update = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBSoftwareUpdateReconciler(self.connection_info)
            software_update = sdsb_reconciler.get_software_update_file()

            self.logger.writeDebug(
                f"MOD:hv_sds_block_storage_controller_facts:storage_controllers= {software_update}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Software Update File Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"software_update_file": software_update}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Software Update File Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockStorageControllerFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
