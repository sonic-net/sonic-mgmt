#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_clpr_facts
short_description: Retrieves information about clprs from Hitachi VSP storage systems.
description:
  - This module retrieves information about clprs from Hitachi VSP storage systems.
  - It provides details about CLPR such as ID, status and other relevant information.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/clpr_facts.yml)
version_added: '3.0.0'
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
- hitachivantara.vspone_block.common.connection_with_type
notes:
  - The output parameters C(entitlement_status), C(subscriber_id) and C(partner_id) were removed in version 3.4.0.
    They were also deprecated due to internal API simplification and are no longer supported.
options:
  storage_system_info:
    description: Information about the storage system. This field is an optional field.
    type: dict
    required: false
    suboptions:
      serial:
        description: The serial number of the storage system.
        type: str
        required: false
  spec:
    description: Specification for retrieving clpr information.
    type: dict
    required: false
    suboptions:
      clpr_id:
        type: int
        description: CLPR id. Required for Get one CLPR using clpr_id.
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all clprs
  hitachivantara.vspone_block.vsp.hv_clpr_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"

    storage_system_info:
      serial: 811150

- name: Retrieve information about a specific clpr
  hitachivantara.vspone_block.vsp.hv_clpr_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    spec:
      clpr_id: 274
"""

RETURN = """
ansible_facts:
  description: CLPR facts collected from the storage system.
  returned: success
  type: dict
  contains:
    clprs:
      description: List of CLPR objects.
      returned: success
      type: list
      elements: dict
      contains:
        clpr_id:
          description: CLPR ID.
          type: int
          sample: 0
        clpr_name:
          description: Name of the CLPR.
          type: str
          sample: "CLPR0"
        cache_memory_capacity_in_gb:
          description: Cache memory capacity in gigabytes.
          type: float
          sample: 498.0
        cache_memory_capacity_in_mb:
          description: Cache memory capacity in megabytes.
          type: int
          sample: 509952
        cache_memory_used_capacity_in_gb:
          description: Used cache memory capacity in gigabytes.
          type: float
          sample: 9.6162109375
        cache_memory_used_capacity_in_mb:
          description: Used cache memory capacity in megabytes.
          type: int
          sample: 9847
        cache_usage_rate:
          description: Cache usage rate as percentage.
          type: int
          sample: 2
        side_files_capacity_in_gb:
          description: Side files capacity in gigabytes.
          type: float
          sample: 0.0
        side_files_capacity_in_mb:
          description: Side files capacity in megabytes.
          type: int
          sample: 0
        side_files_usage_rate:
          description: Side files usage rate as percentage.
          type: int
          sample: 0
        write_pending_data_capacity_in_gb:
          description: Write pending data capacity in gigabytes.
          type: float
          sample: 0.0595703125
        write_pending_data_capacity_in_mb:
          description: Write pending data capacity in megabytes.
          type: int
          sample: 61
        write_pending_data_rate:
          description: Write pending data rate as percentage.
          type: int
          sample: 1
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPClprArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_clpr_reconciler import (
    VSPClprReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPClprManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPClprArguments().get_all_clpr_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        self.parameter_manager = VSPParametersManager(self.module.params)
        self.connection_info = self.parameter_manager.get_connection_info()
        self.storage_serial_number = self.parameter_manager.get_serial()
        self.spec = self.parameter_manager.set_clpr_fact_spec()
        self.logger.writeInfo(f"{self.spec} SPEC")
        self.state = self.parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of CLPR Facts ===")

        registration_message = validate_ansible_product_registration()
        try:
            reconciler = VSPClprReconciler(
                self.connection_info, self.storage_serial_number, self.state
            )

            clprs = reconciler.get_clpr_facts(self.spec)
            msg = ""

            if self.spec.clpr_id is not None:
                msg = "CLPR information retrieved successfully"
            elif clprs is not None:
                msg = "CLPRs retrieved successfully"
            self.logger.writeDebug(f"MOD:hv_clpr_facts:copy_groups= {clprs}")

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of CLPR Facts ===")
            self.module.fail_json(msg=str(e))
        data = {"clprs": clprs, "msg": msg}
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of CLPR Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = VSPClprManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
