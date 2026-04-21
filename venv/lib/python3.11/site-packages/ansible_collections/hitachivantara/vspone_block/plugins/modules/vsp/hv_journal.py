#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_journal
short_description: Create, update, expand, shrink, delete journal from Hitachi VSP storage systems.
description:
  - This module creates, update, expand, shrink, delete journal from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/journal.yml)
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
- hitachivantara.vspone_block.common.connection_with_type
options:
  state:
    description: State of the Journal.
    type: str
    required: false
    choices: ['present', 'absent', 'update', 'expand_journal', 'shrink_journal']
    default: 'present'
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
    description: Specification for creating Journal.
    type: dict
    required: false
    suboptions:
      journal_id:
        description: Journal ID of the Journal.
          Required for the Create a Journal using required details
          /Update a Journal using more details
          /Expand journal
          /Shrink journal
          /Delete Journal by ID tasks.
        type: int
        required: false
      start_ldev_id:
        description: Start LDEV ID of the Journal.
        type: str
        required: false
        aliases: ["startLdevId"]
      end_ldev_id:
        description: End LDEV ID of the Journal.
        type: str
        required: false
        aliases: ["endLdevId"]
      is_cache_mode_enabled:
        description: Cache mode enabled or not.
          Required for the Update a Journal using more details task.
        type: bool
        required: false
      data_overflow_watch_in_seconds:
        description: Data overflow watch in seconds.
          Required for the Update a Journal using more details task.
        type: int
        required: false
        aliases: ["data_overflow_watchIn_seconds"]
      mp_blade_id:
        description: MP Blade ID of the Journal.
          Required for the Update a Journal using more details task.
        type: int
        required: false
      ldev_ids:
        description: List of LDEVs.
          Required for the Create a Journal using required details
          /Expand journal
          /Shrink journal task.
        type: list
        required: false
        elements: str
      mirror_unit_number:
        description: Mirror unit number.
          Required for the Update a Journal using more details task.
        type: int
        required: false
      copy_pace:
        description: Copy pace.
          Required for the Update a Journal using more details task.
        type: str
        required: false
        choices: ['SLOW', 'MEDIUM', 'FAST']
      path_blockade_watch_in_minutes:
        description: Path blockade watch in minutes.
          Required for the Update a Journal using more details task.
        type: int
        required: false
"""

EXAMPLES = """
- name: Create a Journal
  hitachivantara.vspone_block.vsp.hv_journal:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      journal_id: 37
      ldev_ids: [1993, 1994]
"""

RETURN = r"""
data:
  description: >
    Dictionary containing the discovered properties of the Journal.
  returned: always
  type: dict
  contains:
    data_overflow_watch_seconds:
      description: Data overflow watch in seconds.
      type: int
      sample: 60
    is_cache_mode_enabled:
      description: Indicates if cache mode is enabled.
      type: bool
      sample: true
    journal_pool_id:
      description: Journal pool ID.
      type: int
      sample: 116
    journal_status:
      description: Status of the Journal.
      type: str
      sample: "SMPL"
    ldev_ids:
      description: List of LDEV IDs.
      type: list
      elements: int
      sample: [142]
    ldev_ids_hex:
      description: List of LDEV IDs in hexadecimal format.
      type: list
      elements: str
      sample: ["00:00:8E"]
    mirrors:
      description: List of mirror units.
      type: list
      elements: dict
      contains:
        active_path_count:
          description: Number of active paths.
          type: int
          sample: -1
        active_path_watch_seconds:
          description: Active path watch in seconds.
          type: int
          sample: -1
        consistency_group_id:
          description: Consistency group ID.
          type: int
          sample: 0
        copy_pace:
          description: Copy pace setting.
          type: str
          sample: "LOW"
        is_delta_resync_failure_full_copy:
          description: Indicates if delta resync failure triggers full copy.
          type: bool
          sample: null
        mirror_unit_id:
          description: Mirror unit ID.
          type: int
          sample: 0
        path_blockade_watch_seconds:
          description: Path blockade watch in seconds.
          type: int
          sample: 300
        q_count:
          description: Queue count.
          type: int
          sample: -1
        q_marker:
          description: Queue marker.
          type: int
          sample: -1
        status:
          description: Mirror unit status.
          type: str
          sample: "SMPL"
        transfer_speed_mbps:
          description: Transfer speed in Mbps.
          type: int
          sample: 256
    mp_blade_id:
      description: MP Blade ID of the Journal.
      type: int
      sample: 1
    timer_type:
      description: Timer type configuration.
      type: str
      sample: ""
    total_capacity:
      description: Total capacity with units.
      type: str
      sample: "29.03 GB"
    type:
      description: Journal type.
      type: str
      sample: ""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_journal_volume,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPJournalArguments,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPJournalManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPJournalArguments().journal()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.journal_volume_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Journal Operation. ===")
        try:
            registration_message = validate_ansible_product_registration()
            result, res_msg = vsp_journal_volume.VSPJournalVolumeReconciler(
                self.params_manager.connection_info, self.serial
            ).journal_volume_reconcile(self.state, self.spec)

            msg = res_msg if res_msg else self.get_message()
            result = result if not isinstance(result, str) else None
            response_dict = {
                "changed": self.connection_info.changed,
                "data": result,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of Journal Operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Journal Operation. ===")
            self.module.fail_json(msg=str(ex))

    def get_message(self):

        if self.state == "present":
            return "Journal created successfully."
        elif self.state == "absent":
            return "Journal deleted successfully."
        elif self.state == "expand_journal":
            return "Journal expanded successfully."
        elif self.state == "shrink_journal":
            return "Journal shrunk successfully."
        elif self.state == "update":
            return "Journal updated successfully."
        else:
            return "Unknown state provided."


def main(module=None):
    obj_store = VSPJournalManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
