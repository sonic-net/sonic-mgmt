#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_journal_facts
short_description: Retrieves information about Journal Volumes from Hitachi VSP storage systems.
description:
  - This module retrieves information about Journal Volumes from Hitachi VSP storage systems.
  - It provides details such as journalId, journalStatus, and other relevant information..
  - Forexamples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/journal_volume_facts.yml)
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
- hitachivantara.vspone_block.common.connection_with_type
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
    description: Specification for retrieving Journal Volume information.
    type: dict
    required: false
    suboptions:
      journal_id:
        description: Journal ID of the Journal Volume.
          Required for the Get specific Journal task.
        type: int
        required: false
      is_free_journal_pool_id:
        description: Whether to get free journal id.
          Required for the Get Free Journal IDs task.
        type: bool
        required: false
        default: false
      free_journal_pool_id_count:
        description: Number of free journal id to get.
          Required for the Get Free Journal IDs task.
        type: int
        required: false
        default: 1
      is_mirror_not_used:
        description: Whether to get mirror not used.
          Required for the Get Journal data with mirror not used task.
        type: bool
        required: false
        default: false

"""

EXAMPLES = """
- name: Retrieve information about all Journal Volumes
  hitachivantara.vspone_block.vsp.hv_journal_facts:
    storage_system_info:
      serial: "811150"
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about a specific Journal Volume
  hitachivantara.vspone_block.vsp.hv_journal_facts:
    storage_system_info:
      serial: "811150"
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    spec:
      journal_id: 10
"""

RETURN = r"""
ansible_facts:
  description: Dictionary containing the discovered properties of the Journal Volumes.
  returned: always
  type: dict
  contains:
    journal_volume:
      description: List of Journal Volume facts.
      returned: success
      type: list
      elements: dict
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
          sample: 0
        journal_status:
          description: Status of the Journal Volume.
          type: str
          sample: "SMPL"
        ldev_ids:
          description: LDEV IDs in the Journal Volume.
          type: list
          elements: int
          sample: [639]
        ldev_ids_hex:
          description: LDEV IDs in hex format.
          type: list
          elements: str
          sample: ["00:02:7F"]
        mirrors:
          description: Mirror information.
          type: list
          elements: dict
          contains:
            active_path_count:
              description: Number of active paths.
              type: int
              sample: -1
            active_path_watch_seconds:
              description: Active path watch threshold in seconds.
              type: int
              sample: -1
            consistency_group_id:
              description: Consistency group ID.
              type: int
              sample: 0
            copy_pace:
              description: Copy pace.
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
              description: Mirror status.
              type: str
              sample: "SMPL"
            transfer_speed_mbps:
              description: Transfer speed in Mbps.
              type: int
              sample: 256
        mp_blade_id:
          description: MP Blade ID.
          type: int
          sample: 0
        timer_type:
          description: Timer type.
          type: str
          sample: ""
        total_capacity:
          description: Total capacity with unit.
          type: str
          sample: "9.63 GB"
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


class VSPJournalFactManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPJournalArguments().journal_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_journal_volume_fact_spec()
            self.serial = self.params_manager.get_serial()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Journal Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = []
            result = vsp_journal_volume.VSPJournalVolumeReconciler(
                self.params_manager.connection_info, self.serial
            ).journal_volume_facts(self.spec)

        except Exception as ex:

            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Journal Facts ===")
            self.module.fail_json(msg=str(ex))
        data = {
            "journal_volume": result,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Journal Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = VSPJournalFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
