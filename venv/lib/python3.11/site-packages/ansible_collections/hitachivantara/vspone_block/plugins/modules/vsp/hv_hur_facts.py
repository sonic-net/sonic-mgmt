#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_hur_facts
short_description: Retrieves HUR information from Hitachi VSP storage systems.
description:
  - This module retrieves information about HURs from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/hur_facts.yml)
version_added: '3.1.0'
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
  secondary_connection_info:
    description: Information required to establish a connection to the secondary storage system.
    required: false
    type: dict
    suboptions:
      address:
        description: IP address or hostname of the secondary storage system.
        type: str
        required: true
      username:
        description: Username for authentication for the secondary storage system if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication for the secondary storage system if api_token is not provided.
        type: str
        required: false
      api_token:
          description: Value of the lock token to operate on locked resources.
          type: str
          required: false
  spec:
    description: Specification for the HUR facts to be gathered.
    type: dict
    required: false
    suboptions:
      primary_volume_id:
        description: The primary volume identifier. If not provided, it will be omitted.
          Required for the Get HUR pair using primary volume ID task.
        type: str
        required: false
      secondary_volume_id:
        description: The secondary volume identifier. If not provided, it will be omitted.
          Optional for the Get HUR pair using secondary volume ID task.
        type: str
        required: false
      mirror_unit_id:
        description: The mirror unit identifier. If not provided, it will be omitted.
        type: int
        required: false
        choices: [0, 1, 2, 3]
      copy_group_name:
        description: The copy group name. If not provided, it will be omitted.
          Required for the Get HUR pair using copy group
          /Get HUR pair using copy group and copy pair name tasks.
        type: str
        required: false
      secondary_storage_serial_number:
        description: The secondary storage serial number. If not provided, it will be omitted.
        type: int
        required: false
      copy_pair_name:
        description: The copy pair name. If not provided, it will be omitted.
          Required for the Get HUR pair using copy group and copy pair name task.
        type: str
        required: false
      local_device_group_name:
        description: The local device group name. If not provided, it will be omitted.
        type: str
        required: false
      remote_device_group_name:
        description: The remote device group name. If not provided, it will be omitted.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all HUR pairs
  hitachivantara.vspone_block.vsp.hv_truecopy_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"

- name: Gather HUR facts with primary volume and mirror unit ID
  hitachivantara.vspone_block.vsp.hv_hur_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      primary_volume_id: 111
      mirror_unit_id: 10

- name: Gather HUR facts for a specific primary volume
  hitachivantara.vspone_block.vsp.hv_hur_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      primary_volume_id: 111

- name: Gather HUR facts for a specific secondary volume
  hitachivantara.vspone_block.vsp.hv_hur_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      secondary_volume_id: 111
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the HURs.
  returned: always
  type: dict
  contains:
    hurs:
      description: A list of HURs gathered from the storage system.
      type: list
      elements: dict
      contains:
        consistency_group_id:
          description: Consistency Group ID.
          type: int
          sample: 39
        copy_group_name:
          description: Name of the copy group.
          type: str
          sample: "spcA34000810045A34000810050"
        copy_pair_name:
          description: Name of the copy pair.
          type: str
          sample: "spc-7331-6442"
        copy_rate:
          description: Copy rate.
          type: int
          sample: ""
        mirror_unit_id:
          description: Mirror unit ID.
          type: int
          sample: 1
        primary_journal_pool:
          description: Primary journal pool.
          type: int
          sample: 25
        primary_volume_id:
          description: Primary volume ID.
          type: int
          sample: 6442
        primary_volume_id_hex:
          description: Hexadecimal representation of the primary volume ID.
          type: str
          sample: "00:19:2A"
        primary_volume_storage_id:
          description: Primary volume storage ID.
          type: str
          sample: "810050"
        pvol_status:
          description: PVOL status.
          type: str
          sample: "PAIR"
        pvol_storage_device_id:
          description: PVOL storage device ID.
          type: str
          sample: "A34000810050"
        remote_mirror_copy_pair_id:
          description: Remote mirror copy pair ID.
          type: str
          sample: "A34000810050,spcA34000810045A34000810050,spcA34000810045A34000810050,spcA34000810050A34000810045,spc-7331-6442"
        secondary_journal_pool:
          description: Secondary journal pool.
          type: int
          sample: 25
        secondary_volume_id:
          description: Secondary volume ID.
          type: int
          sample: 7331
        secondary_volume_id_hex:
          description: Hexadecimal representation of the secondary volume ID.
          type: str
          sample: "00:1C:A3"
        secondary_volume_storage_id:
          description: Secondary volume storage ID.
          type: str
          sample: "810045"
        svol_status:
          description: SVOL status.
          type: str
          sample: "PAIR"
        svol_storage_device_id:
          description: SVOL storage device ID.
          type: str
          sample: "A34000810045"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPHurArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_hur import (
    VSPHurReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log_decorator import (
    LogDecorator,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


@LogDecorator.debug_methods
class VSPHurFactManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPHurArguments().get_hur_fact_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            # sng20241115 for the secondary_connection_info remote_connection_manager
            self.secondary_connection_info = (
                self.params_manager.secondary_connection_info
            )
            self.storage_serial_number = self.params_manager.storage_system_info.serial
            self.spec = self.params_manager.get_hur_fact_spec()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of HUR Facts ===")
        hur_data = None
        registration_message = validate_ansible_product_registration()

        try:
            hur_data = self.get_hur_facts()
        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of HUR Facts ===")
            self.module.fail_json(msg=str(e))
        data = {
            "hurs": hur_data,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of HUR Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)

    def get_hur_facts(self):
        reconciler = VSPHurReconciler(
            self.connection_info, self.storage_serial_number, None
        )
        self.spec.secondary_connection_info = self.secondary_connection_info
        result = reconciler.get_hur_facts(self.spec)
        return result


def main(module=None):
    """
    Create class instance and invoke apply
    :return: None
    """
    obj_store = VSPHurFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
