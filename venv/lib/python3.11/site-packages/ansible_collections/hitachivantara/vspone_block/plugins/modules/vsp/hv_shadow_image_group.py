#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_shadow_image_group
short_description: Manages Remote Copy Group on Hitachi VSP storage systems.
description: >
  - This module allows for the splitting, re-syncing, restore, deletion and migration of Shadow Image Group on Hitachi VSP storage systems.
  - It supports various Shadow image pairs operations based on the specified task level.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/shadow_image_group.yml)
version_added: '3.2.0'
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
- hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: The level of the Shadow Image Group pairs task. Choices are C(present), C(absent), C(split), C(sync), C(restore), C(migrate).
    type: str
    required: false
    choices: ['present', 'absent', 'split', 'resync', 'sync', 'restore', 'migrate']
    default: 'present'
  spec:
    description: Specification for the Shadow Image Group task.
    type: dict
    required: true
    suboptions:
      copy_group_name:
        description: Copy group name, required for all operations.
          Required for the Split ShadowImage Group
          /Resync ShadowImage Group
          /Restore ShadowImage Group
          /Delete ShadowImage Group
          /Migrate ShadowImage Group
          /Cancel Migration of ShadowImage Group tasks.
        type: str
        required: true
      primary_volume_device_group_name:
        description: Specify the P-VOL device group name .
        type: str
        required: false
      secondary_volume_device_group_name:
        description: Specify the S-VOL device group name .
        type: str
        required: false
      copy_pace:
        description: Specify the copy pace.
          Optional for the Split ShadowImage Group
          /Resync ShadowImage Group
          /Restore ShadowImage Group tasks.
        type: int
        required: false
      quick_mode:
        description: Specify whether quick mode.
          Optional for the Split ShadowImage Group
          /Resync ShadowImage Group
          /Restore ShadowImage Group tasks.
        type: bool
        required: false
      force_suspend:
        description: Specify whether force suspend.
          Optional for the Split ShadowImage Group task.
        type: bool
        required: false
      force_delete:
        description: Specify whether force delete.
          Required for the Delete ShadowImage Group task.
        type: bool
        required: false
      should_force_split:
        description: Specify whether to force split.
          Optional for the Cancel Migration of ShadowImage Group task.
        type: bool
        required: false
"""

EXAMPLES = """
- name: Split local copy group
  hitachivantara.vspone_block.vsp.hv_shadow_image_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: split
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1
      primary_volume_device_group_name: remote_copy_group_local_device_group_name_1
      secondary_volume_device_group_name: remote_copy_group_remote_device_group_name_1
      quick_mode: true
      copy_pace: 100
      force_suspend: true

- name: Resync local copy group
  hitachivantara.vspone_block.vsp.hv_shadow_image_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: sync
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1
      primary_volume_device_group_name: remote_copy_group_local_device_group_name_1
      secondary_volume_device_group_name: remote_copy_group_remote_device_group_name_1
      quick_mode: true
      copy_pace: 100

- name: Restore local copy group
  hitachivantara.vspone_block.vsp.hv_shadow_image_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: swap_split
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1
      primary_volume_device_group_name: remote_copy_group_local_device_group_name_1
      secondary_volume_device_group_name: remote_copy_group_remote_device_group_name_1
      quick_mode: true
      copy_pace: 100

- name: Delete local copy group
  hitachivantara.vspone_block.vsp.hv_shadow_image_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1
      primary_volume_device_group_name: remote_copy_group_local_device_group_name_1
      secondary_volume_device_group_name: remote_copy_group_remote_device_group_name_1
      force_delete: true

- name: Migrate local copy group
  hitachivantara.vspone_block.vsp.hv_shadow_image_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: migrate
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1

- name: Cancel migration of local copy group
  hitachivantara.vspone_block.vsp.hv_shadow_image_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: split
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1
      should_force_split: true
"""

RETURN = """
local_copy_group_info:
  description: Details of the Shadow Image Group.
  returned: success
  type: dict
  contains:
    copy_group_name:
      description: Copy group name.
      type: str
      sample: "SI172"
    local_clone_copygroup_id:
      description: Local clone copy group ID.
      type: str
      sample: "SI172,SI172P_,SI172S_"
    pvol_device_group_name:
      description: PVOL device group name.
      type: str
      sample: "SI172P_"
    svol_device_group_name:
      description: SVOL device group name.
      type: str
      sample: "SI172S_"
    copy_pairs:
      description: List of copy pairs in the copy group.
      type: list
      elements: dict
      contains:
        consistency_group_id:
          description: Consistency group ID.
          type: str
          sample: ""
        copy_group_name:
          description: Copy group name.
          type: str
          sample: "SI172"
        copy_mode:
          description: Copy mode.
          type: str
          sample: "NotSnapshot"
        copy_pair_name:
          description: Copy pair name.
          type: str
          sample: "CPTest"
        copy_progress_rate:
          description: Copy progress rate.
          type: int
          sample: 100
        local_clone_copypair_id:
          description: Local clone copy pair ID.
          type: str
          sample: "SI172,SI172P_,SI172S_,CPTest"
        pvol_difference_data_management:
          description: PVOL difference data management.
          type: str
          sample: "S"
        pvol_ldev_id:
          description: PVOL LDEV ID.
          type: int
          sample: 172
        pvol_mu_number:
          description: PVOL MU number.
          type: int
          sample: 0
        pvol_processing_status:
          description: PVOL processing status.
          type: str
          sample: "N"
        pvol_status:
          description: PVOL status.
          type: str
          sample: "PSUS"
        replication_type:
          description: Replication type.
          type: str
          sample: "SI"
        svol_difference_data_management:
          description: SVOL difference data management.
          type: str
          sample: "S"
        svol_ldev_id:
          description: SVOL LDEV ID.
          type: int
          sample: 173
        svol_processing_status:
          description: SVOL processing status.
          type: str
          sample: "N"
        svol_status:
          description: SVOL status.
          type: str
          sample: "SSUS"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPLocalCopyGroupArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_local_copy_group import (
    VSPLocalCopyGroupReconciler,
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
class VSPLocalCopyGroupManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPLocalCopyGroupArguments().local_copy_group_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.module = AnsibleModule(
                argument_spec=self.argument_spec,
                supports_check_mode=False,
                # can be added mandotary , optional mandatory arguments
            )
            # self.secondary_connection_info = (
            #     self.params_manager.get_secondary_connection_info()
            # )
            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            # self.storage_serial_number = self.params_manager.get_serial()
            self.spec = self.params_manager.get_local_copy_group_spec()
            self.state = self.params_manager.get_state()

        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Remote Copy Group operation ===")
        registration_message = validate_ansible_product_registration()
        try:

            data = self.local_copy_group_module()

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of Remote Copy Group operation ===")
            self.module.fail_json(msg=str(e))

        msg = data if isinstance(data, str) else self.get_message()
        data = data if not isinstance(data, str) else {"local_copy_group_info": {}}

        # if self.state == "split":
        #     if self.spec.is_svol_writable is not None:
        #         data["is_svol_writable"] = self.spec.is_svol_writable
        #     if self.spec.do_data_suspend is not None:
        #         data["do_data_suspend"] = self.spec.do_data_suspend
        #     if self.spec.do_pvol_write_protect is not None:
        #         data["do_pvol_write_protect"] = self.spec.do_pvol_write_protect

        if self.state == "absent":
            resp = {
                "changed": self.connection_info.changed,
                "local_copy_group_info": {},
                "msg": msg,
            }
        else:
            resp = {
                "changed": self.connection_info.changed,
                "local_copy_group_info": data,
                "msg": msg,
            }
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Remote Copy Group operation ===")
        self.module.exit_json(**resp)

    def local_copy_group_module(self):
        reconciler = VSPLocalCopyGroupReconciler(
            self.connection_info,
            self.state,
            # self.secondary_connection_info,
        )
        # if self.connection_info.connection_type == ConnectionTypes.GATEWAY:
        #     found = reconciler.check_storage_in_ucpsystem()
        #     if not found:
        #         raise ValueError(ModuleMessage.STORAGE_SYSTEM_ONBOARDING.value)

        result = reconciler.local_copy_group_reconcile_direct(
            self.state, self.spec  # , self.secondary_connection_info
        )
        result = (
            result if not isinstance(result, str) and result is not None else result
        )
        return result

    def get_message(self):

        if self.state == "absent":
            return "Shadow Image Group deleted successfully."
        elif self.state == "resync" or self.state == "sync":
            return "Shadow Image Group resynced successfully."
        elif self.state == "split" and self.spec.should_force_split is None:
            return "Shadow Image Group split successfully."
        elif self.state == "split" and self.spec.should_force_split is not None:
            return "Shadow Image Group migration cancelled successfully."
        elif self.state == "restore":
            return "Shadow Image Group restored successfully."
        elif self.state == "migrate":
            return "Shadow Image Group migrated successfully."
        else:
            return "Unknown state provided."


def main():
    """
    :return: None
    """
    obj_store = VSPLocalCopyGroupManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
