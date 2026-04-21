#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_remote_copy_group
short_description: Manages Remote Copy Group on Hitachi VSP storage systems.
description: >
  - This module allows for the splitting, swap-splitting, re-syncing, swap-resyncing, takeover and deletion of Remote Copy Group on Hitachi VSP storage systems.
  - It supports various remote copy pairs operations based on the specified task level.
  - The module supports the following replication types: HUR, TC, GAD.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/remote_copy_group.yml)
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
    description: >
      - The level of the Remote Copy Group pairs task.
      - Choices are C(present), C(absent), C(split), C(resync), C(swap_split), C(swap_resync), C(takeover).
    type: str
    required: false
    choices: ['present', 'absent', 'split', 'resync', 'swap_split', 'swap_resync', 'takeover']
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
  secondary_connection_info:
    description: Information required to establish a connection to the secondary storage system.
    required: true
    type: dict
    suboptions:
      address:
        description: IP address or hostname of the secondary storage system.
        type: str
        required: true
      username:
        description: Username for authentication for secondary storage. This is a required field if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication for secondary storage. This is a required field if api_token is not provided.
        type: str
        required: false
      api_token:
        description: Value of the lock token to operate on locked resources.
        type: str
        required: false
  spec:
    description: Specification for the Remote Copy Group task.
    type: dict
    required: true
    suboptions:
      copy_group_name:
        description: Copy group name, required for all operations.
          Required for the Split remote copy group for HUR
          /Split remote copy group for TC
          /Split Remote Copy Group for GAD
          /Resync Remote Copy Group for HUR
          /Resync Remote Copy Group for TC
          /Resync Remote Copy Group for GAD
          /Swap-Split Remote Copy Group for all replication types [HUR, TC, GAD]
          /Swap-Resync Remote Copy Group for HUR
          /Swap-Resync Remote Copy Group for TC
          /Swap-Resync Remote Copy Group for GAD
          /Delete remote copy group
          /Takeover Remote Copy Group for HUR replication type tasks.
        type: str
        required: true
      replication_type:
        description: Replication type, either C(UR), C(TC) or C(GAD).
          Optional for the Split remote copy group for HUR
          /Split remote copy group for TC
          /Resync Remote Copy Group for HUR
          /Resync Remote Copy Group for TC
          /Swap-Split Remote Copy Group for all replication types [HUR, TC, GAD]
          /Swap-Resync Remote Copy Group for HUR
          /Swap-Resync Remote Copy Group for TC
          /Takeover Remote Copy Group for HUR replication type tasks.
          Required for the Split Remote Copy Group for GAD
          /Resync Remote Copy Group for GAD
          /Swap-Resync Remote Copy Group for GAD tasks.
        type: str
        required: false
        choices: ['TC', 'UR', 'GAD', 'HUR']
      is_svol_writable:
        description: Whether svol is writable or not.
          Optional for the Split remote copy group for HUR
          /Split remote copy group for TC tasks.
        type: bool
        required: false
      do_pvol_write_protect:
        description: For TC, specify whether to forcibly disable write operations for the P-VOL.
          Optional for the Split remote copy group for HUR
          /Split remote copy group for TC tasks.
        type: bool
        required: false
      do_data_suspend:
        description: For UR, specify whether to forcibly stop operations on a journal when the amount of access to the journal increases.
          Optional for the Split remote copy group for HUR task.
        type: bool
        required: false
      local_device_group_name:
        description: Device group name in the local storage system.
          Optional for the Split remote copy group for HUR
          /Split Remote Copy Group for GAD
          /Resync Remote Copy Group for HUR
          /Resync Remote Copy Group for TC
          /Resync Remote Copy Group for GAD
          /Swap-Split Remote Copy Group for all replication types [HUR, TC, GAD]
          /Swap-Resync Remote Copy Group for HUR
          /Swap-Resync Remote Copy Group for TC
          /Swap-Resync Remote Copy Group for GAD
          /Delete remote copy group tasks.
          Required for the Split remote copy group for TC task.
        type: str
        required: false
      svol_operation_mode:
        description: Specify this attribute to forcibly change the status of the pairs of the S-VOL in cases such as if a failure occurs
          in the storage system of the primary site.
        type: str
        required: false
      remote_device_group_name:
        description: Device group name in the remote storage system.
          Optional for the Split remote copy group for HUR
          /Split remote copy group for TC
          /Split Remote Copy Group for GAD
          /Resync Remote Copy Group for HUR
          /Resync Remote Copy Group for TC
          /Resync Remote Copy Group for GAD
          /Swap-Split Remote Copy Group for all replication types [HUR, TC, GAD]
          /Swap-Resync Remote Copy Group for HUR
          /Swap-Resync Remote Copy Group for TC
          /Swap-Resync Remote Copy Group for GAD
          /Delete remote copy group tasks.
          Required for the Takeover Remote Copy Group for HUR replication type task.
        type: str
        required: false
      is_consistency_group:
        description:
          - For TC, specify the value as follows according to whether the pair is registered in a consistency group.
          - If the pair is not registered in a consistency group
          - true - Registers the pair in a consistency group.
          - false - Leaves the pair as it is without registering it in a consistency group.
          - If the pair is registered in a consistency group
          - true - Leaves the pair registered in a consistency group.
          - false - Cancels the registration of the pair in a consistency group, and places it in an unregistered state.
          - Optional for the Resync Remote Copy Group for TC
          - /Resync Remote Copy Group for GAD
          - /Swap-Resync Remote Copy Group for TC
          - /Swap-Resync Remote Copy Group for GAD tasks.
        type: bool
        required: false
      consistency_group_id:
        description: For TC, specify the consistency group ID by using a decimal number in the range from 0 to 255.
          Optional for the Resync Remote Copy Group for TC
          /Resync Remote Copy Group for GAD
          /Swap-Resync Remote Copy Group for TC
          /Swap-Resync Remote Copy Group for GAD tasks.
        type: int
        required: false
      fence_level:
        description: Specifies the primary volume fence level setting and determines if the host is denied access or continues to access
            the primary volume when the pair is suspended because of an error.
            Optional for the Resync Remote Copy Group for TC task.
        type: str
        required: false
        choices: ['NEVER', 'DATA', 'STATUS']
      copy_pace:
        description: For TC, specify a decimal number in the range from 1 to 15 for the size of tracks to be copied.
          The larger the value you specify, the faster the copy speed.
          Optional for the Resync Remote Copy Group for TC
          /Swap-Resync Remote Copy Group for TC tasks.
        type: int
        required: false
      do_failback:
        description: Specify whether to perform a failback if a failure occurs in a 3DC cascade configuration.
          If set to true, the failback is performed. If set to false, the failback is not performed.
          If the value is omitted, false is assumed.
        type: bool
        required: false
        default: false
      failback_mirror_unit_number:
        description: Specify the MU (mirror unit) number of the volume to be failed back.
          You can specify this attribute only if the do_failback attribute is set to true.
        type: int
        required: false
"""

EXAMPLES = """
- name: Split remote copy group for HUR
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: split
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: hur
      is_svol_writable: false
      do_data_suspend: false

- name: Resync remote copy group for HUR
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: resync
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: hur

- name: Swap split remote copy group for HUR
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: swap_split
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: hur

- name: Swap resync remote copy group for HUR
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: swap_resync
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: hur

- name: Delete remote copy group for HUR
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1

- name: Split remote copy group for TrueCopy
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: split
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: TC
      is_svol_writable: false
      do_pvol_write_protect: false

- name: Resync remote copy group for TrueCopy
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: resync
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: TC
      is_consistency_group: true
      consistency_group_id: 47
      fence_level: NEVER
      copy_pace: 3

- name: Swap split remote copy group for TrueCopy
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: swap_split
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: TC

- name: Swap resync remote copy group for TrueCopy
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: swap_resync
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: TC

- name: Delete remote copy group for TrueCopy
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1

- name: Split remote copy group for GAD
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: split
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: GAD

- name: Resync remote copy group for GAD
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: resync
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: GAD
      is_consistency_group: true
      consistency_group_id: 47

- name: Swap split remote copy group for GAD
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: swap_split
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: GAD

- name: Swap resync remote copy group for GAD
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: swap_resync
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      remote_device_group_name: remote_copy_group_remote_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: GAD

- name: Delete remote copy group for GAD
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: absent
    spec:
      copy_group_name: remote_copy_group_copy_group_name_1

- name: Takeover remote copy group for HUR
  hitachivantara.vspone_block.vsp.hv_remote_copy_group:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: takeover
    spec:
      local_device_group_name: remote_copy_group_local_device_group_name_1
      copy_group_name: remote_copy_group_copy_group_name_1
      replication_type: hur
"""

RETURN = """
remote_copy_group_info:
  description: Newly created remote copy group object.
  returned: success
  type: dict
  contains:
    copy_group_name:
      description: Copy group name.
      type: str
      sample: "copygroupname001"
    copy_pairs:
      description: List of copy pairs in the copy group.
      type: list
      elements: dict
      contains:
        consistency_group_id:
          description: Consistency group ID.
          type: int
          sample: 51
        copy_group_name:
          description: Copy group name.
          type: str
          sample: "copygroupname001"
        copy_pair_name:
          description: Copy pair name.
          type: str
          sample: "copypairname00190"
        fence_level:
          description: Fence level.
          type: str
          sample: "ASYNC"
        pvol_difference_data_management:
          description: PVOL difference data management.
          type: str
          sample: "S"
        pvol_i_o_mode:
          description: PVOL I/O mode.
          type: str
          sample: null
        pvol_journal_id:
          description: PVOL journal ID.
          type: int
          sample: 37
        pvol_ldev_id:
          description: PVOL LDEV ID.
          type: int
          sample: 1872
        pvol_processing_status:
          description: PVOL processing status.
          type: str
          sample: "N"
        pvol_status:
          description: PVOL status.
          type: str
          sample: "PSUS"
        pvol_storage_device_id:
          description: PVOL storage device ID.
          type: str
          sample: "900000040014"
        quorum_disk_id:
          description: Quorum disk ID.
          type: str
          sample: null
        remote_mirror_copy_pair_id:
          description: Remote mirror copy pair ID.
          type: str
          sample: "900000040015,copygroupname001,copygroupname001P_,copygroupname001S_,copypairname00190"
        replication_type:
          description: Replication type.
          type: str
          sample: "UR"
        svol_difference_data_management:
          description: SVOL difference data management.
          type: str
          sample: "S"
        svol_i_o_mode:
          description: SVOL I/O mode.
          type: str
          sample: null
        svol_journal_id:
          description: SVOL journal ID.
          type: int
          sample: 40
        svol_ldev_id:
          description: SVOL LDEV ID.
          type: int
          sample: 2180
        svol_processing_status:
          description: SVOL processing status.
          type: str
          sample: "N"
        svol_status:
          description: SVOL status.
          type: str
          sample: "SSUS"
        svol_storage_device_id:
          description: SVOL storage device ID.
          type: str
          sample: "900000040015"
    local_device_group_name:
      description: Local device group name.
      type: str
      sample: "copygroupname001P_"
    remote_device_group_name:
      description: Remote device group name.
      type: str
      sample: "copygroupname001S_"
    remote_mirror_copy_group_id:
      description: Remote mirror copy group ID.
      type: str
      sample: "900000040015,copygroupname001,copygroupname001P_,copygroupname001S_"
    remote_storage_device_id:
      description: Remote storage device ID.
      type: str
      sample: "900000040015"
    mu_number:
      description: MU number.
      type: int
      sample: 1
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPRemoteCopyGroupArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_copy_groups import (
    VSPCopyGroupsReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log_decorator import (
    LogDecorator,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    camel_dict_to_snake_case,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


@LogDecorator.debug_methods
class VSPCopyGroupManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPRemoteCopyGroupArguments().get_copy_group_args()
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
            self.secondary_connection_info = (
                self.params_manager.get_secondary_connection_info()
            )
            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = self.params_manager.get_serial()
            self.spec = self.params_manager.copy_group_spec()
            self.state = self.params_manager.get_state()

        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Remote Copy Group operation ===")
        registration_message = validate_ansible_product_registration()
        try:

            data = self.copy_group_module()

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of Remote Copy Group operation ===")
            self.module.fail_json(msg=str(e))

        msg = data if isinstance(data, str) else self.get_message()
        data = data if not isinstance(data, str) else {"remote_copy_group_info": {}}

        if self.state == "split":
            if self.spec.is_svol_writable is not None:
                data["is_svol_writable"] = self.spec.is_svol_writable
            if self.spec.do_data_suspend is not None:
                data["do_data_suspend"] = self.spec.do_data_suspend
            if self.spec.do_pvol_write_protect is not None:
                data["do_pvol_write_protect"] = self.spec.do_pvol_write_protect

        if self.state == "absent":
            resp = {
                "changed": self.connection_info.changed,
                "remote_copy_group_info": {},
                "msg": msg,
            }
        else:
            resp = {
                "changed": self.connection_info.changed,
                "remote_copy_group_info": data,
                "msg": msg,
            }
        if registration_message:
            resp["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of Remote Copy Group operation ===")
        self.module.exit_json(**resp)

    def copy_group_module(self):
        reconciler = VSPCopyGroupsReconciler(
            self.connection_info,
            self.storage_serial_number,
            self.state,
            self.secondary_connection_info,
        )

        result = reconciler.copy_group_reconcile_direct(
            self.state, self.spec, self.secondary_connection_info
        )
        result = (
            camel_dict_to_snake_case(result)
            if not isinstance(result, str) and result is not None
            else result
        )
        return result

    def get_message(self):

        if self.state == "absent":
            return "Copy Group deleted successfully."
        elif self.state == "resync":
            return "Copy Group  resynced successfully."
        elif self.state == "split":
            return "Copy Group  split successfully."
        elif self.state == "swap_split":
            return "Copy Group  swapped split successfully."
        elif self.state == "swap_resync":
            return "Copy Group  swapped resynced successfully"
        elif self.state == "takeover":
            return "HUR Copy Group takeover done successfully."
        else:
            return "Unknown state provided."


def main():
    """
    :return: None
    """
    obj_store = VSPCopyGroupManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
