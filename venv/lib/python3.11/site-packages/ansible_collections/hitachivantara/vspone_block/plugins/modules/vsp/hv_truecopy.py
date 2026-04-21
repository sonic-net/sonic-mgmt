#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_truecopy
short_description: Manages TrueCopy pairs on Hitachi VSP storage systems.
description:
  - This module allows for the creation, deletion, splitting, re-syncing and resizing of TrueCopy pairs.
  - It also allows swap-splitting and swap-resyncing operations of TrueCopy pairs.
  - It supports various TrueCopy pairs operations based on the specified task level..
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/truecopy.yml)
version_added: '3.1.0'
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
notes:
  - The output parameters C(entitlement_status), C(subscriber_id), and C(partner_id) were removed in version 3.4.0.
    They were also deprecated due to internal API simplification and are no longer supported.
options:
  state:
    description:
      - The level of the TrueCopy pairs task.
      - C(present) is used to create or update a TrueCopy pair.
      - C(absent) is used to delete a TrueCopy pair.
      - C(expand) or C(resize) is used to expand the size of the volumes of a TrueCopy pair.
      - C(resync) is used to re-sync a TrueCopy pair.
      - C(split) is used to split a TrueCopy pair.
      - C(swap-split) is used to swap-split a TrueCopy pair.
      - C(swap-resync) is used to swap-resync a TrueCopy pair.
    type: str
    required: false
    choices: ['present', 'absent', 'split', 'resync', 'resize', 'expand', 'swap_split', 'swap_resync']
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
    required: false
    type: dict
    suboptions:
      address:
        description:
          - IP address or hostname of the Hitachi storage system.
        type: str
        required: true
      username:
        description: Username for authentication. This is a required field if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication.This is a required field if api_token is not provided.
        type: str
        required: false
      api_token:
        description: This field is used to pass the value of the lock token of the secondary storage to operate on locked resources.
        type: str
        required: false
  spec:
    description: Specification for the TrueCopy pairs task.
    type: dict
    required: false
    suboptions:
      copy_group_name:
        description: Name of the copy group. This is a required field for create operation.
          For other operations, this field is optional, but when provided, the time to complete the operation is faster.
        type: str
        required: false
      copy_pair_name:
        description: Name of the copy pair. This is a required field for create operation.
          For other operations, this field is optional, but when provided, the time to complete the operation is faster.
        type: str
        required: false
      remote_device_group_name:
        description: Name of the remote device group. This is an optional field.
        type: str
        required: false
      local_device_group_name:
        description: Name of the local device group. This is an optional field.
        type: str
        required: false
      primary_volume_id:
        description: Primary volume ID. This is a required field for create operation.
        type: str
        required: false
      consistency_group_id:
        description: Consistency Group ID, 0 to 255. This is an optional field.
        type: int
        required: false
      fence_level:
        description: Specifies the primary volume fence level setting and determines if the host is denied access or continues to access
            the primary volume when the pair is suspended because of an error. This is an optional field.
        type: str
        required: false
        choices: ['NEVER', 'DATA', 'STATUS']
        default: 'NEVER'
      secondary_pool_id:
        description: ID of the dynamic pool where the secondary volume will be created.
        type: int
        required: false
      provisioned_secondary_volume_id:
        description: ID of the provisioned secondary volume that you want to use for the true copy creation.
        type: str
        required: false
      begin_secondary_volume_id:
        description: >
          Specify beginning ldev id for LDEV range for svol. This is an optional field during create operation.
          If this field is specified, end_secondary_volume_id must also be specified.
          If this field is not specified, Ansible modules will try to create SVOL ID same as the PVOL ID if available,
          otherwise it will use the first available LDEV ID.
        required: false
        type: str
      end_secondary_volume_id:
        description: >
          Specify end ldev id for LDEV range for svol. This is an optional field during create operation.
          If this field is specified, begin_secondary_volume_id must also be specified.
          If this field is not specified, Ansible modules will try to create SVOL ID same as PVOL ID iff available,
          otherwise it will use the first available LDEV ID.
        required: false
        type: str
      copy_pace:
        description: Copy speed.
        type: str
        required: false
        choices: ['SLOW', 'MEDIUM', 'FAST']
        default: 'MEDIUM'
      is_svol_readwriteable:
        description: It is applicable for split pair operation only. If true, the secondary volume will be read-writeable after split.
        type: bool
        required: false
        default: false
      secondary_hostgroup:
        description: Host group details of the secondary volume.
        type: dict
        required: false
        suboptions:
          name:
            description: Name of the host group on the secondary storage system. This is required for create operation.
            type: str
            required: true
          port:
            description: Port of the host group on the secondary storage system. This is required for create operation.
            type: str
            required: true
          lun_id:
            description: LUN ID of the host group on the secondary storage system. This is not required for create operation.
            type: int
            required: false
      secondary_hostgroups:
        description: List of hostgroup objects for the secondary volume.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: Name of the host group on the secondary storage system. This is required for create operation.
            type: str
            required: true
          port:
            description: Port of the host group on the secondary storage system. This is required for create operation.
            type: str
            required: true
          lun_id:
            description: LUN ID of the host group on the secondary storage system. This is not required for create operation.
            type: int
            required: false
      secondary_iscsi_targets:
        description: The list of iscsi targets on the secondary storage device.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: ISCSI target name.
            type: str
            required: true
          port:
            description: Port name.
            type: str
            required: true
          lun_id:
            description: LUN ID.
            type: int
            required: false
      secondary_nvm_subsystem:
        description: NVM subsystem details of the secondary volume.
        type: dict
        required: false
        suboptions:
          name:
            description: Name of the NVM subsystem on the secondary storage system.
            type: str
            required: true
          paths:
            description: Host NQN paths information on the secondary storage system.
            type: list
            elements: str
            required: false
      do_initial_copy:
        description: Perform initial copy. This is an optional field during create operation.
        type: bool
        required: false
        default: true
      is_data_reduction_force_copy:
        description: Force copy for data reduction. This is an optional field during create operation.
        type: bool
        required: false
        default: false
      is_new_group_creation:
        description: Create a new copy group. This is an optional field during create operation.
        type: bool
        required: false
        default: false
      path_group_id:
        description: >
          This is an optional field during create operation.
          Specify the path group ID in the range from 0 to 255. If you are unsure don't use this parameter.
          If you omit this value or specify 0, the lowest path group ID in the specified path group is used.
        type: int
        required: false
      new_volume_size:
        description: Required only for resize or expand operation. Value should be grater than the current volume size.
        type: str
        required: false
      is_consistency_group:
        description: >
          This is an optional field during create operation.
          Depending on the value, this attribute specifies whether to register the new pair in a consistency group.
          If true, the new pair is registered in a consistency group. If false, the new pair is not registered in a consistency group.
        type: bool
        required: false
        default: false
      should_delete_svol:
        description: Specify true to delete the SVOL.
        type: bool
        required: false
        default: false
"""

EXAMPLES = """
- name: Create a TrueCopy pair
  hitachivantara.vspone_block.vsp.hv_truecopy:
    state: "present"
    connection_info:
      address: 172.1.1.126
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: 172.1.1.127
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"
      primary_volume_id: 11
      is_consistency_group: true
      fence_level: 'NEVER'
      secondary_pool_id: 1
      secondary_hostgroup:
        name: ansible_test_group
        port: CL1-A
        lun_id: 1

- name: Split a TrueCopy pair
  hitachivantara.vspone_block.vsp.hv_truecopy:
    state: "split"
    connection_info:
      address: 172.1.1.126
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: 172.1.1.127
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"

- name: Resync a TrueCopy pair
  hitachivantara.vspone_block.vsp.hv_truecopy:
    state: "resync"
    connection_info:
      address: 172.1.1.126
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: 172.1.1.127
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"

- name: Swap-split a TrueCopy pair
  hitachivantara.vspone_block.vsp.hv_truecopy:
    state: "swap_split"
    connection_info:
      address: 172.1.1.127
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: 172.1.1.126
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"

- name: Swap-resync a TrueCopy pair
  hitachivantara.vspone_block.vsp.hv_truecopy:
    state: "swap_resync"
    connection_info:
      address: 172.1.1.127
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: 172.1.1.126
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"

- name: Delete a TrueCopy pair
  hitachivantara.vspone_block.vsp.hv_truecopy:
    state: "swap_resync"
    connection_info:
      address: 172.1.1.126
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: 172.1.1.127
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"

- name: Increase the size of the volumes of a TrueCopy pair
  hitachivantara.vspone_block.vsp.hv_truecopy:
    state: "expand"
    connection_info:
      address: 172.1.1.126
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: 172.1.1.127
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"
      new_volume_size: 4GB
"""

RETURN = r"""
truecopy_info:
  description: List of TrueCopy pair objects returned by the module.
  returned: success
  type: list
  elements: dict
  contains:
    consistency_group_id:
      description: Consistency Group ID.
      type: int
      sample: -1
    copy_group_name:
      description: Name of the copy group.
      type: str
      sample: "ESD_TC_CG"
    copy_pair_name:
      description: Name of the copy pair.
      type: str
      sample: "ESD_TC_CP"
    copy_progress_rate:
      description: Copy progress rate.
      type: int
      sample: -1
    fence_level:
      description: Fence level.
      type: str
      sample: "NEVER"
    primary_volume_id:
      description: Primary volume ID.
      type: int
      sample: 11
    primary_volume_id_hex:
      description: Primary volume ID in hex format.
      type: str
      sample: "00:00:0B"
    pvol_status:
      description: PVOL status.
      type: str
      sample: "PAIR"
    pvol_storage_device_id:
      description: PVOL storage device ID.
      type: str
      sample: "A00000970041"
    remote_mirror_copy_pair_id:
      description: Remote mirror copy pair ID.
      type: str
      sample: "A00000970045,ESD_TC_CG,ESD_TC_CGP_,ESD_TC_CGS_,ESD_TC_CP"
    secondary_volume_id:
      description: Secondary volume ID.
      type: int
      sample: 11
    secondary_volume_id_hex:
      description: Secondary volume ID in hex format.
      type: str
      sample: "00:00:0B"
    storage_serial_number:
      description: Storage serial number.
      type: str
      sample: "70041"
    svol_status:
      description: SVOL status.
      type: str
      sample: "PAIR"
    svol_storage_device_id:
      description: SVOL storage device ID.
      type: str
      sample: "A00000970045"
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPTrueCopyArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_true_copy import (
    VSPTrueCopyReconciler,
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
class VSPSTrueCopyManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPTrueCopyArguments().true_copy()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.connection_info
            self.storage_serial_number = self.params_manager.storage_system_info.serial
            self.spec = self.params_manager.true_cpoy_spec()
            self.state = self.params_manager.get_state()
            self.secondary_connection_info = (
                self.params_manager.get_secondary_connection_info()
            )
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of TrueCopy operation. ===")
        data = None
        registration_message = validate_ansible_product_registration()

        self.logger.writeDebug("state = {}", self.state)
        try:
            data = self.true_copy_module()

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of TrueCopy operation. ===")
            self.module.fail_json(msg=str(e))

        resp = {
            "changed": self.connection_info.changed,
            # "truecopy_info": data,
            # "msg": self.get_message(),
        }

        if data is not None and isinstance(data, list) or isinstance(data, dict):
            resp["truecopy_info"] = data

        if data is not None and isinstance(data, str):
            resp["msg"] = data
        else:
            resp["msg"] = self.get_message()

        if registration_message:
            resp["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of TrueCopy operation. ===")
        self.module.exit_json(**resp)

    def true_copy_module(self):
        reconciler = VSPTrueCopyReconciler(
            self.connection_info,
            self.storage_serial_number,
            self.state,
            self.secondary_connection_info,
        )
        return reconciler.reconcile_true_copy(self.spec)

    def get_message(self):

        if self.state == "present":
            return "TrueCopy Pair created successfully."
        elif self.state == "absent":
            if self.spec.should_delete_svol is True:
                return "TrueCopy Pair and Secondary volume deleted successfully."
            else:
                return "TrueCopy Pair deleted successfully."
        elif self.state == "resize" or self.state == "expand":
            return "TrueCopy Pair expanded successfully."
        elif self.state == "resync":
            return "TrueCopy Pair resynced successfully."
        elif self.state == "split":
            return "TrueCopy Pair split successfully."
        elif self.state == "swap_split":
            return "TrueCopy Pair swap_split successfully."
        elif self.state == "swap_resync":
            return "TrueCopy Pair swap_resynced successfully."
        else:
            return "Unknown state provided."


def main(module=None):
    """
    :return: None
    """
    obj_store = VSPSTrueCopyManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
