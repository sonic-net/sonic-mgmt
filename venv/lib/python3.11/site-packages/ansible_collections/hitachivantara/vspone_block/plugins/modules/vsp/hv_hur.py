#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_hur
short_description: Manages HUR pairs on Hitachi VSP storage systems.
description:
  - This module allows for the creation, deletion, splitting, swap splitting, re-syncing and swap-resyncing of HUR pairs on Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/hur.yml)
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
    These were deprecated due to internal API simplification and are no longer supported.
options:
  state:
    description: The level of the HUR pairs task.
    type: str
    required: false
    choices: ['present', 'absent', 'split', 'resync', 'resize', 'expand', 'swap_split', 'swap_resync', 'takeover']
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
    description: Specification for the HUR pairs task.
    type: dict
    required: true
    suboptions:
      primary_volume_id:
        description: Primary volume id. Required for the Create HUR pair in new copy group
          /Create HUR pair with existing copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Create HUR pair with provisioned_secondary_volume_id
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
        type: str
        required: false
      primary_volume_journal_id:
        description: Primary volume journal id. Required for the Create HUR pair in new copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-ISCSI pair
          /Create HUR pair with provisioned_secondary_volume_id
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
          Optional for the Create HUR-NVMe pair task.
        type: int
        required: false
      secondary_volume_journal_id:
        description: Secondary volume journal id. Required for the Create HUR pair in new copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-ISCSI pair
          /Create HUR pair with provisioned_secondary_volume_id
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
          Optional for the Create HUR-NVMe pair task.
        type: int
        required: false
      copy_group_name:
        description: Name of the copy group. Required for the Create HUR pair in new copy group
          /Create HUR pair with existing copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Create HUR pair with provisioned_secondary_volume_id
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups
          /Split HUR pair
          /Resync HUR pair
          /Swap-Split HUR pair
          /Swap-Resync HUR pair
          /Delete HUR pair
          /Expand HUR pair
          /Secondary volume takeover HUR pair
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
        type: str
        required: false
      copy_pair_name:
        description: Name of the copy pair. Required for the Create HUR pair in new copy group
          /Create HUR pair with existing copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Create HUR pair with provisioned_secondary_volume_id
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups
          /Split HUR pair
          /Resync HUR pair
          /Swap-Split HUR pair
          /Swap-Resync HUR pair
          /Delete HUR pair
          /Expand HUR pair
          /Secondary volume takeover HUR pair
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
        type: str
        required: false
      consistency_group_id:
        description: Consistency group ID. Optional for the Create HUR pair in new copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
        type: int
        required: false
      local_device_group_name:
        description: Name of the local device group name.
          Optional for the Create HUR pair in new copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Split HUR pair
          /Resync HUR pair
          /Swap-Split HUR pair
          /Swap-Resync HUR pair
          /Delete HUR pair
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
        type: str
        required: false
      remote_device_group_name:
        description: Name of the remote device group name.
          Optional for the Create HUR pair in new copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Split HUR pair
          /Resync HUR pair
          /Swap-Split HUR pair
          /Swap-Resync HUR pair
          /Delete HUR pair
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
          Required for the Secondary volume takeover HUR pair task.
        type: str
        required: false
      mirror_unit_id:
        description: Mirror Unit Id.
          Optional for the Create HUR pair in new copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Create HUR pair with provisioned_secondary_volume_id
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
        type: int
        choices: [0, 1, 2, 3]
        required: false
      secondary_pool_id:
        description: Id of dynamic pool on the secondary storage where the secondary volume will be created.
          Required for the Create HUR pair in new copy group
          /Create HUR pair with existing copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair
          /Create HUR pair and debug result
          /Create HUR-iSCSI pair and debug result
          /Create HUR-NVMe pair and debug result tasks.
        type: int
        required: false
      secondary_hostgroup:
        description: Host group details of secondary volume.
          Required for the Create HUR pair in new copy group
          /Create HUR pair with existing copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups tasks.
          Optional for the Create HUR pair and debug result task.
        type: dict
        required: false
        suboptions:
          name:
            description: Name of the host group on the secondary storage system.
              Required for the Create HUR pair in new copy group
              /Create HUR pair with existing copy group
              /Create a HUR pair using a range for secondary volume ID
              /Create HUR pair with provisioned_secondary_volume_id and hostgroups
              /Create HUR pair and debug result tasks.
            type: str
            required: true
          port:
            description: Port of the host group on the secondary storage system.
              Required for the Create HUR pair in new copy group
              /Create HUR pair with existing copy group
              /Create a HUR pair using a range for secondary volume ID
              /Create HUR pair with provisioned_secondary_volume_id and hostgroups
              /Create HUR pair and debug result tasks.
            type: str
            required: true
          lun_id:
            description: LUN ID can be provided along with host group on the secondary storage system.
              Optional for the Create HUR pair in new copy group
              /Create HUR pair with existing copy group tasks.
              Required for the Create HUR pair with provisioned_secondary_volume_id and hostgroups task.
            type: int
            required: false
      secondary_hostgroups:
        description: List of hostgroup objects for the secondary volume.
          Required for the Create HUR pair in new copy group
          /Create HUR pair with existing copy group
          /Create a HUR pair using a range for secondary volume ID
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups tasks.
          Optional for the Create HUR pair and debug result task.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: Name of the host group on the secondary storage system.
              Required for the Create HUR pair in new copy group
              /Create HUR pair with existing copy group
              /Create a HUR pair using a range for secondary volume ID
              /Create HUR pair with provisioned_secondary_volume_id and hostgroups
              /Create HUR pair and debug result tasks.
            type: str
            required: true
          port:
            description: Port of the host group on the secondary storage system.
              Required for the Create HUR pair in new copy group
              /Create HUR pair with existing copy group
              /Create a HUR pair using a range for secondary volume ID
              /Create HUR pair with provisioned_secondary_volume_id and hostgroups
              /Create HUR pair and debug result tasks.
            type: str
            required: true
          lun_id:
            description: LUN ID of the host group on the secondary storage system.
              Optional for the Create HUR pair in new copy group
              /Create HUR pair with existing copy group tasks.
              Required for the Create HUR pair with provisioned_secondary_volume_id and hostgroups task.
            type: int
            required: false
      secondary_iscsi_targets:
        description: The list of iscsi targets on the secondary storage device.
          Required for the Create HUR-ISCSI pair task.
          Optional for the Create HUR-iSCSI pair and debug result task.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: ISCSI target name. Required for the Create HUR-ISCSI pair
              /Create HUR-iSCSI pair and debug result tasks.
            type: str
            required: true
          port:
            description: Port name. Required for the Create HUR-ISCSI pair
              /Create HUR-iSCSI pair and debug result tasks.
            type: str
            required: true
          lun_id:
            description: LUN ID. Required for the Create HUR-ISCSI pair
              /Create HUR-iSCSI pair and debug result tasks.
            type: int
            required: false
      secondary_nvm_subsystem:
        description: NVM subsystem details of the secondary volume.
          Required for the Create HUR-NVMe pair task.
          Optional for the Create HUR-NVMe pair and debug result task.
        type: dict
        required: false
        suboptions:
          name:
            description: Name of the NVM subsystem on the secondary storage system.
              Required for the Create HUR-NVMe pai
              /Create HUR-NVMe pair and debug result tasks.
            type: str
            required: true
          paths:
            description: Host NQN paths information on the secondary storage system.
              Required for the Create HUR-NVMe pair
              /Create HUR-NVMe pair and debug result tasks.
            type: list
            elements: str
            required: false
      fence_level:
        description: Specifies the primary volume fence level setting and determines if the host is denied access or continues to access
            the primary volume when the pair is suspended because of an error. This is an optional field.
        type: str
        required: false
        choices: ['ASYNC']
        default: 'ASYNC'
      allocate_new_consistency_group:
        description: Specify whether to allocate a new consistency group.
        type: bool
        required: false
        default: false
      enable_delta_resync:
        description: Specify whether to enable delta resync.
        type: bool
        required: false
        default: false
      is_consistency_group:
        description: Specify whether to enable consistency group.
        type: bool
        required: false
        default: false
      do_delta_resync_suspend:
        description: Specify whether to enable delta resync suspend.
        type: bool
        required: false
      is_new_group_creation:
        description: Specify whether to enable new group creation.
        type: bool
        required: false
      is_svol_readwriteable:
        description: Specify whether to enable secondary volume read writeable.
          Optional for Split HUR pair task.
        type: bool
        required: false
      secondary_storage_serial_number:
        description: Secondary storage serial number.
        type: int
        required: false
      path_group_id:
        description: >
          Optional for the Create HUR pair in new copy group
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair tasks.
          Specify the path group ID in the range from 0 to 255. If you are unsure don't use this parameter.
          If you omit this value or specify 0, the lowest path group ID in the specified path group is used.
        type: int
        required: false
      new_volume_size:
        description: New volume size. Required for the Expand HUR pair task.
        type: str
        required: false
      provisioned_secondary_volume_id:
        description: ID of the provisioned secondary volume that you want to use for the HUR pair creation.
          Required for the Create HUR pair with provisioned_secondary_volume_id
          /Create HUR pair with provisioned_secondary_volume_id and hostgroups tasks.
        type: str
        required: false
      begin_secondary_volume_id:
        description: >
          Specify beginning ldev id for LDEV range for svol.
          Required for the Create a HUR pair using a range for secondary volume ID task.
          If this field is specified, end_secondary_volume_id must also be specified.
          If this field is not specified, Ansible modules will try to create SVOL ID same as the PVOL ID if available,
          otherwise it will use the first available LDEV ID.
        required: false
        type: str
      end_secondary_volume_id:
        description: >
          Specify end ldev id for LDEV range for svol.
          Required for the Create a HUR pair using a range for secondary volume ID task.
          If this field is specified, begin_secondary_volume_id must also be specified.
          If this field is not specified, Ansible modules will try to create SVOL ID same as PVOL ID iff available,
          otherwise it will use the first available LDEV ID.
        required: false
        type: str
      do_initial_copy:
        description: Perform initial copy. This is an optional field during create operation.
        type: bool
        required: false
        default: true
      is_data_reduction_force_copy:
        description: Force copy for data reduction.
          Optional for the Create HUR pair in new copy group
          /Create HUR-NVMe pair
          /Create HUR-ISCSI pair tasks.
        type: bool
        required: false
        default: false
      should_delete_svol:
        description: Specify true to delete the SVOL. Optional for the Delete HUR pair task.
        type: bool
        required: false
        default: false
"""

EXAMPLES = """
- name: Create a HUR pair in new copy group
  hitachivantara.vspone_block.vsp.hv_hur:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: hur_copy_group_name_1
      copy_pair_name: hur_copy_pair_name_1
      primary_volume_id: 234
      secondary_pool_id: 0
      primary_volume_journal_id: 11
      secondary_volume_journal_id: 12
      local_device_group_name: hur_copy_group_name_1P_
      remote_device_group_name: hur_copy_group_name_1S_
      consistency_group_id: 0
      secondary_hostgroup:
        name: hg_1
        port: CL1-A
        lun_id: 5
      mirror_unit_id: 0

- name: Create a HUR pair in existing copy group
  hitachivantara.vspone_block.vsp.hv_hur:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "hur_copy_group_name_1"
      copy_pair_name: "hur_copy_pair_name_2"
      primary_volume_id: 334
      secondary_pool_id: 0
      secondary_hostgroups:
        - name: hg_1
          port: CL1-A

- name: Split HUR pair
  hitachivantara.vspone_block.vsp.hv_hur:
    state: "split"
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      local_device_group_name: hur_local_device_group_name_3
      remote_device_group_name: hur_remote_device_group_name_3
      copy_group_name: hur_copy_group_name_3
      copy_pair_name: hur_copy_pair_name_3
      is_svol_readwriteable: true

- name: Resync HUR pair
  hitachivantara.vspone_block.vsp.hv_hur:
    state: "resync"
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      local_device_group_name: hur_local_device_group_name_3
      remote_device_group_name: hur_remote_device_group_name_3
      copy_group_name: hur_copy_group_name_3
      copy_pair_name: hur_copy_pair_name_3

- name: Delete HUR pair
  hitachivantara.vspone_block.vsp.hv_hur:
    state: "absent"
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      local_device_group_name: hur_local_device_group_name_3
      remote_device_group_name: hur_remote_device_group_name_3
      copy_group_name: hur_copy_group_name_3
      copy_pair_name: hur_copy_pair_name_3
"""

RETURN = r"""
hur_info:
  description: Newly created HUR pair object.
  returned: success
  type: dict
  contains:
    consistency_group_id:
      description: Consistency group ID.
      type: int
      sample: 51
    copy_group_name:
      description: Name of the copy group.
      type: str
      sample: "snewar_hur_copy_group_12"
    copy_pair_name:
      description: Name of the copy pair.
      type: str
      sample: "snewar_hur_copy_pair_12"
    fence_level:
      description: Fence level setting.
      type: str
      sample: "ASYNC"
    mirror_unit_id:
      description: Mirror unit number.
      type: int
      sample: 1
    primary_journal_pool_id:
      description: Journal ID for primary volume.
      type: int
      sample: 3
    primary_storage_serial:
      description: Storage serial number for primary volume.
      type: str
      sample: "810050"
    primary_volume_difference_data_management:
      description: Difference data management for primary volume.
      type: str
      sample: "D"
    primary_volume_id:
      description: LDEV ID for primary volume.
      type: int
      sample: 6622
    primary_volume_id_hex:
      description: Hexadecimal ID for primary volume.
      type: str
      sample: "00:19:DE"
    primary_volume_processing_status:
      description: Processing status for primary volume.
      type: str
      sample: "N"
    primary_volume_status:
      description: Status of primary volume.
      type: str
      sample: "PAIR"
    primary_volume_storage_device_id:
      description: Storage device ID for primary volume.
      type: str
      sample: "A34000810050"
    remote_mirror_copy_pair_id:
      description: Remote mirror copy pair ID.
      type: str
      sample: "A34000810045,snewar_hur_copy_group_12,snewar_hur_copy_group_12P_,snewar_hur_copy_group_12S_,snewar_hur_copy_pair_12"
    replication_type:
      description: Replication type.
      type: str
      sample: "UR"
    secondary_journal_pool_id:
      description: Journal ID for secondary volume.
      type: int
      sample: 1
    secondary_storage_serial:
      description: Storage serial number for secondary volume.
      type: int
      sample: 810045
    secondary_volume_difference_data_management:
      description: Difference data management for secondary volume.
      type: str
      sample: "D"
    secondary_volume_id:
      description: LDEV ID for secondary volume.
      type: int
      sample: 6623
    secondary_volume_id_hex:
      description: Hexadecimal ID for secondary volume.
      type: str
      sample: "00:19:DF"
    secondary_volume_processing_status:
      description: Processing status for secondary volume.
      type: str
      sample: "N"
    secondary_volume_status:
      description: Status of secondary volume.
      type: str
      sample: "PAIR"
    secondary_volume_storage_device_id:
      description: Storage device ID for secondary volume.
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
class VSPSHurManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPHurArguments().hur()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:

            self.params_manager = VSPParametersManager(self.module.params)
            self.connection_info = self.params_manager.get_connection_info()
            self.secondary_connection_info = (
                self.params_manager.get_secondary_connection_info()
            )
            self.storage_serial_number = self.params_manager.get_serial()
            self.spec = self.params_manager.hur_spec()
            self.state = self.params_manager.get_state()
            if self.secondary_connection_info:
                self.spec.secondary_connection_info = self.secondary_connection_info

        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of HUR operation. ===")

        registration_message = validate_ansible_product_registration()
        try:

            unused, data = self.hur_module()
            if data is None:
                data = []

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of HUR operation. ===")
            self.module.fail_json(msg=str(e))

        # msg = comment
        # if msg is None:
        msg = self.get_message()
        if "already exits in copy group" in data:
            msg = "Please specify unique copy pair name."

        resp = {
            "changed": self.connection_info.changed,
            "hur_info": data,
            "msg": msg,
        }
        if registration_message:
            resp["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{resp}")
        self.logger.writeInfo("=== End of HUR operation. ===")
        self.module.exit_json(**resp)

    def hur_module(self):
        reconciler = VSPHurReconciler(
            self.connection_info,
            self.storage_serial_number,
            self.state,
            self.secondary_connection_info,
        )
        comment, result = reconciler.reconcile_hur(
            self.spec, self.secondary_connection_info
        )
        return comment, result

    def get_message(self):

        if self.state == "present":
            return "HUR Pair created successfully."
        elif self.state == "absent":
            if self.spec.should_delete_svol is True:
                return "HUR Pair and Secondary volume deleted successfully."
            return "HUR Pair deleted successfully."
        elif self.state == "resync":
            return "HUR Pair resynced successfully."
        elif self.state == "split":
            return "HUR Pair split successfully."
        elif self.state == "swap_split":
            return "HUR Pair swapped split successfully."
        elif self.state == "takeover":
            return "HUR Pair secondary volume takeover successfully."
        elif self.state == "swap_resync":
            return "HUR Pair swapped resynced successfully"
        elif self.state == "resize" or self.state == "expand":
            return "HUR Pair expanded successfully"
        else:
            return "Unknown state provided."


def main(module=None):
    """
    :return: None
    """
    obj_store = VSPSHurManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
