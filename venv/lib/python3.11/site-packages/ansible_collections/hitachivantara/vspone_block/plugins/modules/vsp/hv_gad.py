#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_gad
short_description: Manages GAD pairs on Hitachi VSP storage systems.
description:
  - This module allows for the creation, deletion, splitting, and resynchronization of GAD pairs on Hitachi VSP storage systems.
  - It supports various GAD pairs operations based on the specified task level.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/gad_pair.yml)
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
options:
  state:
    description: The level of the GAD pairs task.
    type: str
    required: false
    choices: ['present', 'absent', 'split', 'resync', 'swap_split', 'swap_resync', 'resize', 'expand']
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
        description: IP address or hostname of the secondary storage.
        type: str
        required: true
      username:
        description: Username for authentication. This field is required for secondary storage connection if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication. This field is required for secondary storage connection if api_token is not provided.
        type: str
        required: false
      api_token:
        description: Value of the lock token to operate on locked resources.
        type: str
        required: false
  spec:
    description: Specification for the GAD pairs task.
    type: dict
    required: true
    suboptions:
      primary_storage_serial_number:
        description: The serial number of the primary storage device.
        type: str
        required: false
      secondary_storage_serial_number:
        description: The serial number of the secondary storage device.
        type: str
        required: false
      primary_volume_id:
        description: Primary Volume ID. Required for the Create/Delete tasks.
        type: str
        required: false
      secondary_pool_id:
        description: Pool ID of the secondary storage system. Required for the Create tasks.
        type: int
        required: false
      consistency_group_id:
        description: Consistency Group ID.
        type: int
        required: false
      allocate_new_consistency_group:
        description: Allocate and assign a new consistency group ID.
          Required for the Create GAD pair with server cluster configuration
          /Create GAD pair with cross path server configuration tasks.
        type: bool
        required: false
      set_alua_mode:
        description: Set the ALUA mode to True.
          Required for the Create GAD pair with cross path server configuration task.
        type: bool
        required: false
      primary_resource_group_name:
        description: The primary resource group name.
          Required for the Create GAD pair with cross path server configuration task.
        type: str
        required: false
      secondary_resource_group_name:
        description: The secondary resource group name.
        type: str
        required: false
      quorum_disk_id:
        description: The quorum disk ID. Required for the Create tasks.
        type: int
        required: false
      primary_hostgroups:
        description: The list of host groups on the primary storage device.
          Required for the Create GAD pair with server cluster configuration task.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: Host group name.
              Required for the Create GAD pair with server cluster configuration
              /Create GAD pair with cross path server configuration tasks.
            type: str
            required: true
          lun_id:
            description: LUN ID.
            type: int
            required: false
          port:
            description: Port name.
              Required for the Create GAD pair with server cluster configuration
              /Create GAD pair with cross path server configuration tasks.
            type: str
            required: true
          enable_preferred_path:
            description: Enables the preferred path for the specified host group.
              Required for the Create GAD pair with server cluster configuration
              /Create GAD pair with cross path server configuration tasks.
            type: bool
            required: false
      secondary_hostgroups:
        description: The list of host groups on the secondary storage device. Required for the Create tasks.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: Host group name. Required for the Create tasks.
            type: str
            required: true
          port:
            description: Port name. Required for the Create tasks.
            type: str
            required: true
          enable_preferred_path:
            description: Enables the preferred path for the specified host group.
              Required for the Create tasks.
            type: bool
            required: false
          lun_id:
            description: LUN ID. Required for the Create tasks.
            type: int
            required: false
      secondary_iscsi_targets:
        description: The list of iscsi targets on the secondary storage device.
          Required for the Create GAD-ISCSI Pair task.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: ISCSI target name. Required for the Create GAD-ISCSI Pair task.
            type: str
            required: true
          port:
            description: Port name. Required for the Create GAD-ISCSI Pair task.
            type: str
            required: true
          enable_preferred_path:
            description: Enables the preferred path for the specified ISCSI target.
              Required for the Create GAD-ISCSI Pair task.
            type: bool
            required: false
          lun_id:
            description: LUN ID. Required for the Create GAD-ISCSI Pair task.
            type: int
            required: false
      secondary_nvm_subsystem:
        description: NVM subsystem details of the secondary volume.
          Required for the Create GAD-NVMe Pair task.
        type: dict
        required: false
        suboptions:
          name:
            description: Name of the NVM subsystem on the secondary storage system.
              Required for the Create GAD-NVMe Pair task.
            type: str
            required: true
          paths:
            description: Host NQN paths information on the secondary storage system.
              Required for the Create GAD-NVMe Pair task.
            type: list
            elements: str
            required: false
      local_device_group_name:
        description: The device group name in the local storage system.
          Optional for the Split/Resync/Swap-Split/Swap-Resync tasks.
        type: str
        required: false
      remote_device_group_name:
        description: The device group name in the remote storage system.
          Optional for the Split/Resync/Swap-Split/Swap-Resync tasks.
        type: str
        required: false
      copy_pair_name:
        description: The name for the pair in the copy group.
          Required for the Create/Split/Resync/Swap-Split/Swap-Resync/Expand tasks.
        type: str
        required: false
      path_group_id:
        description: Path group ID.
        type: int
        required: false
      copy_group_name:
        description: The name for the copy group.
          Required for the Create/Split/Resync/Delete/Swap-Split/Swap-Resync/Expand tasks.
        type: str
        required: false
      copy_pace:
        description: Copy pace.
        type: str
        required: false
        choices: ['HIGH', 'MEDIUM', 'LOW']
        default: 'MEDIUM'
      fence_level:
        description: Fence level.
        type: str
        required: false
        choices: ['NEVER', 'DATA', 'STATUS', 'UNKNOWN']
        default: 'NEVER'
      new_volume_size:
        description: Required for resize or expand operation. Value should be grater than the current volume size.
          Required for the Expand GAD pair task.
        type: str
        required: false
      is_data_reduction_force_copy:
        description: Whether to forcibly create a pair.
        type: bool
        required: false
        default: true
      do_initial_copy:
        description: Whether to perform an initial copy.
        type: bool
        required: false
        default: true
      is_new_group_creation:
        description: Specify true for a new copy group name.
        type: bool
        required: false
      is_consistency_group:
        description: Specify true for consistency group.
        type: bool
        required: false
      provisioned_secondary_volume_id:
        description: ID of the provisioned secondary volume that you want to use for the GAD pair creation.
          Required for the Create a GAD pair with provisioned secondary volume id task.
        type: str
        required: false
      begin_secondary_volume_id:
        description: >
          Specify beginning ldev id for LDEV range for svol. This is an optional field during create operation.
          If this field is specified, end_secondary_volume_id must also be specified.
          If this field is not specified, Ansible modules will try to create SVOL ID same as the PVOL ID if available,
          otherwise it will use the first available LDEV ID.
          Required for the Create a GAD pair using a range for secondary volume id task.
        required: false
        type: str
      end_secondary_volume_id:
        description: >
          Specify end ldev id for LDEV range for svol. This is an optional field during create operation.
          If this field is specified, begin_secondary_volume_id must also be specified.
          If this field is not specified, Ansible modules will try to create SVOL ID same as PVOL ID iff available,
          otherwise it will use the first available LDEV ID.
          Required for the Create a GAD pair using a range for secondary volume id task.
        required: false
        type: str
      should_delete_svol:
        description: Specify true to delete the SVOL.
        type: bool
        required: false
        default: false
      mu_number:
        description: The mirror unit number.
        type: str
        required: false
"""

EXAMPLES = """
- name: Swap-Split a GAD pair
  hitachivantara.vspone_block.vsp.hv_gad:
    state: "swap_split"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "gad_copy_group_name_8"
      copy_pair_name: "gad_copy_pair_name_8"
      local_device_group_name: "gad_local_device_group_name_8"
      remote_device_group_name: "gad_remote_device_group_name_8"

- name: Swap-Resync a GAD pair
  hitachivantara.vspone_block.vsp.hv_gad:
    state: "swap_resync"
    connection_info:
      address: storage2.company.com
      username: "username"
      password: "password"
    secondary_connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "gad_copy_group_name_8"
      copy_pair_name: "gad_copy_pair_name_8"
      local_device_group_name: "gad_local_device_group_name_8"
      remote_device_group_name: "gad_remote_device_group_name_8"

- name: Increase size of volumes of a GAD pair
  hitachivantara.vspone_block.vsp.hv_gad:
    state: "resize"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "gad_copy_group_name_9"
      copy_pair_name: "gad_copy_pair_name_9"
      new_volume_size: "4GB"

- name: Create a GAD-NVMe pair
  hitachivantara.vspone_block.vsp.hv_gad:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"

      primary_volume_id: 12
      secondary_pool_id: 1
      secondary_nvm_subsystem:
        name: gk-nvm-sub-75
        paths:
          - "nqn.2014-08.com.ucpa-sc-hv:nvme:gk-test-12346"
      quorum_disk_id: 1

- name: Create a GAD-ISCSI pair
  hitachivantara.vspone_block.vsp.hv_gad:
    state: "present"
    connection_info:
      address: storage1.company.com
      username: "username"
      password: "password"
    secondary_connection_info:
      address: storage2.company.com
      username: "admin"
      password: "secret"
    spec:
      copy_group_name: "copy_group_name_1"
      copy_pair_name: "copy_pair_name_1"

      primary_volume_id: 12
      secondary_pool_id: 1
      secondary_iscsi_targets:
        - name: "test"
          port: "CL1-A"
          enable_preferred_path: false
          lun_id: 1
      quorum_disk_id: 1
"""

RETURN = """
data:
  description: Newly created GAD pair object.
  returned: success
  type: dict
  contains:
    consistency_group_id:
      description: Consistency Group ID.
      type: str
      sample: ""
    copy_group_name:
      description: Copy group name.
      type: str
      sample: "GAD_Test_perform"
    copy_pair_name:
      description: Copy pair name.
      type: str
      sample: "GAD_Pair_20250930032554_1"
    copy_progress_rate:
      description: Copy progress rate.
      type: int
      sample: -1
    fence_level:
      description: Fence level.
      type: str
      sample: "NEVER"
    is_alua_enabled:
      description: Whether ALUA is enabled.
      type: bool
      sample: null
    pvol_difference_data_management:
      description: Primary volume difference data management.
      type: str
      sample: "D"
    pvol_io_mode:
      description: Primary volume I/O mode.
      type: str
      sample: "L/M"
    pvol_journal_id:
      description: Primary volume journal ID.
      type: str
      sample: ""
    pvol_ldev_id:
      description: Primary volume LDEV ID.
      type: int
      sample: 3364
    pvol_processing_status:
      description: Primary volume processing status.
      type: str
      sample: "N"
    pvol_status:
      description: Primary volume status.
      type: str
      sample: "PAIR"
    pvol_storage_device_id:
      description: Primary volume storage device ID.
      type: str
      sample: "900000040014"
    quorum_disk_id:
      description: Quorum disk ID.
      type: int
      sample: 10
    remote_mirror_copy_pair_id:
      description: Remote mirror copy pair ID.
      type: str
      sample: "900000040015,GAD_Test_perform,GAD_Test_performP_,GAD_Test_performS_,GAD_Pair_20250930032554_1"
    replication_type:
      description: Replication type.
      type: str
      sample: "GAD"
    svol_difference_data_management:
      description: Secondary volume difference data management.
      type: str
      sample: "D"
    svol_io_mode:
      description: Secondary volume I/O mode.
      type: str
      sample: "L/M"
    svol_journal_id:
      description: Secondary volume journal ID.
      type: str
      sample: ""
    svol_ldev_id:
      description: Secondary volume LDEV ID.
      type: int
      sample: 6285
    svol_processing_status:
      description: Secondary volume processing status.
      type: str
      sample: "N"
    svol_status:
      description: Secondary volume status.
      type: str
      sample: "PAIR"
    svol_storage_device_id:
      description: Secondary volume storage device ID.
      type: str
      sample: "900000040015"
"""


from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    operation_constants,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_gad_pair,
)
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPGADArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPGADPairManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPGADArguments().gad_pair_args_spec()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.gad_pair_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
            self.secondary_connection_info = (
                self.params_manager.get_secondary_connection_info()
            )
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        try:
            registration_message = validate_ansible_product_registration()
            self.logger.writeInfo("=== Start of GAD operation. ===")
            reconciler = vsp_gad_pair.VSPGadPairReconciler(
                self.connection_info, self.secondary_connection_info, self.serial
            )
            response = reconciler.gad_pair_reconcile(
                self.state, self.spec, self.secondary_connection_info
            )

            result = response if not isinstance(response, str) else None
            operation = operation_constants(self.module.params["state"])

            #  sng1104 gad_pair_reconcile
            if result is None:

                self.logger.writeDebug(f"apply.response: {response}")

                isFailed = True
                #  there response is a string
                if isinstance(response, str) and "successfully" in response:
                    if self.spec.should_delete_svol is True:
                        response = "GAD pair deleted successfully along with secondary volume on secondary storage."
                    isFailed = False
                if isinstance(response, str) and "Gad pair not present" in response:
                    isFailed = False

                response_dict = {
                    "failed": isFailed,
                    "data": None,
                    "changed": self.connection_info.changed,
                    "msg": response,
                }
            else:
                response_dict = {
                    "failed": False,
                    "changed": self.connection_info.changed,
                    "data": result,
                    "msg": f"Gad Pair {operation} successfully.",
                }
            if registration_message:
                response_dict["user_consent_required"] = registration_message

            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of GAD operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of GAD operation. ===")
            self.module.fail_json(msg=str(ex))


def main(module=None):
    obj_store = VSPGADPairManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
