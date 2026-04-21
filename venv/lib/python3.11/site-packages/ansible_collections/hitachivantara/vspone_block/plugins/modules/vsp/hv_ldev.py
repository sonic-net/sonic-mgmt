#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_ldev
short_description: Manages logical devices (LDEVs) on Hitachi VSP storage systems.
description:
  - This module allows for the creation, modification, or deletion of logical devices (LDEVs) on Hitachi VSP storage systems.
  - It supports operations such as creating a new LDEV, updating an existing LDEV, or deleting a LDEV.
  - To create multiple volumes/LDEVs in a single task on VSP One Block or VSP E
      Series storage systems, use `hv_vsp_one_volume` module for faster execution.
      See `hv_vsp_one_volume` module documentation for more information. For other
      volume/LDEV configurations not available in `hv_vsp_one_volume` module, use
      `hv_ldev` module.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/ldev.yml)
version_added: '3.0.0'
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
  - The output parameters C(entitlement_status), C(subscriber_id) and C(partner_id) were removed in version 3.4.0.
    They were also deprecated due to internal API simplification and are no longer supported.
options:
  state:
    description: The desired state of the LDEV.
    type: str
    required: false
    choices: ['present', 'absent', 'assign_virtual_ldev']
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
    description: Specification for the LDEV.
    type: dict
    required: true
    suboptions:
      pool_id:
        description: ID of the pool where the LDEV will be created. Options pool_id and parity_group_id are mutually exclusive.
          Required for the Create LDEV with a specific LDEV ID
          /Create ldev with free ID and present to NVM System
          /Create LDEV within a range of LDEV IDs using parallel execution
          /Create LDEV with capacity saving and data_reduction_share
          /Configuring QoS settings for a new volume
          /Create new volume with tiering policy
          /Create new volume with virtual ldev tasks.
        type: int
        required: false
      parity_group:
        description: ID of the parity_group where the LDEV will be created. Options pool_id and parity_group_id are mutually exclusive.
          Required for the Create LDEV using a parity group and auto-free LDEV ID selection task.
        type: str
        required: false
      size:
        description: Size of the LDEV. Can be specified in units such as GB, TB, or MB (e.g., '10GB', '5TB', '100MB', 200).
          Required for the Create LDEV with a specific LDEV ID
          /Create ldev with free ID and present to NVM System
          /Create LDEV within a range of LDEV IDs using parallel execution
          /Expand the size of LDEV
          /Create LDEV using a parity group and auto-free LDEV ID selection
          /Create LDEV using external parity group and auto free LDEV ID selection
          /Create LDEV with capacity saving and data_reduction_share
          /Configuring QoS settings for a new volume
          /Create new volume with tiering policy
          /Create new volume with virtual ldev tasks.
        type: str
        required: false
      ldev_id:
        description: ID of the LDEV (required for delete and update operations), for new it will assigned to this ldev if it's free.
          Required for the Create LDEV with a specific LDEV ID
          /Present existing volume to NVM System
          /Expand the size of LDEV
          /Remove host NQNs from existing volume of NVM System
          /Delete LDEV
          /Force delete LDEV removes the LDEV from hostgroups, iSCSI targets or NVM subsystem namespace
          /Shredding an existing volume
          /Shredding an existing volume before deleting
          /Configuring QoS settings for an existing volume
          /Assign virtual LDEV Id for a volume
          /Unassign virtual LDEV Id for a volume
          /Set MP blade ID of a volume
          /Set CLPR id of a volume
          /Reclaiming zero pages of a DP volume
          /Format a volume
          /Change volume settings tasks.
        type: str
        required: false
      name:
        description: Name of the LDEV (optional). If not given, it assigns the name of the LDEV to "smrha-<ldev_id>".
          Optional for the Create ldev with free ID and present to NVM System
          /Create LDEV within a range of LDEV IDs using parallel execution
          /Create LDEV using a parity group and auto-free LDEV ID selection
          /Create LDEV using external parity group and auto free LDEV ID selection tasks.
        type: str
        required: false
      capacity_saving:
        description: >
          Whether to enable the capacity saving functions. Valid value is one of the following three options:
          - 1. compression -  Enable the capacity saving function (compression).
          - 2. compression_deduplication - Enable the capacity saving function (compression and deduplication).
          - 3 disabled - Disable the capacity saving function (compression and deduplication)
          Default value is disabled.
          Optional for the Create ldev with free ID and present to NVM System
          /Create LDEV within a range of LDEV IDs using parallel execution tasks.
          Required for the Create LDEV with capacity saving and data_reduction_share task.
        type: str
        required: false
      data_reduction_share:
        description: Specify whether to create a data reduction shared volume.
          This value is set to true for Thin Image Advance.
          Optional for the Create ldev with free ID and present to NVM System task.
          Required for the Create LDEV with capacity saving and data_reduction_share task.
        type: bool
        required: false
      nvm_subsystem_name:
        description: Specify whether the LDEV created will be part of an NVM subsystem.
          Required for the Create ldev with free ID and present to NVM System
          /Present existing volume to NVM System
          /Remove host NQNs from existing volume of NVM System tasks.
        type: str
        required: false
      state:
        description:
          - State of the NVM subsystems task. This is valid only when nvm_subsystem_name is specified.
          - C(add_host_nqn) - Add the host NQNs to the LDEV.
          - C(remove_host_nqn) - Remove the host NQNs from the LDEV.
          - Optional for the Create ldev with free ID and present to NVM System task.
        type: str
        required: false
        choices: ['add_host_nqn', 'remove_host_nqn']
        default: 'add_host_nqn'
      host_nqns:
        description: List of host nqns to add to or remove from the LDEV depending on the state value.
          Required for the Create ldev with free ID and present to NVM System
          /Remove host NQNs from existing volume of NVM System tasks.
          Optional for the Present existing volume to NVM System task.
        type: list
        required: false
        elements: str
      is_relocation_enabled:
        description: Specify whether to enable the tier relocation setting for the HDT volume.
          Required for the Create new volume with tiering policy task.
          Optional for the Change volume settings task.
        type: bool
        required: false
      tier_level_for_new_page_allocation:
        description: Specify which tier of the HDT pool will be prioritized when a new page is allocated.
          Required for the Create new volume with tiering policy task.
        type: str
        required: false
      tiering_policy:
        description: Tiering policy for the LDEV.
          Required for the Create new volume with tiering policy task.
        type: dict
        required: false
        suboptions:
          tier_level:
            description: Tier level, a value from 0 to 31.
              Optional for the Create new volume with tiering policy task.
            type: int
            required: false
          tier1_allocation_rate_min:
            description: Tier1 min, a value from 1 to 100.
              Optional for the Create new volume with tiering policy task.
            type: int
            required: false
          tier1_allocation_rate_max:
            description: Tier1 max, a value from 1 to 100.
              Optional for the Create new volume with tiering policy task.
            type: int
            required: false
          tier3_allocation_rate_min:
            description: Tier3 min, a value from 1 to 100.
              Optional for the Create new volume with tiering policy task.
            type: int
            required: false
          tier3_allocation_rate_max:
            description: Tier3 max, a value from 1 to 100.
              Optional for the Create new volume with tiering policy task.
            type: int
            required: false
      vldev_id:
        description: Specify the virtual LDEV id. Specify -1 if you want to unassign the vldev_id.
          Required for the Create new volume with virtual ldev
          /Assign virtual LDEV Id for a volume
          /Unassign virtual LDEV Id for a volume tasks.
        type: str
        required: false
      force:
        description: Force delete. Delete the LDEV and removes the LDEV from hostgroups, iscsi targets or NVM subsystem namespace.
          Required for the Force delete LDEV removes the LDEV from hostgroups,
          iSCSI targets or NVM subsystem namespace task.
        type: bool
        required: false
      should_shred_volume_enable:
        description: It shreds an LDEV (basic volume) or DP volume. Overwrites the volume three times with dummy data.
          Required for the Shredding an existing volume
          /Shredding an existing volume before deleting task.
        type: bool
        required: false
      qos_settings:
        description: QoS settings for the LDEV.
          Required for the Configuring QoS settings for an existing volume
          /Configuring QoS settings for a new volume tasks.
        type: dict
        required: false
        suboptions:
          upper_iops:
            description: Upper IOPS limit.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tasks.
            type: int
            required: false
          lower_iops:
            description: Lower IOPS limit.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tasks.
            type: int
            required: false
          upper_transfer_rate:
            description: Upper transfer rate limit.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tasks.
            type: int
            required: false
          lower_transfer_rate:
            description: Lower transfer rate limit.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tasks.
            type: int
            required: false
          upper_alert_allowable_time:
            description: Upper alert allowable time.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tasks.
            type: int
            required: false
          lower_alert_allowable_time:
            description: Lower alert allowable time.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tasks.
            type: int
            required: false
          response_priority:
            description: Response priority.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tasks.
            type: int
            required: false
          response_alert_allowable_time:
            description: Response alert allowable time.
              Optional for the Configuring QoS settings for an existing volume
              /Configuring QoS settings for a new volume tassk.
            type: int
            required: false
      is_compression_acceleration_enabled:
        description: Whether the compression accelerator of the capacity saving function is enabled.
          Optional for the Create LDEV within a range of LDEV IDs using parallel execution
          /Change volume settings tasks.
        type: bool
        required: false
      data_reduction_process_mode:
        description: >
          The data reduction process mode of the capacity saving function.
          Valid values are:
          - "post_process" -  Post-process mode.
          - "inline" - Inline mode.
          Optional for the Change volume settings task.
        choices: ["post_process", "inline"]
        type: str
      is_alua_enabled:
        description: Whether the ALUA (Asymmetric Logical Unit Access) is enabled for the LDEV.
          Optional for the Change volume settings task.
        type: bool
        required: false
      is_full_allocation_enabled:
        description: Whether the LDEV is a full allocation volume.
          Optional for the Change volume settings task.
        type: bool
        required: false
      should_format_volume:
        description: Whether to format the volume after creation or existing volume.
          Required for the Format a volume task.
        type: bool
        required: false
      format_type:
        description: >
          The format type of the volume. Valid values are:
          - "quick" - Quick formatting.
          - "normal" - Normal formatting, It may take time to finish the formatting process.
          Optional for the Format a volume task.
        type: str
        required: false
        choices: ["quick", "normal"]
        default: "quick"
      start_ldev_id:
        description: >
          The starting LDEV ID for the range of LDEVs to be created. This is used when creating multiple LDEVs.
          If not specified, a free LDEV ID will be assigned.
          Required for the Create LDEV within a range of LDEV IDs using parallel execution task.
        type: str
        required: false
      end_ldev_id:
        description: >
          The ending LDEV ID for the range of LDEVs to be created. This is used when creating multiple LDEVs.
          If not specified, only one LDEV will be created.
          Required for the Create LDEV within a range of LDEV IDs using parallel execution task.
        type: str
        required: false
      mp_blade_id:
        description: >
          The MP blade ID to which the LDEV will be assigned. This is used for specifying the MP blade for the LDEV.
          If not specified, the LDEV will be assigned to the default MP blade.
          Optional for the Set MP blade ID of a volume task.
        type: int
        required: false
      clpr_id:
        description: >
          The CLPR (Control Logical Partition) ID to which the LDEV will be assigned. This is used for specifying the CLPR for the LDEV.
          If not specified, the LDEV will be assigned to the default CLPR.
          Required for the Set CLPR id of a volume task.
        type: int
        required: false
      should_reclaim_zero_pages:
        description: >
          Whether to reclaim zero pages of a DP volume. This is used to reclaim space in a DP volume.
          If set to true, it will reclaim the zero pages of the DP volume.
          Required for the Reclaiming zero pages of a DP volume task.
        type: bool
        required: false
      external_parity_group:
        description: >
          The external parity group ID to which the LDEV will be assigned. This is used for specifying the external parity group for the LDEV.
          If not specified, the LDEV will be assigned to the default parity group.
          Optional for the Create LDEV using external parity group and auto free LDEV ID selection task.
        type: str
        required: false
      is_parallel_execution_enabled:
        description: >
          Whether to enable parallel execution for the LDEV operations. This is used to speed up the LDEV operations.
          If set to true, it will enable parallel execution for the LDEV operations.
          Required for the Create LDEV within a range of LDEV IDs using parallel execution task.
        type: bool
"""

EXAMPLES = """
- name: Create ldev with free id and present to NVM System
  hitachivantara.vspone_block.vsp.hv_ldev:
    state: present
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    spec:
      pool_id: 1
      size: "10GB"
      name: "New_LDEV"
      capacity_saving: "compression_deduplication"
      data_reduction_share: true
      state: "add_host_nqn"
      nvm_subsystem_name: "nvm_subsystem_01"
      host_nqns: ["nqn.2014-08.org.example:uuid:4b73e622-ddc1-449a-99f7-412c0d3baa39"]

- name: Present existing volume to NVM System
  hitachivantara.vspone_block.vsp.hv_ldev:
    state: present
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    spec:
      ldev_id: 1
      state: "add_host_nqn"
      nvm_subsystem_name: "nvm_subsystem_01"
      host_nqns: ["nqn.2014-08.org.example:uuid:4b73e622-ddc1-449a-99f7-412c0d3baa39"]

- name: Force delete ldev removes the ldev from hostgroups, iscsi targets or NVMe subsystem namespace
  hitachivantara.vspone_block.vsp.hv_ldev:
    state: absent
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    spec:
      ldev_id: 123
      force: true

- name: Update the qos settings for an existing LDEV
  hitachivantara.vspone_block.vsp.hv_ldev:
    state: absent
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    spec:
      ldev_id: 123
      qos_settings:
        upper_iops: 1000
        lower_iops: 500
        upper_transfer_rate: 1000
        lower_transfer_rate: 500
        upper_alert_allowable_time: 1000
        lower_alert_allowable_time: 500
        response_priority: 1000
        response_alert_allowable_time: 1000

- name: Set MP blade id of a volume.
  hitachivantara.vspone_block.vsp.hv_ldev:
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    state: "present"
    spec:
      ldev_id: 11
      mp_blade_id: 1

- name: Set CLPR ID of a volume.
  hitachivantara.vspone_block.vsp.hv_ldev:
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    state: "present"
    spec:
      ldev_id: 11
      clpr_id: 1

- name: Reclaiming zero pages of a DP volume.
  hitachivantara.vspone_block.vsp.hv_ldev:
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    state: "present"
    spec:
      ldev_id: 12
      should_reclaim_zero_pages: true

- name: Format a volume.
  hitachivantara.vspone_block.vsp.hv_ldev:
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    state: "present"
    spec:
      ldev_id: 12
      should_format_volume: true

- name: Change volume settings.
  hitachivantara.vspone_block.vsp.hv_ldev:
    connection_info:
      address: storage.company.com
      username: "admin"
      password: "passw0rd"
    state: "present"
    spec:
      ldev_id: 12
      is_alua_enabled: true
      is_full_allocation_enabled: true
      is_compression_acceleration_enabled: true
      is_relocation_enabled: true
      data_reduction_process_mode: "inline"
"""

RETURN = r"""
volume:
  description: Storage volume with its attributes.
  returned: success
  type: dict
  contains:
    canonical_name:
      description: Unique identifier for the volume.
      type: str
      sample: "naa.60060e8028273d005080273d00000102"
    clpr_id:
      description: CLPR (Control Logical Partition) ID.
      type: int
      sample: 0
    compression_acceleration_status:
      description: Status of compression accelerator.
      type: str
      sample: "ENABLED"
    data_reduction_process_mode:
      description: Data reduction process mode.
      type: str
      sample: "inline"
    dedup_compression_progress:
      description: Progress percentage of deduplication and compression.
      type: int
      sample: -1
    dedup_compression_status:
      description: Status of deduplication and compression.
      type: str
      sample: "ENABLED"
    deduplication_compression_mode:
      description: Mode of deduplication and compression.
      type: str
      sample: "compression_deduplication"
    emulation_type:
      description: Emulation type of the volume.
      type: str
      sample: "OPEN-V-CVS"
    hostgroups:
      description: List of host groups associated with the volume.
      type: list
      elements: dict
      sample: []
    is_alua:
      description: Indicates if ALUA is enabled.
      type: bool
      sample: false
    is_command_device:
      description: Indicates if the volume is a command device.
      type: bool
      sample: null
    is_compression_acceleration_enabled:
      description: Whether compression accelerator is enabled.
      type: bool
      sample: true
    is_data_reduction_share_enabled:
      description: Indicates if data reduction share is enabled.
      type: bool
      sample: true
    is_device_group_definition_enabled:
      description: Indicates if device group definition is enabled.
      type: bool
      sample: null
    is_encryption_enabled:
      description: Indicates if encryption is enabled.
      type: bool
      sample: false
    is_full_allocation_enabled:
      description: Indicates if full allocation is enabled.
      type: bool
      sample: false
    is_relocation_enabled:
      description: Indicates if tier relocation is enabled.
      type: bool
      sample: null
    is_security_enabled:
      description: Indicates if security is enabled.
      type: bool
      sample: null
    is_user_authentication_enabled:
      description: Indicates if user authentication is enabled.
      type: bool
      sample: null
    is_write_protected:
      description: Indicates if write protection is enabled.
      type: bool
      sample: null
    is_write_protected_by_key:
      description: Indicates if write protection by key is enabled.
      type: bool
      sample: null
    iscsi_targets:
      description: List of iSCSI targets associated with the volume.
      type: list
      elements: dict
      sample: []
    ldev_id:
      description: Logical Device ID.
      type: int
      sample: 258
    ldev_id_hex:
      description: Logical Device ID in hexadecimal.
      type: str
      sample: "00:01:02"
    mp_blade_id:
      description: MP blade ID.
      type: int
      sample: 0
    name:
      description: Name of the volume.
      type: str
      sample: "smrha-258"
    num_of_ports:
      description: Number of ports associated with the volume.
      type: int
      sample: -1
    nvm_subsystems:
      description: List of NVMe subsystems associated with the volume.
      type: list
      elements: dict
      sample: []
    parity_group_id:
      description: Parity group ID.
      type: str
      sample: ""
    path_count:
      description: Path count to the volume.
      type: int
      sample: -1
    pool_id:
      description: Pool ID where the volume resides.
      type: int
      sample: 13
    provision_type:
      description: Provisioning type of the volume.
      type: str
      sample: "CVS,HDP,DRS"
    qos_settings:
      description: QoS settings for the volume.
      type: dict
      sample: null
    resource_group_id:
      description: Resource group ID of the volume.
      type: int
      sample: 0
    snapshots:
      description: List of snapshots associated with the volume.
      type: list
      elements: dict
      sample: []
    status:
      description: Current status of the volume.
      type: str
      sample: "NML"
    storage_serial_number:
      description: Serial number of the storage system.
      type: str
      sample: "810045"
    tiering_policy:
      description: Tiering policy details.
      type: dict
      sample: {}
    total_capacity:
      description: Total capacity of the volume.
      type: str
      sample: "1.00GB"
    total_capacity_in_mb:
      description: Total capacity of the volume in megabytes.
      type: float
      sample: 1024.0
    used_capacity:
      description: Used capacity of the volume.
      type: str
      sample: "0.00B"
    used_capacity_in_mb:
      description: Used capacity of the volume in megabytes.
      type: float
      sample: 0
    virtual_ldev_id:
      description: Virtual Logical Device ID.
      type: int
      sample: -1
    virtual_ldev_id_hex:
      description: Virtual Logical Device ID in hexadecimal.
      type: str
      sample: ""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPVolumeArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_constants import (
    StateValue,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_volume,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPVolume:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPVolumeArguments().volume()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.set_volume_spec()
            self.connection_info = params_manager.get_connection_info()
            self.serial = params_manager.get_serial()
            self.state = params_manager.get_state()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of LDEV operation ===")
        registration_message = validate_ansible_product_registration()

        try:
            comment = ""

            volume_data = self.direct_volume()

            if self.state == StateValue.ABSENT and not volume_data:
                volume_response = "Volume deleted"
            else:
                if isinstance(volume_data, str):
                    volume_response = volume_data
                else:
                    if isinstance(volume_data, dict):
                        comment = volume_data.get("comment", None)
                    volume_response = self.extract_volume_properties(volume_data)
                if self.spec.should_shred_volume_enable:
                    comment = "Volume shredded successfully," + comment
                if self.spec.should_format_volume:
                    if self.spec.is_task_timeout:
                        comment = (
                            "Volume format task is still in progress. It will finish after sometime "
                            + comment
                        )
                    else:
                        comment = "Volume formatted successfully," + comment
                if self.spec.should_reclaim_zero_pages:
                    comment = "Volume reclaimed to zero pages successfully," + comment

                if self.spec.vldev_id:
                    vldev_id = self.spec.vldev_id
                    if comment is None:
                        comment = ""
                    else:
                        comment = comment + " "
                    if vldev_id == -1:
                        comment = "Unassigned vldev_id successfully." + comment
                    else:
                        comment = (
                            "Assigned vldev_id "
                            + str(self.spec.vldev_id)
                            + " successfully."
                            + comment
                        )
                if self.spec.comment:
                    comment = f"{self.spec.comment} " + comment

        except Exception as e:
            self.logger.writeError(f"An error occurred: {str(e)}")
            self.logger.writeInfo("=== End of LDEV operation ===")
            self.module.fail_json(msg=str(e))

        response = {"changed": self.connection_info.changed, "volume": volume_response}
        if comment:
            response["comment"] = comment

        if registration_message:
            response["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{response}")
        self.logger.writeInfo("=== End of LDEV operation ===")
        self.module.exit_json(**response)

    def direct_volume(self):

        result = vsp_volume.VSPVolumeReconciler(
            self.connection_info,
            self.serial,
        ).volume_reconcile(self.state, self.spec)
        return result

    def extract_volume_properties(self, volume_data):
        if not volume_data:
            return None

        # self.logger.writeDebug('20240726 volume_data={}',volume_data)
        self.logger.writeDebug("115 type={}", type(volume_data))
        if isinstance(volume_data, dict):
            volume_dict = volume_data.get("lun")
        else:
            volume_dict = volume_data.to_dict() if volume_data else {}
        return vsp_volume.VolumeCommonPropertiesExtractor(self.serial).extract(
            [volume_dict]
        )[0]


def main(module=None):
    """
    :return: None
    """
    obj_store = VSPVolume()
    obj_store.apply()


if __name__ == "__main__":
    main()
