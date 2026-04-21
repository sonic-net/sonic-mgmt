#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_hg
short_description: Manages host group on Hitachi VSP storage system.
description:
  - This module provides the following host group management operations
  - 1. create host group.
  - 2. delete host group.
  - 3. add logical unit to host group.
  - 4. remove logical unit from host group.
  - 5. add host WWN to host group.
  - 6. remove host WWN from host group.
  - 7. set host mode.
  - 8. add host mode option to host group.
  - 9. remove host mode option from host group.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/hostgroup.yml)
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
    description:
      - Set state to C(present) for create and update host group
      - Set state to C(absent) for delete host group
    type: str
    required: false
    choices: ['present', 'absent']
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
    description: Specification for hostgroup operation.
    type: dict
    required: false
    suboptions:
      state:
        description: Subtask operation.
        type: str
        required: false
        choices: ['present_ldev', 'unpresent_ldev', 'add_wwn', 'remove_wwn', 'set_host_mode_and_hmo', 'present']
        default: 'present'
      name:
        description: Name of the host group. If not given,
          it will create the name with prefix "smrha-" and add 10 digit random number at the end, for example "smrha-0806262996".
          Optional for the Create a host group task. Required for the Update host mode and host mode options/Add WWNs to a host group
          /Remove WWNs from a host group/Present LDEVS/Unpresent LDEVS/Delete/Change or unset nick name of a WWN tasks.
        type: str
        required: false
      port:
        description: FC Port. Required for the Create a host group/Update host mode and host mode options/Add WWNs to a host group
          /Remove WWNs from a host group/Present LDEVS/Unpresent LDEVS/Delete/Change or unset nick name of a WWN
          /Asymmetric access priority level for ALUA host group/Release the host reservation status by specifying a host group
          /Release the host reservation status by specifying the LU path tasks.
        type: str
        required: true
      wwns:
        description: List of host WWN to add or remove. Required for the Create a host group/Add WWNs to a host group
          /Remove WWNs from a host group tasks.
        type: list
        elements: dict
        suboptions:
          wwn:
            description: WWN of the host. Required for the Create a host group/Add WWNs to a host group
              /Remove WWNs from a host group/Change or unset nick name of a WWN tasks.
            type: str
            required: true
          nick_name:
            description: Nickname of the host. Optional for the Create a host group/Add WWNs to a host group
              /Remove WWNs from a host group tasks. Required for the Change or unset nick name of a WWN task.
            type: str
            required: false
        required: false
      ldevs:
        description: LDEVs to be mapped/unmapped with the host group. Supported format can be decimal or HEX.
           Optional for the Create a host group task. Required for the Present LDEVS/Unpresent LDEVS tasks.
        type: list
        elements: str
        required: false
      host_mode:
        description: Host mode of host group. Optional for the Create a host group task.
          Required for the Update host mode and host mode options task.
        type: str
        required: false
        choices: ['LINUX', 'VMWARE', 'HP', 'OPEN_VMS', 'TRU64', 'SOLARIS',
          'NETWARE', 'WINDOWS', 'HI_UX', 'AIX', 'VMWARE_EXTENSION',
          'WINDOWS_EXTENSION', 'UVM', 'HP_XP', 'DYNIX']
      host_mode_options:
        description:
          - List of host group host mode option numbers. Optional for the Create a host group task.
            Required for the Update host mode and host mode options task.
          - '0 # RESERVED'
          - '2 # VERITAS_DB_EDITION_ADV_CLUSTER'
          - '6 # TPRLO'
          - '7 # AUTO_LUN_RECOGNITION'
          - '12 # NO_DISPLAY_FOR_GHOST_LUN'
          - '13 # SIM_REPORT_AT_LINK_FAILURE'
          - '14 # HP_TRUECLUSTER_WITH_TRUECOPY'
          - '15 # RAID_HACMP'
          - '22 # VERITAS_CLUSTER_SERVER'
          - '23 # REC_COMMAND_SUPPORT'
          - '25 # SUPPORT_SPC_3_PERSISTENT_RESERVATION'
          - '33 # SET_REPORT_DEVICE_ID_ENABLE'
          - '39 # CHANGE_NEXUS_SPECIFIED_IN_SCSI_TARGET_RESET'
          - '40 # VVOL_EXPANSION'
          - '41 # PRIORITIZED_DEVICE_RECOGNITION'
          - '42 # PREVENT_OHUB_PCI_RETRY'
          - '43 # QUEUE_FULL_RESPONSE'
          - '48 # HAM_SVOL_READ'
          - '49 # BB_CREDIT_SETUP_1'
          - '50 # BB_CREDIT_SETUP_2'
          - '51 # ROUND_TRIP_SETUP'
          - '52 # HAM_AND_CLUSTER_SW_FOR_SCSI_2'
          - '54 # EXTENDED_COPY'
          - '57 # HAM_RESPONSE_CHANGE'
          - '60 # LUN0_CHANGE_GUARD'
          - '61 # EXPANDED_PERSISTENT_RESERVE_KEY'
          - '63 # VSTORAGE_APIS_ON_T10_STANDARDS'
          - '65 # ROUND_TRIP_EXTENDED_SETUP'
          - '67 # CHANGE_OF_ED_TOV_VALUE'
          - '68 # PAGE_RECLAMATION_LINUX'
          - '69 # ONLINE_LUSE_EXPANSION'
          - '71 # CHANGE_UNIT_ATTENTION_FOR_BLOCKED_POOL_VOLS'
          - '72 # AIX_GPFS'
          - '73 # WS2012'
          - '78 # NON_PREFERRED_PATH'
          - '91 # DISABLE_IO_WAIT_FOR_OPEN_STACK'
          - '95 # CHANGE_SCSI_LU_RESET_NEXUS_VSP_HUS_VM'
          - '96 # CHANGE_SCSI_LU_RESET_NEXUS'
          - '97 # PROPRIETARY_ANCHOR_COMMAND_SUPPORT'
          - '100 # HITACHI_HBA_EMULATION_CONNECTION_OPTION'
          - '102 # GAD_STANDARD_INQURY_EXPANSION_HCS'
          - '105 # TASK_SET_FULL_RESPONSE_FOR_IO_OVERLOAD'
          - '110 # ODX Support for WS2012'
          - '113 # iSCSI CHAP Authentication Log'
          - '114 # Auto Asynchronous Reclamation on ESXi 6.5+ '
          - '122 # TASK_SET_FULL_RESPONSE_AFTER_QOS_UPPER_LIMIT'
          - '124 # GUARANTEED_RESPONSE_DURING_CONTROLLER_FAILURE'
          - '131 # WCE_BIT_OFF_MODE'
        type: list
        elements: int
        required: false
      should_delete_all_ldevs:
        description: If the value is true, destroy the logical devices that are no longer attached to any host group or iSCSI target.
        required: false
        type: bool
      host_group_number:
        description: The host group number. Required for the Asymmetric access priority level for ALUA host group
          /Release the host reservation status by specifying a host group
          /Release the host reservation status by specifying the LU path tasks.
        type: int
        required: false
      should_release_host_reserve:
        description: If the value is true, release the host reserve.
          Required for the Release the host reservation status by specifying a host group
          /Release the host reservation status by specifying the LU path tasks.
        type: bool
        required: false
      lun:
        description: LUN ID to be releases the host reservation status of the LU mapped to a specified LU path.
          Required for the Release the host reservation status by specifying the LU path task.
        type: int
        required: false
      asymmetric_access_priority:
        description: Asymmetric access priority level for ALUA host group.
          Required for the Asymmetric access priority level for ALUA host group task.
        type: str
        required: false
        choices: ['low', 'high']
"""

EXAMPLES = """
- name: Create host group with LDEVs and WWNs
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      name: 'testhg26dec'
      port: 'CL1-A'
      host_mode: 'VMWARE_EXTENSION'
      host_mode_options: [40]
      wwns:
        - wwn: '100000109B583B2D'
          nick_name: 'test1'
        - wwn: '100000109B583B2C'
          nick_name: 'test2'
      ldevs: [393, 851]

- name: Delete host group
  hitachivantara.vspone_block.vsp.hv_hg:
    state: absent
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      name: 'testhg26dec'
      port: 'CL1-A'

- name: Present LDEVs to hostgroup
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      state: present_ldev
      name: 'testhg26dec'
      port: 'CL1-A'
      ldevs: [300, 400]

- name: Unpresent LDEVs from hostgroup
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      state: unpresent_ldev
      name: 'testhg26dec'
      port: 'CL1-A'
      ldevs: [800, 801]

- name: Add WWNs to hostgroup
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      state: add_wwn
      name: 'testhg26dec'
      port: 'CL1-A'
      wwns:
        - wwn: '200000109B3C0FD3'
          nick_name: 'test1'
        - wwn: '200000109B3C0FD4'
        - wwn: '200000109B3C0FD5'

- name: Remove WWNs from hostgroup
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      state: remove_wwn
      name: 'testhg26dec'
      port: 'CL1-A'
      wwns:
        - wwn: '200000109B3C0FD3'

- name: Update host group
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      state: set_host_mode_and_hmo
      name: 'testhg26dec'
      port: 'CL1-A'
      host_mode: 'VMWARE_EXTENSION'
      host_mode_options: [54, 63]

- name: Asymmetric access priority level for ALUA host group.
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      host_group_number: 208
      port: 'CL1-A'
      asymmetric_access_priority: 'high'

- name: Release the host reservation status by specifying the LU path.
  hitachivantara.vspone_block.vsp.hv_hg:
    state: present
    connection_info:
      address: storage1.company.com
      username: "dummy_user"
      password: "dummy_password"
    spec:
      host_group_number: 150
      port: 'CL1-A'
      should_release_host_reserve: true
      lun: 0
"""

RETURN = """
host_group:
  description: Detailed information about the host group on the storage system.
  returned: always
  type: dict
  contains:
    host_group_id:
      description: ID of the host group (internal identifier used by the storage system).
      type: int
      sample: 33
    host_group_name:
      description: Human readable name of the host group.
      type: str
      sample: "AutoAnsibleHurPri01"
    host_mode:
      description: Configured host mode for the host group (OS type or special mode).
      type: str
      sample: "LINUX"
    host_mode_options:
      description: List of host mode option identifiers currently set for the host group.
      type: list
      elements: int
      sample: []
    lun_paths:
      description: List of LUN path entries associated with this host group. Each entry describes an LDEV mapping and path metadata.
      type: list
      elements: dict
      contains:
        asymmetric_access_state:
          description: Asymmetric access state for the path (for ALUA-capable devices).
          type: str
          sample: "Active/Optimized"
        host_group_number:
          description: Numeric host group identifier as exposed via the path.
          type: int
          sample: 33
        host_mode:
          description: Host mode string reported for the path (may include extra qualifiers).
          type: str
          sample: "LINUX/IRIX"
        host_mode_options:
          description: Host mode option identifiers reported for the path.
          type: list
          elements: int
          sample: []
        is_alua_enabled:
          description: Whether ALUA is enabled for the path.
          type: bool
          sample: false
        is_command_device:
          description: Whether the LDEV is marked as a command device.
          type: bool
          sample: false
        ldev_id:
          description: Logical device ID (decimal).
          type: int
          sample: 3694
        ldev_id_hex:
          description: Logical device ID formatted in hex (colon separated).
          type: str
          sample: "00:0E:6E"
        lu_host_reserve:
          description: Host reservation information for the LU path, presented as booleans for reservation types and keys.
          type: dict
          contains:
            aca_reserve:
              description: Whether ACA (Auto Contingent Allegiance) reserve is set.
              type: bool
              sample: false
            mainframe:
              description: Whether mainframe-style reserve is set.
              type: bool
              sample: false
            open_system:
              description: Whether open system (standard SCSI-based) reserve is set.
              type: bool
              sample: false
            persistent:
              description: Whether persistent reservation is active.
              type: bool
              sample: false
            pgr_key:
              description: Presence of a persistent group reservation key.
              type: bool
              sample: false
        lun:
          description: LUN number assigned to this path.
          type: int
          sample: 17
        lun_id:
          description: Identifier string for the LU path, typically combining port, hostgroup number and LUN.
          type: str
          sample: "CL4-B,33,17"
        port_id:
          description: Port identifier associated with this path entry.
          type: str
          sample: "CL4-B"
    port_id:
      description: Default or requested port associated with the host group operations (e.g., CLx-A).
      type: str
      sample: "CL4-B"
    resource_group_id:
      description: Resource group ID associated with the host group (if applicable).
      type: int
      sample: 0
    wwns:
      description: List of WWN entries (host HBA identifiers) that belong to the host group.
      type: list
      elements: dict
      contains:
        wwn:
          description: World Wide Name string for the host HBA.
          type: str
          sample: "100000109B583B2D"
        nick_name:
          description: Optional human readable nickname assigned to the WWN.
          type: str
          sample: "app-server-1"
      sample: []
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPHostGroupArguments,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_host_group,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.message.module_msgs import (
    ModuleMessage,
)


class VSPHostGroupManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = VSPHostGroupArguments().host_group()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        try:
            params_manager = VSPParametersManager(self.module.params)
            self.connection_info = params_manager.get_connection_info()
            self.serial_number = params_manager.get_serial()
            self.state = params_manager.get_state()
            self.spec = params_manager.host_group_spec()
        except Exception as e:
            self.logger.writeError(str(e))
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Host Group operation ===")
        registration_message = validate_ansible_product_registration()
        host_group_data = None
        host_group_data_extracted = None
        try:
            host_group_data = self.direct_host_group_modification()
            self.logger.writeInfo("host_group_data {}", host_group_data)
            host_group_data_extracted = host_group_data

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Host Group operation ===")
            self.module.fail_json(msg=str(e))
        if registration_message:
            host_group_data_extracted["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{host_group_data_extracted}")
        self.logger.writeInfo("=== End of Host Group operation ===")
        self.module.exit_json(**host_group_data_extracted)

    def direct_host_group_modification(self):
        result = vsp_host_group.VSPHostGroupReconciler(
            self.connection_info, self.serial_number
        ).host_group_reconcile(self.state, self.spec)
        if result is None:
            raise ValueError(ModuleMessage.HOST_GROUP_NOT_FOUND.value)
        return result


def main(module=None):
    obj_store = VSPHostGroupManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
