#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_external_volume
short_description: Manages External Volumes in the Hitachi VSP storage systems.
description:
  - This module creates and deletes the External Volumes in the Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/external_volume.yml)
version_added: '3.3.0'
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
    description: The level of the Disk Drives task.
    type: str
    required: false
    choices: ['present', 'absent', 'disconnect']
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
    description: Specification for the External Volume management.
    type: dict
    required: false
    suboptions:
      ldev_id:
        description: LDEV ID, it will be auto-selected if omitted. Required for the Create/Delete tasks.
        type: str
        required: false
      external_storage_serial:
        description: The external storage serial number. Required for the Create/Delete tasks.
        type: str
        required: false
      external_ldev_id:
        description: The external LDEV ID. Required for the Create/Delete tasks.
        type: str
        required: false
      external_parity_group:
        description: The external parity group ID. Required for the Disconnect from a volume tasks.
        type: str
        required: false
"""

EXAMPLES = """
- name: Create a External Volume
  hitachivantara.vspone_block.vsp.hv_external_volume_facts:
    connection_info:
      address: storage1.company.com
      username: 'username'
      password: 'password'
    spec:
      external_storage_serial: '410109'
      external_ldev_id: 1354
      ldev_id: 151

- name: Delete External Volume
  hitachivantara.vspone_block.vsp.hv_external_volume:
    connection_info:
      address: storage1.company.com
      username: 'username'
      password: 'password'
    state: "absent"
    spec:
      ldev_id: 151

- name: Disconnect from a volume on the external storage system
  hitachivantara.vspone_block.vsp.hv_external_volume:
    connection_info:
      address: storage1.company.com
      username: 'username'
      password: 'password'
    state: "disconnect"
    spec:
      external_parity_group: "1-2"
"""

RETURN = """
external_volume:
  description: Detailed information about the external volume on the storage system.
  returned: when state is present
  type: dict
  contains:
    canonical_name:
      description: Canonical name of the external volume.
      type: str
      sample: ""
    emulation_type:
      description: Emulation type of the external volume.
      type: str
      sample: "OPEN-V"
    externalPorts:
      description: List of external ports associated with the volume.
      type: list
      elements: dict
      contains:
        host_group_number:
          description: Host group number for the external port.
          type: int
          sample: 0
        lun:
          description: Logical unit number.
          type: int
          sample: 17
        port_id:
          description: Port identifier.
          type: str
          sample: "CL6-A"
        wwn:
          description: World Wide Name of the port.
          type: str
          sample: "50060e8012277d61"
    externalVolumeId:
      description: External volume identifier.
      type: str
      sample: "484954414348492035303430323737443035353400000000000000000000000000000000"
    ldev_id:
      description: Logical device ID.
      type: int
      sample: 1579
    logical_unit_id_hex_format:
      description: Logical unit ID in hexadecimal format.
      type: str
      sample: "00:06:2B"
    name:
      description: Name of the external volume.
      type: str
      sample: "quorum-1364"
    provision_type:
      description: Provisioning type of the volume.
      type: str
      sample: "ELUN,QRD"
    resource_group_id:
      description: Resource group ID.
      type: int
      sample: 0
    status:
      description: Status of the external volume.
      type: str
      sample: "BLK"
    total_capacity:
      description: Total capacity in human readable format.
      type: str
      sample: "20.00GB"
    total_capacity_in_mb:
      description: Total capacity in megabytes.
      type: float
      sample: 20480.0
    virtual_ldev_id:
      description: Virtual logical device ID.
      type: int
      sample: -1
external_parity_group:
  description: Information about the external parity group.
  returned: when state is disconnect
  type: dict
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_external_volume_reconciler import (
    VSPExternalVolumeReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPExternalVolumeArguments,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_volume,
    vsp_external_volume_reconciler,
)


class ModuleManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPExternalVolumeArguments().external_volume()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.external_volume_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of External Volume operation ===")
        try:
            registration_message = validate_ansible_product_registration()
            result, res_msg = VSPExternalVolumeReconciler(
                self.params_manager.connection_info, self.serial
            ).external_volume_reconcile(self.state, self.spec)
            self.logger.writeInfo(f"20250303 result={result}")

            self.connection_info.changed = False
            msg = res_msg if res_msg else self.get_message()

            if self.state == "absent":
                failed = True if result is None else False
            elif self.state == "disconnect":
                result = self.extract_ext_pg_properties(result)
                failed = False
            else:
                result = result if not isinstance(result, str) else None
                if result:
                    result = self.extract_volume_properties(result)
                failed = result is None

            if result is None:
                result = []

            response_dict = {
                "failed": failed,
                "changed": self.connection_info.changed,
                "msg": msg,
            }
            if self.state == "disconnect":
                response_dict["external_parity_group"] = result
            else:
                response_dict["external_volume"] = result

            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of External Volume operation. ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of External Volume operation. ===")
            self.module.fail_json(msg=str(ex))

    def get_message(self):

        if self.state == "present":
            self.connection_info.changed = True
            return "External Volume created successfully."
        elif self.state == "absent":
            self.connection_info.changed = True
            return "External Volume deleted successfully."
        elif self.state == "disconnect":
            self.connection_info.changed = True
            return "Disconnected from a volume on the external storage system successfully."
        else:
            return "Unknown state provided."

    def extract_volume_properties(self, volume_data):
        if not volume_data:
            return None

        # self.logger.writeDebug('20240726 volume_data={}',volume_data)
        self.logger.writeDebug("20250228 type={}", type(volume_data))
        self.logger.writeDebug("20250228 volume_data={}", volume_data)
        volume_dicts = volume_data.to_dict() if volume_data else {}
        self.logger.writeDebug("20250228 volume_data={}", volume_data)
        self.logger.writeDebug("20250228 volume_dicts={}", volume_dicts)
        return vsp_volume.ExternalVolumePropertiesExtractor(self.serial).extract(
            volume_dicts
        )[0]

    def extract_ext_pg_properties(self, epg_data):
        if not epg_data:
            return None

        # self.logger.writeDebug('20240726 volume_data={}',volume_data)
        self.logger.writeDebug("20250228 type={}", type(epg_data))
        self.logger.writeDebug("20250228 volume_data={}", epg_data)
        epg_dicts = epg_data.to_dict() if epg_data else {}
        self.logger.writeDebug("20250228 volume_data={}", epg_data)
        self.logger.writeDebug("20250228 volume_dicts={}", epg_data)
        return vsp_external_volume_reconciler.ExternalParityGroupInfoExtractor(
            self.serial
        ).extract([epg_dicts])[0]


def main(module=None):
    obj_store = ModuleManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
