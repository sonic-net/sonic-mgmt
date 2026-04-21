#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_external_volume_facts
short_description: Retrieves information about External Volume from Hitachi VSP storage systems.
description:
  - This module retrieves information about External Volume from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/external_volume_facts.yml)
version_added: '3.3.0'
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
    description: Specification for retrieving External Volume information.
    type: dict
    required: false
    suboptions:
      external_storage_serial:
        description: The external storage serial number. Required for the Get all external volume for specific ldev_id task.
        type: str
        required: false
      external_ldev_id:
        description: The external LDEV ID. Required for the Get all external volume for specific ldev_id task.
        type: str
        required: false

"""

EXAMPLES = """
- name: Retrieve information about all External Volume
  hitachivantara.vspone_block.vsp.hv_external_volume_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "changeme"
    spec:
      external_storage_serial: '410109'
      external_ldev_id: 1354
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the external volumes.
  returned: always
  type: dict
  contains:
    external_volume:
      description: The list of external volumes.
      type: list
      elements: dict
      contains:
        external_ldev_id:
          description: External LDEV ID.
          type: int
          sample: 1323
        external_ldev_id_hex:
          description: External LDEV ID in hexadecimal format.
          type: str
          sample: "00:05:2B"
        external_lun:
          description: External LUN number.
          type: int
          sample: 0
        external_path_group_id:
          description: External path group ID.
          type: int
          sample: 0
        external_product_id:
          description: Product ID of the external storage system.
          type: str
          sample: "VSP Gx00"
        external_serial_number:
          description: Serial number of the external storage system.
          type: str
          sample: "410109"
        external_volume_capacity:
          description: External volume capacity in blocks.
          type: int
          sample: 41943040
        external_volume_capacity_in_mb:
          description: External volume capacity in MB.
          type: float
          sample: 20480.0
        external_volume_info:
          description: External volume information string.
          type: str
          sample: "OPEN-V HITACHI 5040277D052B"
        external_wwn:
          description: WWN of the external storage system.
          type: str
          sample: "50060e8012277d71"
        ldev_ids:
          description: List of LDEV IDs associated with the external volume.
          type: list
          elements: int
          sample: [1351, 1465, 1670, 1510, 1511, 1512, 1513]
        port_id:
          description: Port ID of the external storage system.
          type: str
          sample: "CL6-B"
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


class VSPExternalVolumeFactManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPExternalVolumeArguments().external_volume_fact()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_external_volume_fact_spec()
            self.serial = self.params_manager.get_serial()
            self.logger.writeDebug("20250228 serial={}", self.serial)
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of External Volume Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = []
            result = VSPExternalVolumeReconciler(
                self.params_manager.connection_info, self.serial
            ).external_volume_facts(self.spec)

        except Exception as ex:

            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of External Volume Facts ===")
            self.module.fail_json(msg=str(ex))
        data = {
            "external_volume": result,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        # self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of External Volume Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = VSPExternalVolumeFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
