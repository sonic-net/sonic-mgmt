#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_server_priority_manager_facts
short_description: Retrieves Server Priority Manager information from Hitachi VSP storage systems.
description:
  - This module retrieves information about Server Priority Manager from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/server_priority_manager_facts.yml)

version_added: '4.0.0'
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
options:
  connection_info:
    description: Information required to establish a connection to the storage system.
    type: dict
    required: true
    suboptions:
      address:
        description: IP address or hostname of the storage system.
        type: str
        required: true
      username:
        description: Username for authentication. This is a required field if api_token is not provided.
        type: str
        required: false
      password:
        description: Password for authentication. This is a required field if api_token is not provided.
        type: str
        required: false
      api_token:
        description: This field is used to pass the value of the lock token to operate on locked resources.
        type: str
        required: false
      connection_type:
        description: Type of connection to the storage system.
        type: str
        required: false
        choices: ['direct']
        default: 'direct'
  spec:
    description: Specification for the Server Priority Manager facts to be gathered.
    type: dict
    required: false
    suboptions:
      ldev_id:
        description: LDEV number.
          Required for the Get Server Priority Manager information by specifying a volume and the
          WWN of the HBA
          /Get Server Priority Manager information by specifying a volume and the iSCSI
          name of the HBA tasks.
        type: str
        required: false
      host_wwn:
        description: WWN of the HBA.
          Required for the Get Server Priority Manager information by specifying a volume and the
          WWN of the HBA task.
        type: str
        required: false
      iscsi_name:
        description: iSCSI name of the HBA (iSCSI initiator).
          Required for the Get Server Priority Manager information by specifying a volume and the
          iSCSI name of the HBA task.
        type: str
        required: false
"""

EXAMPLES = """
- name: Get all Server Priority Manager information
  hitachivantara.vspone_block.vsp.hv_server_priority_manager_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"

- name: Get Server Priority Manager information by specifying a volume and the WWN of an HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      ldev_id: 0
      host_wwn: "210003e08b0256f9"

- name: Get Server Priority Manager information by specifying a volume and the iSCSI name of an HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      ldev_id: 80
      iscsi_name: "eui.0900ABDC32598D269"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the Server Priority Manager information.
  returned: always
  type: dict
  contains:
    server_priority_manager:
      description: The Server Priority Manager information.
      type: list
      elements: dict
      contains:
        io_control_ldev_wwn_iscsi_id:
          description: Object ID of the SPM information.
          type: str
          sample: "0,210003e08b0256f9"
        ldev_id:
          description: LDEV number.
          type: int
          sample: 80
        ldev_id_hex:
          description: LDEV number in hexadecimal.
          type: int
          sample: "00:50"
        host_wwn:
          description: WWN of the HBA.
          type: str
          sample: "210003e08b0256f9"
        iscsi_name:
          description: iSCSI name of the HBA (iSCSI initiator).
          type: str
          sample: "iqn.myrestapiiscsi20150907"
        priority:
          description: Prioritized or not prioritized.
          type: str
          sample: "Prioritize"
        upper_limit_for_iops:
          description: Upper limit on IOPS.
          type: int
          sample: 9999
        upper_limit_for_transfer_rate:
          description: Upper limit on the transfer rate (MBps).
          type: int
          sample: 30
"""

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_server_priority_manager,
)
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPServerPriorityManagerArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.message.module_msgs import (
    ModuleMessage,
)


class VspSPMFactManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = (
            VSPServerPriorityManagerArguments().server_priority_manager_fact()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_spm_fact_spec()
            self.serial = self.params_manager.get_serial()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Server Priority Manager Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = vsp_server_priority_manager.VSPServerPriorityManagerReconciler(
                self.params_manager.connection_info, self.serial
            ).server_priority_manager_facts(self.spec)
            if result is None:
                err_msg = ModuleMessage.SPM_INFO_NOT_FOUND.value
                self.logger.writeError(f"{err_msg}")
                self.logger.writeInfo("=== End of Server Priority Manager Facts ===")
                self.module.fail_json(msg=err_msg)

            data = {
                "server_priority_manager": result,
            }
            if registration_message:
                data["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{data}")
            self.logger.writeInfo("=== End of Server Priority Manager Facts ===")
            self.module.exit_json(changed=False, ansible_facts=data)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Server Priority Manager Facts ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VspSPMFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
