#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_server_priority_manager
short_description: Manage Server Priority Manager information on Hitachi VSP storage systems.
description:
  - Set, change, or delete Server Priority Manager information on Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/server_priority_manager.yml)
version_added: '4.0.0'
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
options:
  state:
    description: The level of the storage pool task. Choices are C(present), C(absent) .
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
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
    description: Specification for the Server Priority Manager.
    type: dict
    required: false
    suboptions:
      ldev_id:
        description: Specify the LDEV number as a decimal (base 10) number.
          Required for the Set Server Priority Manager information by specifying a volume and the
          WWN of the HBA
          /Set Server Priority Manager information by specifying a volume and the iSCSI name
          of the HBA
          /Change the upper limit on IOPS for hosts for which the LDEV number of a volume and
          the WWN of the HBA are already specified in Server Priority Manager
          /Change the upper limit on the transfer rate for hosts for which the LDEV number of a
          volume and iSCSI name of the HBA are already specified in Server Priority Manager
          /Delete Server Priority Manager information by specifying a volume and the WWN of the HBA
          /Delete Server Priority Manager information by specifying a volume and the iSCSI name
          of the HBA tasks.
        type: str
        required: true
      host_wwn:
        description: WWN of the HBA. Specify a hexadecimal number consisting of 16 characters.
          Required for the Set Server Priority Manager information by specifying a volume and the
          WWN of the HBA
          /Change the upper limit on IOPS for hosts for which the LDEV number of a volume and
          the WWN of the HBA are already specified in Server Priority Manager
          /Delete Server Priority Manager information by specifying a volume and the WWN of the HBA tasks.
        type: str
        required: false
      iscsi_name:
        description: iSCSI name of the HBA (iSCSI initiator). Specify the name in iqn format or eui format.
          Required for the Set Server Priority Manager information by specifying a volume and the
          iSCSI name of the HBA
          /Change the upper limit on the transfer rate for hosts for which the LDEV number of a
          volume and iSCSI name of the HBA are already specified in Server Priority Manager
          /Delete Server Priority Manager information by specifying a volume and the iSCSI name
          of the HBA tasks.
        type: str
        required: false
      upper_limit_for_iops:
        description: Upper limit on IOPS. Specify a value in the range from 1 to 65535.
          Required for the Set Server Priority Manager information by specifying a volume and the
          WWN of the HBA
          /Change the upper limit on IOPS for hosts for which the LDEV number of a volume and
          the WWN of the HBA are already specified in Server Priority Manager tasks.
        type: int
        required: false
      upper_limit_for_transfer_rate_in_MBps:
        description: Upper limit on the transfer rate (MBps). Specify a value in the range from 1 to 31.
          Required for the Set Server Priority Manager information by specifying a volume and the
          iSCSI name of the HBA
          /Change the upper limit on the transfer rate for hosts for which the LDEV number of a
          volume and iSCSI name of the HBA are already specified in Server Priority Manager tasks.
        type: int
        required: false
"""

EXAMPLES = """
- name: Set Server Priority Manager information by specifying a volume and the WWN of the HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: "present"
    spec:
      ldev_id: 0
      host_wwn: "210003e08b0256f9"
      upper_limit_for_iops: 999

- name: Set Server Priority Manager information by specifying a volume and the iSCSI name of the HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: "present"
    spec:
      ldev_id: 80
      iscsi_name: "eui.0900ABDC32598D269"
      upper_limit_for_transfer_rate_in_MBps: 30

- name: Change the upper limit on IOPS for an SPM by specifying LDEV number and the WWN of the HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: "present"
    spec:
      ldev_id: 0
      host_wwn: "210003e08b0256f9"
      upper_limit_for_iops: 8888

- name: Change the upper limit on the transfer rate for an SPM by specifying a volume and the iSCSI name  of the HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: "present"
    spec:
      ldev_id: 80
      iscsi_name: "eui.0900ABDC32598D269"
      upper_limit_for_transfer_rate_in_MBps: 30

- name: Delete Server Priority Manager information by specifying a volume and the WWN of the HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: "absent"
    spec:
      ldev_id: 0
      host_wwn: "210003e08b0256f9"

- name: Delete Server Priority Manager information by specifying a volume and the iSCSI name of the HBA
  hitachivantara.vspone_block.vsp.hv_server_priority_manager:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
    state: "absent"
    spec:
      ldev_id: 80
      iscsi_name: "eui.0900ABDC32598D269"
      upper_limit_for_transfer_rate_in_MBps: 25
"""

RETURN = """
server_priority_manager:
  description: The Server Priority Manager information.
  returned: success
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
    upper_limit_for_transfer_rate_in_MBps:
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


class VspSpmManager:

    def __init__(self):
        self.logger = Log()
        self.argument_spec = (
            VSPServerPriorityManagerArguments().server_priority_manager()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_spm_spec()
            self.serial = self.params_manager.get_serial()
            self.state = self.params_manager.get_state()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        try:
            self.logger.writeInfo("=== Start of Server Priority Manager operation ===")
            registration_message = validate_ansible_product_registration()
            response, msg = (
                vsp_server_priority_manager.VSPServerPriorityManagerReconciler(
                    self.connection_info, self.serial
                ).spm_reconcile(self.state, self.spec)
            )

            msg = response if isinstance(response, str) else msg
            result = response if not isinstance(response, str) else None
            response_dict = {
                "changed": self.connection_info.changed,
                "data": result,
                "msg": msg,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message

            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo("=== End of Server Priority Manager operation ===")
            self.module.exit_json(**response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Server Priority Manager operation ===")
            self.module.fail_json(msg=str(ex))


def main(module=None):
    obj_store = VspSpmManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
