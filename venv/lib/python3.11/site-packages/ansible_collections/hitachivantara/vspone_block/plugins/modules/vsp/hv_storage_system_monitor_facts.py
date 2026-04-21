#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_storage_system_monitor_facts
short_description: Retrieves alerts, hardware installed, and channel boards information from Hitachi VSP storage systems.
description:
  - This module retrieves information about Storage System Monitor information from Hitachi VSP storage systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/storage_system_monitor_facts.yml)

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
    description: Specification for the Storage System Monitor facts to be gathered.
    type: dict
    required: true
    suboptions:
      query:
        description: Specify the component for which you want the monitor information from the storage system.
          Possible value is one of, C(alerts), C(hardware_installed), C(channel_boards).
        type: str
        required: true
        choices: ['alerts', 'hardware_installed', 'channel_boards']
      alert_type:
        description: Type of the alerts. This field is valid when query field is C(alerts). Then this field is required.
          Possible value is one of, C(DKC), C(CTL1), C(CTL2)
        type: str
        required: false
        choices: ['DKC', 'CTL1', 'CTL2']
      alert_start_number:
        description: This field is valid when query field is C(alerts). Then this field is optional.
          Alerts are sorted by date and time in descending order. Specify the number of the
          alert from which you want to start obtaining information.
          If you specified C(DKC) for the alert_type parameter, specify a value in the range from 1 to 10240.
          If you specified C(CTL1) or C(CTL2) for the alert_type parameter, specify a value in the range from 1 to 256.
          If this parameter is omitted, alert information will be obtained starting from the first alert.
        type: int
        required: false
      alert_count:
        description: This field is valid when query field is C(alerts). Then this field is optional.
          Numbrt of alerts to be retrieved. If you specified C(DKC) for the alert_type parameter,
          specify a value in the range from 1 to 10240. If you specified C(CTL1) or C(CTL2) for the alert_type parameter,
          specify a value in the range from 1 to 256. If this parameter is omitted, 10 alerts will be obtained.
        type: int
        required: false
      include_component_option:
        description: This field is valid when query field is C(hardware_installed). Then this field is optional.
          If set to true, it will bring the information about the components, otherwise not.
        type: bool
        required: false
"""

EXAMPLES = """
- name: Get alerts information
  hitachivantara.vspone_block.vsp.hv_storage_system_monitor_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      alert_type: "CTL1"
      alert_start_number: 1
      alert_count: 2
      query: "alerts"

- name: Get Hardware Installed information
  hitachivantara.vspone_block.vsp.hv_storage_system_monitor_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      query: "hardware_installed"
      include_component_option: false

- name: Get Channel Boards information
  hitachivantara.vspone_block.vsp.hv_storage_system_monitor_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    spec:
      query: "channel_boards"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the Storage System Monitor information.
  returned: always
  type: dict
  contains:
    alerts:
      description: The alerts information.
      type: list
      elements: dict
      contains:
        alert_id:
          description: Alert ID.
          type: int
          sample: 1
        alertIndex:
          description: Character string that uniquely identifies an alert.
          type: str
          sample: "134fe7104e8b-0f06a-7d1700"
        error_detail:
          description: Details of the alert.
          type: str
          sample: "Failed ESM force stop succeeded"
        error_level:
          description: One of the following values is displayed as the error level. Service, Moderate, Serious, Acute.
          type: str
          sample: "Moderate"
        error_section:
          description: Information about where the alert occurred.
          type: str
          sample: "ESM detection error"
        location:
          description: The location of the component or part for which the error occurred.
          type: str
          sample: "CTL01"
        occurence_time:
          description: Date and time when the alert occurred.
          type: str
          sample:  "2025-02-25T05:35:07"
        reference_code:
          description: SIM reference code (in decimal number format).
          type: int
          sample: 8197888
        storage_serial_number:
          description: The serial number of the storage.
          type: str
          sample: "810045"
        action_codes:
          description: The following information related to the action code of the alert is displayed.
          type: dict
          contains:
            acc_location:
              description: The location of the component in which the error occurred is displayed.
              type: str
              sample: "-"
            action_code:
              description: Action code.
              type: int
              sample: 1492123648
            possible_failure_parts:
              description: The name of the part that is assumed to be the cause of the error is displayed.
              type: str
              sample: "TSC CALL"
"""

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_storage_system_monitor,
)
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPStorageSystemMonitorArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.message.module_msgs import (
    ModuleMessage,
)


class VspStorageSystemMonitorFactManager:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = (
            VSPStorageSystemMonitorArguments().storage_system_monitor_fact()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_storage_system_monitor_fact_spec()
            self.serial = self.params_manager.get_serial()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of Storage System Monitor Facts ===")
        registration_message = validate_ansible_product_registration()
        try:
            result = vsp_storage_system_monitor.VSPStorageSystemMonitorReconciler(
                self.params_manager.connection_info, self.serial
            ).storage_system_monitor_facts(self.spec)
            if result is None:
                err_msg = ModuleMessage.SPM_INFO_NOT_FOUND.value
                self.logger.writeError(f"{err_msg}")
                self.logger.writeInfo("=== End of Storage System Monitor Facts ===")
                self.module.fail_json(msg=err_msg)

            if self.spec.query == "channel_boards":
                data = {
                    "channel_boards": result,
                }
            elif self.spec.query == "alerts":
                data = {
                    "alerts": result,
                }
            elif self.spec.query == "hardware_installed":
                data = {
                    "hardware_installed": result,
                }
            if registration_message:
                data["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{data}")
            self.logger.writeInfo("=== End of Storage System Monitor Facts ===")
            self.module.exit_json(changed=False, ansible_facts=data)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo("=== End of Storage System Monitor Facts ===")
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VspStorageSystemMonitorFactManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
