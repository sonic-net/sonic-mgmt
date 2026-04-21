#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_storage_system
short_description: This module specifies storage systems settings like updating the date and time.
description:
  - This module allows you to configure various storage system settings, such as updating the date and time, enabling or disabling NTP, setting time zones.
  - For example usage, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/storage_system.yml)
version_added: '4.0.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.8
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.gateway_note
  - hitachivantara.vspone_block.common.connection_info
options:
  spec:
    description: Specification storage system.
    type: dict
    required: true
    suboptions:
      date_time:
        description: Date and time configuration for the storage system.
        type: dict
        required: true
        suboptions:
          is_ntp_enabled:
            description: Whether NTP is enabled.
            type: bool
            required: true
          ntp_server_names:
            description: List of NTP server names.
            type: list
            elements: str
            required: false
          time_zone_id:
            description: Time zone identifier.
            type: str
            required: true
          system_time:
            description: System time in ISO format.
            type: str
            required: true
          synchronizing_local_time:
            description: Synchronizing local time.
            type: str
            required: false
          adjusts_daylight_saving_time:
            description: Whether daylight saving time is adjusted.
            type: bool
            required: false
          synchronizes_now:
            description: Whether to synchronize time immediately.
            type: bool
            required: false
"""

EXAMPLES = """
- name: Configure storage system date and time settings
  hitachivantara.vspone_block.vsp.hv_storage_system:
    connection_info:
      address: 192.0.2.10
      username: admin
      password: secret
    spec:
      date_time:
        is_ntp_enabled: true
        ntp_server_names:
          - "ntp1.example.com"
          - "ntp2.example.com"
        time_zone_id: "UTC"
        system_time: "2024-06-01T12:00:00Z"
        synchronizing_local_time: "2024-06-01T12:00:00Z"
        adjusts_daylight_saving_time: true
        synchronizes_now: false
"""

RETURN = """
system_info:
  description: Detailed information about the storage system, including configuration, capacity, and health status.
  returned: always
  type: dict
  contains:
    controller_address:
      description: Controller IP address of the storage system.
      type: str
      sample: ""
    device_limits:
      description: Device number limits and ranges for parity and external groups.
      type: dict
      contains:
        external_group_number_range:
          description: Range of valid external group numbers.
          type: dict
          contains:
            is_valid:
              description: Indicates if the range is valid.
              type: bool
              sample: false
            max_value:
              description: Maximum value of the external group number.
              type: int
              sample: -1
            min_value:
              description: Minimum value of the external group number.
              type: int
              sample: -1
        external_group_sub_number_range:
          description: Range of valid sub-numbers for external groups.
          type: dict
          contains:
            is_valid:
              description: Indicates if the range is valid.
              type: bool
              sample: false
            max_value:
              description: Maximum value of the sub-number.
              type: int
              sample: -1
            min_value:
              description: Minimum value of the sub-number.
              type: int
              sample: -1
        parity_group_number_range:
          description: Range of valid parity group numbers.
          type: dict
          contains:
            is_valid:
              description: Indicates if the range is valid.
              type: bool
              sample: false
            max_value:
              description: Maximum parity group number.
              type: int
              sample: -1
            min_value:
              description: Minimum parity group number.
              type: int
              sample: -1
        parity_group_sub_number_range:
          description: Range of valid sub-numbers for parity groups.
          type: dict
          contains:
            is_valid:
              description: Indicates if the range is valid.
              type: bool
              sample: false
            max_value:
              description: Maximum sub-number.
              type: int
              sample: -1
            min_value:
              description: Minimum sub-number.
              type: int
              sample: -1
    free_capacity:
      description: Total available free capacity in human-readable format.
      type: str
      sample: "1.68TB"
    free_capacity_in_mb:
      description: Free capacity in megabytes.
      type: int
      sample: 1756387
    free_gad_consistency_group_id:
      description: Available GAD consistency group ID.
      type: int
      sample: -1
    free_local_clone_consistency_group_id:
      description: Available local clone consistency group ID.
      type: int
      sample: -1
    free_remote_clone_consistency_group_id:
      description: Available remote clone consistency group ID.
      type: int
      sample: -1
    free_logical_unit_list:
      description: List of available logical units.
      type: list
      sample: null
    health_description:
      description: Detailed description of the system health.
      type: str
      sample: ""
    health_status:
      description: Overall system health status.
      type: str
      sample: ""
    journal_pools:
      description: List of journal pools configured in the system.
      type: list
      sample: []
    management_address:
      description: Management IP address of the storage system.
      type: str
      sample: ""
    microcode_version:
      description: Microcode (firmware) version of the system.
      type: str
      sample: "A3-04-21-40/00"
    model:
      description: Model name of the storage system.
      type: str
      sample: "VSP One B26"
    operational_status:
      description: Current operational status of the system.
      type: str
      sample: ""
    ports:
      description: List of configured ports in the system.
      type: list
      sample: []
    quorum_disks:
      description: List of quorum disks configured in the system.
      type: list
      sample: []
    resource_state:
      description: Current resource state of the system.
      type: str
      sample: ""
    serial_number:
      description: Serial number of the storage system.
      type: str
      sample: "810045"
    storage_pools:
      description: List of available storage pools in the system.
      type: list
      sample: []
    syslog_config:
      description: Syslog server configuration for system logging.
      type: dict
      contains:
        detailed:
          description: Indicates if detailed syslog output is enabled.
          type: bool
          sample: true
        syslog_servers:
          description: List of configured syslog servers.
          type: list
          elements: dict
          contains:
            id:
              description: ID of the syslog server.
              type: int
              sample: 0
            syslog_server_address:
              description: IP address or hostname of the syslog server.
              type: str
              sample: "203.0.113.2"
            syslog_server_port:
              description: Syslog server port number.
              type: str
              sample: "514"
    system_date_time:
      description: System date, time, and time synchronization information.
      type: dict
      contains:
        adjusts_daylight_saving_time:
          description: Indicates if daylight saving time adjustment is enabled.
          type: bool
          sample: null
        is_ntp_enabled:
          description: Indicates if NTP synchronization is enabled.
          type: bool
          sample: false
        ntp_server_names:
          description: List of configured NTP servers.
          type: list
          sample: []
        synchronizing_local_time:
          description: Local time synchronization status.
          type: str
          sample: ""
        system_time:
          description: Current system time in ISO 8601 format.
          type: str
          sample: "2025-10-23T11:32:50Z"
        time_zone_id:
          description: Configured system time zone.
          type: str
          sample: "Etc/GMT"
    time_zones_info:
      description: Information about available time zones.
      type: list
      sample: null
    total_capacity:
      description: Total system capacity in human-readable format.
      type: str
      sample: "28.98TB"
    total_capacity_in_mb:
      description: Total system capacity in megabytes.
      type: int
      sample: 30387994
    total_efficiency:
      description: Efficiency and compression metrics of the system.
      type: dict
      contains:
        accelerated_compression:
          description: Accelerated compression efficiency ratios.
          type: dict
          contains:
            compression_ratio:
              description: Compression ratio for accelerated compression.
              type: str
              sample: "1.00"
            reclaim_ratio:
              description: Reclaim ratio for accelerated compression.
              type: str
              sample: "1.00"
            total_ratio:
              description: Total efficiency ratio for accelerated compression.
              type: str
              sample: "1.00"
        calculation_start_time:
          description: Start time of the efficiency calculation.
          type: str
          sample: "2025-10-04T06:52:58Z"
        calculation_end_time:
          description: End time of the efficiency calculation.
          type: str
          sample: "2025-10-04T06:55:45Z"
        compression_ratio:
          description: Overall compression ratio.
          type: str
          sample: "1.26"
        dedupe_and_compression:
          description: Dedupe and compression efficiency ratios.
          type: dict
          contains:
            compression_ratio:
              description: Compression ratio after deduplication.
              type: str
              sample: "1.07"
            dedupe_ratio:
              description: Deduplication ratio.
              type: str
              sample: "1.02"
            reclaim_ratio:
              description: Reclaim ratio for dedupe and compression.
              type: str
              sample: "1.80"
            total_ratio:
              description: Total ratio combining dedupe and compression.
              type: str
              sample: "1.98"
        is_calculated:
          description: Indicates if efficiency ratios were calculated successfully.
          type: bool
          sample: true
        provisioning_rate:
          description: Provisioning rate percentage.
          type: str
          sample: "99"
        snapshot_ratio:
          description: Snapshot space efficiency ratio.
          type: str
          sample: "1156.81"
        total_ratio:
          description: Overall total efficiency ratio.
          type: str
          sample: "1056.78"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPStorageSystemARgs,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_storage_system import (
    VSPStorageSystemReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class StorageSystemModule:
    """
    Class representing StorageSystemModule Module.
    """

    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPStorageSystemARgs().storage_system_args()

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
        )
        try:
            self.parameter_manager = VSPParametersManager(self.module.params)
            self.spec = self.parameter_manager.set_storage_system_spec()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):

        self.logger.writeInfo("=== Start of Storage System Module ===")
        registration_message = validate_ansible_product_registration()

        try:
            response, msg = VSPStorageSystemReconciler(
                self.parameter_manager.connection_info
            ).storage_system_reconcile(self.spec)

        except Exception as e:
            self.logger.writeError(str(e))
            self.logger.writeInfo("=== End of Storage System Module ===")
            self.module.fail_json(msg=str(e))

        data = {
            "system_info": response,
            "changed": self.parameter_manager.connection_info.changed,
            "message": msg,
        }
        if registration_message:
            data["user_consent_required"] = registration_message

        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of Storage System Module ===")
        self.module.exit_json(**data)


def main():
    obj_store = StorageSystemModule()
    obj_store.apply()


if __name__ == "__main__":
    main()
