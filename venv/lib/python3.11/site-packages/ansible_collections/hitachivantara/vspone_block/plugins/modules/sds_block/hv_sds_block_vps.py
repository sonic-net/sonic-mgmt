#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_vps
short_description: Manages VSP One SDS Block and Cloud systems Virtual Private Storages (VPS) volume ADR setting.
description:
  - This module allows to update the Virtual Private Storages volume ADR setting.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/update_vps_volume_adr_setting.yml)
version_added: '4.4.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  state:
    description: State of the VPS volume ADR setting.
    required: false
    type: str
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for VPS information.
    required: true
    type: dict
    suboptions:
      id:
        description: ID of the VPS to retrieve information for.
        type: str
        required: false
      name:
        description: VPS name to retrieve information for. Mandatory for creating a VPS.
        type: str
        required: false
      upper_limit_for_number_of_user_groups:
        description: The maximum number of user groups that can belong to the VPS. Values between 0 and 256.
          If this property is omitted, 256 is assumed to be specified.
        type: int
        required: false
      upper_limit_for_number_of_users:
        description: The maximum number of users that can belong to the VPS. Values between 0 and 256.
          If this property is omitted, 256 is assumed to be specified.
        type: int
        required: false
      upper_limit_for_number_of_sessions:
        description: The maximum number of sessions that can be established for the VPS. Values between 0 and 436.
          If this property is omitted, 436 is assumed to be specified.
        type: int
        required: false
      upper_limit_for_number_of_servers:
        description: The maximum allowable number of compute nodes on the VPS. Values between 0 and 1024.
          Mandatory for creating a VPS.
        type: int
        required: false
      volume_settings:
        description: List of volume_setting objects. This field is valid and mandatory for creating a VPS.
        type: list
        elements: dict
        required: false
        suboptions:
          pool_id:
            description: The ID of the storage pool to be used on the virtual private storage (VPS).
              Mandatory for creating a VPS.
            type: str
            required: true
          upper_limit_for_number_of_volumes:
            description: The upper limit of the number of volumes on the VPS. Mandatory for creating a VPS.
              For details about the values to be specified for upper_limit_for_number_of_volumes, contact customer support.
            type: int
            required: true
          upper_limit_for_capacity_of_volumes_mb:
            description: The upper limit of the total volume capacity (in MiB) of the VPS. Values between 0 and 9223372036854775807.
              Mandatory for creating a VPS.
              For details about the values to be specified for upper_limit_for_capacity_of_volumes_mb, contact customer support.
            type: int
            required: true
          upper_limit_for_capacity_of_single_volume_mb:
            description: The upper limit of the capacity (in MiB) of a single volume of the VPS. Values between 0 and 6871947674.
              To place no limit on the capacity of a single volume, specify -1.
              For details about the values to be specified for upper_limit_for_capacity_of_single_volume_mb, contact customer support.
            type: int
            required: false
          upper_limit_for_iops_of_volume:
            description: The upper limit of volume performance (in IOPS) of the VPS.
              This is used as the default value for the upper limit of performance (in IOPS) of volumes created on the VPS.
              To set the upper limit of volume performance (in IOPS), specify a value in the range from 100 to 2147483647.
              To set no upper limit, specify -1. If you specify values from 0 to 99, jobs will be unsuccessful.
              The VPS administrator who creates volumes can set a value that is no more than this value as the upper limit of performance
              (in IOPS) for each volume. If you make both of the upper_limit_for_iops_of_volume and upper_limit_for_transfer_rate_of_volume_mbps
              settings unavailable, the setting of upper_alert_allowable_time_of_volume is also made unavailable.
              If this property is omitted, -1 is assumed to be specified.
            type: int
            required: false
          upper_limit_for_transfer_rate_of_volume_mbps:
            description: The upper limit of volume performance (in MiB/s) for the VPS.
              This is used as the default value for the upper limit of performance (in MiB/s) of volumes created on the VPS.
              To set the upper limit of volume performance (in MiB/s), specify a value in the range from 1 to 2097151. To set no
              upper limit, specify -1. If you specify 0, jobs will be unsuccessful.
              The VPS administrator who creates volumes can set a value that is no more than this value as the upper limit of performance
              (in MiB/s) for each volume. If you make both of the upper_limit_for_iops_of_volume and upper_limit_for_transfer_rate_of_volume_mbps
              settings unavailable, the setting of upperAlertAllowableTimeOfVolume is also made unavailable.
              If this property is omitted, -1 is assumed to be specified.
            type: int
            required: false
          upper_alert_allowable_time_of_volume:
            description: The alert threshold value (in seconds) for the upper limit of volume performance for the VPS.
              This is used as the default value for the alert threshold for the upper limit of performance of volumes created on the VPS.
              To set the alert threshold, specify a value in the range from 1 to 600. To set no alert threshold, specify -1.
              If you specify 0, jobs will be unsuccessful.
              A message is output to the event log when restriction of the upper limit of performance specified by upper_limit_for_iops_of_volume or
              upper_limit_for_transfer_rate_of_volume_mbps continues for the specified length of time. This property can be specified if either
              upper_limit_for_iops_of_volume or upper_limit_for_transfer_rate_of_volume_mbps, or both, is set.
              If this property is omitted, -1 is assumed to be specified.
            type: int
            required: false
          capacity_saving:
            description: Capacity saving for the VPS volumes.
            type: str
            required: false
            choices: ['Disabled', 'Compression']
            default: 'Disabled'
      upper_limit_for_number_of_volumes:
        description: The upper limit of the number of volumes on the VPS. Valid for update VPS settings.
          For details about the values to be specified for upper_limit_for_number_of_volumes, contact customer support.
        type: int
        required: false
      upper_limit_for_capacity_of_volumes_mb:
        description: The upper limit of the total volume capacity (in MiB) of the VPS. Values between 0 and 9223372036854775807.
          This field is valid for update VPS settings.
          For details about the values to be specified for upper_limit_for_capacity_of_volumes_mb, contact customer support.
        type: int
        required: false
      upper_limit_for_capacity_of_single_volume_mb:
        description: The upper limit of the capacity (in MiB) of a single volume of the VPS. Values between 0 and 6871947674.
          This field is valid for update VPS settings. To place no limit on the capacity of a single volume, specify -1.
          For details about the values to be specified for upper_limit_for_capacity_of_single_volume_mb, contact customer support.
        type: int
        required: false
      upper_limit_for_iops_of_volume:
        description: The upper limit of volume performance (in IOPS) of the VPS. This field is valid for update VPS settings.
          This is used as the default value for the upper limit of performance (in IOPS) of volumes created on the VPS.
          To set the upper limit of volume performance (in IOPS), specify a value in the range from 100 to 2147483647.
          To set no upper limit, specify -1. If you specify values from 0 to 99, jobs will be unsuccessful.
          The VPS administrator who creates volumes can set a value that is no more than this value as the upper limit of performance
          (in IOPS) for each volume. If you make both of the upper_limit_for_iops_of_volume and upper_limit_for_transfer_rate_of_volume_mbps
          settings unavailable, the setting of upper_alert_allowable_time_of_volume is also made unavailable.
          If this property is omitted, -1 is assumed to be specified.
        type: int
        required: false
      upper_limit_for_transfer_rate_of_volume_mbps:
        description: The upper limit of volume performance (in MiB/s) for the VPS. This field is valid for update VPS settings.
          This is used as the default value for the upper limit of performance (in MiB/s) of volumes created on the VPS.
          To set the upper limit of volume performance (in MiB/s), specify a value in the range from 1 to 2097151. To set no
          upper limit, specify -1. If you specify 0, jobs will be unsuccessful.
          The VPS administrator who creates volumes can set a value that is no more than this value as the upper limit of performance
          (in MiB/s) for each volume. If you make both of the upper_limit_for_iops_of_volume and upper_limit_for_transfer_rate_of_volume_mbps
          settings unavailable, the setting of upperAlertAllowableTimeOfVolume is also made unavailable.
          If this property is omitted, -1 is assumed to be specified.
        type: int
        required: false
      upper_alert_allowable_time_of_volume:
        description: The alert threshold value (in seconds) for the upper limit of volume performance for the VPS. This field is valid for update VPS settings.
          This is used as the default value for the alert threshold for the upper limit of performance of volumes created on the VPS.
          To set the alert threshold, specify a value in the range from 1 to 600. To set no alert threshold, specify -1.
          If you specify 0, jobs will be unsuccessful.
          A message is output to the event log when restriction of the upper limit of performance specified by upper_limit_for_iops_of_volume or
          upper_limit_for_transfer_rate_of_volume_mbps continues for the specified length of time. This property can be specified if either
          upper_limit_for_iops_of_volume or upper_limit_for_transfer_rate_of_volume_mbps, or both, is set.
          If this property is omitted, -1 is assumed to be specified.
        type: int
        required: false
      capacity_saving:
        description: Capacity saving for the VPS volumes.
        type: str
        required: false
        choices: ['Disabled', 'Compression']
        default: 'Disabled'
"""

EXAMPLES = """
- name: Create a VPS
  hitachivantara.vspone_block.sds_block.hv_sds_block_vps:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      name: "RKD_VPS_02"
      upper_limit_for_number_of_user_groups: 10
      upper_limit_for_number_of_users: 5
      upper_limit_for_number_of_sessions: 20
      upper_limit_for_number_of_servers: 200
      volume_settings:
        - pool_id: "b78fe7d7-22f3-4d43-a9cf-81af3b4d7bf6"
          upper_limit_for_number_of_volumes: 20
          upper_limit_for_capacity_of_volumes_mb: 300000
          upper_limit_for_capacity_of_single_volume_mb: -1
          upper_limit_for_iops_of_volume: -1
          upper_limit_for_transfer_rate_of_volume_mbps: -1
          upper_alert_allowable_time_of_volume: -1
          capacity_saving: "Disabled"

- name: Update settings of a VPS
  hitachivantara.vspone_block.sds_block.hv_sds_block_vps:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "ae0f247c-dc56-491c-9cb9-4b2b6d33b345"
      name: "RKD_VPS_03"
      upper_limit_for_number_of_user_groups: 15
      upper_limit_for_number_of_users: 10
      upper_limit_for_number_of_servers: 300
      upper_limit_for_number_of_sessions: 25
      upper_limit_for_number_of_volumes: 22
      upper_limit_for_capacity_of_volumes_mb: 330000
      upper_limit_for_capacity_of_single_volume_mb: 30000
      capacity_saving: "Disabled"
      upper_limit_for_iops_of_volume: 21474836
      upper_limit_for_transfer_rate_of_volume_mbps: 50
      upper_alert_allowable_time_of_volume: 40

- name: Delete a VPS by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_vps:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
      spec:
        id: "ae0f247c-dc56-491c-9cb9-4b2b6d33b345"
"""

RETURN = """
vps:
  description: Attributes of the VPS.
  returned: always
  type: dict
  contains:
    id:
      description: ID of the VPS.
      type: str
      sample: "969963dd-6f5c-418d-abd0-2341e767d898"
    name:
      description: Name of the VPS.
      type: str
      sample: "testvps"
    number_of_hbas_created:
      description: Number of HBAs created.
      type: int
      sample: 0
    number_of_servers_created:
      description: Number of servers created.
      type: int
      sample: 0
    number_of_sessions_created:
      description: Number of sessions created.
      type: int
      sample: 0
    number_of_user_groups_created:
      description: Number of user groups created.
      type: int
      sample: 0
    number_of_users_created:
      description: Number of users created.
      type: int
      sample: 0
    number_of_volume_server_connections_created:
      description: Number of volume server connections created.
      type: int
      sample: 0
    upper_limit_for_number_of_hbas:
      description: Upper limit for the number of HBAs.
      type: int
      sample: 800
    upper_limit_for_number_of_servers:
      description: Upper limit for the number of servers.
      type: int
      sample: 200
    upper_limit_for_number_of_sessions:
      description: Upper limit for the number of sessions.
      type: int
      sample: 20
    upper_limit_for_number_of_user_groups:
      description: Upper limit for the number of user groups.
      type: int
      sample: 10
    upper_limit_for_number_of_users:
      description: Upper limit for the number of users.
      type: int
      sample: 5
    upper_limit_for_number_of_volume_server_connections:
      description: Upper limit for the number of volume server connections.
      type: int
      sample: 40
    volume_settings:
      description: Settings for the volumes.
      type: dict
      contains:
        capacity_of_volumes_created:
          description: Capacity of volumes created (MiB).
          type: int
          sample: 0
        capacity_saving_of_volume:
          description: Capacity saving mode of the volume.
          type: str
          sample: "Disabled"
        number_of_volumes_created:
          description: Number of volumes created.
          type: int
          sample: 0
        pool_id:
          description: Pool ID associated with the volume.
          type: str
          sample: "80d306ea-d224-4fb1-a746-5ed41994e708"
        qos_param:
          description: Quality of Service parameters for the volume.
          type: dict
          contains:
            upper_alert_allowable_time_of_volume:
              description: Upper alert allowable time of the volume.
              type: int
              sample: -1
            upper_limit_for_iops_of_volume:
              description: Upper limit for IOPS of the volume.
              type: int
              sample: -1
            upper_limit_for_transfer_rate_of_volume:
              description: Upper limit for transfer rate of the volume.
              type: int
              sample: -1
        saving_mode_of_volume:
          description: Saving mode of the volume (boolean flag).
          type: bool
          sample: false
        upper_limit_for_capacity_of_single_volume:
          description: Upper limit for the capacity of a single volume (MiB).
          type: int
          sample: -1
        upper_limit_for_capacity_of_volumes:
          description: Upper limit for the capacity of volumes (MiB).
          type: int
          sample: 300000
        upper_limit_for_number_of_volumes:
          description: Upper limit for the number of volumes.
          type: int
          sample: 20
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_vps import (
    SDSBVpsReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBVpsArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

logger = Log()


class SDSBVpsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBVpsArguments().vps()
        logger.writeDebug(f"MOD:hv_sds_block_vps:argument_spec= {self.argument_spec}")
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.state = parameter_manager.get_state()
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_vps_spec()
        logger.writeDebug(f"MOD:hv_sds_block_vsp:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB VPS Operation ===")
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBVpsReconciler(self.connection_info)
            vps = sdsb_reconciler.reconcile_vps(self.state, self.spec)

            logger.writeDebug(f"MOD:hv_sds_block_vps:vps= {vps}")

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB VPS Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "vps": vps,
        }

        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB VPS Operation ===")
        self.module.exit_json(**response)


def main(module=None):
    obj_store = SDSBVpsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
