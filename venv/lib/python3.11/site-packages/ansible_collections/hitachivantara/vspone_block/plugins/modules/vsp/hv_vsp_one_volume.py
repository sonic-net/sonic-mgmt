#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_volume
short_description: Manages volumes on VSP E series and VSP One Block 20 series storage systems.
description:
  - This module enables creation, modification, and deletion of volumes, as well as attaching and detaching to servers.
  - Supports various volume operations depending on the specified state parameter.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for volume management across VSP one B20 series and VSP E series models.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_volume.yml)
version_added: '4.2.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Specifies whether the module operates in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.connection_info
options:
  state:
    description: Defines the volume operation type. Available options include C(present), C(absent), C(attach_server), and C(detach_server).
    type: str
    required: false
    choices: ['present', 'absent', 'attach_server', 'detach_server', 'change_qos_settings', 'server_present']
    default: 'present'
  spec:
    description: Configuration parameters for the volume operation.
    type: dict
    required: true
    suboptions:
      capacity:
        description: Volume size specification.
        type: str
        required: false
      number_of_volumes:
        description: Quantity of volumes to create.
        type: int
        required: false
        default: 1
      volume_name:
        description: Naming configuration for the volume.
        type: dict
        required: false
        suboptions:
          base_name:
            description: Foundation name for volume naming.
            type: str
            required: true
          start_number:
            description: Initial number for volume name sequencing.
            type: int
            required: false
          number_of_digits:
            description: Digit count for the numerical portion of volume names.
            type: int
            required: false
      is_data_reduction_share_enabled:
        description: Activates data reduction sharing functionality.
        type: bool
        required: false
        default: false
      pool_id:
        description: Storage pool identifier.
        type: int
        required: false
      volume_id:
        description: Volume identifier.
        type: str
        required: false
      volume_ids:
        description: Collection of volume identifiers for batch operations to add servers.
        type: list
        required: false
        elements: str
      qos_settings:
        description: Quality of service configuration for the volume.
        type: dict
        required: false
        suboptions:
          threshold:
            description: QoS threshold configuration.
            type: dict
            required: false
            suboptions:
              is_upper_iops_enabled:
                description: Activates maximum IOPS restriction.
                type: bool
                required: false
              upper_iops:
                description: Maximum IOPS threshold.
                type: int
                required: false
              is_upper_transfer_rate_enabled:
                description: Activates maximum transfer rate restriction.
                type: bool
                required: false
              upper_transfer_rate:
                description: Maximum transfer rate threshold.
                type: int
                required: false
              is_lower_iops_enabled:
                description: Activates minimum IOPS restriction.
                type: bool
                required: false
              lower_iops:
                description: Minimum IOPS threshold.
                type: int
                required: false
              is_lower_transfer_rate_enabled:
                description: Activates minimum transfer rate restriction.
                type: bool
                required: false
              lower_transfer_rate:
                description: Minimum transfer rate threshold.
                type: int
                required: false
              is_response_priority_enabled:
                description: Activates response priority setting.
                type: bool
                required: false
              response_priority:
                description: Response priority level.
                type: int
                required: false
          alert_setting:
            description: QoS alert configuration.
            type: dict
            required: false
            suboptions:
              is_upper_alert_enabled:
                description: Activates upper threshold alerts.
                type: bool
                required: false
              upper_alert_allowable_time:
                description: Permitted duration for upper threshold alerts.
                type: int
                required: false
              is_lower_alert_enabled:
                description: Activates lower threshold alerts.
                type: bool
                required: false
              lower_alert_allowable_time:
                description: Permitted duration for lower threshold alerts.
                type: int
                required: false
              is_response_alert_enabled:
                description: Activates response time alerts.
                type: bool
                required: false
              response_alert_allowable_time:
                description: Permitted duration for response time alerts.
                type: int
                required: false
      server_ids:
        description: Collection of server identifiers for volume attachment.
        type: list
        required: false
        elements: int
      capacity_saving:
        description: Data reduction function configuration.
        type: str
        required: false
        aliases: ["saving_setting"]
        choices: ["compression", "deduplication_and_compression", "disable"]
      compression_acceleration:
        description: Controls compression acceleration feature.
        type: bool
        required: false
"""

EXAMPLES = """
- name: Create a volume with capacity and pool_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      capacity: 1GB
      pool_id: 1

- name: Create multiple volumes with custom nickname sequence
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      number: 3
      volume_name:
        base_name: "DataVol"
        start_number: 10
        number_of_digits: 3
      pool_id: 2

- name: Create volume with data reduction sharing enabled
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      capacity: 200MB
      is_data_reduction_share_enabled: true
      pool_id: 3

- name: Update volume with QoS threshold settings
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      volume_id: 12
      qos_settings:
        threshold:
          is_upper_iops_enabled: true
          upper_iops: 5000
          is_lower_iops_enabled: true
          lower_iops: 1000
          is_upper_transfer_rate_enabled: true
          upper_transfer_rate: 200
          is_lower_transfer_rate_enabled: false
          is_response_priority_enabled: true
          response_priority: 2

- name: Attach volume to servers
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: attach_server
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      volume_id: 1234
      server_ids:
        - "server-01"
        - "server-02"

- name: Detach volume from servers
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: detach_server
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      volume_id: 1234
      server_ids:
        - "server-01"

- name: Create volume with data reduction setting
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      capacity: 120GB
      pool_id: 5
      capacity_saving: "deduplication_and_compression"

- name: Delete volume by volume_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_volume:
    state: absent
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      volume_id: 1234
"""

RETURN = """
volume:
  description: Information of the volume object.
  returned: always
  type: list
  elements: dict
  contains:
    id:
      description: ID of the volume.
      type: int
    id_hex:
      description: ID of the volume in hexadecimal.
      type: str
    nickname:
      description: Nickname of the volume.
      type: str
    pool_id:
      description: ID of the pool.
      type: int
    pool_name:
      description: Name of the pool.
      type: str
    total_capacity:
      description: Total capacity of the volume.
      type: int
    total_capacity_in_mb:
      description: Total capacity in MB.
      type: str
    used_capacity:
      description: Used capacity of the volume.
      type: int
    used_capacity_in_mb:
      description: Used capacity in MB.
      type: str
    free_capacity:
      description: Free capacity of the volume.
      type: int
    free_capacity_in_mb:
      description: Free capacity in MB.
      type: str
    reserved_capacity:
      description: Reserved capacity of the volume.
      type: int
    capacity_saving:
      description: Capacity saving setting (e.g., COMPRESSION).
      type: str
    capacity_saving_status:
      description: Capacity saving status.
      type: str
    compression_acceleration:
      description: Whether compression acceleration is enabled.
      type: bool
    compression_acceleration_status:
      description: Compression acceleration status.
      type: str
    is_data_reduction_share_enabled:
      description: Whether data reduction share is enabled.
      type: bool
    luns:
      description: List of LUNs associated with the volume.
      type: list
      elements: dict
    number_of_connecting_servers:
      description: Number of servers connected to the volume.
      type: int
    number_of_snapshots:
      description: Number of snapshots for the volume.
      type: int
    qos_settings:
      description: QoS settings for the volume.
      type: dict
    volume_types:
      description: List of volume types.
      type: list
      elements: str
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_volume_simple_api_reconciler import (
    VSPVolumeSimpleAPIReconciler,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPVolumeSimpleAPIArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPSimpleVolume:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPVolumeSimpleAPIArguments().get_volume_simple_api_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_volume_spec()
            self.connection_info = params_manager.get_connection_info()
            self.serial = params_manager.get_serial()
            self.state = params_manager.get_state()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP Volume Operation ===")
        volume = None
        registration_message = validate_ansible_product_registration()

        try:
            volume_reconciler = VSPVolumeSimpleAPIReconciler(self.connection_info)
            volume = volume_reconciler.reconcile(self.state, self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP Volume Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "volume": volume,
            "comments": self.spec.comments if self.spec.comments else [],
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP Volume Operation ===")
        self.module.exit_json(**response)


def main():
    obj_store = VSPSimpleVolume()
    obj_store.apply()


if __name__ == "__main__":
    main()
