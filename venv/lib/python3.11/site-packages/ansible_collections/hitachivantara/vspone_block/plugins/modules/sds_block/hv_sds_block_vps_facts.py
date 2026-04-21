#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_vps_facts
short_description: Retrieves information about Virtual Private Storages (VPS) of VSP One SDS Block and Cloud systems.
description:
  - This module retrieves information about Virtual Private Storages.
  - It provides details about a Virtual Private Storages such as number of servers created, number of volumes created etc.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/vps_facts.yml)
version_added: '3.1.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
options:
  spec:
    description: Specification for retrieving VPS information.
    type: dict
    required: false
    suboptions:
      id:
        description: ID of the VPS to retrieve information for.
        type: str
        required: false
      name:
        description: VPS name to retrieve information for.
        type: str
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all VPS
  hitachivantara.vspone_block.sds_block.hv_sds_block_vps_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about a specific VPS by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_vps_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      id: "464e1fd1-9892-4134-866c-6964ce786676"

- name: Retrieve information about a specific VPS user by name
  hitachivantara.vspone_block.sds_block.hv_sds_block_vps_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

    spec:
      name: "VPS_01"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the Virtual Private Storages (VPS).
  returned: always
  type: dict
  contains:
    vsp_info:
      description: Dictionary containing VPS list and summary information.
      type: dict
      contains:
        vsp_info:
          description: List of VPS with their attributes.
          type: list
          elements: dict
          contains:
            id:
              description: ID of the VPS.
              type: str
              sample: "d2c1fa60-5c41-486a-9551-ec41c74d9f01"
            name:
              description: Name of the VPS.
              type: str
              sample: "VPS_01"
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
              description: Upper limit for number of HBAs.
              type: int
              sample: 400
            upper_limit_for_number_of_servers:
              description: Upper limit for number of servers.
              type: int
              sample: 100
            upper_limit_for_number_of_sessions:
              description: Upper limit for number of sessions.
              type: int
              sample: 436
            upper_limit_for_number_of_user_groups:
              description: Upper limit for number of user groups.
              type: int
              sample: 256
            upper_limit_for_number_of_users:
              description: Upper limit for number of users.
              type: int
              sample: 256
            upper_limit_for_number_of_volume_server_connections:
              description: Upper limit for number of volume server connections.
              type: int
              sample: 100
            volume_settings:
              description: Volume settings for the VPS.
              type: dict
              contains:
                capacity_of_volumes_created:
                  description: Capacity of volumes created.
                  type: int
                  sample: 0
                capacity_saving_of_volume:
                  description: Capacity saving mode of the volume.
                  type: str
                  sample: "Compression"
                number_of_volumes_created:
                  description: Number of volumes created.
                  type: int
                  sample: 0
                pool_id:
                  description: Pool ID associated with the volume.
                  type: str
                  sample: "f5ef8935-ed38-4894-a90b-f821ab6d3d89"
                qos_param:
                  description: QoS parameters for the volume.
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
                  description: Saving mode of the volume.
                  type: raw
                  sample: false
                upper_limit_for_capacity_of_single_volume:
                  description: Upper limit for capacity of a single volume.
                  type: int
                  sample: -1
                upper_limit_for_capacity_of_volumes:
                  description: Upper limit for capacity of volumes.
                  type: int
                  sample: 100
                upper_limit_for_number_of_volumes:
                  description: Upper limit for number of volumes.
                  type: int
                  sample: 50
        vsp_summary_info:
          description: Summary information of the VPS.
          type: dict
          contains:
            total_count:
              description: Total count of VPS.
              type: int
              sample: 1
            total_upper_limit_for_capacity_of_volumes:
              description: Total upper limit for capacity of volumes.
              type: int
              sample: 100
            total_upper_limit_for_number_of_hbas:
              description: Total upper limit for number of HBAs.
              type: int
              sample: 400
            total_upper_limit_for_number_of_servers:
              description: Total upper limit for number of servers.
              type: int
              sample: 100
            total_upper_limit_for_number_of_sessions:
              description: Total upper limit for number of sessions.
              type: int
              sample: 436
            total_upper_limit_for_number_of_user_groups:
              description: Total upper limit for number of user groups.
              type: int
              sample: 256
            total_upper_limit_for_number_of_users:
              description: Total upper limit for number of users.
              type: int
              sample: 256
            total_upper_limit_for_number_of_volume_server_connections:
              description: Total upper limit for number of volume server connections.
              type: int
              sample: 100
            total_upper_limit_for_number_of_volumes:
              description: Total upper limit for number of volumes.
              type: int
              sample: 50
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


class SDSBVpsFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBVpsArguments().vps_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_vps_fact_spec()
        self.logger.writeDebug(f"MOD:hv_sds_block_vsp_facts:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB VPS Facts ===")
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBVpsReconciler(self.connection_info)
            vps = sdsb_reconciler.get_vps_facts(self.spec)

            self.logger.writeDebug(f"MOD:hv_sds_block_vps_facts:vps= {vps}")

        except Exception as e:
            self.logger.writeInfo("=== End of SDSB VPS Facts ===")
            self.module.fail_json(msg=str(e))
        data = {"vsp_info": vps}

        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB VPS Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main(module=None):
    obj_store = SDSBVpsFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
