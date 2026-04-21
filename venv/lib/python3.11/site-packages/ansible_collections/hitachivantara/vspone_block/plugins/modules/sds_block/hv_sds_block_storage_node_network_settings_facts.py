#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_storage_node_network_settings_facts
short_description: Get storage node network settings from VSP One SDS Block and Cloud systems.
description:
  - Get storage node network settings from the storage system.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/storage_node_facts.yml)
version_added: '4.1.0'
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
    description: Specification for retrieving job information.
    type: dict
    required: false
    suboptions:
      id:
        description: Filter internode port by ID (UUID format).
        type: str
      storage_node_name:
        description: Filter control port by storage node name.
        type: str
        required: false
"""

EXAMPLES = """
- name: Retrieve information about all storage_node_network_settings
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_network_settings_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve information about storage_node_network_settings by specifying id
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_node_network_settings_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "126f360e-c79e-4e75-8f7c-7d91bfd2f0b8"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered storage_node_network_settings.
  returned: always
  type: dict
  contains:
    storage_node_network_settings:
      description: Storage node network settings facts.
      type: dict
      contains:
        data:
          description: List of storage node network setting entries.
          type: list
          elements: dict
          contains:
            id:
              description: Unique identifier for the storage node network setting.
              type: str
              sample: "1a21c76d-614a-45e1-bd02-6bd2c18dddd7"
            ipv4_route:
              description: List of IPv4 route entries configured on the storage node.
              type: list
              elements: dict
              contains:
                destination:
                  description: Destination network for the route.
                  type: str
                  sample: "default"
                gateway:
                  description: Gateway IP address used for the route.
                  type: str
                  sample: "10.76.34.1"
                interface:
                  description: Network interface name used for the route.
                  type: str
                  sample: "eth0"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBControlPortArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_control_port_reconciler import (
    SDSBControlPortReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockStorageNodeNetworkSettingFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = (
            SDSBControlPortArguments().storage_node_nw_setting_port_facts()
        )
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_control_port_fact_spec()
        self.logger.writeDebug(f"MOD:storage_node_network_settings:spec= {self.spec}")

    def apply(self):
        self.logger.writeInfo(
            "=== Start of SDSB Storage Node Network Setting Facts ==="
        )
        control_port = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBControlPortReconciler(self.connection_info)
            control_port = sdsb_reconciler.get_storage_node_network_settings(self.spec)

            self.logger.writeDebug(
                f"MOD:storage_node_network_settings:storage_node_network_settings= {control_port}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo(
                "=== End of SDSB Storage Node Network Setting Facts ==="
            )
            self.module.fail_json(msg=str(e))

        data = {"storage_node_network_settings": control_port}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Storage Node Network Setting Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockStorageNodeNetworkSettingFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
