#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_storage_network_setting_facts
short_description: Get storage network settings from VSP One SDS Block and Cloud systems.
description:
  - Get storage network settings from the storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_storage_node_network_setting_facts.yml)
version_added: "4.1.0"
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
"""

EXAMPLES = """
- name: Retrieve information about Storage Time
  hitachivantara.vspone_block.sds_block.hv_sds_block_storage_network_setting_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered storage network settings and optional
    registration/user-consent message.
  returned: always
  type: dict
  contains:
    network_settings:
      description: Storage network settings.
      type: dict
      returned: always
      contains:
        primary_dns_server_ip_address:
          description: IP address of the primary DNS server. Empty if not configured.
          type: str
          sample: "10.76.46.10"
        secondary_dns_server_ip_address:
          description: IP address of the secondary DNS server. Empty if not configured.
          type: str
          sample: ""
        virtual_ipv4_address:
          description: Virtual IPv4 address assigned to the system.
          type: str
          sample: "10.76.34.110"
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBParametersManager,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_cluster_information_reconciler import (
    SDSBClusterInformationReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockNetworkSettingsFactsManager:
    def __init__(self):
        self.logger = Log()
        argument_spec = {
            "connection_info": {
                "required": True,
                "type": "dict",
                "options": {
                    "address": {"required": True, "type": "str"},
                    "username": {"required": True, "type": "str"},
                    "password": {"required": True, "type": "str", "no_log": True},
                    "connection_type": {
                        "required": False,
                        "type": "str",
                        "choices": ["direct"],
                        "default": "direct",
                    },
                },
            }
        }

        self.module = AnsibleModule(
            argument_spec=argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Storage Network Setting Facts ===")
        settings = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBClusterInformationReconciler(self.connection_info)
            settings = sdsb_reconciler.get_storage_network_settings()

            self.logger.writeDebug(
                f"MOD:get_storage_network_settings:get_storage_time_settings= {settings}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Storage Network Setting Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"network_settings": settings}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Storage Network Setting Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockNetworkSettingsFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
