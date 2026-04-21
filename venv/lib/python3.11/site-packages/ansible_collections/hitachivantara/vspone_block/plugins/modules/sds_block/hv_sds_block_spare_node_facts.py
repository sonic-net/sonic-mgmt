#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_spare_node_facts
short_description: Get spare node information from VSP One SDS Block and Cloud systems.
description:
    - This module retrieves spare node information and configuration details from VSP One SDS Block and Cloud systems.
    - For examples, go to URL
        U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/spare_node_facts.yml)
version_added: "4.4.0"
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
      description: Configuration specifications for spare node management.
      required: false
      type: dict
      suboptions:
        id:
            description: Unique identifier for the spare node.
            required: false
            type: str

"""

EXAMPLES = """
- name: Retrieve all spare node information
  hitachivantara.vspone_block.hv_sds_block_spare_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Retrieve specific spare node information by ID
  hitachivantara.vspone_block.hv_sds_block_spare_node_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "spare-node-001"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the spare nodes.
  returned: always
  type: dict
  contains:
    spare_nodes:
      description: List of spare node configurations.
      type: list
      elements: dict
      contains:
        id:
          description: Unique identifier for the spare node.
          type: str
          sample: "spare-node-01"
        name:
          description: Name of the spare node.
          type: str
          sample: "spare-node-01"
        fault_domain_id:
          description: Identifier for the fault domain where the spare node belongs.
          type: str
          sample: "fd-001"
        fault_domain_name:
          description: Name of the fault domain where the spare node belongs.
          type: str
          sample: "fault-domain-001"
        control_port_ipv4_address:
          description: IPv4 address for the control port of the spare node.
          type: str
          sample: "192.168.1.100"
        software_version:
          description: Software version of the spare node.
          type: str
          sample: "1.0.0"
        bios_uuid:
          description: BIOS UUID of the spare node.
          type: str
          sample: "12345678-1234-1234-1234-123456789abc"
        model_name:
          description: Model name of the spare node.
          type: str
          sample: "HV-SDSB-001"
        serial_number:
          description: Serial number of the spare node.
          type: str
          sample: "SN123456789"
        bmc_name:
          description: Name of the Baseboard Management Controller (BMC).
          type: str
          sample: "spare-bmc-01"
        bmc_user:
          description: Username for BMC authentication.
          type: str
          sample: "admin"
"""

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_storage_cluster_mgmt_reconciler import (
    SDSBStorageControllerReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SpareNodeArgs,
    SDSBParametersManager,
)
from ansible.module_utils.basic import AnsibleModule


class SDSBBlockSpareNodeFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SpareNodeArgs().spare_node_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.spare_node_fact_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of Spare Nodes Facts ===")
        spare_nodes = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBStorageControllerReconciler(self.connection_info)
            spare_nodes = sdsb_reconciler.spare_node_facts_reconcile(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of Spare Nodes Facts ===")
            self.module.fail_json(msg=str(e))

        data = {"spare_nodes": spare_nodes}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of Spare Nodes Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBBlockSpareNodeFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
