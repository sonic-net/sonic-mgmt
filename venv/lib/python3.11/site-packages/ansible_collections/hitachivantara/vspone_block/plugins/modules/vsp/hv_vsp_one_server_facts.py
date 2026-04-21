#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_server_facts
short_description: Retrieves server information from VSP E series and VSP One Block 20 series storage systems.
description:
  - This module retrieves information about servers from VSP E series and VSP One Block 20 series storage systems.
  - Supports filtering servers by various criteria such as server ID, nickname, HBA WWN, or iSCSI name.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for server facts retrieval across VSP one B20 series and VSP E series models.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_server_facts.yml)
version_added: '4.3.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Specifies whether the module operates in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.connection_info
options:
  spec:
    description: Query parameters for retrieving server information.
    type: dict
    required: false
    suboptions:
      server_id:
        description: Server identifier to retrieve specific server information.
        type: int
        required: false
      nick_name:
        description: Server nickname to filter servers by name.
        type: str
        required: false
      hba_wwn:
        description: HBA WWN address to filter servers containing this WWN.
        type: str
        required: false
      iscsi_name:
        description: iSCSI name to filter servers containing this iSCSI initiator.
        type: str
        required: false
      include_details:
        description: Whether to include detailed server information.
        type: bool
        required: false
        default: false
"""

EXAMPLES = """
- name: Get all servers
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"

- name: Get all servers with details
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      include_details: true

- name: Get server by server ID
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123

- name: Get servers by nickname
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "WebServer01"

- name: Get servers containing specific HBA WWN
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      hba_wwn: "210003e08b0256f9"

- name: Get servers containing specific iSCSI name
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      iscsi_name: "iqn.1991-05.com.microsoft:server01"
"""

RETURN = """
ansible_facts:
  description: Facts about servers retrieved from the storage system.
  returned: always
  type: dict
  contains:
    servers:
      description: Server information retrieved from the storage system.
      returned: always
      type: list
      elements: dict
      contains:
        compatibility:
          description: Server compatibility information.
          type: str
          sample: ""
        has_non_fullmesh_lu_paths:
          description: Whether the server has non-fullmesh LU paths.
          type: bool
          sample: null
        has_unaligned_os_type_options:
          description: Whether the server has unaligned OS type options.
          type: bool
          sample: null
        has_unaligned_os_types:
          description: Whether the server has unaligned OS types.
          type: bool
          sample: false
        id:
          description: Server identifier.
          type: int
          sample: 17
        is_inconsistent:
          description: Whether the server configuration is inconsistent.
          type: bool
          sample: false
        is_reserved:
          description: Whether the server is reserved.
          type: bool
          sample: false
        iscsi_targets:
          description: List of iSCSI targets for the server.
          type: list
          elements: dict
          sample: []
        modification_in_progress:
          description: Whether modification is in progress.
          type: bool
          sample: false
        nickname:
          description: Server nickname.
          type: str
          sample: "WebServer414"
        number_of_paths:
          description: Number of paths configured for the server.
          type: int
          sample: 1
        number_of_volumes:
          description: Number of volumes attached to the server.
          type: int
          sample: -1
        os_type:
          description: Operating system type.
          type: str
          sample: "Linux"
        os_type_options:
          description: List of OS type option identifiers.
          type: list
          elements: int
          sample: []
        paths:
          description: List of server paths with HBA and port information.
          type: list
          elements: dict
          contains:
            hba_wwn:
              description: HBA WWN address for the path.
              type: str
              sample: "210003e08b0256f9"
            iscsi_name:
              description: iSCSI name for the path (empty for FC).
              type: str
              sample: ""
            port_ids:
              description: List of port identifiers for this path.
              type: list
              elements: str
              sample: ["CL1-A"]
          sample: []
        protocol:
          description: Server protocol type.
          type: str
          sample: "FC"
        total_capacity:
          description: Total capacity allocated to the server.
          type: int
          sample: 0
        used_capacity:
          description: Used capacity by the server.
          type: int
          sample: 0
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.vsp_one_server_reconciler import (
    VSPServerSimpleAPIReconciler,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPOneServerArguments,
    VSPParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPOneServerFacts:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPOneServerArguments().get_vsp_one_server_facts_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_one_server_facts_spec()
            self.connection_info = params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One Server Facts Retrieval ===")
        servers = None
        registration_message = validate_ansible_product_registration()

        try:
            server_reconciler = VSPServerSimpleAPIReconciler(self.connection_info)
            servers = server_reconciler.server_facts_reconcile(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP One Server Facts Retrieval ===")
            self.module.fail_json(msg=str(e))

        response = {
            "servers": servers,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One Server Facts Retrieval ===")
        self.module.exit_json(changed=False, ansible_facts=response)


def main():
    obj_store = VSPOneServerFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
