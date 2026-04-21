#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_server_hba_facts
short_description: Retrieves server HBA information from VSP E series and VSP One Block 20 series storage systems.
description:
    - This module retrieves HBA (Host Bus Adapter) information about servers from  VSP E series and VSP One Block 20 series storage systems.
    - Utilizes the Hitachi Virtual Storage Platform One Simple API for server HBA facts retrieval across VSP one B20 series and VSP E series models.
    - For usage examples, visit
        U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_server_hba_facts.yml)
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
        description: Query parameters for retrieving server HBA information.
        type: dict
        required: false
        suboptions:
            server_id:
                description: Server identifier to retrieve specific server HBA information.
                type: int
                required: false
            nick_name:
                description: Server nickname to filter servers.
                type: str
                required: false
            hba_wwn:
                description: HBA WWN to filter servers.
                type: str
                required: false
            iscsi_name:
                description: iSCSI name to filter servers.
                type: str
                required: false
"""

EXAMPLES = """
- name: Get server HBA information by server ID
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_hba_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 31

- name: Get server HBA information by HBA WWN
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_hba_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      hba_wwn: "210003e08b0256f9"
      server_id: 31

- name: Get server HBA information by iSCSI name
  hitachivantara.vspone_block.vsp.hv_vsp_one_server_hba_facts:
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      iscsi_name: "iqn.1994-04.jp.co.hitachi:rsd.has.i.00001d.1c"
      server_id: 31
"""

RETURN = """
ansible_facts:
  description: Facts about server HBAs retrieved from the storage system.
  returned: always
  type: dict
  contains:
    hbas:
      description: Server HBA information retrieved from the storage system.
      returned: always
      type: dict
      contains:
        hba_wwn:
          description: HBA WWN address.
          type: str
          sample: ""
        iscsi_name:
          description: iSCSI name for the HBA.
          type: str
          sample: "iqn.1994-04.jp.co.hitachi:rsd.has.i.00001d.1c"
        port_ids:
          description: List of port identifiers associated with this HBA.
          type: list
          elements: str
          sample: ["CL1-C"]
        server_id:
          description: Server identifier that this HBA belongs to.
          type: int
          sample: 31
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


class VSPOneHBAFacts:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPOneServerArguments().get_vsp_one_hba_facts_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_server_hba_facts_spec()
            self.connection_info = params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One HBA Server Facts Retrieval ===")
        hbas = None
        registration_message = validate_ansible_product_registration()

        try:
            server_reconciler = VSPServerSimpleAPIReconciler(self.connection_info)
            hbas = server_reconciler.server_hbas_facts_reconcile(self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP One HBA Server Facts Retrieval ===")
            self.module.fail_json(msg=str(e))

        response = {
            "hbas": hbas,
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One HBA Server Facts Retrieval ===")
        self.module.exit_json(changed=False, ansible_facts=response)


def main():
    obj_store = VSPOneHBAFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
