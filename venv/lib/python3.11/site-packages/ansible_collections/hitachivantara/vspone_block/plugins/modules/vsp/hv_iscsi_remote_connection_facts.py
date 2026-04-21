#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_iscsi_remote_connection_facts
short_description: Retrieves Remote connection details from Hitachi VSP storage systems.
description: >
  - This module retrieves information about remote connections thorough iSCSI ports from Hitachi VSP storage systems.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/remote_iscsi_connection_facts.yml)
version_added: '3.3.0'
author:
  - Hitachi Vantara, LTD. (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
- hitachivantara.vspone_block.common.gateway_note
- hitachivantara.vspone_block.common.connection_without_token
"""

EXAMPLES = """
- name: Get all remote connection details
  hitachivantara.vspone_block.vsp.hv_iscsi_remote_connection_facts:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "password"
"""

RETURN = """
ansible_facts:
    description: The collected facts.
    returned: success
    type: dict
    contains:
        remote_connections:
            description: Newly created remote connection object.
            returned: success
            type: list
            elements: dict
            contains:
                local_port_id:
                    description: Local port ID.
                    type: str
                    sample: "CL1-C"
                remote_ip_address:
                    description: Remote IP address.
                    type: str
                    sample: "10.12.10.120"
                remote_iscsi_port_id:
                    description: Remote iSCSI port ID.
                    type: str
                    sample: "CL1-C,810045,M8,CL1-C"
                remote_port_id:
                    description: Remote port ID.
                    type: str
                    sample: "CL1-C"
                remote_serial_number:
                    description: Remote serial number.
                    type: str
                    sample: "810045"
                remote_storage_device_id:
                    description: Remote storage device ID.
                    type: str
                    sample: "A34000810045"
                remote_storage_model:
                    description: Remote storage model.
                    type: str
                    sample: "VSP One B26"
                remote_storage_type_id:
                    description: Remote storage type ID.
                    type: str
                    sample: "M8"
                remote_tcp_port:
                    description: Remote TCP port.
                    type: int
                    sample: 3260
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler import (
    vsp_iscsi_remote_connection_reconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.vsp_utils import (
    VSPParametersManager,
    VSPRemoteConnectionArgs,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class VSPRemoteConnectionFacts:
    def __init__(self):
        self.logger = Log()

        self.argument_spec = VSPRemoteConnectionArgs().remote_iscsi_connection_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        try:
            self.params_manager = VSPParametersManager(self.module.params)
            self.spec = self.params_manager.get_iscsi_remote_connection_facts_spec()
            self.serial = self.params_manager.get_serial()
            self.connection_info = self.params_manager.get_connection_info()
        except Exception as e:
            self.logger.writeException(e)
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo(
            "=== Start of Remote iSCSI Connection facts operation. ==="
        )
        try:
            registration_message = validate_ansible_product_registration()
            result = vsp_iscsi_remote_connection_reconciler.VSPRemoteIscsiConnectionReconciler(
                self.params_manager.connection_info, self.serial
            ).remote_iscsi_connection_facts(
                self.spec
            )

            result = result if not isinstance(result, str) else None
            response_dict = {
                "remote_connections": result,
            }
            if registration_message:
                response_dict["user_consent_required"] = registration_message
            self.logger.writeInfo(f"{response_dict}")
            self.logger.writeInfo(
                "=== End of Remote iSCSI Connection facts operation. ==="
            )
            self.module.exit_json(changed=False, ansible_facts=response_dict)
        except Exception as ex:
            self.logger.writeException(ex)
            self.logger.writeInfo(
                "=== End of Remote iSCSI Connection facts operation. ==="
            )
            self.module.fail_json(msg=str(ex))


def main():
    obj_store = VSPRemoteConnectionFacts()
    obj_store.apply()


if __name__ == "__main__":
    main()
