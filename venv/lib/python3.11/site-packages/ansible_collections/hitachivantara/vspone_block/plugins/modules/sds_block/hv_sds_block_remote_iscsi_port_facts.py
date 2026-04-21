#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: hv_sds_block_remote_iscsi_port_facts
short_description: Retrieves information about remote iSCSI ports.
description:
  - Get information about remote iSCSI ports from storage system.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/remote_iscsi_port_facts.yml)
version_added: "4.2.0"
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
    description: Parameters for filtering or identifying remote iSCSI ports to
      gather facts about.
    type: dict
    required: false
    suboptions:
      id:
        description: Remote iSCSI port ID..
        type: str
        required: false
      local_port:
        description: Port number of the local storage system in CLx-y format.
        type: str
        required: false
      remote_serial:
        description: Serial number of the remote storage system.
        type: str
        required: false
      remote_storage_system_type:
        description: ID indicating the remote storage system model.
        type: str
        required: false
        choices:
          - R9
          - M8
      remote_port:
        description: Port number of the remote storage system in CLx-y format.
        type: int
        required: false
"""

EXAMPLES = """
- name: Get all remote iscsi ports
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_iscsi_port_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"

- name: Get remote iscsi port by ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_iscsi_port_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
    spec:
      id: "da87655a-3958-4921-b4c0-437986397d11"
"""

RETURN = r"""
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the remote iSCSI ports.
  returned: always
  type: dict
  contains:
    remote_iscsi_ports:
      description: Container for remote iSCSI ports data.
      returned: always
      type: dict
      contains:
        data:
          description: A list of remote iSCSI ports.
          returned: always
          type: list
          elements: dict
          contains:
            id:
              description: The ID of a remote iSCSI port.
              type: str
              sample: "da87655a-3958-4921-b4c0-437986397d11"
            local_port_number:
              description: Port number of the local storage system in CLx-y format.
              type: str
              sample: "CL1-C"
            remote_serial_number:
              description: Serial number of the remote storage system.
              type: str
              sample: "810045"
            remote_storage_type_id:
              description: ID indicating the remote storage system model.
              type: str
              sample: "M8"
            remote_port_number:
              description: Port number of the remote storage system in CLx-y format.
              type: str
              sample: "CL1-C"
            remote_ip_address:
              description: iSCSI port IP address (IPv4/IPv6) for the remote storage system.
              type: str
              sample: "172.25.59.213"
            remote_tcp_port:
              description: TCP port number of the iSCSI target for the remote storage system.
              type: int
              sample: 3260
"""


from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBRemoteIscsiPortArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)

from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_remote_iscsi_port import (
    SDSBRemoteIscsiPortReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBRemoteIscsiPortFactsManager:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = SDSBRemoteIscsiPortArguments().remote_iscsi_port_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )

        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_remote_iscsi_port_fact_spec()
        self.logger.writeDebug(
            f"MOD:hv_sds_block_remote_iscsi_port_facts:spec= {self.spec}"
        )

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Remote iSCSI Port Facts ===")
        remote_iscsi_ports = None
        registration_message = validate_ansible_product_registration()

        try:
            sdsb_reconciler = SDSBRemoteIscsiPortReconciler(self.connection_info)
            remote_iscsi_ports = sdsb_reconciler.get_remote_iscsi_ports(self.spec)

            self.logger.writeDebug(
                f"MOD:hv_sds_block_remote_iscsi_port_facts:remote_iscsi_ports= {remote_iscsi_ports}"
            )

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Remote iSCSI Port Facts ===")
            self.module.fail_json(msg=str(e))
        if remote_iscsi_ports is None:
            remote_iscsi_ports = []
        data = {"remote_iscsi_ports": remote_iscsi_ports}
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of SDSB Remote iSCSI Port Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBRemoteIscsiPortFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
