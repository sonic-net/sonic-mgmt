#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_remote_iscsi_port
short_description: Manages remote iSCSI ports in VSP One SDS Block and Cloud systems.
description:
  - This module allows registers a remote iSCSI port,
    and deletes information about registered remote iSCSI ports on VSP One SDS Block and Cloud systems.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/remote_iscsi_port.yml)
version_added: "4.2.0"
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
    description: The desired state of the remote iSCSI port.
    type: str
    required: false
    choices: ['present', 'absent']
    default: 'present'
  spec:
    description: Specification for the remote iSCSI port.
    type: dict
    required: false
    suboptions:
      id:
        description: The ID of the remote iSCSI port. Required for delete operation.
        type: str
        required: false
      local_port:
        description: Port number of the local storage system in CLx-y format. Required for create operation.
        type: str
        required: false
      remote_serial:
        description: Serial number of the remote storage system. Required for create operation.
        type: str
        required: false
      remote_storage_system_type:
        description: ID indicating the remote storage system model. Required for create operation.
        type: str
        required: false
        choices: ['R9', 'M8']
      remote_port:
        description: Port number of the remote storage system in CLx-y format. Required for create operation.
        type: str
        required: false
      remote_ip_address:
        description: iSCSI port IP address for the remote storage system. Required for create operation.
        type: str
        required: false
      remote_tcp_port:
        description: TCP port number of the iSCSI target for the remote storage system. Used in create operation.
          If this is omitted, the TCP port number of the iSCSI target for the local storage system is set.
        type: int
        required: false
"""

EXAMPLES = """
- name: Register a remote iscsi port
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_iscsi_port:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "present"
    spec:
      local_port: "CL1-C"
      remote_serial: "810045"
      remote_storage_system_type: "M8"
      remote_port: "CL1-C"
      remote_ip_address: "172.25.59.213"

- name: Restore storage node from maintenance
  hitachivantara.vspone_block.sds_block.hv_sds_block_remote_iscsi_port:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
    state: "restore"
    spec:
      id: "3d0997ce-7065-4e4a-9095-4dc62b36f300"
"""

RETURN = """
remote_iscsi_ports:
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
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_remote_iscsi_port import (
    SDSBRemoteIscsiPortReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBRemoteIscsiPortArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBBlockRemoteIscsiPortManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBRemoteIscsiPortArguments().remote_iscsi_port()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_remote_iscsi_port_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Remote iSCSI Port Operation ===")
        remote_iscsi_ports = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBRemoteIscsiPortReconciler(self.connection_info)
            remote_iscsi_ports = sdsb_reconciler.reconcile_remote_iscsi_port(
                self.spec, self.state
            )
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Remote iSCSI Port Operation ===")
            self.module.fail_json(msg=str(e))
        data = {
            "changed": self.connection_info.changed,
            "remote_iscsi_ports": remote_iscsi_ports,
        }
        if self.state == "absent":
            data.pop("remote_iscsi_ports")
            if remote_iscsi_ports is None:
                data["message"] = "Successfully removed the remote iSCSI port."
            else:
                data["message"] = "Failed to remove the remote iSCSI port."
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Remote iSCSI Port Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBBlockRemoteIscsiPortManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
