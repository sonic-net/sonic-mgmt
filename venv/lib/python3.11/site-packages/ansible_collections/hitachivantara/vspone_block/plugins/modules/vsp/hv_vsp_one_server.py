#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
---
module: hv_vsp_one_server
short_description: Manages servers on  VSP E series and VSP One Block 20 series storage systems.
description:
  - This module enables register, modification, and deletion of servers, as well as various server operations.
  - Supports various server operations depending on the specified state parameter.
  - Utilizes the Hitachi Virtual Storage Platform One Simple API for server management across VSP one B20 series and VSP E series models.
  - For usage examples, visit
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/vsp_direct/vsp_one_server.yml)
version_added: '4.3.0'
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
    description: Defines the server operation type. Available options include C(present), C(absent),
      C(sync_server_nick_name), C(add_host_groups), C(add_hba), C(remove_hba), C(add_path), and C(remove_path).
    type: str
    required: false
    choices: ['present', 'absent', 'sync_server_nick_name', 'add_host_groups', 'add_hba',
            'remove_hba', 'add_path', 'remove_path', 'change_iscsi_target_settings']
    default: 'present'
  spec:
    description: Configuration parameters for the server operation.
    type: dict
    required: true
    suboptions:
      nick_name:
        description: Server nickname specification.
        type: str
        required: false
      protocol:
        description: Server protocol type.
        type: str
        required: false
        choices: ["FC", "iSCSI"]
      server_id:
        description: Server identifier.
        type: int
        required: false
      os_type:
        description: Operating system type of the server.
        type: str
        required: false
        choices: ["Linux", "HP-UX", "Solaris", "AIX", "VMware", "Windows"]
      port_ids:
        description: List of port identifiers.
        type: list
        required: false
        elements: str
      is_reserved:
        description: Indicates if the server is reserved.
        type: bool
        required: false
      os_type_options:
        description: List of OS type option identifiers.
        type: list
        required: false
        elements: int
      hbas:
        description: List of HBA configurations.
        type: list
        required: false
        elements: dict
        suboptions:
          hba_wwn:
            description: HBA WWN address.
            type: str
            required: false
          iscsi_name:
            description: iSCSI name.
            type: str
            required: false
      paths:
        description: List of path configurations.
        type: list
        required: false
        elements: dict
        suboptions:
          port_ids:
            description: List of port identifiers.
            type: list
            required: true
            elements: str
          hba_wwn:
            description: HBA WWN address.
            type: str
            required: false
          iscsi_name:
            description: iSCSI name.
            type: str
            required: false
      keep_lun_config:
        description: Whether to keep LUN configuration.
        type: bool
        required: false
      iscsi_target_settings:
        description: List of iSCSI target configurations.
        type: list
        required: false
        elements: dict
        suboptions:
          port_id:
            description: Port identifier.
            type: str
            required: true
          target_iscsi_name:
            description: iSCSI target name.
            type: str
            required: true
      host_groups:
        description: List of host group configurations.
        type: list
        required: false
        elements: dict
        suboptions:
          host_group_id:
            description: Host group identifier.
            type: int
            required: false
          host_group_name:
            description: Host group name.
            type: str
            required: false
          port_id:
            description: Port identifier.
            type: str
            required: false
      iscsi_targets:
        description: List of iSCSI target configurations.
        type: list
        required: false
        elements: dict
        suboptions:
          iscsi_target_id:
            description: iSCSI target identifier.
            type: int
            required: false
          iscsi_target_name:
            description: iSCSI target name.
            type: str
            required: false
          port_id:
            description: Port identifier.
            type: str
            required: false
"""

EXAMPLES = """
- name: Register a FC server with HBA WWN
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "WebServer01"
      protocol: "FC"
      os_type: "Linux"
      hbas:
        - hba_wwn: "50060e8010203040"

- name: Register an iSCSI server with iSCSI name
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "DatabaseServer01"
      protocol: "iSCSI"
      os_type: "Windows"
      hbas:
        - iscsi_name: "iqn.1991-05.com.microsoft:server01"

- name: Register server with host groups configuration
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "VMwareCluster01"
      protocol: "FC"
      os_type: "VMware"
      host_groups:
        - host_group_name: "VMware_HG01"
          port_id: "CL1-A"
        - host_group_name: "VMware_HG02"
          port_id: "CL1-B"

- name: Register server with multiple HBAs and paths configuration
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "AppServer01"
      protocol: "FC"
      os_type: "Linux"
      hbas:
        - hba_wwn: "50060e8010203040"
        - hba_wwn: "50060e8010203041"
      paths:
        - port_ids: ["CL1-A", "CL1-B"]
          hba_wwn: "50060e8010203040"
        - port_ids: ["CL2-A", "CL2-B"]
          hba_wwn: "50060e8010203041"

- name: Register iSCSI server with multiple iSCSI names and paths
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "HybridServer01"
      protocol: "iSCSI"
      os_type: "Linux"
      hbas:
        - iscsi_name: "iqn.1991-05.com.example:server01-iscsi1"
        - iscsi_name: "iqn.1991-05.com.example:server01-iscsi2"
      paths:
        - port_ids: ["CL1-A"]
          iscsi_name: "iqn.1991-05.com.example:server01-iscsi1"
        - port_ids: ["CL1-B"]
          iscsi_name: "iqn.1991-05.com.example:server01-iscsi2"

- name: Update existing server nick_name with server_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123
      nick_name: "UpdatedServerName"

- name: Update existing server settings like os type os type options using server_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123
      os_type: "Windows"
      os_type_options: [1, 2]

- name: Add host groups to existing server
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: add_host_groups
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123
      host_groups:
        - host_group_name: "NewHostGroup01"
          port_id: "CL2-A"
- name: Add HBA to existing server using server_id
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: add_hba
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123
      hbas:
        - hba_wwn: "50060e8010203042"
- name: Remove HBA from server
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: remove_hba
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 12
      hbas:
        - hba_wwn: "50060e8010203042"

- name: Add path to server
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: add_path
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 12
      paths:
        - port_ids: ["CL1-C", "CL1-D"]
          hba_wwn: "50060e8010203040"

- name: Remove path from server
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: remove_path
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 12
      paths:
        - port_ids: ["CL1-C"]
          hba_wwn: "50060e8010203040"

- name: Sync server nickname with host group
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: sync_server_nick_name
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123

- name: Register reserved server with specific configuration
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "ReservedServer01"
      protocol: "FC"
      os_type: "Solaris"
      is_reserved: true
      keep_lun_config: true
      os_type_options: [1, 2]

- name: Change the iSCSI target settings for existing server (change target name)
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: present
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123
      iscsi_targets:
        - port_id: "CL1-A"
          iscsi_target_name: "iqn.1992-04.com.hitachi:target01"
        - port_id: "CL1-B"
          iscsi_target_name: "iqn.1992-04.com.hitachi:target02"

- name: Delete server using server_id and keep lun configuration
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: absent
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      server_id: 123
      keep_lun_config: true

- name: Delete server using nick_name.
  hitachivantara.vspone_block.vsp.hv_vsp_one_server:
    state: absent
    connection_info:
      address: vsp.company.com
      username: "admin"
      password: "password"
    spec:
      nick_name: "WebServer01"
"""

RETURN = """
server:
  description: Server information returned after operation
  returned: always
  type: dict
  contains:
    compatibility:
      description: Server compatibility status
      type: str
      returned: always
      sample: ""
    has_non_fullmesh_lu_paths:
      description: Indicates if server has non-fullmesh LU paths
      type: bool
      returned: always
      sample: true
    has_unaligned_os_type_options:
      description: Indicates if server has unaligned OS type options
      type: bool
      returned: always
      sample: true
    has_unaligned_os_types:
      description: Indicates if server has unaligned OS types
      type: bool
      returned: always
      sample: true
    id:
      description: Server identifier
      type: int
      returned: always
      sample: 13
    is_inconsistent:
      description: Indicates if server configuration is inconsistent
      type: bool
      returned: always
      sample: false
    is_reserved:
      description: Indicates if server is reserved
      type: bool
      returned: always
      sample: false
    modification_in_progress:
      description: Indicates if server modification is in progress
      type: bool
      returned: always
      sample: false
    nickname:
      description: Server nickname
      type: str
      returned: always
      sample: "WebServer414"
    number_of_paths:
      description: Number of paths configured for the server
      type: int
      returned: always
      sample: 2
    number_of_volumes:
      description: Number of volumes attached to the server
      type: int
      returned: always
      sample: 1
    os_type:
      description: Operating system type of the server
      type: str
      returned: always
      sample: "Linux"
    os_type_options:
      description: List of OS type option identifiers
      type: list
      elements: int
      returned: always
      sample: [68]
    paths:
      description: List of server path configurations
      type: list
      elements: dict
      returned: always
      contains:
        hba_wwn:
          description: HBA WWN address
          type: str
          returned: always
          sample: "210003e08b0256f9"
        iscsi_name:
          description: iSCSI name
          type: str
          returned: always
          sample: ""
        port_ids:
          description: List of port identifiers
          type: list
          elements: str
          returned: always
          sample: ["CL1-A"]
    protocol:
      description: Server protocol type
      type: str
      returned: always
      sample: "FC"
    total_capacity:
      description: Total capacity in GB
      type: int
      returned: always
      sample: 50
    used_capacity:
      description: Used capacity in GB
      type: int
      returned: always
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


class VSPOneServer:
    def __init__(self):

        self.logger = Log()
        self.argument_spec = VSPOneServerArguments().get_vsp_one_server_args()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        try:
            params_manager = VSPParametersManager(self.module.params)
            self.spec = params_manager.get_vsp_one_server_spec()
            self.connection_info = params_manager.get_connection_info()
            self.state = params_manager.get_state()
        except Exception as e:
            self.logger.writeError(f"An error occurred during initialization: {str(e)}")
            self.module.fail_json(msg=str(e))

    def apply(self):
        self.logger.writeInfo("=== Start of VSP One Server Operation ===")
        server = None
        registration_message = validate_ansible_product_registration()

        try:
            server_reconciler = VSPServerSimpleAPIReconciler(self.connection_info)
            server = server_reconciler.reconcile(self.state, self.spec)

        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of VSP One Server Operation ===")
            self.module.fail_json(msg=str(e))

        response = {
            "changed": self.connection_info.changed,
            "server": server,
            "comments": self.spec.comments if self.spec.comments else [],
            "errors": self.spec.errors if self.spec.errors else [],
        }
        if registration_message:
            response["user_consent_required"] = registration_message
        self.logger.writeInfo("=== End of VSP One Server Operation ===")
        self.module.exit_json(**response)


def main():
    obj_store = VSPOneServer()
    obj_store.apply()


if __name__ == "__main__":
    main()
