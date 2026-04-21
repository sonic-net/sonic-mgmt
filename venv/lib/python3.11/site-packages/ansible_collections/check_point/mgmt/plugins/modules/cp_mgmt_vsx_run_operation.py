#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_vsx_run_operation
short_description: Run the VSX operation by its name and parameters.
description:
  - Run the VSX operation by its name and parameters.
  - An automatic session publish is part of all the operations in this API.
  - All operations are performed over Web Services API.
  - Available from R81 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  operation:
    description:
      - The name of the operation to run. Each operation has its specific parameters.<br>The available operations are,<ul><li><i>upgrade</i> -
        Upgrades the VSX Gateway or VSX Cluster object to a higher version</li><li><i>downgrade</i> - Downgrades the VSX Gateway or VSX Cluster object to a
        lower version</li><li><i>add-member</i> - Adds a new VSX Cluster member object</li><li><i>remove-member</i> - Removes a VSX Cluster member
        object</li><li><i>reconf-gw</i> - Reconfigures a VSX Gateway after a clean install</li><li><i>reconf-member</i> - Reconfigures a VSX Cluster member
        after a clean install</li></ul>.
    type: str
    choices: ['upgrade', 'downgrade', 'add-member', 'remove-member', 'reconf-gw', 'reconf-member']
  add_member_params:
    description:
      - Parameters for the operation to add a VSX Cluster member.
    type: dict
    suboptions:
      ipv4_address:
        description:
          - The IPv4 address of the management interface of the VSX Cluster member.
        type: str
      ipv4_sync_address:
        description:
          - The IPv4 address of the sync interface of the VSX Cluster member.
        type: str
      member_name:
        description:
          - Name of the new VSX Cluster member object.
        type: str
      vsx_name:
        description:
          - Name of the VSX Cluster object.
        type: str
      vsx_uid:
        description:
          - UID of the VSX Cluster object.
        type: str
  downgrade_params:
    description:
      - Parameters for the operation to downgrade a VSX Gateway or VSX Cluster object to a lower version.<br>In case the current version is already
        the target version, or is lower than the target version, no change is done.
    type: dict
    suboptions:
      target_version:
        description:
          - The target version.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway or VSX Cluster object.
        type: str
      vsx_uid:
        description:
          - UID of the VSX Gateway or VSX Cluster object.
        type: str
  reconf_gw_params:
    description:
      - Parameters for the operation to reconfigure a VSX Gateway after a clean install.
    type: dict
    suboptions:
      ipv4_corexl_number:
        description:
          - Number of IPv4 CoreXL Firewall instances on the target VSX Gateway.<br>Valid values,<br><ul><li>To configure CoreXL Firewall
            instances, enter an integer greater or equal to 2.</li><li>To disable CoreXL, enter 1.</li></ul>.
        type: int
      one_time_password:
        description:
          - A password required for establishing a Secure Internal Communication (SIC). Enter the same password you used during the First Time
            Configuration Wizard on the target VSX Gateway.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway object.
        type: str
      vsx_uid:
        description:
          - UID of the VSX Gateway object.
        type: str
  reconf_member_params:
    description:
      - Parameters for the operation to reconfigure a VSX Cluster member after a clean install.
    type: dict
    suboptions:
      ipv4_corexl_number:
        description:
          - Number of IPv4 CoreXL Firewall instances on the target VSX Cluster member.<br>Valid values,<br><ul><li>To configure CoreXL Firewall
            instances, enter an integer greater or equal to 2.</li><li>To disable CoreXL, enter 1.</li></ul>Important - The CoreXL configuration must be the
            same on all the cluster members.
        type: int
      member_uid:
        description:
          - UID of the VSX Cluster member object.
        type: str
      member_name:
        description:
          - Name of the VSX Cluster member object.
        type: str
      one_time_password:
        description:
          - A password required for establishing a Secure Internal Communication (SIC). Enter the same password you used during the First Time
            Configuration Wizard on the target VSX Cluster member.
        type: str
  remove_member_params:
    description:
      - Parameters for the operation to remove a VSX Cluster member object.
    type: dict
    suboptions:
      member_uid:
        description:
          - UID of the VSX Cluster member object.
        type: str
      member_name:
        description:
          - Name of the VSX Cluster member object.
        type: str
  upgrade_params:
    description:
      - Parameters for the operation to upgrade a VSX Gateway or VSX Cluster object to a higher version.<br>In case the current version is already the
        target version, or is higher than the target version, no change is done.
    type: dict
    suboptions:
      target_version:
        description:
          - The target version.
        type: str
      vsx_name:
        description:
          - Name of the VSX Gateway or VSX Cluster object.
        type: str
      vsx_uid:
        description:
          - UID of the VSX Gateway or VSX Cluster object.
        type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: vsx-run-operation
  cp_mgmt_vsx_run_operation:
    add_member_params:
      ipv4_address: 25.25.25.223
      ipv4_sync_address: 20.20.20.223
      member_name: Mem3
      vsx_name: VSX_CLUSTER
    operation: add-member
"""

RETURN = """
cp_mgmt_vsx_run_operation:
  description: The checkpoint vsx-run-operation output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        operation=dict(type='str', choices=['upgrade', 'downgrade', 'add-member', 'remove-member', 'reconf-gw', 'reconf-member']),
        add_member_params=dict(type='dict', options=dict(
            ipv4_address=dict(type='str'),
            ipv4_sync_address=dict(type='str'),
            member_name=dict(type='str'),
            vsx_name=dict(type='str'),
            vsx_uid=dict(type='str')
        )),
        downgrade_params=dict(type='dict', options=dict(
            target_version=dict(type='str'),
            vsx_name=dict(type='str'),
            vsx_uid=dict(type='str')
        )),
        reconf_gw_params=dict(type='dict', options=dict(
            ipv4_corexl_number=dict(type='int'),
            one_time_password=dict(type='str', no_log=True),
            vsx_name=dict(type='str'),
            vsx_uid=dict(type='str')
        )),
        reconf_member_params=dict(type='dict', options=dict(
            ipv4_corexl_number=dict(type='int'),
            member_uid=dict(type='str'),
            member_name=dict(type='str'),
            one_time_password=dict(type='str', no_log=True)
        )),
        remove_member_params=dict(type='dict', options=dict(
            member_uid=dict(type='str'),
            member_name=dict(type='str')
        )),
        upgrade_params=dict(type='dict', options=dict(
            target_version=dict(type='str'),
            vsx_name=dict(type='str'),
            vsx_uid=dict(type='str')
        ))
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "vsx-run-operation"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
