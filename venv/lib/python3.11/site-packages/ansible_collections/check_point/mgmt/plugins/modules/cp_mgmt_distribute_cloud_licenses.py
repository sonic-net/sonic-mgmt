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
module: cp_mgmt_distribute_cloud_licenses
short_description: Distribute licenses to target CloudGuard gateways.
description:
  - Distribute licenses to target CloudGuard gateways. For more information, see the <A HREF =
    "https://sc1.checkpoint.com/documents/IaaS/WebAdminGuides/EN/CP_CloudGuard_Central_License_Tool_Admin_Guide/Content/Topics-Central-License-Tool/Overview.h
    m?tocpath=Overview%7C_____0#Overview"><b>Central License Administration Guide</b></A>.
  - All operations are performed over Web Services API.
  - Available from R81.20 JHF management version.
version_added: "5.2.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  targets:
    description:
      - Targets are uid or name of the security gateway(s). In case no target specified, the license will be distributed to all CloudGuard security gateways.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: distribute-cloud-licenses
  cp_mgmt_distribute_cloud_licenses:
    targets:
      - GW1
      - GW2
"""

RETURN = """
cp_mgmt_distribute_cloud_licenses:
  description: The checkpoint distribute-cloud-licenses output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        targets=dict(type='list', elements='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "distribute-cloud-licenses"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
