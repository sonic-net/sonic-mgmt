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
module: cp_mgmt_set_api_settings
short_description: Edit API settings, the changes will be applied after publish followed by running 'api restart' command.
description:
  - Edit API settings, the changes will be applied after publish followed by running 'api restart' command.
  - All operations are performed over Web Services API.
  - Available from R80 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  accepted_api_calls_from:
    description:
      - Clients allowed to connect to the API Server.
    type: str
    choices: ['management server only', 'all ip addresses that can be used for gui clients', 'all ip addresses']
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-api-settings
  cp_mgmt_set_api_settings:
    accepted_api_calls_from: 'all ip addresses'
"""

RETURN = """
cp_mgmt_set_api_settings:
  description: The checkpoint set-api-settings output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        accepted_api_calls_from=dict(type='str', choices=['management server only', 'all ip addresses that can be used for gui clients', 'all ip addresses'])
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-api-settings"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
