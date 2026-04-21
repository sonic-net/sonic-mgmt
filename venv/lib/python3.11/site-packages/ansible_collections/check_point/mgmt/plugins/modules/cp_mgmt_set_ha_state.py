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
module: cp_mgmt_set_ha_state
short_description: Switch domain server high availability state.
description:
  - Switch domain server high availability state. </br>After switching domain server to standby state, the session expires and you need to login again.
    <br/>You can run this command from a user or global domain on Multi Domain Server and from the user domain on Security Management Server.
  - All operations are performed over Web Services API.
  - Available from R80.40 JHF management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  new_state:
    description:
      - Domain server new state.
    type: str
    choices: ['active', 'standby']
  ignore_errors:
    description:
      - Apply changes ignoring errors.
      - Available from R81.20 management version.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-ha-state
  cp_mgmt_set_ha_state:
    new_state: active
"""

RETURN = """
cp_mgmt_set_ha_state:
  description: The checkpoint set-ha-state output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        new_state=dict(type='str', choices=['active', 'standby']),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-ha-state"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
