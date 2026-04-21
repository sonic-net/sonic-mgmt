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
module: cp_mgmt_set_policy_settings
short_description: Edit Policy settings, the changes will be applied after publish.
description:
  - Edit Policy settings, the changes will be applied after publish.
  - All operations are performed over Web Services API.
  - Available from R81.10 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  last_in_cell:
    description:
      - Added object after removing the last object in cell.
    type: str
    choices: ['none', 'restore to default']
  none_object_behavior:
    description:
      - a 'None' object behavior. Rules with object 'None' will never be matched.
    type: str
    choices: ['warning', 'error', 'none']
  security_access_defaults:
    description:
      - Access Policy default values.
    type: dict
    suboptions:
      destination:
        description:
          - Destination default value for new rule creation. Any or None.
        type: str
      service:
        description:
          - Service and Applications default value for new rule creation. Any or None.
        type: str
      source:
        description:
          - Source default value for new rule creation. Any or None.
        type: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-policy-settings
  cp_mgmt_set_policy_settings:
    last_in_cell: any
    none_object_behavior: none
    security_access_defaults:
      destination: any
      service: any
      source: any
"""

RETURN = """
cp_mgmt_set_policy_settings:
  description: The checkpoint set-policy-settings output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        last_in_cell=dict(type='str', choices=['none', 'restore to default']),
        none_object_behavior=dict(type='str', choices=['warning', 'error', 'none']),
        security_access_defaults=dict(type='dict', options=dict(
            destination=dict(type='str'),
            service=dict(type='str'),
            source=dict(type='str')
        ))
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-policy-settings"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
