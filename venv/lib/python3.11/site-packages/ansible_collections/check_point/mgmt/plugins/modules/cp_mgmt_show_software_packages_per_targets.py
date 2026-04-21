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
module: cp_mgmt_show_software_packages_per_targets
short_description: Shows software packages on targets.
description:
  - Shows software packages on targets.
  - All operations are performed over Web Services API.
  - Available from R80.40 management version.
version_added: "5.0.0"
author: "Shiran Golzar (@chkp-shirango)"
options:
  display:
    description:
      - Filter the displayed results.
    type: dict
    suboptions:
      category:
        description:
          - The package categories to include in the results.
        type: list
        elements: str
      installed:
        description:
          - Show installed packages, available packages, or both.
        type: str
        choices: ['yes', 'no', 'any']
      recommended:
        description:
          - Show only recommended packages, other packages, or both.
        type: str
        choices: ['yes', 'no', 'any']
  targets:
    description:
      - On what targets to execute this command. Targets may be identified by their object name, or object unique identifier.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: show-software-packages-per-targets
  cp_mgmt_show_software_packages_per_targets:
    display:
      category: major
      installed: 'no'
      recommended: any
    targets:
      - corporate-gateway
"""

RETURN = """
cp_mgmt_show_software_packages_per_targets:
  description: The checkpoint show-software-packages-per-targets output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, \
    api_command


def main():
    argument_spec = dict(
        display=dict(type='dict', options=dict(
            category=dict(type='list', elements='str'),
            installed=dict(type='str', choices=['yes', 'no', 'any']),
            recommended=dict(type='str', choices=['yes', 'no', 'any'])
        )),
        targets=dict(type='list', elements='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "show-software-packages-per-targets"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
