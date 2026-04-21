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
module: cp_mgmt_add_repository_package
short_description: Add the software package to the central repository.
description:
  - Add the software package to the central repository.
  - On Multi-Domain Server this command is available only after logging in to the Global domain.
  - All operations are performed over Web Services API.
  - Available from R81 management version.
version_added: "5.0.0"
author: "Shiran Golzar (@chkp-shirango)"
options:
  name:
    description:
      - The name of the repository package.
    type: str
  path:
    description:
      - The path of the repository package.<br><font color="red">Required only for</font> adding package from local.
    type: str
  source:
    description:
      - The source of the repository package.
    type: str
    choices: ['cloud', 'local']
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: add-repository-package
  cp_mgmt_add_repository_package:
    name: Check_Point_R80_20_JUMBO_HF_Bundle_T118_sk137592_Security_Gateway_and_Standalone_2_6_18_FULL.tgz
    path: /home/admin/
    source: local
"""

RETURN = """
cp_mgmt_add_repository_package:
  description: The checkpoint add-repository-package output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, \
    api_command


def main():
    argument_spec = dict(
        name=dict(type='str'),
        path=dict(type='str'),
        source=dict(type='str', choices=['cloud', 'local'])
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "add-repository-package"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
