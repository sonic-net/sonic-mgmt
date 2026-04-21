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
module: cp_mgmt_abort_get_interfaces
short_description: Attempt to abort an on-going "get-interfaces" operation.
description:
  - Attempt to abort an on-going "get-interfaces" operation.
    This API might fail if the "get-interfaces" operation is in its final stage.
  - All operations are performed over Web Services API.
  - Available from R81 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  task_id:
    description:
      - get-interfaces task UID.
    type: str
  force_cleanup:
    description:
      - Forcefully abort the "get-interfaces" task.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: abort-get-interfaces
  cp_mgmt_abort_get_interfaces:
    task_id: 45b185e7-9ccd-4971-b74b-d212282f8f96
"""

RETURN = """
cp_mgmt_abort_get_interfaces:
  description: The checkpoint abort-get-interfaces output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        task_id=dict(type='str'),
        force_cleanup=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "abort-get-interfaces"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
