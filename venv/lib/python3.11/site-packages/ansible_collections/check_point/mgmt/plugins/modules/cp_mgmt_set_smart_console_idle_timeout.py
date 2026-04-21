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
module: cp_mgmt_set_smart_console_idle_timeout
short_description: Set SmartConsole idle timeout settings.
description:
  - Set SmartConsole idle timeout settings.
  - This command is available only after logging in to the System Data domain.
  - All operations are performed over Web Services API.
  - Available from R82.10 management version.
version_added: "6.7.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  enabled:
    description:
      - Indicates whether to perform logout after being idle.
    type: bool
  timeout_duration:
    description:
      - Number of minutes that the SmartConsole will automatically logout after being idle.
      - Updating the interval will take effect only on the next login.
      - Valid values are between 1 and 120.
    type: int
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-smart-console-idle-timeout
  cp_mgmt_set_smart_console_idle_timeout:
    enabled: true
    timeout_duration: 30
"""

RETURN = """
cp_mgmt_set_smart_console_idle_timeout:
  description: The checkpoint set-smart-console-idle-timeout output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        enabled=dict(type='bool'),
        timeout_duration=dict(type='int')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-smart-console-idle-timeout"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
