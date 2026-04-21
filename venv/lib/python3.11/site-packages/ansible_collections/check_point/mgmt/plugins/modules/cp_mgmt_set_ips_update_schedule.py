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
module: cp_mgmt_set_ips_update_schedule
short_description: Edit IPS Update Schedule.
description:
  - Edit IPS Update Schedule.
  - All operations are performed over Web Services API.
  - Available from R80 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  enabled:
    description:
      - Enable/Disable IPS Update Schedule.
    type: bool
  time:
    description:
      - Time in format HH,mm.
    type: str
  recurrence:
    description:
      - Days recurrence.
    type: dict
    suboptions:
      days:
        description:
          - Valid on specific days. Multiple options, support range of days in months. Example,["1","3","9-20"].
        type: list
        elements: str
      minutes:
        description:
          - Valid on interval. The length of time in minutes between updates.
        type: int
      pattern:
        description:
          - Valid on "Interval", "Daily", "Weekly", "Monthly" base.
        type: str
      weekdays:
        description:
          - Valid on weekdays. Example, "Sun", "Mon"..."Sat".
        type: list
        elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-ips-update-schedule
  cp_mgmt_set_ips_update_schedule:
    enabled: true
    recurrence:
      minutes: 121
      pattern: interval
"""

RETURN = """
cp_mgmt_set_ips_update_schedule:
  description: The checkpoint set-ips-update-schedule output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        enabled=dict(type='bool'),
        time=dict(type='str'),
        recurrence=dict(type='dict', options=dict(
            days=dict(type='list', elements='str'),
            minutes=dict(type='int'),
            pattern=dict(type='str'),
            weekdays=dict(type='list', elements='str')
        ))
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-ips-update-schedule"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
