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
module: cp_mgmt_set_compliance_settings
short_description: Edit existing Compliance Settings.
description:
  - Edit existing Compliance Settings.
  - All operations are performed over Web Services API.
  - Available from R82.10 management version.
version_added: "6.7.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  automatic_scan_scheduler:
    description:
      - Schedule for an automatic full Compliance scan.
    type: dict
    suboptions:
      scan_day:
        description:
          - The scheduled day of the week for the Compliance scan. The default value is 'every_day'.
        type: str
        choices: ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'every_day']
      scan_time:
        description:
          - The scheduled time of day for the Compliance scan in format, "HH:mm:ss".
          - The default value is "23:59:59".
        type: str
      scheduled_scan_on:
        description:
          - Enables or disables the scheduled scan. The default value is true.
        type: bool
  enable_email_alerts:
    description:
      - Enables or disables sending email alerts to SmartEvent (only for alerts). The default value is true.
    type: bool
  enable_smart_event_logs:
    description:
      - Enables or disables sending logs to SmartEvent. The default value is true.
    type: bool
  initialize_best_practices:
    description:
      - If true, creates all the default Best Practices again.
      - After the first scan completes, the value of this parameter is automatically set to false.
      - The default value is true for initial setup and false after first scan.
    type: bool
  partial_scan_delay:
    description:
      - Controls when the partial scan starts after publishing a session. The partial scan checks only the relevant firewall best practices.
      - If the value is < 0, the partial scan is disabled.
      - If the value is 0, the partial scan starts immediately after publishing.
      - If the value is > 0, the partial scan is delayed by the specified number of seconds after publishing.
      - The default value is '0'.
    type: int
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-compliance-settings
  cp_mgmt_set_compliance_settings:
    automatic_scan_scheduler:
      scan_day: sunday
      scan_time: 08:00:00
      scheduled_scan_on: false
    partial_scan_delay: -1
"""

RETURN = """
cp_mgmt_set_compliance_settings:
  description: The checkpoint set-compliance-settings output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        automatic_scan_scheduler=dict(type='dict', options=dict(
            scan_day=dict(type='str', choices=['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'every_day']),
            scan_time=dict(type='str'),
            scheduled_scan_on=dict(type='bool')
        )),
        enable_email_alerts=dict(type='bool'),
        enable_smart_event_logs=dict(type='bool'),
        initialize_best_practices=dict(type='bool'),
        partial_scan_delay=dict(type='int')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-compliance-settings"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
