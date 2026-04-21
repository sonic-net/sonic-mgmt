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
module: cp_mgmt_set_default_administrator_settings
short_description: Set default administrator settings.
description:
  - Set default administrator settings.
  - This command is available only after logging in to the System Data domain.
  - All operations are performed over Web Services API.
  - Available from R82.10 management version.
version_added: "6.7.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  authentication_method:
    description:
      - Authentication method for new administrator.
    type: str
    choices: ['undefined', 'check point password', 'os password', 'securid', 'radius', 'tacacs', 'ad authentication', 'api key', 'identity provider']
  expiration_type:
    description:
      - Expiration type for new administrator.
    type: str
    choices: ['never', 'expiration date', 'expiration period']
  expiration_date:
    description:
      - Expiration date for new administrator in YYYY-MM-DD format. <font color="red">Required only when</font> 'expiration-type' is set to 'expiration date'.
    type: str
  expiration_period:
    description:
      - Expiration period for new administrator. <font color="red">Required only when</font> 'expiration-type' is set to 'expiration period'.
      - Valid values are between 1 and 99.
    type: int
  expiration_period_time_units:
    description:
      - Expiration period time units for new administrator. <font color="red">Required only when</font> 'expiration-type' is set to 'expiration period'.
    type: str
    choices: ['days', 'months', 'years']
  indicate_expiration_in_admin_view:
    description:
      - Indicates whether to notify administrator about expiration.
    type: bool
  notify_expiration_to_admin:
    description:
      - Indicates whether to show 'about to expire' indication in administrator view.
    type: bool
  days_to_indicate_expiration_in_admin_view:
    description:
      - Number of days in advanced to show 'about to expire' indication in administrator view.
      - Valid values are between 1 and 99.
    type: int
  days_to_notify_expiration_to_admin:
    description:
      - Number of days in advanced to notify administrator about expiration.
      - Valid values are between 1 and 99.
    type: int
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-default-administrator-settings
  cp_mgmt_set_default_administrator_settings:
    days_to_notify_expiration_to_admin: 5
    expiration_date: '2025-06-23'
    expiration_type: expiration date
    indicate_expiration_in_admin_view: false
    notify_expiration_to_admin: true
"""

RETURN = """
cp_mgmt_set_default_administrator_settings:
  description: The checkpoint set-default-administrator-settings output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        authentication_method=dict(type='str', choices=['undefined', 'check point password',
                                                        'os password', 'securid', 'radius', 'tacacs', 'ad authentication', 'api key', 'identity provider']),
        expiration_type=dict(type='str', choices=['never', 'expiration date', 'expiration period']),
        expiration_date=dict(type='str'),
        expiration_period=dict(type='int'),
        expiration_period_time_units=dict(type='str', choices=['days', 'months', 'years']),
        indicate_expiration_in_admin_view=dict(type='bool'),
        notify_expiration_to_admin=dict(type='bool'),
        days_to_indicate_expiration_in_admin_view=dict(type='int'),
        days_to_notify_expiration_to_admin=dict(type='int')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-default-administrator-settings"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
