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
module: cp_mgmt_set_login_restrictions
short_description: Set login restrictions.
description:
  - Set login restrictions.
  - This command is available only after logging in to the System Data domain.
  - All operations are performed over Web Services API.
  - Available from R82.10 management version.
version_added: "6.7.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  lockout_admin_account:
    description:
      - Indicates whether to lockout administrator's account after specified number of failed authentication attempts.
    type: bool
  failed_authentication_attempts:
    description:
      - Number of failed authentication attempts before lockout administrator account. <font color="red">Required only when</font>
        lockout-admin-account is set to true.
      - Valid values are between 1 and 120.
    type: int
  unlock_admin_account:
    description:
      - Indicates whether to unlock administrator account after specified number of minutes. <font color="red">Required only when</font>
        lockout-admin-account is set to true.
    type: bool
  lockout_duration:
    description:
      - Number of minutes of administrator account lockout. <font color="red">Required only when</font> lockout-admin-account is set to true.
      - Valid values are between 1 and 120.
    type: int
  display_access_denied_message:
    description:
      - Indicates whether to display informative message upon denying access. <font color="red">Required only when</font> lockout-admin-account is set to true.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: set-login-restrictions
  cp_mgmt_set_login_restrictions:
    display_access_denied_message: false
    failed_authentication_attempts: 10
    lockout_admin_account: true
    lockout_duration: 30
    unlock_admin_account: false
"""

RETURN = """
cp_mgmt_set_login_restrictions:
  description: The checkpoint set-login-restrictions output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        lockout_admin_account=dict(type='bool'),
        failed_authentication_attempts=dict(type='int'),
        unlock_admin_account=dict(type='bool'),
        lockout_duration=dict(type='int'),
        display_access_denied_message=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "set-login-restrictions"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
