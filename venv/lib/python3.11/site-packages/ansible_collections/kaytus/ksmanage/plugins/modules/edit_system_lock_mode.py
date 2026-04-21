#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_system_lock_mode
version_added: "2.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set system lock mode information
description:
   - Set system lock mode information on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    lock_status:
        description:
            - System lock mode status.
        choices: ['close', 'open']
        type: str
        required: true
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: System lock mode test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set system lock mode to close"
    kaytus.ksmanage.edit_system_lock_mode:
      lock_status: "close"
      provider: "{{ ksmanage }}"

  - name: "Set system lock mode to open"
    kaytus.ksmanage.edit_system_lock_mode:
      lock_status: "open"
      provider: "{{ ksmanage }}"
'''

RETURN = '''
message:
    description: Messages returned after module execution.
    returned: always
    type: str
state:
    description: Status after module execution.
    returned: always
    type: str
changed:
    description: Check to see if a change was made on the device.
    returned: always
    type: bool
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.kaytus.ksmanage.plugins.module_utils.ksmanage import (ksmanage_argument_spec, get_connection)


class Lock(object):
    def __init__(self, argument_spec):
        self.spec = argument_spec
        self.module = None
        self.init_module()
        self.results = dict()

    def init_module(self):
        """Init module object"""

        self.module = AnsibleModule(
            argument_spec=self.spec, supports_check_mode=False)

    def run_command(self):
        self.module.params['subcommand'] = 'setSystemLockdownMode'
        self.results = get_connection(self.module)
        if self.results['State'] == 'Success':
            self.results['changed'] = True

    def show_result(self):
        """Show result"""
        self.module.exit_json(**self.results)

    def work(self):
        """Worker"""
        self.run_command()
        self.show_result()


def main():
    argument_spec = dict(
        lock_status=dict(type='str', required=True, choices=['close', 'open']),
    )
    argument_spec.update(ksmanage_argument_spec)
    psu_obj = Lock(argument_spec)
    psu_obj.work()


if __name__ == '__main__':
    main()
