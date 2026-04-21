#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: user
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Manage user
description:
   - Manage user on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    state:
        description:
            - Whether the user should exist or not, taking action if the state is different from what is stated.
        choices: ['present', 'absent']
        default: present
        type: str
    uid:
        description:
            - User id, The range is 1 to 16.
        type: int
    uname:
        description:
            - User name, Required when uid is None.
        type: str
    upass:
        description:
            - User password.
        type: str
    role_id:
        description:
            - User group.
            - Default user group 'Administrator', 'Operator', 'User'.
            - Use command C(user_group_info) can get all group information.
        type: str
    access:
        description:
            - User access.
        choices: ['enable', 'disable']
        type: str
    priv:
        description:
            - Other user permissions, select one or more from None/KVM/VMM/SOL.
        choices: ['kvm', 'vmm', 'sol', 'none']
        type: list
        elements: str
    email:
        description:
            - User email.
        type: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: User test
  hosts: inmanage
  no_log: true
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Add user"
    ieisystem.inmanage.user:
      state: "present"
      uname: "wbs"
      upass: "admin"
      role_id: "Administrator"
      priv: "kvm,sol"
      email: "wbs@ieisystem.com"
      provider: "{{ inmanage }}"

  - name: "Set user"
    ieisystem.inmanage.user:
      state: "present"
      uname: "wbs"
      upass: "12345678"
      role_id: "user"
      priv: "kvm,sol"
      provider: "{{ inmanage }}"
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
from ansible_collections.ieisystem.inmanage.plugins.module_utils.inmanage import (inmanage_argument_spec, get_connection)


class User(object):
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
        self.module.params['subcommand'] = 'edituser'
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
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        uid=dict(type='int', required=False),
        uname=dict(type='str', required=False),
        upass=dict(type='str', required=False, no_log=True),
        role_id=dict(type='str', required=False),
        access=dict(type='str', required=False, choices=['enable', 'disable']),
        priv=dict(type='list', elements='str', required=False, choices=['kvm', 'vmm', 'sol', 'none']),
        email=dict(type='str', required=False)
    )
    argument_spec.update(inmanage_argument_spec)
    user_obj = User(argument_spec)
    user_obj.work()


if __name__ == '__main__':
    main()
