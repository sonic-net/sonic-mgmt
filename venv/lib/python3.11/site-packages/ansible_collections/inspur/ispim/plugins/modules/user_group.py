#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: user_group
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Manage user group
description:
   - Manage user group on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    state:
        description:
            - Whether the user group should exist or not, taking action if the state is different from what is stated.
        choices: ['present', 'absent']
        default: present
        type: str
    name:
        description:
            - Group name.
            - The range of group name for M6 model is OEM1,OEM2,OEM3,OEM4.
        required: true
        type: str
    pri:
        description:
            - Group privilege.
            - Required when I(state=present).
            - Only the M5 model supports this parameter.
        choices: ['administrator', 'operator', 'user', 'oem', 'none']
        type: str
    general:
        description:
            - General configuration privilege.
            - Required when I(state=present).
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    power:
        description:
            - Power control privilege.
            - Required when I(state=present).
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    media:
        description:
            - Remote media configuration privilege.
            - Required when I(state=present).
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    kvm:
        description:
            - Remote KVM configuration privilege.
            - Required when I(state=present).
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    security:
        description:
            - Security configuration privilege.
            - Required when I(state=present).
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    debug:
        description:
            - Debug diagnose privilege.
            - Required when I(state=present).
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    self:
        description:
            - Itself configuration privilege.
            - Required when I(state=present).
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: User group test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Add user group"
    inspur.ispim.user_group:
      state: "present"
      name: "test"
      pri: "administrator"
      provider: "{{ ism }}"

  - name: "Set user group"
    inspur.ispim.user_group:
      state: "present"
      name: "test"
      pri: "user"
      provider: "{{ ism }}"

  - name: "Set m6 user group"
    inspur.ispim.user_group:
      state: "present"
      name: "OEM1"
      general: "enable"
      kvm: "enable"
      provider: "{{ ism }}"

  - name: "Delete user group"
    inspur.ispim.user_group:
      state: "absent"
      name: "test"
      provider: "{{ ism }}"
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

from ansible_collections.inspur.ispim.plugins.module_utils.ism import (ism_argument_spec, get_connection)
from ansible.module_utils.basic import AnsibleModule


class UserGroup(object):
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
        self.module.params['subcommand'] = 'editusergroup'
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
        name=dict(type='str', required=True),
        pri=dict(type='str', required=False, choices=['administrator', 'operator', 'user', 'oem', 'none']),
        general=dict(type='str', required=False, choices=['enable', 'disable']),
        power=dict(type='str', required=False, choices=['enable', 'disable']),
        media=dict(type='str', required=False, choices=['enable', 'disable']),
        kvm=dict(type='str', required=False, choices=['enable', 'disable']),
        security=dict(type='str', required=False, choices=['enable', 'disable']),
        debug=dict(type='str', required=False, choices=['enable', 'disable']),
        self=dict(type='str', required=False, choices=['enable', 'disable']),
    )
    argument_spec.update(ism_argument_spec)
    usergroup_obj = UserGroup(argument_spec)
    usergroup_obj.work()


if __name__ == '__main__':
    main()
