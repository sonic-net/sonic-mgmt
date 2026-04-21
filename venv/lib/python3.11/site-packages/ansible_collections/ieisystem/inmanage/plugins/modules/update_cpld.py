#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: update_cpld
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Update CPLD
description:
   - Update CPLD on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    list:
        description:
            - Get cpld list.
            - Only the M5 model supports this parameter.
        choices: [True, False]
        default: False
        type: bool
    id:
        description:
            - CPLD id.
            - Required when I(list=False).
            - Only the M5 model supports this parameter.
        type: int
    file_url:
        description:
            - CPLD image file path.
            - Required when I(list=False).
        type: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: CPLD test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Get cpld list"
    ieisystem.inmanage.update_cpld:
      list: True
      provider: "{{ inmanage }}"

  - name: "Update cpld"
    update_cpld:
      id: 1
      file_url: "home/wbs/raw.bin"
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


class CPLD(object):
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
        self.module.params['subcommand'] = 'updatecpld'
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
        list=dict(type='bool', default=False, choices=[True, False]),
        id=dict(type='int', required=False),
        file_url=dict(type='str', required=False),
    )
    argument_spec.update(inmanage_argument_spec)
    cpld_obj = CPLD(argument_spec)
    cpld_obj.work()


if __name__ == '__main__':
    main()
