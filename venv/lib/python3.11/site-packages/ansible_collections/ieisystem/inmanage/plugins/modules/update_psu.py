#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: update_psu
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Update PSU
description:
   - Update psu on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    url:
        description:
            - Firmware image url.
        required: true
        type: str
    mode:
        description:
            - Server Auto Reset Option, Manual or Auto(default).
        default: Auto
        choices: ['Auto', 'Manual']
        type: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Update psu test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "update psu"
    ieisystem.inmanage.update_psu:
      url: "/home/wbs/CRPS1300D2W_00.01.04_BootLoader_Pri_Sec.hpm"
      mode: "Auto"
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


class Update(object):
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
        self.module.params['subcommand'] = 'updatepsu'
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
        url=dict(type='str', required=True),
        mode=dict(type='str', default='Auto', choices=['Auto', 'Manual']),
    )
    argument_spec.update(inmanage_argument_spec)
    update_obj = Update(argument_spec)
    update_obj.work()


if __name__ == '__main__':
    main()
