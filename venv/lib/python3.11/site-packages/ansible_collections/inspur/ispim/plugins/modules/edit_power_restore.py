#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_power_restore
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Set power restore information
description:
   - Set power restore information on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    option:
        description:
            - Set power policy option.
        choices: ['on', 'off', 'restore']
        type: str
        required: true
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Power restore test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set power restore information"
    inspur.ispim.edit_power_restore:
      option: "on"
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.inspur.ispim.plugins.module_utils.ism import (ism_argument_spec, get_connection)


class Power(object):
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
        self.module.params['subcommand'] = 'setpowerrestore'
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
        option=dict(type='str', required=True, choices=['on', 'off', 'restore']),
    )
    argument_spec.update(ism_argument_spec)
    power_obj = Power(argument_spec)
    power_obj.work()


if __name__ == '__main__':
    main()
