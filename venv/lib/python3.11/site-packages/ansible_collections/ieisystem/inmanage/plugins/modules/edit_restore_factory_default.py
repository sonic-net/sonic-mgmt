#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_restore_factory_default
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set preserver config
description:
   - Set preserver config on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    mode:
        description:
            - Restore factory defaults mode.
        choices: ['all', 'none', 'manual']
        type: str
        required: true
    override:
        description:
            - Configuration items that need to be retained.
            - Required when I(mode=manual).
        choices: ['authentication', 'dcmi', 'fru', 'hostname', 'ipmi', 'kvm', 'network', 'ntp', 'pef',
         'sdr', 'sel', 'smtp', 'snmp', 'sol', 'ssh', 'syslog', 'user']
        type: list
        elements: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Restore default test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set restore default auto"
    ieisystem.inmanage.edit_restore_factory_default:
      mode: "all"
      provider: "{{ inmanage }}"

  - name: "Set restore default manual"
    ieisystem.inmanage.edit_restore_factory_default:
      mode: "manual"
      override:
        - fru
        - ntp
        - network
        - user
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


class Preserver(object):
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
        self.module.params['subcommand'] = 'restorefactorydefaults'
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
        mode=dict(type='str', required=True, choices=['all', 'none', 'manual']),
        override=dict(type='list', elements='str', required=False,
                      choices=['authentication', 'dcmi', 'fru', 'hostname', 'ipmi', 'kvm', 'network', 'ntp',
                               'pef', 'sdr', 'sel', 'smtp', 'snmp', 'sol', 'ssh', 'syslog', 'user']),
    )
    argument_spec.update(inmanage_argument_spec)
    pre_obj = Preserver(argument_spec)
    pre_obj.work()


if __name__ == '__main__':
    main()
