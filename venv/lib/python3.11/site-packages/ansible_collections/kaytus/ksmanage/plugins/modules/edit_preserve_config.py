#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_preserve_config
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set preserve config
description:
   - Set preserve config on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    setting:
        description:
            - Preserve option, all - preserve all config; none - overwrite all config; manual - manual choose.
        choices: ['all', 'none', 'manual']
        type: str
        required: true
    override:
        description:
            - Configuration items that need to be retained.
            - Required when I(setting=manual).
        choices: ['authentication', 'dcmi', 'fru', 'hostname', 'ipmi', 'kvm', 'network', 'ntp', 'pef',
         'sdr', 'sel', 'smtp', 'snmp', 'sol', 'ssh', 'syslog', 'user']
        type: list
        elements: str
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Preserve test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set preserve all"
    kaytus.ksmanage.edit_preserve_config:
      setting: "all"
      provider: "{{ ksmanage }}"

  - name: "Set preserve none"
    edit_preserve_config:
      setting: "none"
      provider: "{{ ksmanage }}"

  - name: "Set preserve manual"
    edit_preserve_config:
      setting: "manual"
      override:
        - fru
        - ntp
        - network
        - user
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


class Preserve(object):
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
        self.module.params['subcommand'] = 'preserveconfig'
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
        setting=dict(type='str', required=True, choices=['all', 'none', 'manual']),
        override=dict(type='list', elements='str', required=False,
                      choices=['authentication', 'dcmi', 'fru', 'hostname', 'ipmi', 'kvm', 'network', 'ntp',
                               'pef', 'sdr', 'sel', 'smtp', 'snmp', 'sol', 'ssh', 'syslog', 'user']),
    )
    argument_spec.update(ksmanage_argument_spec)
    pre_obj = Preserve(argument_spec)
    pre_obj.work()


if __name__ == '__main__':
    main()
