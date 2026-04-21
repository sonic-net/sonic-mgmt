#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: backup
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Backup server settings
description:
   - Backup server settings on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    bak_file:
        description:
            - Backup file or bak folder.
        required: true
        type: str
    item:
        description:
            - Export item.
            - The values for M5 modules are 'all', 'network', 'service', 'ntp', 'snmptrap', 'dns', 'smtp', 'ad', 'ldap', 'user','bios'.
            - The values for M6 modules are 'all', 'network', 'service', 'ntp', 'snmptrap',  'kvm', 'ipmi', 'authentication', 'syslog'.
            - The values for M7 modules are 'all', 'network', 'service', 'syslog', 'ncsi'.
        choices: ['all', 'network', 'service', 'ntp', 'snmptrap', 'dns', 'smtp', 'ad', 'ldap', 'user','bios', 'kvm', 'ipmi', 'authentication', 'syslog', 'ncsi']
        required: true
        type: str
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Backup test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Backup server settings"
    inspur.ispim.backup:
      bak_file: "/home/wbs/"
      item: "all"
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


class Backup(object):
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
        self.module.params['subcommand'] = 'backup'
        self.results = get_connection(self.module)

    def show_result(self):
        """Show result"""
        self.module.exit_json(**self.results)

    def work(self):
        """Worker"""
        self.run_command()
        self.show_result()


def main():
    argument_spec = dict(
        bak_file=dict(type='str', required=True),
        item=dict(type='str', required=True, choices=['all', 'network', 'service', 'ntp', 'snmptrap', 'dns', 'smtp', 'ad',
                                                      'ldap', 'user', 'bios', 'kvm', 'ipmi', 'authentication', 'syslog', 'ncsi']),
    )
    argument_spec.update(ism_argument_spec)
    backup_obj = Backup(argument_spec)
    backup_obj.work()


if __name__ == '__main__':
    main()
