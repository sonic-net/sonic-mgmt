#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_ldisk
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set logical disk
description:
   - Set logical disk on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    ctrl_id:
        description:
            - Raid controller ID.
        type: int
    ldisk_id:
        description:
            - Logical disk ID.
        type: int
    option:
        description:
            - Set operation options for a logical disk.
            - LOC is Locate Logical Drive, STL is Stop Locate LogicalDrive.
            - FI is Fast Initialization, SFI is Slow/Full Initialization.
            - SI is Stop Initialization, DEL is Delete LogicalDrive.
        choices: ['LOC', 'STL', 'FI', 'SFI', 'SI', 'DEL']
        type: str
    duration:
        description:
            - Duration range is 1-255, physical drive under PMC raid controller.
            - Required when I(option=LOC).
            - Only the M6 model supports this parameter.
        type: int
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Edit ldisk test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Edit ldisk"
    kaytus.ksmanage.edit_ldisk:
      ctrl_id: 0
      ldisk_id: 1
      option: "LOC"
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


class Disk(object):
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
        self.module.params['subcommand'] = 'setldisk'
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
        ctrl_id=dict(type='int', required=False),
        ldisk_id=dict(type='int', required=False),
        option=dict(type='str', required=False, choices=['LOC', 'STL', 'FI', 'SFI', 'SI', 'DEL']),
        duration=dict(type='int', required=False),
    )
    argument_spec.update(ksmanage_argument_spec)
    disk_obj = Disk(argument_spec)
    disk_obj.work()


if __name__ == '__main__':
    main()
