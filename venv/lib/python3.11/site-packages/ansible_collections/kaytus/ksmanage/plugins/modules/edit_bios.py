#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_bios
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set BIOS setup attributes
description:
   - Set BIOS setup attributes on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    list:
        description:
            - Show attribute name and configurable value.
        default: False
        type: bool
    attribute:
        description:
            - BIOS setup option.
            - Required when I(list=False) and I(file_url=None).
        type: str
    value:
        description:
            - BIOS setup option value.
            - Required when I(list=False) and I(file_url=None).
        type: str
    file_url:
        description:
            - BIOS option file. attribute must be used with value.
            - Mutually exclusive with fileurl format, "/directory/filename".
        type: str
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Bios test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set bios setup"
    kaytus.ksmanage.edit_bios:
      attribute: "VMX"
      value: "Disable"
      provider: "{{ ksmanage }}"

  - name: "Set bios setup"
    kaytus.ksmanage.edit_bios:
      attribute: "VMX"
      value: "Enable"
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


class BIOS(object):
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
        self.module.params['subcommand'] = 'setbios'
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
        list=dict(type='bool', required=False, default=False),
        attribute=dict(type='str', required=False),
        value=dict(type='str', required=False),
        file_url=dict(type='str', required=False)
    )
    argument_spec.update(ksmanage_argument_spec)
    bios_obj = BIOS(argument_spec)
    bios_obj.work()


if __name__ == '__main__':
    main()
