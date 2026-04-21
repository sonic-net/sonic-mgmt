#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_network_bond
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set network bond
description:
   - Set network bond on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    bond:
        description:
            - Network bond status, If VLAN is enabled for slave interfaces, then Bonding cannot be enabled.
        choices: ['enable', 'disable']
        type: str
    interface:
        description:
            - Interface name.
        choices: ['shared', 'dedicated', 'both']
        type: str
    auto_config:
        description:
            - Enable this option to configure the interfaces in service configuration automatically.
        choices: ['enable', 'disable']
        type: str
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Bond test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set network bond"
    kaytus.ksmanage.edit_network_bond:
      bond: "enable"
      interface: "dedicated"
      auto_config: "enable"
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


class Bond(object):
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
        self.module.params['subcommand'] = 'setnetworkbond'
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
        bond=dict(type='str', required=False, choices=['enable', 'disable']),
        interface=dict(type='str', required=False, choices=['shared', 'dedicated', 'both']),
        auto_config=dict(type='str', required=False, choices=['enable', 'disable']),
    )
    argument_spec.update(ksmanage_argument_spec)
    bond_obj = Bond(argument_spec)
    bond_obj.work()


if __name__ == '__main__':
    main()
