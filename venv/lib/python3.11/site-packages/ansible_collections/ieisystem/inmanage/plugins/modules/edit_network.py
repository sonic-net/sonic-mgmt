#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_network
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set network information
description:
   - Set netowrk information on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    interface_name:
        description:
            - Set interface name. Select the LAN interface to be configured.
        choices: ['eth0', 'eth1', 'bond0']
        required: true
        type: str
    lan_enable:
        description:
            - Enable or disable this interface. If disable, you cannot use this interface any more.
        choices: ['enable', 'disable']
        required: true
        type: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Network test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set network information"
    ieisystem.inmanage.edit_network:
      interface_name: "eth0"
      lan_enable: "enable"
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


class Network(object):
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
        self.module.params['subcommand'] = 'setnetwork'
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
        interface_name=dict(type='str', required=True, choices=['eth0', 'eth1', 'bond0']),
        lan_enable=dict(type='str', required=True, choices=['enable', 'disable']),
    )
    argument_spec.update(inmanage_argument_spec)
    net_obj = Network(argument_spec)
    net_obj.work()


if __name__ == '__main__':
    main()
