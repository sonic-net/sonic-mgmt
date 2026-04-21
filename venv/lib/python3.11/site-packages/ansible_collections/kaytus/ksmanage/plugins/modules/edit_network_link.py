#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_network_link
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set network link
description:
   - Set network link on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    interface:
        description:
            - Interface name.
        choices: ['shared', 'dedicated', 'both']
        type: str
        required: true
    auto_nego:
        description:
            - This option allows the device to perform auto-configuration.
            - To achieve the best mode of operation (speed and duplex) on the link.
        choices: ['enable', 'disable']
        type: str
    link_speed:
        description:
            - Link speed will list all the supported capabilities of the network interface. It can be 10/100 Mbps.
            - Required when I(auto_nego=disable).
        choices: [10, 100]
        type: int
    duplex_mode:
        description:
            - Select any one of the following Duplex Mode.
            - Required when I(auto_nego=disable).
        choices: ['HALF', 'FULL']
        type: str
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Link test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set network link"
    kaytus.ksmanage.edit_network_link:
      interface: "dedicated"
      auto_nego: "enable"
      provider: "{{ ksmanage }}"

  - name: "Set network link"
    kaytus.ksmanage.edit_network_link:
      interface: "dedicated"
      auto_nego: "disable"
      link_speed: 100
      duplex_mode: "FULL"
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


class Link(object):
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
        self.module.params['subcommand'] = 'setnetworklink'
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
        interface=dict(type='str', required=True, choices=['shared', 'dedicated', 'both']),
        auto_nego=dict(type='str', required=False, choices=['enable', 'disable']),
        link_speed=dict(type='int', required=False, choices=[10, 100]),
        duplex_mode=dict(type='str', required=False, choices=['HALF', 'FULL']),
    )
    argument_spec.update(ksmanage_argument_spec)
    link_obj = Link(argument_spec)
    link_obj.work()


if __name__ == '__main__':
    main()
