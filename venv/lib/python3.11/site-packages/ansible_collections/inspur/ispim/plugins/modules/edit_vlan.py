#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_vlan
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Set vlan information
description:
   - Set vlan information on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    interface_name:
        description:
            - Set interface_name.
        choices: ['eth0', 'eth1', 'bond0']
        required: true
        type: str
    vlan_status:
        description:
            - Enable or disable vlan.
        choices: ['enable', 'disable']
        type: str
    vlan_id:
        description:
            - The Identification for VLAN configuration(2-4094).
        type: int
    vlan_priority:
        description:
            - The priority for VLAN configuration(1-7).
        type: int
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Vlan test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set vlan information"
    inspur.ispim.edit_vlan:
      interface_name: "eth0"
      vlan_status: "disable"
      provider: "{{ ism }}"

  - name: "Set vlan information"
    inspur.ispim.edit_vlan:
      interface_name: "eth0"
      vlan_status: "enable"
      vlan_id: 2
      vlan_priority: 1
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
        self.module.params['subcommand'] = 'setvlan'
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
        vlan_status=dict(type='str', required=False, choices=['enable', 'disable']),
        vlan_id=dict(type='int', required=False),
        vlan_priority=dict(type='int', required=False),

    )
    argument_spec.update(ism_argument_spec)
    net_obj = Network(argument_spec)
    net_obj.work()


if __name__ == '__main__':
    main()
