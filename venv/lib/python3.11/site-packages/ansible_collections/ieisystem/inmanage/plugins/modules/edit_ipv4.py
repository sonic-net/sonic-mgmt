#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_ipv4
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set ipv4 information
description:
   - Set ipv4 information on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    interface_name:
        description:
            - Set interface name. Select the LAN interface to be configured.
        choices: ['eth0', 'eth1', 'bond0']
        required: true
        type: str
    ipv4_status:
        description:
            - Enable or disable IPV4.
        choices: ['enable', 'disable']
        type: str
    ipv4_dhcp_enable:
        description:
            - Enable 'Enable DHCP' to dynamically configure IPv4 address using Dynamic Host Configuration Protocol (DHCP).
        choices: ['dhcp', 'static']
        type: str
    ipv4_address:
        description:
            - If DHCP is disabled, specify a static IPv4 address to be configured for the selected interface.
            - Required when I(ipv4_dhcp_enable=static).
        type: str
    ipv4_subnet:
        description:
            - If DHCP is disabled, specify a static Subnet Mask to be configured for the selected interface.
            - Required when I(ipv4_dhcp_enable=static).
        type: str
    ipv4_gateway:
        description:
            - If DHCP is disabled, specify a static Default Gateway to be configured for the selected interface.
            - Required when I(ipv4_dhcp_enable=static).
        type: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Ipv4 test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set ipv4 information"
    ieisystem.inmanage.edit_ipv4:
      interface_name: "eth0"
      ipv4_status: "disable"
      provider: "{{ inmanage }}"

  - name: "Set ipv4 information"
    ieisystem.inmanage.edit_ipv4:
      interface_name: "eth0"
      ipv4_status: "enable"
      ipv4_dhcp_enable: "dhcp"
      provider: "{{ inmanage }}"

  - name: "Set ipv4 information"
    ieisystem.inmanage.edit_ipv4:
      interface_name: "eth0"
      ipv4_status: "enable"
      ipv4_dhcp_enable: "static"
      ipv4_address: "100.2.36.10"
      ipv4_subnet: "255.255.255.0"
      ipv4_gateway: "100.2.36.1"
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
        self.module.params['subcommand'] = 'setipv4'
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
        ipv4_status=dict(type='str', required=False, choices=['enable', 'disable']),
        ipv4_dhcp_enable=dict(type='str', required=False, choices=['dhcp', 'static']),
        ipv4_address=dict(type='str', required=False),
        ipv4_subnet=dict(type='str', required=False),
        ipv4_gateway=dict(type='str', required=False),

    )
    argument_spec.update(inmanage_argument_spec)
    net_obj = Network(argument_spec)
    net_obj.work()


if __name__ == '__main__':
    main()
