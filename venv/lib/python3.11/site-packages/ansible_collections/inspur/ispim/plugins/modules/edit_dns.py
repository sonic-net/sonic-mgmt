#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_dns
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Set dns information
description:
   - Set dns information on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    dns_status:
        description:
            - DNS status.
        choices: ['enable', 'disable']
        type: str
    host_cfg:
        description:
            - Host Settings.
        choices: ['manual', 'auto']
        type: str
    host_name:
        description:
            - Host Name.
            - Required when I(host_cfg=manual).
        type: str
    domain_manual:
        description:
            - Domain Settings.
        choices: ['manual', 'auto']
        type: str
    domain_iface:
        description:
            - Network Interface,input like 'eth0_v4', 'eth0_v6', 'eth1_v4', 'eth1_v6', 'bond0_v4', 'bond0_v6'.
            - Required when I(domain_manual=auto).
        type: str
    domain_name:
        description:
            - Domain Name.
            - Required when I(domain_manual=manual).
        type: str
    dns_manual:
        description:
            - DNS Settings.
        choices: ['manual', 'auto']
        type: str
    dns_iface:
        description:
            - DNS Interface,input like 'eth0', 'eth1', 'bond0'.
            - Required when I(dns_manual=auto).
        type: str
    dns_priority:
        description:
            - IP Priority.
            - Required when I(dns_manual=auto).
        choices: ['4', '6']
        type: str
    dns_server1:
        description:
            - DNS Server1 IPv4 or IPv6 address.
            - Required when I(dns_manual=manual).
        type: str
    dns_server2:
        description:
            - DNS Server2 IPv4 or IPv6 address.
            - Required when I(dns_manual=manual).
        type: str
    dns_server3:
        description:
            - DNS Server3 IPv4 or IPv6 address.
            - Required when I(dns_manual=manual).
        type: str
    register_status1:
        description:
            - BMC register status 1.
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    registration_method1:
        description:
            - Registration method 1.
            - Only the M6 model supports this parameter.
            - Required when I(register_status1=enable).
        choices: ['nsupdate', 'dhcp', 'hostname']
        type: str
    register_status2:
        description:
            - BMC register status 2.
            - Only the M6 model supports this parameter.
        choices: ['enable', 'disable']
        type: str
    registration_method2:
        description:
            - Registration method 2.
            - Only the M6 model supports this parameter.
            - Required when I(register_status2=enable).
        choices: ['nsupdate', 'dhcp', 'hostname']
        type: str
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: DNS test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set dns information"
    inspur.ispim.edit_dns:
      dns_status: "disable"
      provider: "{{ ism }}"

  - name: "Set dns information"
    inspur.ispim.edit_dns:
      dns_status: "enable"
      host_cfg: "manual"
      host_name: "123456789"
      domain_manual: "auto"
      domain_iface: "eth0_v4"
      dns_manual: "manual"
      dns_server1: "100.2.2.2"
      dns_server2: "100.2.2.3"
      dns_server3: "100.2.2.4"
      provider: "{{ ism }}"

  - name: "Set dns information"
    inspur.ispim.edit_dns:
      dns_status: "enable"
      host_cfg: "manual"
      host_name: "123456789"
      domain_manual: "manual"
      domain_name: "inspur.com"
      dns_manual: "auto"
      dns_iface: "eth0"
      dns_priority: "4"
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


class DNS(object):
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
        self.module.params['subcommand'] = 'setdns'
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
        dns_status=dict(type='str', required=False, choices=['enable', 'disable']),
        host_cfg=dict(type='str', required=False, choices=['manual', 'auto']),
        host_name=dict(type='str', required=False),
        domain_manual=dict(type='str', required=False, choices=['manual', 'auto']),
        domain_iface=dict(type='str', required=False),
        domain_name=dict(type='str', required=False),
        dns_manual=dict(type='str', required=False, choices=['manual', 'auto']),
        dns_iface=dict(type='str', required=False),
        dns_priority=dict(type='str', required=False, choices=['4', '6']),
        dns_server1=dict(type='str', required=False),
        dns_server2=dict(type='str', required=False),
        dns_server3=dict(type='str', required=False),
        register_status1=dict(type='str', required=False, choices=['enable', 'disable']),
        registration_method1=dict(type='str', required=False, choices=['nsupdate', 'dhcp', 'hostname']),
        register_status2=dict(type='str', required=False, choices=['enable', 'disable']),
        registration_method2=dict(type='str', required=False, choices=['nsupdate', 'dhcp', 'hostname']),
    )
    argument_spec.update(ism_argument_spec)
    dns_obj = DNS(argument_spec)
    dns_obj.work()


if __name__ == '__main__':
    main()
