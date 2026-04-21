#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_smtp
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set SMTP information
description:
   - Set SMTP information on kaytus Server.
   - Only the M5 models support this feature.
notes:
   - Does not support C(check_mode).
options:
    interface:
        description:
            - LAN Channel, eth0 is shared, eth1 is dedicated.
        choices: ['eth0', 'eth1', 'bond0']
        type: str
        required: true
    email:
        description:
            - Sender email.
        type: str
    primary_status:
        description:
            - Primary SMTP Support.
        choices: ['enable', 'disable']
        type: str
    primary_ip:
        description:
            - Primary SMTP server IP.
        type: str
    primary_name:
        description:
            - Primary SMTP server name.
        type: str
    primary_port:
        description:
            - Primary SMTP server port, The Identification for retry count configuration(1-65535).
        type: int
    primary_auth:
        description:
            - Primary SMTP server authentication.
        choices: ['enable', 'disable']
        type: str
    primary_username:
        description:
            - Primary SMTP server Username, length be 4 to 64 bits.
            - Must start with letters and cannot contain ', '(comma) ':'(colon) ' '(space) ';'(semicolon) '\\'(backslash).
        type: str
    primary_password:
        description:
            - Primary SMTP server Password, length be 4 to 64 bits, cannot contain ' '(space).
            - Required when I(primary_auth=enable).
        type: str
    secondary_status:
        description:
            - Secondary SMTP Support.
        choices: ['enable', 'disable']
        type: str
    secondary_ip:
        description:
            - Secondary SMTP server IP.
        type: str
    secondary_name:
        description:
            - Secondary SMTP server name.
        type: str
    secondary_port:
        description:
            - Secondary SMTP server port, The Identification for retry count configuration(1-65535).
        type: int
    secondary_auth:
        description:
            - Secondary SMTP server authentication.
        choices: ['enable', 'disable']
        type: str
    secondary_username:
        description:
            - Secondary SMTP server Username, length be 4 to 64 bits.
            - Must start with letters and cannot contain ','(comma) ':'(colon) ' '(space) ';'(semicolon) '\\'(backslash).
        type: str
    secondary_password:
        description:
            - Secondary SMTP server Password, length be 4 to 64 bits, cannot contain ' '(space).
            - Required when I(secondary_auth=enable).
        type: str
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Smtp test
  hosts: ksmanage
  no_log: true
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set smtp information"
    kaytus.ksmanage.edit_smtp:
      interface: "eth0"
      email: "ieit@ieisystem.com"
      primary_status: "enable"
      primary_ip: "100.2.2.2"
      primary_name: "test"
      primary_auth: "disable"
      provider: "{{ ksmanage }}"

  - name: "Set smtp information"
    kaytus.ksmanage.edit_smtp:
      interface: "eth0"
      email: "ieit@ieisystem.com"
      primary_status: "enable"
      primary_ip: "100.2.2.2"
      primary_name: "test"
      primary_auth: "enable"
      primary_username: "test"
      primary_password: my_password
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


class SMTP(object):
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
        self.module.params['subcommand'] = 'setsmtp'
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
        interface=dict(type='str', required=True, choices=['eth0', 'eth1', 'bond0']),
        email=dict(type='str', required=False),
        primary_status=dict(type='str', required=False, choices=['enable', 'disable']),
        primary_ip=dict(type='str', required=False),
        primary_name=dict(type='str', required=False),
        primary_port=dict(type='int', required=False),
        primary_auth=dict(type='str', required=False, choices=['enable', 'disable']),
        primary_username=dict(type='str', required=False),
        primary_password=dict(type='str', required=False, no_log=True),
        secondary_status=dict(type='str', required=False, choices=['enable', 'disable']),
        secondary_ip=dict(type='str', required=False),
        secondary_name=dict(type='str', required=False),
        secondary_port=dict(type='int', required=False),
        secondary_auth=dict(type='str', required=False, choices=['enable', 'disable']),
        secondary_username=dict(type='str', required=False),
        secondary_password=dict(type='str', required=False, no_log=True),

    )
    argument_spec.update(ksmanage_argument_spec)
    smtp_obj = SMTP(argument_spec)
    smtp_obj.work()


if __name__ == '__main__':
    main()
