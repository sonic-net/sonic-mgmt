#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_smtp_com
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set SMTP information
description:
   - Set SMTP com information on kaytus Server.
   - Only the M6 models support this feature.
notes:
   - Does not support C(check_mode).
options:
    status:
        description:
            - SMTP Support.
        choices: ['enable', 'disable']
        required: true
        type: str
    server_ip:
        description:
            - SMTP server IP.
        type: str
    server_port:
        description:
            - SMTP server port, The Identification for retry count configuration(1-65535).
        type: int
    server_secure_port:
        description:
            - SMTP server secure port, The Identification for retry count configuration(1-65535).
        type: int
    email:
        description:
            - Sender email.
        type: str
    server_auth:
        description:
            - SMTP server authentication.
        choices: ['enable', 'disable']
        type: str
    server_username:
        description:
            - SMTP server Username, length be 4 to 64 bits.
            - Must start with letters and cannot contain ','(comma) ':'(colon) ' '(space) ';'(semicolon) '\\'(backslash).
            - Required when I(server_auth=enable).
        type: str
    server_password:
        description:
            - SMTP server Password, length be 4 to 64 bits, cannot contain ' '(space).
            - Required when I(server_auth=enable).
        type: str
    ssl_tls_enable:
        description:
            - SMTP SSLTLS Enable.
            - I(ssl_tls_enable=disable), when I(star_tls_enable=enable).
        choices: ['enable', 'disable']
        type: str
    star_tls_enable:
        description:
            - SMTP STARTTLS Enable.
            - I(star_tls_enable=disable), when I(ssl_tls_enable=enable).
        choices: ['enable', 'disable']
        type: str
    subject:
        description:
            - Email theme.
        type: str
    host_name:
        description:
            - Server name.
        choices: ['enable', 'disable']
        type: str
    serial_number:
        description:
            - Serial number.
        choices: ['enable', 'disable']
        type: str
    asset_tag:
        description:
            - Product asset label.
        choices: ['enable', 'disable']
        type: str
    event_level:
        description:
            - Events above this level will be sent.
        choices: ['Info', 'Warning', 'Critical']
        type: str
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Smtp com test
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

  - name: "Set smtp com information"
    kaytus.ksmanage.edit_smtp_com:
      status: "disable"
      provider: "{{ ksmanage }}"

  - name: "Set smtp com information"
    kaytus.ksmanage.edit_smtp_com:
      status: "enable"
      server_ip: "100.2.2.2"
      email: "ks@kaytus.com"
      server_auth: "enable"
      server_username: "admin"
      server_password: "1234qwer!@#$"
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
        self.module.params['subcommand'] = 'setsmtpcom'
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
        status=dict(type='str', required=True, choices=['enable', 'disable']),
        server_ip=dict(type='str', required=False),
        server_port=dict(type='int', required=False),
        server_secure_port=dict(type='int', required=False),
        email=dict(type='str', required=False),
        server_auth=dict(type='str', required=False, choices=['enable', 'disable']),
        server_username=dict(type='str', required=False),
        server_password=dict(type='str', required=False, no_log=True),
        ssl_tls_enable=dict(type='str', required=False, choices=['enable', 'disable']),
        star_tls_enable=dict(type='str', required=False, choices=['enable', 'disable']),
        subject=dict(type='str', required=False),
        host_name=dict(type='str', required=False, choices=['enable', 'disable']),
        serial_number=dict(type='str', required=False, choices=['enable', 'disable']),
        asset_tag=dict(type='str', required=False, choices=['enable', 'disable']),
        event_level=dict(type='str', required=False, choices=['Info', 'Warning', 'Critical']),
    )
    argument_spec.update(ksmanage_argument_spec)
    smtp_obj = SMTP(argument_spec)
    smtp_obj.work()


if __name__ == '__main__':
    main()
