#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_ldap
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Set ldap information
description:
   - Set ldap information on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    enable:
        description:
            - LDAP/E-Directory Authentication Status.
        choices: ['enable', 'disable']
        type: str
    encry:
        description:
            - Encryption Type.
        choices: ['no', 'SSL', 'StartTLS']
        type: str
    address:
        description:
            - Server Address.
        type: str
    server_port:
        description:
            - Server Port.
        type: int
    dn:
        description:
            - Bind DN.
            - Bind DN is a string of 4 to 64 alpha-numeric characters;
            - It must start with an alphabetical character;
            - Special Symbols like dot(.), comma(,), hyphen(-), underscore(_), equal-to(=) are allowed.
        type: str
    code:
        description:
            - Password.
            - Required when I(enable=enable).
        type: str
    base:
        description:
            - Search Base,
            - Search base is a string of 4 to 64 alpha-numeric characters;
            - It must start with an alphabetical character;
            - Special Symbols like dot(.), comma(,), hyphen(-), underscore(_), equal-to(=) are allowed.
        type: str
    attr:
        description:
            - Attribute of User Login.
        choices: ['cn', 'uid']
        type: str
    cn:
        description:
            - Common name type.
            - Required when I(encry=StartTLS).
        choices: ['ip', 'fqdn']
        type: str
    ca:
        description:
            - CA certificate file path.
            - Required when I(encry=StartTLS).
        type: str
    ce:
        description:
            - Certificate file path.
            - Required when I(encry=StartTLS).
        type: str
    pk:
        description:
            - Private Key file path.
            - Required when I(encry=StartTLS).
        type: str
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Ldap test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set ldap information"
    inspur.ispim.edit_ldap:
      enable: "disable"
      provider: "{{ ism }}"

  - name: "Set ldap information"
    inspur.ispim.edit_ldap:
      enable: "enable"
      encry: "SSL"
      address: "100.2.2.2"
      server_port: 389
      dn: "cn=manager,ou=login,dc=domain,dc=com"
      code: "123456"
      base: "cn=manager"
      attr: "uid"
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


class LDAP(object):
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
        self.module.params['subcommand'] = 'setldap'
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
        enable=dict(type='str', required=False, choices=['enable', 'disable']),
        encry=dict(type='str', required=False, choices=['no', 'SSL', 'StartTLS']),
        address=dict(type='str', required=False),
        server_port=dict(type='int', required=False),
        dn=dict(type='str', required=False),
        code=dict(type='str', required=False),
        base=dict(type='str', required=False),
        attr=dict(type='str', required=False, choices=['cn', 'uid']),
        cn=dict(type='str', required=False, choices=['ip', 'fqdn']),
        ca=dict(type='str', required=False),
        ce=dict(type='str', required=False),
        pk=dict(type='str', required=False),
    )
    argument_spec.update(ism_argument_spec)
    ldap_obj = LDAP(argument_spec)
    ldap_obj.work()


if __name__ == '__main__':
    main()
