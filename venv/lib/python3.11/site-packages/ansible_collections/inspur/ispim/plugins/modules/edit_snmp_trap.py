#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_snmp_trap
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Set snmp trap
description:
   - Set snmp trap on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    version:
        description:
            - SNMP trap version,1 is v1,2 is v2c(v2),3 is v3,0 is disable snmp trap.
            - Only the M6 model supports C(0) Settings.
        choices: [0, 1, 2, 3]
        type: int
    event_severity:
        description:
            - Event Severity.
        choices: ['all', 'warning', 'critical']
        type: str
    community:
        description:
            - Community of v1/v2c.
        type: str
    host_id:
        description:
            - Host id.
            - Only the M6 model supports this parameter.
        choices: ['HostName', 'SerialNum', 'AssertTag']
        type: str
    v3username:
        description:
            - Set user name of V3 trap.
        type: str
    engine_id:
        description:
            - Set Engine ID of V3 trap, engine ID is a string of 10 to 48 hex characters, must even, can set NULL.
        type: str
    auth_protocol:
        description:
            - Choose authentication.
        choices: ['NONE', 'SHA', 'MD5']
        type: str
    auth_password:
        description:
            - Set auth password of V3 trap, password is a string of 8 to 16 alpha-numeric characters.
            - Required when I(auth_protocol) is either C(SHA) or C(MD5).
        type: str
    priv_protocol:
        description:
            - Choose Privacy.
        choices: ['NONE', 'DES', 'AES']
        type: str
    priv_password:
        description:
            - Set privacy password of V3 trap, password is a string of 8 to 16 alpha-numeric characters.
            - Required when I(priv_protocol) is either C(DES) or C(AES).
        type: str
    system_name:
        description:
            - Set system name, can set NULL.
            - Only the M5 model supports this parameter.
        type: str
    system_id:
        description:
            - Set system ID, can set NULL.
            - Only the M5 model supports this parameter.
        type: str
    location:
        description:
            - Set host Location, can set NULL.
            - Only the M5 model supports this parameter.
        type: str
    contact:
        description:
            - Set contact, can set NULL.
            - Only the M5 model supports this parameter.
        type: str
    os:
        description:
            - Set host OS, can set NULL.
            - Only the M5 model supports this parameter.
        type: str
    trap_port:
        description:
            - Set SNMP trap Port(1-65535).
            - Only the M5 model supports this parameter.
        type: int
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Trap test
  hosts: ism
  no_log: true
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set snmp trap v2c"
    inspur.ispim.edit_snmp_trap:
      version: 2
      event_severity: "warning"
      inspur: "test"
      system_name: "Inspur"
      provider: "{{ ism }}"

  - name: "Set snmp trap v3"
    inspur.ispim.edit_snmp_trap:
      version: 3
      event_severity: "all"
      v3username: "Inspur"
      engine_id: "1234567890"
      auth_protocol: "SHA"
      auth_password: "12345678"
      priv_protocol: "AES"
      priv_password: "123454678"
      trap_port: 162
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


class SNMP(object):
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
        self.module.params['subcommand'] = 'setsnmptrap'
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
        version=dict(type='int', required=False, choices=[0, 1, 2, 3]),
        event_severity=dict(type='str', required=False, choices=['all', 'warning', 'critical']),
        community=dict(type='str', required=False),
        host_id=dict(type='str', required=False, choices=['HostName', 'SerialNum', 'AssertTag']),
        v3username=dict(type='str', required=False),
        engine_id=dict(type='str', required=False),
        auth_protocol=dict(type='str', required=False, choices=['NONE', 'SHA', 'MD5']),
        auth_password=dict(type='str', required=False, no_log=True),
        priv_protocol=dict(type='str', required=False, choices=['NONE', 'DES', 'AES']),
        priv_password=dict(type='str', required=False, no_log=True),
        system_name=dict(type='str', required=False),
        system_id=dict(type='str', required=False),
        location=dict(type='str', required=False),
        contact=dict(type='str', required=False),
        os=dict(type='str', required=False),
        trap_port=dict(type='int', required=False),
    )
    argument_spec.update(ism_argument_spec)
    snmp_obj = SNMP(argument_spec)
    snmp_obj.work()


if __name__ == '__main__':
    main()
