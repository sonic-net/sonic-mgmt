#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_m6_log_setting
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set bmc system and audit log setting
description:
   - Set bmc system and audit log setting on kaytus Server.
   - Only the M6 models support this feature.
notes:
   - Does not support C(check_mode).
options:
    status:
        description:
            - System Log Status.
        choices: ['enable', 'disable']
        type: str
    host_tag:
        description:
            - System log host tag, set when I(status=enable).
        choices: ['HostName', 'SerialNum', 'AssertTag']
        type: str
    level:
        description:
            - Events Level, set when I(status=enable).
        choices: ['Critical', 'Warning', 'Info']
        type: str
    protocol_type:
        description:
            - Protocol Type, set when I(status=enable).
        choices: ['UDP', 'TCP']
        type: str
    server_id:
        description:
            - Syslog Server ID, set when I(status=enable).
        choices: [0, 1, 2, 3]
        type: int
    server_addr:
        description:
            - Server Address, set when server_id is not none.
        type: str
    server_port:
        description:
            - Server Address, set when server_id is not none.
        type: int
    log_type:
        description:
            - Remote Log Type, set when server_id is not none.
        choices: ['idl', 'audit', 'both']
        type: str
    test:
        description:
            - Test remote log settings, set when server_id is not none.
        default: False
        type: bool
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Edit log setting test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Edit bmc system log setting"
    kaytus.ksmanage.edit_m6_log_setting:
      status: "disable"
      provider: "{{ ksmanage }}"

  - name: "Edit bmc audit log setting"
    kaytus.ksmanage.edit_m6_log_setting:
      status: "enable"
      host_tag: "HostName"
      level: "Info"
      protocol_type: "TCP"
      server_id: 0
      server_addr: "100.2.126.11"
      server_port: 514
      log_type: "both"
      provider: "{{ ksmanage }}"

  - name: "test bmc audit log"
    kaytus.ksmanage.edit_m6_log_setting:
      server_id: 0
      test: True
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


class LogSetting(object):
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
        self.module.params['subcommand'] = 'setbmclogcfg'
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
        status=dict(type='str', required=False, choices=['enable', 'disable']),
        host_tag=dict(type='str', required=False, choices=['HostName', 'SerialNum', 'AssertTag']),
        level=dict(type='str', required=False, choices=['Critical', 'Warning', 'Info']),
        protocol_type=dict(type='str', required=False, choices=['UDP', 'TCP']),
        server_id=dict(type='int', required=False, choices=[0, 1, 2, 3]),
        server_addr=dict(type='str', required=False),
        server_port=dict(type='int', required=False),
        log_type=dict(type='str', required=False, choices=['idl', 'audit', 'both']),
        test=dict(type='bool', required=False, default=False),
    )
    argument_spec.update(ksmanage_argument_spec)
    log_obj = LogSetting(argument_spec)
    log_obj.work()


if __name__ == '__main__':
    main()
