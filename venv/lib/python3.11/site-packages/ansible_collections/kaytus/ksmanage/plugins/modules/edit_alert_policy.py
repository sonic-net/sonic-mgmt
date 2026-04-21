#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_alert_policy
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set alert policy
description:
   - Set alert policy on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    id:
        description:
            - Alert id. Customize the channel for sending alarms in Trap.
            - The values for M5 modules are 1, 2, 3.
            - The values for M6 modules are 1, 2, 3, 4.
        choices: [1, 2, 3, 4]
        required: true
        type: int
    status:
        description:
            - Alert policy status. Whether to enable the receiving end for sending messages in trap mode.
        choices: ['enable', 'disable']
        type: str
    type:
        description:
            - Alert Type.
            - Only the M5 model supports this parameter.
        choices: ['snmp', 'email', 'snmpdomain']
        type: str
    destination:
        description:
            - Alert destination. The address of the server receiving trap information sent by Trap.
            - when type is snmp, specify an IP address.
            - When type is email, specify a username.
            - When type is snmpdomain, specify a domain.
        type: str
    channel:
        description:
            - LAN Channel.
            - Only the M5 model supports this parameter.
        choices: ['shared', 'dedicated']
        type: str
    trap_port:
        description:
            - SNMP trap port(1-65535).
            - Only the M6 model supports this parameter.
        type: int
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Alert policy test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set alert policy"
    kaytus.ksmanage.edit_alert_policy:
      id: 1
      status: "enable"
      type: "snmp"
      destination: "100.2.2.2"
      channel: "shared"
      provider: "{{ ksmanage }}"

  - name: "Set alert policy"
    kaytus.ksmanage.edit_alert_policy:
      id: 1
      status: "disable"
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
        self.module.params['subcommand'] = 'setalertpolicy'
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
        id=dict(type='int', required=True, choices=[1, 2, 3, 4]),
        status=dict(type='str', required=False, choices=['enable', 'disable']),
        type=dict(type='str', required=False, choices=['snmp', 'email', 'snmpdomain']),
        destination=dict(type='str', required=False),
        channel=dict(type='str', required=False, choices=['shared', 'dedicated']),
        trap_port=dict(type='int', required=False),
    )
    argument_spec.update(ksmanage_argument_spec)
    snmp_obj = SNMP(argument_spec)
    snmp_obj.work()


if __name__ == '__main__':
    main()
