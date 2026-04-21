#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_ncsi
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set ncsi information
description:
   - Set ncsi information on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    nic_type:
        description:
            - Nic type.
            - Only NF3280A6 and NF3180A6 model supports C(Disable) Settings, but not support C(PHY) Settings.
            - M6 model only support C(OCP), C(OCP1), C(PCIE) settings.
        choices: ['PHY', 'OCP', 'OCP1', 'PCIE', 'auto', 'Disable']
        type: str
    mode:
        description:
            - NCSI mode, auto-Auto Failover, manual-Manual Switch.
            - Only M6 model supports C(Disable) Settings.
        choices: ['auto', 'manual', 'Disable']
        type: str
    interface_name:
        description:
            - Interface name, for example eth0.
            - Only the M5 model supports this parameter.
        type: str
    channel_number:
        description:
            - Channel number.
        choices: [0, 1, 2, 3]
        type: int
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: NCSI test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set ncsi information"
    ieisystem.inmanage.edit_ncsi:
      mode: "manual"
      nic_type: "PCIE"
      interface_name: "eth0"
      channel_number: 1
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


class NCSI(object):
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
        self.module.params['subcommand'] = 'setncsi'
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
        nic_type=dict(type='str', required=False, choices=['PHY', 'OCP', 'OCP1', 'PCIE', 'auto', 'Disable']),
        mode=dict(type='str', required=False, choices=['auto', 'manual', 'Disable']),
        interface_name=dict(type='str', required=False),
        channel_number=dict(type='int', required=False, choices=[0, 1, 2, 3]),
    )
    argument_spec.update(inmanage_argument_spec)
    ncsi_obj = NCSI(argument_spec)
    ncsi_obj.work()


if __name__ == '__main__':
    main()
