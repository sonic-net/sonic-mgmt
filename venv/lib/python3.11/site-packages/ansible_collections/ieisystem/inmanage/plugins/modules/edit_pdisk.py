#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_pdisk
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set physical disk
description:
   - Set physical disk on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    ctrl_id:
        description:
            - Raid controller ID.
        type: int
    device_id:
        description:
            - Physical drive id.
        type: int
    option:
        description:
            - Set operation options for a physical disk.
            - UG is Unconfigured Good, UB is Unconfigured Bad.
            - OFF is offline, FAIL is Failed, RBD is Rebuild.
            - ON is Online, JB is JBOD, ES is Drive Erase stop.
            - EM is Drive Erase Simple, EN is Drive Erase Normal.
            - ET is Drive Erase Through, LOC is Locate, STL is Stop Locate.
            - HS is Hot spare.
            - Only the M5 model supports C(HS) Settings.
        choices: ['UG', 'UB', 'OFF', 'FAIL', 'RBD', 'ON', 'JB', 'ES', 'EM', 'EN', 'ET', 'LOC', 'STL', 'HS']
        type: str
    action:
        description:
            - Action while set physical drive hotspare.
            - Required when I(option=HS).
            - Only the M5 model supports this parameter.
        choices: ['remove', 'global', 'dedicate']
        type: str
    revertible:
        description:
            - IsRevertible while set physical drive hotspare.
            - Required when I(option=HS) and I(action=dedicate).
            - Only the M5 model supports this parameter.
        choices: ['yes', 'no']
        type: str
    encl:
        description:
            - IsEnclAffinity while set physical drive hotspare.
            - Required when I(option=HS) and I(action=dedicate).
            - Only the M5 model supports this parameter.
        choices: ['yes', 'no']
        type: str
    logical_drivers:
        description:
            - Logical Drivers while set physical drive hotspare, input multiple Logical Drivers index like 0, 1, 2.....
            - Required when I(option=HS) and I(action=dedicate).
            - Only the M5 model supports this parameter.
        type: list
        elements: int
    duration:
        description:
            - Duration range is 1-255, physical drive under PMC raid controller.
            - Required when I(option=LOC).
            - Only the M6 model supports this parameter.
        type: int
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Edit pdisk test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Edit pdisk"
    ieisystem.inmanage.edit_pdisk:
      ctrl_id: 0
      device_id: 1
      option: "LOC"
      provider: "{{ inmanage }}"

  - name: "M5 Edit pdisk"
    ieisystem.inmanage.edit_pdisk:
      ctrl_id: 0
      device_id: 1
      option: "HS"
      action: "dedicate"
      revertible: "yes"
      encl: "yes"
      logical_drivers: 1
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


class Disk(object):
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
        self.module.params['subcommand'] = 'setpdisk'
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
        ctrl_id=dict(type='int', required=False),
        device_id=dict(type='int', required=False),
        option=dict(type='str', required=False, choices=['UG', 'UB', 'OFF', 'FAIL', 'RBD', 'ON', 'JB', 'ES', 'EM', 'EN', 'ET', 'LOC', 'STL', 'HS']),
        action=dict(type='str', required=False, choices=['remove', 'global', 'dedicate']),
        revertible=dict(type='str', required=False, choices=['yes', 'no']),
        encl=dict(type='str', required=False, choices=['yes', 'no']),
        logical_drivers=dict(type='list', elements='int', required=False),
        duration=dict(type='int', required=False),
    )
    argument_spec.update(inmanage_argument_spec)
    disk_obj = Disk(argument_spec)
    disk_obj.work()


if __name__ == '__main__':
    main()
