#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_power_budget
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set power budget information
description:
   - Set power budget information on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    range:
        description:
            - Range of power budget watts.
        choices: ['True', 'False']
        default: False
        type: bool
    domain:
        description:
            - Domain id.
            - Required when I(range=False).
        choices: ['system', 'cpu']
        type: str
    action:
        description:
            - Type to action.
            - Required when I(range=False).
        choices: ['add', 'delete', 'open', 'close']
        type: str
    id:
        description:
            - Policy id.
            - Required when I(range=False).
        choices: [1, 2, 3, 4]
        type: int
    watts:
        description:
            - Power budget watts of add.
            - Required when I(action=add).
        type: int
    except_action:
        description:
            - Except action, 0 is do nothing, 1 is send alert, 2 is shutdown system, 3 is shutdown system and send alert.
            - Only the M7 model supports this parameter.
        choices: [0, 1, 2, 3]
        type: int
    start1:
        description:
            - Pause period of add, start time, from 0 to 24.
        type: int
    end1:
        description:
            - Pause period of add, end time, must be greater than start time, from 0 to 24.
        type: int
    week1:
        description:
            - Pause period of add, repetition period.
            - The input parameters are 'Mon', 'Tue', 'Wed', 'Thur', 'Fri', 'Sat', 'Sun', separated by commas, such as Mon, Wed, Fri.
        type: list
        elements: str
    start2:
        description:
            - Pause period of add, start time, from 0 to 24.
        type: int
    end2:
        description:
            - Pause period of add, end time, must be greater than start time, from 0 to 24.
        type: int
    week2:
        description:
            - Pause period of add, repetition period.
            - The input parameters are 'Mon', 'Tue', 'Wed', 'Thur', 'Fri', 'Sat', 'Sun', separated by commas, such as Mon, Wed, Fri.
        type: list
        elements: str
    start3:
        description:
            - Pause period of add, start time, from 0 to 24.
        type: int
    end3:
        description:
            - Pause period of add, end time, must be greater than start time, from 0 to 24.
        type: int
    week3:
        description:
            - Pause period of add, repetition period.
            - The input parameters are 'Mon', 'Tue', 'Wed', 'Thur', 'Fri', 'Sat', 'Sun', separated by commas, such as Mon, Wed, Fri.
        type: list
        elements: str
    start4:
        description:
            - Pause period of add, start time, from 0 to 24.
        type: int
    end4:
        description:
            - Pause period of add, end time, must be greater than start time, from 0 to 24.
        type: int
    week4:
        description:
            - Pause period of add, repetition period.
            - The input parameters are 'Mon', 'Tue', 'Wed', 'Thur', 'Fri', 'Sat', 'Sun', separated by commas, such as Mon, Wed, Fri.
        type: list
        elements: str
    start5:
        description:
            - Period of add, start time, from 0 to 24.
        type: int
    end5:
        description:
            - Pause period of add, end time, must be greater than start time, from 0 to 24.
        type: int
    week5:
        description:
            - Pause period of add, repetition period.
            - The input parameters are 'Mon', 'Tue', 'Wed', 'Thur', 'Fri', 'Sat', 'Sun', separated by commas, such as Mon, Wed, Fri.
        type: list
        elements: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Power budget test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Get power budget range"
    ieisystem.inmanage.edit_power_budget:
      range: True
      provider: "{{ inmanage }}"

  - name: "add power budget"
    ieisystem.inmanage.edit_power_budget:
      action: "add"
      id: 1
      watts: 1500
      start1: 2
      end1: 5
      week1:
        - Mon
        - Wed
        - Fri
      provider: "{{ inmanage }}"

  - name: "Set power budget status to open"
    ieisystem.inmanage.edit_power_budget:
      action: "open"
      id: 1
      provider: "{{ inmanage }}"

  - name: "Set power budget status to close"
    ieisystem.inmanage.edit_power_budget:
      action: "close"
      id: 1
      provider: "{{ inmanage }}"

  - name: "Delete power budget"
    ieisystem.inmanage.edit_power_budget:
      action: "delete"
      id: 1
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


class Power(object):
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
        self.module.params['subcommand'] = 'setpowerbudget'
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
        range=dict(type='bool', default=False, choices=[True, False]),
        domain=dict(type='str', required=False, choices=['system', 'cpu']),
        action=dict(type='str', required=False, choices=['add', 'delete', 'open', 'close']),
        id=dict(type='int', required=False, choices=[1, 2, 3, 4]),
        watts=dict(type='int', required=False),
        except_action=dict(type='int', required=False, choices=[0, 1, 2, 3]),
        start1=dict(type='int', required=False),
        end1=dict(type='int', required=False),
        week1=dict(type='list', elements='str', required=False),
        start2=dict(type='int', required=False),
        end2=dict(type='int', required=False),
        week2=dict(type='list', elements='str', required=False),
        start3=dict(type='int', required=False),
        end3=dict(type='int', required=False),
        week3=dict(type='list', elements='str', required=False),
        start4=dict(type='int', required=False),
        end4=dict(type='int', required=False),
        week4=dict(type='list', elements='str', required=False),
        start5=dict(type='int', required=False),
        end5=dict(type='int', required=False),
        week5=dict(type='list', elements='str', required=False),
    )
    argument_spec.update(inmanage_argument_spec)
    power_obj = Power(argument_spec)
    power_obj.work()


if __name__ == '__main__':
    main()
