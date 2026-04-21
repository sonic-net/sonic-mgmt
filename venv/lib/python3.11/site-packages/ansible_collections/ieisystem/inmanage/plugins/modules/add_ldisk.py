#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: add_ldisk
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Create logical disk
description:
   - Create logical disk on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    ctrl_id:
        description:
            - Raid controller ID.
            - Required when controller type is LSI, PMC or MV.
        type: int
    level:
        description:
            - RAID Level, 0 - RAID0, 1 - RAID1, 5 - RAID5, 6 - RAID6, 10 - RAID10.
            - Required when controller type is LSI or PMC.
        choices: [0, 1, 5, 6, 10]
        type: int
    size:
        description:
            - Strip Size, 0 - 32k, 1 - 64k, 2 - 128k, 3 - 256k, 4 - 512k, 5 - 1024k.
            - Required when controller type is LSI, PMC or MV.
            - When the controller type is MV, size is [0, 1].
            - When the controller type is LSI or PMC, size is [1, 2, 3, 4, 5].
        choices: [0, 1, 2, 3, 4, 5]
        type: int
    access:
        description:
            - Access Policy, 1 - Read Write, 2 - Read Only, 3 - Blocked.
            - Required when controller type is LSI.
        choices: [1, 2, 3]
        type: int
    r:
        description:
            - Read Policy, 1 - Read Ahead, 2 - No Read Ahead.
            - Required when controller type is LSI.
        choices: [1, 2]
        type: int
    w:
        description:
            - Write Policy, 1 - Write Through, 2 - Write Back, 3 - Write caching ok if bad BBU.
            - Required when controller type is LSI.
        choices: [1, 2, 3]
        type: int
    io:
        description:
            - IO Policy, 1 - Direct IO, 2 - Cached IO.
            - Required when controller type is LSI.
        choices: [1, 2]
        type: int
    cache:
        description:
            - Drive Cache, 1 - Unchanged, 2 - Enabled, 3 - Disabled.
            - Required when controller type is LSI.
        choices: [1, 2, 3]
        type: int
    init:
        description:
            - Init State, 1 - No Init, 2 - Quick Init, 3 - Full Init.
            - Required when controller type is LSI.
        choices: [1, 2, 3]
        type: int
    select:
        description:
            - Select Size, from 1 to 100.
            - Required when controller type is LSI.
        type: int
    slot:
        description:
            - Slot Num, input multiple slotNumber like 0, 1, 2....
            - Required when controller type is LSI or PMC.
        type: list
        elements: int
    accelerator:
        description:
            - Driver accelerator, 1 - 1h, 2 - 2h, 3 - 3h.
            - Required when controller type is PMC.
        choices: [1, 2, 3]
        type: int
    vname:
        description:
            - Virtual drive name.
            - Required when controller type is PMC or server model is M7.
            - Required when controller type is MV.
        type: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Add ldisk test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Add LSI ldisk"
    ieisystem.inmanage.add_ldisk:
      ctrl_id: 0
      level: 1
      size: 1
      access: 1
      r: 1
      w: 1
      io: 1
      cache: 1
      init: 2
      select: 10
      slot: 0,1
      provider: "{{ inmanage }}"

  - name: "Add PMC ldisk"
    ieisystem.inmanage.add_ldisk:
      ctrl_id: 0
      level: 1
      size: 1
      accelerator: 1
      slot: 0,1
      vname: "test"
      provider: "{{ inmanage }}"

  - name: "Add MV ldisk"
    ieisystem.inmanage.add_ldisk:
      ctrl_id: 0
      size: 1
      vname: "test"
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
        self.module.params['subcommand'] = 'addldisk'
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
        level=dict(type='int', required=False, choices=[0, 1, 5, 6, 10]),
        size=dict(type='int', required=False, choices=[0, 1, 2, 3, 4, 5]),
        access=dict(type='int', required=False, choices=[1, 2, 3]),
        r=dict(type='int', required=False, choices=[1, 2]),
        w=dict(type='int', required=False, choices=[1, 2, 3]),
        io=dict(type='int', required=False, choices=[1, 2]),
        cache=dict(type='int', required=False, choices=[1, 2, 3]),
        init=dict(type='int', required=False, choices=[1, 2, 3]),
        select=dict(type='int', required=False),
        slot=dict(type='list', elements='int', required=False),
        accelerator=dict(type='int', required=False, choices=[1, 2, 3]),
        vname=dict(type='str', required=False),
    )
    argument_spec.update(inmanage_argument_spec)
    disk_obj = Disk(argument_spec)
    disk_obj.work()


if __name__ == '__main__':
    main()
