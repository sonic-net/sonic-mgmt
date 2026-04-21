#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_connect_media
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Start/Stop virtual media Image
description:
   - Start/Stop virtual media Image on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    image_type:
        description:
            - Virtual media type.
            - Only the M5 model supports this parameter.
        choices: ['CD', 'FD', 'HD']
        type: str
        required: true
    op_type:
        description:
            - Start or stop media.
        choices: ['start', 'stop']
        type: str
        required: true
    image_name:
        description:
            - Image name.
        type: str
        required: true
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Connect media test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set remote image redirection"
    ieisystem.inmanage.edit_connect_media:
      image_type: "CD"
      op_type: "start"
      image_name: "aa.iso"
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


class Connect(object):
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
        self.module.params['subcommand'] = 'setconnectmedia'
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
        image_type=dict(type='str', required=True, choices=['CD', 'FD', 'HD']),
        op_type=dict(type='str', required=True, choices=['start', 'stop']),
        image_name=dict(type='str', required=True),
    )
    argument_spec.update(inmanage_argument_spec)
    connect_obj = Connect(argument_spec)
    connect_obj.work()


if __name__ == '__main__':
    main()
