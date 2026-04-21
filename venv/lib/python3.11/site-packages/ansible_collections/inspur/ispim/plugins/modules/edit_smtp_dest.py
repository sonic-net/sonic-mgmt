#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright (C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_smtp_dest
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Set SMTP information
description:
   - Set SMTP dest information on Inspur server.
   - Only the M6 models support this feature.
notes:
   - Does not support C(check_mode).
options:
    id:
        description:
            - Email destination id.
        choices: [1, 2, 3, 4]
        type: int
        required: true
    status:
        description:
            - Email enable.
        choices: ['enable', 'disable']
        type: str
    address:
        description:
            - Email address.
        type: str
    description:
        description:
            - Description information.
        type: str
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Smtp  dest test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set smtp dest information"
    inspur.ispim.edit_smtp_dest:
      id: 1
      status: "disable"
      provider: "{{ ism }}"

  - name: "Set smtp dest information"
    inspur.ispim.edit_smtp_dest:
      id: 1
      status: "enable"
      address: "100.2.2.2"
      description": "test"
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
        self.module.params['subcommand'] = 'setsmtpdest'
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
        address=dict(type='str', required=False),
        description=dict(type='str', required=False),
    )
    argument_spec.update(ism_argument_spec)
    smtp_obj = SMTP(argument_spec)
    smtp_obj.work()


if __name__ == '__main__':
    main()
