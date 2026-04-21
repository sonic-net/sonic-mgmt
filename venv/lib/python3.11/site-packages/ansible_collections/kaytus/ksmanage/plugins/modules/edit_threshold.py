#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_threshold
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set threshold information
description:
   - Set threshold information on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    name:
        description:
            - Sensor name.
        type: str
        required: true
    lnr:
        description:
            - Lower non recoverable threshold, should be integer.
        type: int
    lc:
        description:
            - Lower critical threshold, should be integer.
        type: int
    lnc:
        description:
            - Lower non critical threshold, should be integer.
        type: int
    unc:
        description:
            - Up non critical threshold, should be integer.
        type: int
    uc:
        description:
            - Up critical threshold, should be integer.
        type: int
    unr:
        description:
            - Up non recoverable threshold, should be integer.
        type: int
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Threshold test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set threshold information"
    kaytus.ksmanage.edit_threshold:
      name: "GPU1_Temp"
      uc: 94
      unc: 92
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


class Threshold(object):
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
        self.module.params['subcommand'] = 'setthreshold'
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
        name=dict(type='str', required=True),
        lnr=dict(type='int', required=False),
        lc=dict(type='int', required=False),
        lnc=dict(type='int', required=False),
        unc=dict(type='int', required=False),
        uc=dict(type='int', required=False),
        unr=dict(type='int', required=False),
    )
    argument_spec.update(ksmanage_argument_spec)
    threshoold_obj = Threshold(argument_spec)
    threshoold_obj.work()


if __name__ == '__main__':
    main()
