#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: adapter_info
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Get adapter information
description:
   - Get adapter information on kaytus Server.
notes:
   - Supports C(check_mode).
options: {}
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: Adapter test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Get adapter information"
    kaytus.ksmanage.adapter_info:
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


class Adapter(object):
    def __init__(self, argument_spec):
        self.spec = argument_spec
        self.module = None
        self.init_module()
        self.results = dict()

    def init_module(self):
        """Init module object"""
        self.module = AnsibleModule(
            argument_spec=self.spec, supports_check_mode=True)

    def run_command(self):
        self.module.params['subcommand'] = 'getnic'
        self.results = get_connection(self.module)

    def show_result(self):
        """Show result"""
        nic_result = self.results
        if nic_result['State'] == "Success":
            nic = nic_result['Message'][0]
            sysadapter_len = nic.get('Maximum', 0)
            idx = 0
            sortedRes = dict()
            if sysadapter_len > 0:
                nic = nic.get('NIC', [])
                List = []
                while idx < sysadapter_len:
                    nic_info = nic[idx]
                    sysadapter_info = nic_info.get('Controller')
                    List.extend(sysadapter_info)
                    idx = idx + 1
                sortedRes["State"] = "Success"
                sortedRes["Message"] = List
            else:
                sortedRes["State"] = "Failure"
                sortedRes["Message"] = "cannot get information"
            self.module.exit_json(**sortedRes)
        else:
            self.module.exit_json(**self.results)

    def work(self):
        """Worker"""
        self.run_command()
        self.show_result()


def main():
    argument_spec = dict()
    argument_spec.update(ksmanage_argument_spec)
    adapter_obj = Adapter(argument_spec)
    adapter_obj.work()


if __name__ == '__main__':
    main()
