#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: ad_group
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Manage active directory group information
description:
   - Manage active directory group information on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    state:
        description:
            - Whether the active directory group should exist or not, taking action if the state is different from what is stated.
        choices: ['present', 'absent']
        default: present
        type: str
    name:
        description:
            - Group name.
        type: str
        required: true
    domain:
        description:
            - Group domain.
        type: str
    pri:
        description:
            - Group privilege.
        choices: ['administrator', 'user', 'operator', 'oem', 'none']
        type: str
    kvm:
        description:
            - Kvm privilege.
        choices: ['enable', 'disable']
        type: str
    vm:
        description:
            - Vmedia privilege.
        choices: ['enable', 'disable']
        type: str
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Ad group test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Add active directory group information"
    inspur.ispim.ad_group:
      state: "present"
      name: "wbs"
      domain: "inspur.com"
      pri: "administrator"
      kvm: "enable"
      vm: "disable"
      provider: "{{ ism }}"

  - name: "Set active directory group information"
    inspur.ispim.ad_group:
      state: "present"
      name: "wbs"
      pri: "user"
      kvm: "disable"
      provider: "{{ ism }}"

  - name: "Delete active directory group information"
    inspur.ispim.ad_group:
      state: "absent"
      name: "wbs"
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


class AD(object):
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
        self.module.params['subcommand'] = 'editadgroup'
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
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        name=dict(type='str', required=True),
        domain=dict(type='str', required=False),
        pri=dict(type='str', required=False, choices=['administrator', 'user', 'operator', 'oem', 'none']),
        kvm=dict(type='str', required=False, choices=['enable', 'disable']),
        vm=dict(type='str', required=False, choices=['enable', 'disable']),
    )
    argument_spec.update(ism_argument_spec)
    ad_obj = AD(argument_spec)
    ad_obj.work()


if __name__ == '__main__':
    main()
