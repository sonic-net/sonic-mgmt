#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2020 Inspur Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_media_instance
version_added: "1.0.0"
author:
    - WangBaoshan (@ispim)
short_description: Set Virtual Media Instance
description:
   - Set Virtual Media Instance on Inspur server.
notes:
   - Does not support C(check_mode).
options:
    num_fd:
        description:
            - Select the number of floppy devices that support for Virtual Media redirection.
        choices: [0, 1, 2, 3, 4]
        type: int
    num_cd:
        description:
            - Select the number of CD/DVD devices that support for Virtual Media redirection.
        choices: [0, 1, 2, 3, 4]
        type: int
    num_hd:
        description:
            - Select the number of harddisk devices that support for Virtual Media redirection.
        choices: [0, 1, 2, 3, 4]
        type: int
    kvm_num_fd:
        description:
            - Select the number of Remote KVM floppy devices that support for Virtual Media redirection.
        choices: [0, 1, 2, 3, 4]
        type: int
    kvm_num_cd:
        description:
            - Select the number of Remote KVM CD/DVD devices that support for virtual Media redirection,
            - The max support number of html5 KVM is 2 and java KVM is 4.
        choices: [0, 1, 2, 3, 4]
        type: int
    kvm_num_hd:
        description:
            - Select the number of Remote KVM Hard disk devices to support for Virtual Media redirection.
        choices: [0, 1, 2, 3, 4]
        type: int
    sd_media:
        description:
            - Check this option to enable SD Media support in BMC.
        choices: ['Enable', 'Disable']
        type: str
    secure_channel:
        description:
            - Check this option to enable encrypt media recirection packets.
            - Only the M5/M6 model supports this parameter.
        choices: ['Enable', 'Disable']
        type: str
    power_save_mode:
        description:
            - Check this option to enable Power Save Mode in BMC.
        choices: ['Enable', 'Disable']
        type: str
extends_documentation_fragment:
    - inspur.ispim.ism
'''

EXAMPLES = '''
- name: Media instance test
  hosts: ism
  connection: local
  gather_facts: no
  vars:
    ism:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set media instance"
    inspur.ispim.edit_media_instance:
      num_fd: 1
      num_cd: 1
      num_hd: 1
      kvm_num_fd: 1
      kvm_num_cd: 1
      kvm_num_hd: 1
      sd_media: "Enable"
      secure_channel: "Enable"
      power_save_mode: "Enable"
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


class Instance(object):
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
        self.module.params['subcommand'] = 'setmediainstance'
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
        num_fd=dict(type='int', required=False, choices=[0, 1, 2, 3, 4]),
        num_cd=dict(type='int', required=False, choices=[0, 1, 2, 3, 4]),
        num_hd=dict(type='int', required=False, choices=[0, 1, 2, 3, 4]),
        kvm_num_fd=dict(type='int', required=False, choices=[0, 1, 2, 3, 4]),
        kvm_num_cd=dict(type='int', required=False, choices=[0, 1, 2, 3, 4]),
        kvm_num_hd=dict(type='int', required=False, choices=[0, 1, 2, 3, 4]),
        sd_media=dict(type='str', required=False, choices=['Enable', 'Disable']),
        secure_channel=dict(type='str', required=False, choices=['Enable', 'Disable']),
        power_save_mode=dict(type='str', required=False, choices=['Enable', 'Disable']),
    )
    argument_spec.update(ism_argument_spec)
    instance_obj = Instance(argument_spec)
    instance_obj.work()


if __name__ == '__main__':
    main()
