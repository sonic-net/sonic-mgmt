#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_ntp
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set NTP
description:
   - Set NTP on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    auto_date:
        description:
            - Date auto synchronize.
        choices: ['enable', 'disable']
        type: str
    ntp_time:
        description:
            - NTP time(YYYYmmddHHMMSS).
            - Only the M5 model supports this parameter.
        type: str
    time_zone:
        description:
            - UTC time zone, chose from {-12, -11.5, -11, ... , 11, 11.5, 12}.
        type: str
    server1:
        description:
            - NTP Server1(ipv4 or ipv6 or domain name), set when auto_date is enable.
        type: str
    server2:
        description:
            - NTP Server2(ipv4 or ipv6 or domain name), set when auto_date is enable.
        type: str
    server3:
        description:
            - NTP Server3(ipv4 or ipv6 or domain name), set when auto_date is enable.
        type: str
    server4:
        description:
            - NTP Server4(ipv4 or ipv6 or domain name), set when auto_date is enable.
        type: str
    server5:
        description:
            - NTP Server5(ipv4 or ipv6 or domain name), set when auto_date is enable.
        type: str
    server6:
        description:
            - NTP Server6(ipv4 or ipv6 or domain name), set when auto_date is enable.
        type: str
    syn_cycle:
        description:
            - NTP syn cycle(minute), sync cycle(5-1440).
        type: int
    max_variety:
        description:
            - NTP Maximum jump time(minute), max variety(1-60).
            - Only the M6 model supports this parameter.
        type: int
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: NTP test
  hosts: inmanage
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set ntp"
    ieisystem.inmanage.edit_ntp:
      auto_date: "enable"
      server2: "time.nist.gov"
      provider: "{{ inmanage }}"

  - name: "Set ntp"
    ieisystem.inmanage.edit_ntp:
      auto_date: "disable"
      ntp_time: "20200609083600"
      provider: "{{ inmanage }}"

  - name: "set ntp"
    ieisystem.inmanage.edit_ntp:
      time_zone: "8"
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


class NTP(object):
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
        self.module.params['subcommand'] = 'settime'
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
        auto_date=dict(type='str', required=False, choices=['enable', 'disable']),
        ntp_time=dict(type='str', required=False),
        time_zone=dict(type='str', required=False),
        server1=dict(type='str', required=False),
        server2=dict(type='str', required=False),
        server3=dict(type='str', required=False),
        server4=dict(type='str', required=False),
        server5=dict(type='str', required=False),
        server6=dict(type='str', required=False),
        syn_cycle=dict(type='int', required=False),
        max_variety=dict(type='int', required=False),
    )
    argument_spec.update(inmanage_argument_spec)
    ntp_obj = NTP(argument_spec)
    ntp_obj.work()


if __name__ == '__main__':
    main()
