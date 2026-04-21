#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 Kaytus Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_kvm
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set KVM
description:
   - Set KVM on kaytus Server.
notes:
   - Does not support C(check_mode).
options:
    client_type:
        description:
            - Client Type.
            - Only the M6 model supports this parameter.
        choices: ['vnc', 'viewer']
        type: str
    kvm_encryption:
        description:
            - Encrypt KVM packets.
        choices: ['enable', 'disable']
        type: str
    media_attach:
        description:
            - Two types of VM attach mode are available.
            - Attach is Immediately attaches Virtual Media to the server upon bootup.
            - Auto is Attaches Virtual Media to the server only when a virtual media session is started.
            - Only the M5 model supports this parameter.
        choices: ['attach', 'auto']
        type: str
    keyboard_language:
        description:
            - Select the Keyboard Language.
            - AD is Auto Detect, DA is Danish, NL-BE is Dutch Belgium, NL-NL is Dutch Netherland.
            - GB is English UK , US is English US, FI is Finnish, FR-BE is French Belgium, FR is French France.
            - DE is German Germany, DE-CH is German Switzerland, IT is Italian, JP is Japanese.
            - NO is Norwegian, PT is Portuguese, ES is Spanish, SV is Swedish, TR_F is Turkish F, TR_Q is Turkish Q.
        choices: ['AD', 'DA', 'NL-BE', 'NL-NL', 'GB', 'US', 'FI', 'FR-BE', 'FR', 'DE', 'DE-CH', 'IT', 'JP', 'ON', 'PT', 'EC', 'SV', 'TR_F', 'TR_Q']
        type: str
    retry_count:
        description:
            - Number of times to be retried in case a KVM failure occurs.Retry count ranges from 1 to 20.
            - Only the M5 model supports this parameter.
        type: int
    retry_time_interval:
        description:
            - The Identification for retry time interval configuration (5-30) seconds.
            - Only the M5 model supports this parameter.
        type: int
    local_monitor_off:
        description:
            - Server Monitor OFF Feature Status.
        choices: ['enable', 'disable']
        type: str
    automatic_off:
        description:
            - Automatically OFF Server Monitor, When KVM Launches.
        choices: ['enable', 'disable']
        type: str
    non_secure:
        description:
            - Enable/disable Non Secure Connection Type.
            - Only the M6 model supports this parameter.
            - Required when I(client_type=vnc).
        choices: ['enable', 'disable']
        type: str
    ssh_vnc:
        description:
            - Enable/disable VNC over SSH in BMC.
            - Only the M6 model supports this parameter.
            - Required when I(client_type=vnc).
        choices: ['enable', 'disable']
        type: str
    stunnel_vnc:
        description:
            - Enable/disable VNC over Stunnel in BMC.
            - Only the M6 model supports this parameter.
            - Required when I(client_type=vnc).
        choices: ['enable', 'disable']
        type: str
extends_documentation_fragment:
    - kaytus.ksmanage.ksmanage
'''

EXAMPLES = '''
- name: KVM test
  hosts: ksmanage
  connection: local
  gather_facts: false
  vars:
    ksmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set KVM"
    kaytus.ksmanage.edit_kvm:
      kvm_encryption: "enable"
      media_attach: "auto"
      keyboard_language: "AD"
      retry_count: 13
      retry_time_interval: 10
      local_monitor_off: "enable"
      automatic_off: "enable"
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


class KVM(object):
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
        self.module.params['subcommand'] = 'setkvm'
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
        client_type=dict(type='str', required=False, choices=['vnc', 'viewer']),
        kvm_encryption=dict(type='str', required=False, choices=['enable', 'disable']),
        media_attach=dict(type='str', required=False, choices=['attach', 'auto']),
        keyboard_language=dict(type='str', required=False,
                               choices=['AD', 'DA', 'NL-BE', 'NL-NL', 'GB', 'US', 'FI', 'FR-BE', 'FR',
                                        'DE', 'DE-CH', 'IT', 'JP', 'ON', 'PT', 'EC', 'SV', 'TR_F', 'TR_Q']),
        retry_count=dict(type='int', required=False),
        retry_time_interval=dict(type='int', required=False),
        local_monitor_off=dict(type='str', required=False, choices=['enable', 'disable']),
        automatic_off=dict(type='str', required=False, choices=['enable', 'disable']),
        non_secure=dict(type='str', required=False, choices=['enable', 'disable']),
        ssh_vnc=dict(type='str', required=False, choices=['enable', 'disable']),
        stunnel_vnc=dict(type='str', required=False, choices=['enable', 'disable']),
    )
    argument_spec.update(ksmanage_argument_spec)
    kvm_obj = KVM(argument_spec)
    kvm_obj.work()


if __name__ == '__main__':
    main()
