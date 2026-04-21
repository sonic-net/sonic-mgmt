#!/usr/bin/python
# -*- coding:utf-8 -*-

# Copyright(C) 2023 IEIT Inc. All Rights Reserved.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
---
module: edit_virtual_media
version_added: "1.0.0"
author:
    - WangBaoshan (@ieisystem)
short_description: Set virtual media
description:
   - Set virtual media on ieisystem Server.
notes:
   - Does not support C(check_mode).
options:
    local_media_support:
        description:
            - To enable or disable Local Media Support, check or uncheck the checkbox respectively.
            - Only the M5 model supports this parameter.
        choices: ['Enable', 'Disable']
        type: str
    remote_media_support:
        description:
            - To enable or disable Remote Media support, check or uncheck the checkbox respectively.
        choices: ['Enable', 'Disable']
        type: str
    mount_type:
        description:
            - Virtual mount type.
            - The I(FD) option is not supported in M6.
        choices: ['CD', 'FD', 'HD']
        type: str
    same_settings:
        description:
            - Same settings with I(CD), 0 is No, 1 is Yes.
            - Required when I(mount_type=0).
        choices: [0, 1]
        type: int
    mount:
        description:
            - Whether to mount virtual media.
            - Only the M5 model supports this parameter.
        choices: ['Enable', 'Disable']
        type: str
    remote_server_address:
        description:
            - Address of the server where the remote media images are stored.
        type: str
    remote_source_path:
        description:
            - Source path to the remote media images..
        type: str
    remote_share_type:
        description:
            - Share Type of the remote media server either NFS or Samba(CIFS).
        choices: ['nfs', 'cifs']
        type: str
    remote_domain_name:
        description:
            - Remote Domain Name, Domain Name field is optional.
        type: str
    remote_user_name:
        description:
            - Remote User Name.
            - Required when I(remote_share_type=cifs).
        type: str
    remote_password:
        description:
            - Remote Password.
            - Required when I(remote_share_type=cifs).
        type: str
extends_documentation_fragment:
    - ieisystem.inmanage.inmanage
'''

EXAMPLES = '''
- name: Media test
  hosts: inmanage
  no_log: true
  connection: local
  gather_facts: false
  vars:
    inmanage:
      host: "{{ ansible_ssh_host }}"
      username: "{{ username }}"
      password: "{{ password }}"

  tasks:

  - name: "Set local media"
    ieisystem.inmanage.edit_virtual_media:
      local_media_support: "Enable"
      provider: "{{ inmanage }}"

  - name: "Set remote media"
    ieisystem.inmanage.edit_virtual_media:
      remote_media_support: "Enable"
      mount_type: 'CD'
      same_settings: 0
      mount: "Enable"
      remote_server_address: "100.2.28.203"
      remote_source_path: "/data/nfs/server/"
      remote_share_type: "nfs"
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


class Media(object):
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
        self.module.params['subcommand'] = 'setvirtualmedia'
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
        local_media_support=dict(type='str', required=False, choices=['Enable', 'Disable']),
        remote_media_support=dict(type='str', required=False, choices=['Enable', 'Disable']),
        mount_type=dict(type='str', required=False, choices=['CD', 'FD', 'HD']),
        same_settings=dict(type='int', required=False, choices=[0, 1]),
        mount=dict(type='str', required=False, choices=['Enable', 'Disable']),
        remote_server_address=dict(type='str', required=False),
        remote_source_path=dict(type='str', required=False),
        remote_share_type=dict(type='str', required=False, choices=['nfs', 'cifs']),
        remote_domain_name=dict(type='str', required=False),
        remote_user_name=dict(type='str', required=False),
        remote_password=dict(type='str', required=False, no_log=True),
    )
    argument_spec.update(inmanage_argument_spec)
    media_obj = Media(argument_spec)
    media_obj.work()


if __name__ == '__main__':
    main()
