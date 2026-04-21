#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage CheckPoint Firewall (c) 2019
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
---
module: cp_mgmt_tacacs_server
short_description: Manages tacacs-server objects on Checkpoint over Web Services API
description:
  - Manages tacacs-server objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R81 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  secret_key:
    description:
      - The server's secret key.<br><font color="red">Required only when</font> "server-type" was selected to be "TACACS+".
    type: str
  server:
    description:
      - The UID or Name of the host that is the TACACS Server.
    type: str
  encryption:
    description:
      - Is there a secret key defined on the server. Must be set true when "server-type" was selected to be "TACACS+".
    type: bool
  priority:
    description:
      - The priority of the TACACS Server in case it is a member of a TACACS Group.
    type: int
  server_type:
    description:
      - Server type, TACACS or TACACS+.
    type: str
    choices: ['TACACS', 'TACACS+']
  service:
    description:
      - Server service, only relevant when "server-type" is TACACS.
    type: str
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
  color:
    description:
      - Color of the object. Should be one of existing colors.
    type: str
    choices: ['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green', 'khaki', 'orchid', 'dark orange', 'dark sea green',
             'pink', 'turquoise', 'dark blue', 'firebrick', 'brown', 'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon',
             'coral', 'sea green', 'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna', 'yellow']
  comments:
    description:
      - Comments string.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  groups:
    description:
      - Collection of group identifiers.
    type: list
    elements: str
  ignore_warnings:
    description:
      - Apply changes ignoring warnings.
    type: bool
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-tacacs-server
  cp_mgmt_tacacs_server:
    name: tacacs7
    server: h1
    state: present

- name: set-tacacs-server
  cp_mgmt_tacacs_server:
    encryption: 'true'
    name: tacacs server
    priority: '5'
    secret_key: '**secret**'
    server: d700e8d5-d010-4f37-ab14-f78f5a26426c
    server_type: TACACS
    state: present

- name: delete-tacacs-server
  cp_mgmt_tacacs_server:
    name: tacacs server
    state: absent
"""

RETURN = """
cp_mgmt_tacacs_server:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        secret_key=dict(type='str', no_log=True),
        server=dict(type='str'),
        encryption=dict(type='bool'),
        priority=dict(type='int'),
        server_type=dict(type='str', choices=['TACACS', 'TACACS+']),
        service=dict(type='str'),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        groups=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'tacacs-server'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
