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
module: cp_mgmt_radius_server
short_description: Manages radius-server objects on Checkpoint over Web Services API
description:
  - Manages radius-server objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R81.20 management version.
version_added: "5.0.0"
author: "Shiran Golzar (@chkp-shirango)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  server:
    description:
      - The UID or Name of the host that is the RADIUS Server.
    type: str
  shared_secret:
    description:
      - The secret between the RADIUS server and the Security Gateway.
    type: str
  service:
    description:
      - The UID or Name of the Service to which the RADIUS server listens.
    type: str
  server_version:
    description:
      - The version can be either RADIUS Version 1.0, which is RFC 2138 compliant, and RADIUS Version 2.0 which is RFC 2865 compliant.
    type: str
    choices: ['RADIUS Ver. 1.0', 'RADIUS Ver. 2.0']
  protocol:
    description:
      - The type of authentication protocol that will be used when authenticating the user to the RADIUS server.
    type: str
    choices: ['PAP', 'MS_CHAP2']
  priority:
    description:
      - The priority of the RADIUS Server in case it is a member of a RADIUS Group.
    type: int
  accounting:
    description:
      - Accounting settings.
    type: dict
    suboptions:
      enable_ip_pool_management:
        description:
          - IP pool management, enables Accounting service.
        type: bool
      accounting_service:
        description:
          - The UID or Name of the the accounting interface to notify the server when users login and logout which will then lock and release the
            IP addresses that the server allocated to those users.
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
- name: add-radius-server
  cp_mgmt_radius_server:
    name: radServer
    server: hostRad
    shared_secret: '123'
    state: present

- name: set-radius-server
  cp_mgmt_radius_server:
    name: t4
    server: hostRadius
    state: present

- name: delete-radius-server
  cp_mgmt_radius_server:
    ignore_warnings: 'true'
    name: radiusServer
    state: absent
"""

RETURN = """
cp_mgmt_radius_server:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, \
    api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        server=dict(type='str'),
        shared_secret=dict(type='str', no_log=True),
        service=dict(type='str'),
        server_version=dict(type='str', choices=['RADIUS Ver. 1.0', 'RADIUS Ver. 2.0']),
        protocol=dict(type='str', choices=['PAP', 'MS_CHAP2']),
        priority=dict(type='int'),
        accounting=dict(type='dict', options=dict(
            enable_ip_pool_management=dict(type='bool'),
            accounting_service=dict(type='str')
        )),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise',
                                        'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green',
                                        'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue',
                                        'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        groups=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'radius-server'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
