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
module: cp_mgmt_if_map_server
short_description: Manages if-map-server objects on Checkpoint over Web Services API
description:
  - Manages if-map-server objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 JHF management version.
version_added: "6.5.0"
author: "Dor Berenstein (@chkp-dorbe)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  host:
    description:
      - Host that is IF-MAP server. Identified by name or UID.
    type: str
  monitored_ips:
    description:
      - IP ranges to be monitored by the IF-MAP client.
    type: list
    elements: dict
    suboptions:
      first_ip:
        description:
          - First IPv4 address in the range to be monitored.
        type: str
      last_ip:
        description:
          - Last IPv4 address in the range to be monitored.
        type: str
  port:
    description:
      - IF-MAP server port number.
    type: int
  server_version:
    description:
      - IF-MAP version.
    type: str
    choices: ['2.0', '1.1']
  path:
    description:
      - N/A
    type: str
  query_whole_ranges:
    description:
      - Indicate whether to query whole ranges instead of single IP.
    type: bool
  authentication:
    description:
      - Authentication configuration for the IF-MAP server.
    type: dict
    suboptions:
      authentication_method:
        description:
          - Authentication method for the IF-MAP server.
        type: str
        choices: ['certificate_based', 'basic']
      username:
        description:
          - Username for the IF-MAP server authentication. <font color="red">Required only when</font> 'authentication-method' is set to 'basic'.
        type: str
      password:
        description:
          - Username for the IF-MAP server authentication. <font color="red">Required only when</font> 'authentication-method' is set to 'basic'.
        type: str
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
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
    type: list
    elements: str
  tags:
    description:
      - Collection of tag identifiers.
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
- name: add-if-map-server
  cp_mgmt_if_map_server:
    authentication:
      authentication_method: certificate_based
    host: TestHost
    monitored_ips:
    - first_ip: 1.1.1.1
      last_ip: 1.1.1.2
    - first_ip: 2.1.1.1
      last_ip: 2.1.1.2
    name: TestIfMapServer
    path: path
    port: 1
    state: present
    version: 2

- name: set-if-map-server
  cp_mgmt_if_map_server:
    host: TestHost2
    monitored_ips:
    - first_ip: 3.1.1.1
      last_ip: 3.1.1.2
    name: TestIfMapServer
    path: newPath
    port: 2
    query_whole_ranges: false
    state: present
    version: 1.1

- name: delete-if-map-server
  cp_mgmt_if_map_server:
    name: TestIdp
    state: absent
"""

RETURN = """
cp_mgmt_if_map_server:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        host=dict(type='str'),
        monitored_ips=dict(type='list', elements="dict", options=dict(
            first_ip=dict(type='str'),
            last_ip=dict(type='str')
        )),
        port=dict(type='int'),
        server_version=dict(type='str', choices=['2.0', '1.1']),
        path=dict(type='str'),
        query_whole_ranges=dict(type='bool'),
        authentication=dict(type='dict', options=dict(
            authentication_method=dict(type='str', choices=['certificate_based', 'basic']),
            username=dict(type='str'),
            password=dict(type='str', no_log=True)
        )),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements="str"),
        tags=dict(type='list', elements="str"),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'if-map-server'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
