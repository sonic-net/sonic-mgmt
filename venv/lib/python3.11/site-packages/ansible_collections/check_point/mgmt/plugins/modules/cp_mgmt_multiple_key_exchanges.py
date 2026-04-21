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
module: cp_mgmt_multiple_key_exchanges
short_description: Manages multiple-key-exchanges objects on Checkpoint over Web Services API
description:
  - Manages multiple-key-exchanges objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R82 management version.
version_added: "6.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  key_exchange_methods:
    description:
      - Key-Exchange methods to use. Can contain only Diffie-Hellman groups.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24']
  additional_key_exchange_1_methods:
    description:
      - Additional Key-Exchange 1 methods to use.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24', 'kyber-512', 'kyber-768', 'kyber-1024', 'none']
  additional_key_exchange_2_methods:
    description:
      - Additional Key-Exchange 2 methods to use.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24', 'kyber-512', 'kyber-768', 'kyber-1024', 'none']
  additional_key_exchange_3_methods:
    description:
      - Additional Key-Exchange 3 methods to use.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24', 'kyber-512', 'kyber-768', 'kyber-1024', 'none']
  additional_key_exchange_4_methods:
    description:
      - Additional Key-Exchange 4 methods to use.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24', 'kyber-512', 'kyber-768', 'kyber-1024', 'none']
  additional_key_exchange_5_methods:
    description:
      - Additional Key-Exchange 5 methods to use.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24', 'kyber-512', 'kyber-768', 'kyber-1024', 'none']
  additional_key_exchange_6_methods:
    description:
      - Additional Key-Exchange 6 methods to use.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24', 'kyber-512', 'kyber-768', 'kyber-1024', 'none']
  additional_key_exchange_7_methods:
    description:
      - Additional Key-Exchange 7 methods to use.
    type: list
    elements: str
    choices: ['group-1', 'group-2', 'group-5', 'group-14', 'group-15', 'group-16', 'group-17', 'group-18', 'group-19',
             'group-20', 'group-24', 'kyber-512', 'kyber-768', 'kyber-1024', 'none']
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
  domains_to_process:
    description:
      - Indicates which domains to process the commands on. It cannot be used with the details-level full, must be run from the System Domain only and
        with ignore-warnings true. Valid values are, CURRENT_DOMAIN, ALL_DOMAINS_ON_THIS_SERVER.
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
- name: add-multiple-key-exchanges
  cp_mgmt_multiple_key_exchanges:
    additional_key_exchange_1_methods: kyber-768
    key_exchange_methods: group-2
    name: Multiple Key Exchanges
    state: present

- name: set-multiple-key-exchanges
  cp_mgmt_multiple_key_exchanges:
    name: Multiple Key Exchanges
    state: present

- name: delete-multiple-key-exchanges
  cp_mgmt_multiple_key_exchanges:
    name: Multiple Key Exchanges
    state: absent
"""

RETURN = """
cp_mgmt_multiple_key_exchanges:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        key_exchange_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5', 'group-14',
                                                                        'group-15', 'group-16', 'group-17', 'group-18',
                                                                        'group-19', 'group-20', 'group-24']),
        additional_key_exchange_1_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5',
                                                                                     'group-14', 'group-15', 'group-16',
                                                                                     'group-17', 'group-18', 'group-19',
                                                                                     'group-20', 'group-24', 'kyber-512',
                                                                                     'kyber-768', 'kyber-1024', 'none']),
        additional_key_exchange_2_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5',
                                                                                     'group-14', 'group-15', 'group-16',
                                                                                     'group-17', 'group-18', 'group-19',
                                                                                     'group-20', 'group-24', 'kyber-512',
                                                                                     'kyber-768', 'kyber-1024', 'none']),
        additional_key_exchange_3_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5',
                                                                                     'group-14', 'group-15', 'group-16',
                                                                                     'group-17', 'group-18', 'group-19',
                                                                                     'group-20', 'group-24', 'kyber-512',
                                                                                     'kyber-768', 'kyber-1024', 'none']),
        additional_key_exchange_4_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5',
                                                                                     'group-14', 'group-15', 'group-16',
                                                                                     'group-17', 'group-18', 'group-19',
                                                                                     'group-20', 'group-24', 'kyber-512',
                                                                                     'kyber-768', 'kyber-1024', 'none']),
        additional_key_exchange_5_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5',
                                                                                     'group-14', 'group-15', 'group-16',
                                                                                     'group-17', 'group-18', 'group-19',
                                                                                     'group-20', 'group-24', 'kyber-512',
                                                                                     'kyber-768', 'kyber-1024', 'none']),
        additional_key_exchange_6_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5',
                                                                                     'group-14', 'group-15', 'group-16',
                                                                                     'group-17', 'group-18', 'group-19',
                                                                                     'group-20', 'group-24', 'kyber-512',
                                                                                     'kyber-768', 'kyber-1024', 'none']),
        additional_key_exchange_7_methods=dict(type='list', elements='str', choices=['group-1', 'group-2', 'group-5',
                                                                                     'group-14', 'group-15', 'group-16',
                                                                                     'group-17', 'group-18', 'group-19',
                                                                                     'group-20', 'group-24', 'kyber-512',
                                                                                     'kyber-768', 'kyber-1024', 'none']),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str'),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'multiple-key-exchanges'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
