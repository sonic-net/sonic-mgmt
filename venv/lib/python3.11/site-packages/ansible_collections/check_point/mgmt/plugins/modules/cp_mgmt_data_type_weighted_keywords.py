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
module: cp_mgmt_data_type_weighted_keywords
short_description: Manages data-type-weighted-keywords objects on Checkpoint over Web Services API
description:
  - Manages data-type-weighted-keywords objects on Checkpoint devices including creating, updating and removing objects.
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
  weighted_keywords:
    description:
      - List of keywords or phrases.
    type: list
    elements: dict
    suboptions:
      keyword:
        description:
          - keyword or regular expression to be weighted.
        type: str
      weight:
        description:
          - Weight of the expression.
        type: int
      max_weight:
        description:
          - Max weight of the expression.
        type: int
      regex:
        description:
          - Determine whether to consider the expression as a regular expression.
        type: bool
  description:
    description:
      - For built-in data types, the description explains the purpose of this type of data representation.
        For custom-made data types, you can use this field to provide more details.
    type: str
  sum_of_weights_threshold:
    description:
      - Define the number of appearances, by weight, of all the keywords that, beyond this threshold,
        the data containing this list of words or phrases will be recognized as data to be protected.
    type: int
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
- name: add-data-type-weighted-keywords
  cp_mgmt_data_type_weighted_keywords:
    name: weighted-words-obj
    state: present
    sum_of_weights_threshold: 10
    weighted_keywords:
      - keyword: word1
        max_weight: 4
        regex: true
        weight: 3

- name: set-data-type-weighted-keywords
  cp_mgmt_data_type_weighted_keywords:
    name: weighted-words-obj
    state: present
    sum_of_weights_threshold: 15
    weighted_keywords:
      - keyword: word1
        max_weight: 4
        regex: true
        weight: 3
      - keyword: word2
        max_weight: 5
        regex: false
        weight: 2

- name: delete-data-type-weighted-keywords
  cp_mgmt_data_type_weighted_keywords:
    name: weighted-words-obj
    state: absent
"""

RETURN = """
cp_mgmt_data_type_weighted_keywords:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        weighted_keywords=dict(type='list', elements='dict', no_log=False, options=dict(
            keyword=dict(type='str', no_log=False),
            weight=dict(type='int'),
            max_weight=dict(type='int'),
            regex=dict(type='bool')
        )),
        description=dict(type='str'),
        sum_of_weights_threshold=dict(type='int'),
        tags=dict(type='list', elements='str'),
        color=dict(type='str', choices=['aquamarine', 'black', 'blue', 'crete blue', 'burlywood', 'cyan', 'dark green',
                                        'khaki', 'orchid', 'dark orange', 'dark sea green', 'pink', 'turquoise', 'dark blue', 'firebrick', 'brown',
                                        'forest green', 'gold', 'dark gold', 'gray', 'dark gray', 'light green', 'lemon chiffon', 'coral', 'sea green',
                                        'sky blue', 'magenta', 'purple', 'slate blue', 'violet red', 'navy blue', 'olive', 'orange', 'red', 'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        ignore_warnings=dict(type='bool'),
        ignore_errors=dict(type='bool')
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'data-type-weighted-keywords'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
