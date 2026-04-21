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
module: cp_mgmt_passcode_profile
short_description: Manages passcode-profile objects on Checkpoint over Web Services API
description:
  - Manages passcode-profile objects on Checkpoint devices including creating, updating and removing objects.
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
  allow_simple_passcode:
    description:
      - The passcode length is 4 and only numeric values allowed.
    type: bool
  min_passcode_length:
    description:
      - Minimum passcode length - relevant if "allow-simple-passcode" is disable.
    type: int
  require_alphanumeric_passcode:
    description:
      - Require alphanumeric characters in the passcode - relevant if "allow-simple-passcode" is disable.
    type: bool
  min_passcode_complex_characters:
    description:
      - Minimum number of complex characters (if "require-alphanumeric-passcode" is enabled). The number of the complex characters cannot be greater
        than number of the passcode length.
    type: int
  force_passcode_expiration:
    description:
      - Enable/disable expiration date to the passcode.
    type: bool
  passcode_expiration_period:
    description:
      - The period in days after which the passcode will expire.
    type: int
  enable_inactivity_time_lock:
    description:
      - Lock the device if app is inactive.
    type: bool
  max_inactivity_time_lock:
    description:
      - Time without user input before passcode must be re-entered (in minutes).
    type: int
  enable_passcode_failed_attempts:
    description:
      - Exit after few failures in passcode verification.
    type: bool
  max_passcode_failed_attempts:
    description:
      - Number of failed attempts allowed.
    type: int
  enable_passcode_history:
    description:
      - Check passcode history for reparations.
    type: bool
  passcode_history:
    description:
      - Number of passcodes that will be kept in history.
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
- name: add-passcode-profile
  cp_mgmt_passcode_profile:
    name: New App Passcode Policy
    state: present

- name: set-passcode-profile
  cp_mgmt_passcode_profile:
    allow_simple_passcode: 'true'
    max_inactivity_time_lock: '30'
    name: New App Passcode Policy
    require_alphanumeric_passcode: 'false'
    state: present

- name: delete-passcode-profile
  cp_mgmt_passcode_profile:
    name: My App Passcode Policy
    state: absent
"""

RETURN = """
cp_mgmt_passcode_profile:
  description: The checkpoint object created or updated.
  returned: always, except when deleting the object.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_objects, api_call


def main():
    argument_spec = dict(
        name=dict(type='str', required=True),
        allow_simple_passcode=dict(type='bool'),
        min_passcode_length=dict(type='int', no_log=True),
        require_alphanumeric_passcode=dict(type='bool'),
        min_passcode_complex_characters=dict(type='int', no_log=True),
        force_passcode_expiration=dict(type='bool'),
        passcode_expiration_period=dict(type='int'),
        enable_inactivity_time_lock=dict(type='bool'),
        max_inactivity_time_lock=dict(type='int'),
        enable_passcode_failed_attempts=dict(type='bool'),
        max_passcode_failed_attempts=dict(type='int', no_log=True),
        enable_passcode_history=dict(type='bool'),
        passcode_history=dict(type='int', no_log=True),
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
    api_call_object = 'passcode-profile'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
