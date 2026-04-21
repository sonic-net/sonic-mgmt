#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Ansible module to manage Check Point Firewall (c) 2019
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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
---
module: cp_mgmt_user
short_description: Manages user objects on Checkpoint over Web Services API
description:
  - Manages user objects on Checkpoint devices including creating, updating and removing objects.
  - All operations are performed over Web Services API.
  - Available from R80.40 JHF management version.
version_added: "6.3.0"
author: "Dor Berenstein (@chkp-dorbe)"
options:
  name:
    description:
      - Object name.
    type: str
    required: True
  template:
    description:
      - User template name or UID.
    type: str
  email:
    description:
      - User email.
    type: str
  expiration_date:
    description:
      - Expiration date in format, yyyy-MM-dd.
    type: str
  phone_number:
    description:
      - User phone number.
    type: str
  authentication_method:
    description:
      - Authentication method.
    type: str
    choices: ['undefined', 'check point password', 'os password', 'securid', 'radius', 'tacacs']
  password:
    description:
      - Check Point password authentication method identified by the name or UID. Must be set when "authentication-method" was selected to be "Check
        Point Password".
    type: str
  radius_server:
    description:
      - RADIUS server object identified by the name or UID. Must be set when "authentication-method" was selected to be "RADIUS".
    type: str
  tacacs_server:
    description:
      - TACACS server object identified by the name or UID. Must be set when "authentication-method" was selected to be "TACACS".
    type: str
  connect_on_days:
    description:
      - Days users allow to connect.
    type: list
    elements: str
  connect_daily:
    description:
      - Connect every day.
    type: bool
  from_hour:
    description:
      - Allow users connect from hour.
    type: str
  to_hour:
    description:
      - Allow users connect until hour.
    type: str
  allowed_locations:
    description:
      - User allowed locations.
    type: dict
    suboptions:
      destinations:
        description:
          - Collection of allowed destination locations name or uid.
        type: list
        elements: str
      sources:
        description:
          - Collection of allowed source locations name or uid.
        type: list
        elements: str
  encryption:
    description:
      - User encryption. Doesn't support shared secret.
    type: dict
    suboptions:
      ike:
        description:
          - Enable IKE encryption for users.
        type: bool
      public_key:
        description:
          - Enable IKE public key.
        type: bool
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
  groups:
    description:
      - Collection of group identifiers.
    type: list
    elements: str
  ignore_errors:
    description:
      - Apply changes ignoring errors. You won't be able to publish such a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
    type: bool
  tags:
    description:
      - Collection of tag identifiers.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_objects
"""

EXAMPLES = """
- name: add-user
  cp_mgmt_user:
    authentication_method: securid
    connect_daily: 'True'
    email: myuser@email.com
    encryption:
      enable_ike: 'True'
      enable_public_key: 'True'
    expiration_date: '2030-05-30'
    from_hour: 08:00
    name: myuser
    phone_number: '0501112233'
    state: present
    to_hour: '17:00'

- name: set-user
  cp_mgmt_user:
    authentication_method: undefined
    expiration_date: '2035-01-15'
    from_hour: '12:00'
    name: myuser
    state: present

- name: delete-user
  cp_mgmt_user:
    name: myuser
    state: absent
"""

RETURN = """
cp_mgmt_user:
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
        template=dict(type='str'),
        email=dict(type='str'),
        expiration_date=dict(type='str'),
        phone_number=dict(type='str'),
        authentication_method=dict(type='str',
                                   choices=['undefined',
                                            'check point password',
                                            'os password',
                                            'securid',
                                            'radius',
                                            'tacacs']),
        password=dict(type='str', no_log=True),
        radius_server=dict(type='str'),
        tacacs_server=dict(type='str'),
        connect_on_days=dict(type='list', elements="str"),
        connect_daily=dict(type='bool'),
        from_hour=dict(type='str'),
        to_hour=dict(type='str'),
        allowed_locations=dict(type='dict', options=dict(
            destinations=dict(type='list', elements="str"),
            sources=dict(type='list', elements="str")
        )),
        encryption=dict(type='dict', options=dict(
            ike=dict(type='bool'),
            public_key=dict(type='bool')
        )),
        color=dict(type='str', choices=['aquamarine',
                                        'black',
                                        'blue',
                                        'crete blue',
                                        'burlywood',
                                        'cyan',
                                        'dark green',
                                        'khaki',
                                        'orchid',
                                        'dark orange',
                                        'dark sea green',
                                        'pink',
                                        'turquoise',
                                        'dark blue',
                                        'firebrick',
                                        'brown',
                                        'forest green',
                                        'gold',
                                        'dark gold',
                                        'gray',
                                        'dark gray',
                                        'light green',
                                        'lemon chiffon',
                                        'coral',
                                        'sea green',
                                        'sky blue',
                                        'magenta',
                                        'purple',
                                        'slate blue',
                                        'violet red',
                                        'navy blue',
                                        'olive',
                                        'orange',
                                        'red',
                                        'sienna',
                                        'yellow']),
        comments=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        ignore_warnings=dict(type='bool'),
        groups=dict(type='list', elements="str"),
        ignore_errors=dict(type='bool'),
        tags=dict(type='list', elements="str")
    )
    argument_spec.update(checkpoint_argument_spec_for_objects)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    api_call_object = 'user'

    result = api_call(module, api_call_object)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
