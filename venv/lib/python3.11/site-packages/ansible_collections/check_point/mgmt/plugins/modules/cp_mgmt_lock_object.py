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
module: cp_mgmt_lock_object
short_description: Lock object using name and type.
description:
  - Lock object using name and type. Can lock object only if the object is not locked by another session.
  - The object can be unlocked by the unlock, publish or discard commands.
  - All operations are performed over Web Services API.
  - Available from R81 JHF management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  name:
    description:
      - Object name. Must be unique in the domain.
    type: str
  type:
    description:
      - Object type.
    type: str
  layer:
    description:
      - Object layer, need to specify the layer if the object is rule/section and uid is not supplied.
    type: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: lock-object
  cp_mgmt_lock_object:
    name: host5
    type: host
"""

RETURN = """
cp_mgmt_lock_object:
  description: The checkpoint lock-object output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        name=dict(type='str'),
        type=dict(type='str'),
        layer=dict(type='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full'])
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "lock-object"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
