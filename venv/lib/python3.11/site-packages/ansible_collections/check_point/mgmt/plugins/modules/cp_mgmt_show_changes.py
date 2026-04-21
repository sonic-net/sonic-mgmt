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
module: cp_mgmt_show_changes
short_description: Show changes between two sessions.
description:
  - Show changes between two sessions.
  - All operations are performed over Web Services API.
  - Available from R80.10 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  from_date:
    description:
      - The date from which tracking changes is to be performed. ISO 8601. If timezone isn't specified in the input, the Management server's timezone is used.
    type: str
  from_session:
    description:
      - The session UID from which tracking changes is to be performed.
    type: str
  limit:
    description:
      - Maximum number of sessions to analyze.
    type: int
  offset:
    description:
      - Number of sessions to skip (beginning with from-session).
    type: int
  to_date:
    description:
      - The date until which tracking changes is to be performed. ISO 8601. If timezone isn't specified in the input, the Management server's timezone is used.
    type: str
  to_session:
    description:
      - The session UID until which tracking changes is to be performed.
    type: str
  dereference_group_members:
    description:
      - Indicates whether to dereference "members" field by details level for every object in reply.
    type: bool
  show_membership:
    description:
      - Indicates whether to calculate and show "groups" field for every object in reply.
    type: bool
  dereference_max_depth:
    description:
      - When details level is full you can choose the number of levels in the API reply.
    type: int
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: show-changes
  cp_mgmt_show_changes:
    from_date: '2017-02-01T08:20:50'
    to_date: '2017-02-21'
"""

RETURN = """
cp_mgmt_show_changes:
  description: The checkpoint show-changes output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        from_date=dict(type='str'),
        from_session=dict(type='str'),
        limit=dict(type='int'),
        offset=dict(type='int'),
        to_date=dict(type='str'),
        to_session=dict(type='str'),
        dereference_group_members=dict(type='bool'),
        show_membership=dict(type='bool'),
        dereference_max_depth=dict(type='int'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full'])
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "show-changes"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
