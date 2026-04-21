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
module: cp_mgmt_show_updatable_objects_repository_content
short_description: Shows the content of the available updatable objects from the Check Point User Center.
description:
  - Shows the content of the available updatable objects from the Check Point User Center.
  - All operations are performed over Web Services API.
  - Available from R80.20 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  uid_in_updatable_objects_repository:
    description:
      - The object's unique identifier in the Updatable Objects repository.
    type: str
  filter:
    description:
      - Return results matching the specified filter.
    type: dict
    suboptions:
      text:
        description:
          - Return results containing the specified text value.
        type: str
      uri:
        description:
          - Return results under the specified uri value.
        type: str
      parent_uid_in_updatable_objects_repository:
        description:
          - Return results under the specified Updatable Object.
        type: str
  limit:
    description:
      - The maximal number of returned results.
    type: int
  offset:
    description:
      - Number of the results to initially skip.
    type: int
  order:
    description:
      - Sorts the results by search criteria. Automatically sorts the results by Name, in the ascending order.
    type: list
    elements: dict
    suboptions:
      ASC:
        description:
          - Sorts results by the given field in ascending order.
        type: str
        choices: ['name']
      DESC:
        description:
          - Sorts results by the given field in descending order.
        type: str
        choices: ['name']
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
      - Available from R81 management version.
    type: list
    elements: str
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: show-updatable-objects-repository-content
  cp_mgmt_show_updatable_objects_repository_content:
    limit: 1
"""

RETURN = """
cp_mgmt_show_updatable_objects_repository_content:
  description: The checkpoint show-updatable-objects-repository-content output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_commands, api_command


def main():
    argument_spec = dict(
        uid_in_updatable_objects_repository=dict(type='str'),
        filter=dict(type='dict', options=dict(
            text=dict(type='str'),
            uri=dict(type='str'),
            parent_uid_in_updatable_objects_repository=dict(type='str')
        )),
        limit=dict(type='int'),
        offset=dict(type='int'),
        order=dict(type='list', elements='dict', options=dict(
            ASC=dict(type='str', choices=['name']),
            DESC=dict(type='str', choices=['name'])
        )),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        domains_to_process=dict(type='list', elements='str')
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "show-updatable-objects-repository-content"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
