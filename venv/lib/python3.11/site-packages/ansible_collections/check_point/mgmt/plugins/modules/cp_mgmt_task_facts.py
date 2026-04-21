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
module: cp_mgmt_task_facts
short_description: Get task objects facts on Checkpoint over Web Services API
description:
  - Get task objects facts on Checkpoint devices.
  - All operations are performed over Web Services API.
  - This module handles both operations, get a specific object and get several objects,
    For getting a specific object use the parameter 'name'.
  - Available from R80.20 management version.
version_added: "5.0.0"
author: "Eden Brillant (@chkp-edenbr)"
options:
  task_id:
    description:
      - Unique identifier of one or more tasks.
    type: list
    elements: str
  details_level:
    description:
      - The level of detail for some of the fields in the response can vary from showing only the UID value of the object to a fully detailed
        representation of the object.
    type: str
    choices: ['uid', 'standard', 'full']
  initiator:
    description:
      - Initiator's name. If name isn't specified, tasks from all initiators will be shown.
    type: str
  status:
    description:
      - Status.
    type: str
    choices: ['successful', 'failed', 'in-progress', 'all']
  from_date:
    description:
      - The date from which tracking tasks is to be performed, by the task's last update date. ISO 8601. If timezone isn't specified in the input, the
        Management server's timezone is used.
    type: str
  to_date:
    description:
      - The date until which tracking tasks is to be performed, by the task's last update date. ISO 8601. If timezone isn't specified in the input,
        the Management server's timezone is used.
    type: str
  limit:
    description:
      - The maximal number of returned results.
        This parameter is relevant only for getting few objects.
    type: int
  offset:
    description:
      - Number of the results to initially skip.
        This parameter is relevant only for getting few objects.
    type: int
  order:
    description:
      - Sorts results by the given field. By default the results are sorted in the descending order by the task's last update date.
        This parameter is relevant only for getting few objects.
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
extends_documentation_fragment: check_point.mgmt.checkpoint_facts
"""

EXAMPLES = """
- name: show-task
  cp_mgmt_task_facts:
    task_id: 2eec70e5-78a8-4bdb-9a76-cfb5601d0bcb

- name: show-tasks
  cp_mgmt_task_facts:
    from_date: '2018-05-23T08:00:00'
    initiator: admin1
    status: successful
"""

RETURN = """
ansible_facts:
  description: The checkpoint object facts.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import checkpoint_argument_spec_for_facts, api_call_facts


def main():
    argument_spec = dict(
        task_id=dict(type='list', elements='str'),
        details_level=dict(type='str', choices=['uid', 'standard', 'full']),
        initiator=dict(type='str'),
        status=dict(type='str', choices=['successful', 'failed', 'in-progress', 'all']),
        from_date=dict(type='str'),
        to_date=dict(type='str'),
        limit=dict(type='int'),
        offset=dict(type='int'),
        order=dict(type='list', elements='dict', options=dict(
            ASC=dict(type='str', choices=['name']),
            DESC=dict(type='str', choices=['name'])
        ))
    )
    argument_spec.update(checkpoint_argument_spec_for_facts)

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    api_call_object = "task"
    api_call_object_plural_version = "tasks"

    result = api_call_facts(module, api_call_object, api_call_object_plural_version)
    module.exit_json(ansible_facts=result)


if __name__ == '__main__':
    main()
