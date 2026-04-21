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

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["deprecated"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_show_tasks
short_description: Retrieve all tasks and show their progress and details.
description:
  - Retrieve all tasks and show their progress and details.
  - All operations are performed over Web Services API.
  - Available from R80.20 management version.
version_added: "2.0.0"
author: "Or Soffer (@chkp-orso)"
deprecated:
  alternative: cp_mgmt_task_facts
  why: Newer single facts module released.
  removed_at_date: '2024-11-01'
options:
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
    type: int
  offset:
    description:
      - Number of the results to initially skip.
    type: int
  order:
    description:
      - Sorts results by the given field. By default the results are sorted in the descending order by the task's last update date.
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
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: show-tasks
  cp_mgmt_show_tasks:
    from_date: '2018-05-23T08:00:00'
    initiator: admin1
    status: successful
"""

RETURN = """
cp_mgmt_show_tasks:
  description: The checkpoint show-tasks output.
  returned: always.
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    checkpoint_argument_spec_for_commands,
    api_command,
)


def main():
    argument_spec = dict(
        initiator=dict(type="str"),
        status=dict(
            type="str", choices=["successful", "failed", "in-progress", "all"]
        ),
        from_date=dict(type="str"),
        to_date=dict(type="str"),
        limit=dict(type="int"),
        offset=dict(type="int"),
        order=dict(
            type="list",
            elements="dict",
            options=dict(
                ASC=dict(type="str", choices=["name"]),
                DESC=dict(type="str", choices=["name"]),
            ),
        ),
        details_level=dict(type="str", choices=["uid", "standard", "full"]),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "show-tasks"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
