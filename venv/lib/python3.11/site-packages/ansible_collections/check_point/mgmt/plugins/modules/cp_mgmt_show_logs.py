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
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: cp_mgmt_show_logs
short_description: Showing logs according to the given filter.
description:
  - Showing logs according to the given filter.
  - All operations are performed over Web Services API.
  - Available from R80.40 JHF management version.
version_added: "2.0.0"
author: "Or Soffer (@chkp-orso)"
options:
  new_query:
    description:
      - Running a new query.
    type: dict
    suboptions:
      filter:
        description:
          - The filter as entered in SmartConsole/SmartView.
        type: str
      time_frame:
        description:
          - Specify the time frame to query logs.
        type: str
        choices: ['last-7-days', 'last-hour', 'today', 'last-24-hours', 'yesterday', 'this-week', 'this-month', 'last-30-days', 'all-time', 'custom']
      custom_start:
        description:
          - This option is only applicable when using the custom time-frame option.
        type: str
      custom_end:
        description:
          - This option is only applicable when using the custom time-frame option.
        type: str
      max_logs_per_request:
        description:
          - Limit the number of logs to be retrieved.
        type: int
      top:
        description:
          - Top results configuration.
        type: dict
        suboptions:
          field:
            description:
              - The field on which the top command is executed.
            type: str
            choices: ['sources', 'destinations', 'services', 'actions', 'blades' , 'origins', 'users', 'applications']
          count:
            description:
              - The number of results to retrieve.
            type: int
      type:
        description:
          - Type of logs to return.
        type: str
        choices: ['logs', 'audit']
      log_servers:
        description:
          - List of IP's of logs servers to query.
        type: list
        elements: str
  query_id:
    description:
      - Get the next page of last run query with specified limit.
    type: str
  ignore_warnings:
    description:
      - Ignore warnings if exist.
    type: bool
extends_documentation_fragment: check_point.mgmt.checkpoint_commands
"""

EXAMPLES = """
- name: show-logs
  cp_mgmt_show_logs:
    new_query:
      filter: blade:"Threat Emulation"
      max_logs_per_request: '2'
      time_frame: today
"""

RETURN = """
cp_mgmt_show_logs:
  description: The checkpoint show-logs output.
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
        new_query=dict(
            type="dict",
            options=dict(
                filter=dict(type="str"),
                time_frame=dict(
                    type="str",
                    choices=[
                        "last-7-days",
                        "last-hour",
                        "today",
                        "last-24-hours",
                        "yesterday",
                        "this-week",
                        "this-month",
                        "last-30-days",
                        "all-time",
                        "custom",
                    ],
                ),
                custom_start=dict(type="str"),
                custom_end=dict(type="str"),
                max_logs_per_request=dict(type="int"),
                top=dict(
                    type="dict",
                    options=dict(
                        field=dict(
                            type="str",
                            choices=[
                                "sources",
                                "destinations",
                                "services",
                                "actions",
                                "blades",
                                "origins",
                                "users",
                                "applications",
                            ],
                        ),
                        count=dict(type="int"),
                    ),
                ),
                type=dict(type="str", choices=["logs", "audit"]),
                log_servers=dict(type="list", elements="str"),
            ),
        ),
        query_id=dict(type="str"),
        ignore_warnings=dict(type="bool"),
    )
    argument_spec.update(checkpoint_argument_spec_for_commands)

    module = AnsibleModule(argument_spec=argument_spec)

    command = "show-logs"

    result = api_command(module, command)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
