#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2020 Peter Ondrejka <pondrejk@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: job_invocation
short_description: Invoke Remote Execution Jobs
version_added: 1.4.0
description:
  - "Invoke and schedule Remote Execution Jobs"
author:
  - "Peter Ondrejka (@pondrejk)"
options:
  search_query:
    description:
      - Search query to identify hosts
    type: str
  bookmark:
    description:
      - Bookmark to infer the search query from
    type: str
  job_template:
    description:
      - Job template to execute
    required: true
    type: str
  targeting_type:
    description:
      - Dynamic query updates the search results before execution (useful for scheduled jobs)
    choices:
      - static_query
      - dynamic_query
    default: static_query
    type: str
  randomized_ordering:
    description:
      - Whether to order the selected hosts randomly
    type: bool
  execution_timeout_interval:
    description:
      - Override the timeout interval from the template for this invocation only
    type: int
  ssh:
    description:
      - ssh related options
    type: dict
    suboptions:
      effective_user:
        description:
          - What user should be used to run the script (using sudo-like mechanisms)
          - Defaults to a template parameter or global setting
        type: str
  command:
    description:
      - Command to be executed on host. Required for command templates
    type: str
  inputs:
    description:
      - Inputs to use
    type: dict
  recurrence:
    description:
      - Schedule a recurring job
    type: dict
    suboptions:
      cron_line:
        description:
          - How often the job should occur, in the cron format
        type: str
      max_iteration:
        description:
          - Repeat a maximum of N times
        type: int
      end_time:
        description:
          - Perform no more executions after this time
        type: str
      purpose:
        description:
          - Designation of a special purpose
        type: str
  scheduling:
    description:
      - Schedule the job to start at a later time
    type: dict
    suboptions:
      start_at:
        description:
          - Schedule the job for a future time
        type: str
      start_before:
        description:
          - Indicates that the action should be cancelled if it cannot be started before this time.
        type: str
  concurrency_control:
    description:
      - Control concurrency level and distribution over time
    type: dict
    suboptions:
      time_span:
        description:
          - Distribute tasks over given number of seconds
          - This is removed since foreman_remote_execution-11.0.0
        type: int
      concurrency_level:
        description:
          - Maximum jobs to be executed at once
        type: int
  description_format:
    description:
      - Override the description format from the template for this invocation only
    type: str
extends_documentation_fragment:
  - theforeman.foreman.foreman
'''

EXAMPLES = '''

- name: "Run remote command on a single host once"
  theforeman.foreman.job_invocation:
    search_query: "name ^ (foreman.example.com)"
    command: 'ls'
    job_template: "Run Command - SSH Default"
    ssh:
      effective_user: "tester"

- name: "Run ansible command on active hosts once a day"
  theforeman.foreman.job_invocation:
    bookmark: 'active'
    command: 'pwd'
    job_template: "Run Command - Ansible Default"
    recurrence:
      cron_line: "30 2 * * *"
    concurrency_control:
      concurrency_level: 2
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    job_invocations:
      description: List of job invocations
      type: list
      elements: dict
'''

from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import (
    ForemanAnsibleModule,
)

ssh_foreman_spec = {
    'effective_user': dict(),
}

recurrence_foreman_spec = {
    'cron_line': dict(),
    'max_iteration': dict(type='int'),
    'end_time': dict(),
    'purpose': dict(),
}

scheduling_foreman_spec = {
    'start_at': dict(),
    'start_before': dict(),
}

concurrency_control_foreman_spec = {
    'time_span': dict(type='int'),
    'concurrency_level': dict(type='int'),
}


class ForemanJobInvocationModule(ForemanAnsibleModule):
    pass


def main():
    module = ForemanJobInvocationModule(
        foreman_spec=dict(
            search_query=dict(),
            bookmark=dict(type='entity'),
            job_template=dict(required=True, type='entity'),
            targeting_type=dict(default='static_query', choices=['static_query', 'dynamic_query']),
            randomized_ordering=dict(type='bool'),
            command=dict(),
            inputs=dict(type='dict'),
            execution_timeout_interval=dict(type='int'),
            ssh=dict(type='dict', options=ssh_foreman_spec),
            recurrence=dict(type='dict', options=recurrence_foreman_spec),
            scheduling=dict(type='dict', options=scheduling_foreman_spec),
            concurrency_control=dict(type='dict', options=concurrency_control_foreman_spec),
            description_format=dict(),
        ),
        required_one_of=[['search_query', 'bookmark']],
        required_if=[
            ['job_template', 'Run Command - SSH Default', ['command']],
            ['job_template', 'Run Command - Ansible Default', ['command']],
        ],
    )

    # command input required by api
    if 'command' in module.foreman_params:
        module.foreman_params['inputs'] = {"command": module.foreman_params.pop('command')}

    with module.api_connection():
        if 'bookmark' in module.foreman_params:
            module.set_entity('bookmark', module.find_resource('bookmarks', search='name="{0}",controller="hosts"'.format(
                module.foreman_params['bookmark']),
                failsafe=False,
            ))
        module.auto_lookup_entities()
        module.ensure_entity('job_invocations', module.foreman_params, None, state='present')


if __name__ == '__main__':
    main()
