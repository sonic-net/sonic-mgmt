#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2023, Julien Godin <julien.godin@camptocamp.com>
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
module: wait_for_task
version_added: 3.13.0
short_description: Wait for a task
description:
  - Wait for a task to finish
author:
  - "Julien Godin (@JGodin-C2C)"
options:
  task:
    description:
      - Task id to wait for.
    required: true
    type: str
  timeout:
    description:
      - How much time the task should take to be finished
    required: false
    type: int
    default: 60
extends_documentation_fragment:
  - theforeman.foreman.foreman
'''


EXAMPLES = '''
- name: Wait for a task to finish
  theforeman.foreman.wait_for_task:
    server_url: "https://foreman.example.com"
    password: changeme
    username: admin
    task: a03ba49f-4dc2-4ad6-a48b-b271b46f3347
    timeout: 60

- name: Sarch for previously created tasks
  resource_info:
    server_url: "https://foreman.example.com"
    password: changeme
    username: admin
    resource: foreman_tasks
    search: "(label = Actions::Katello::Product::Destroy and action ~ 'Test Product' and state = running)"
  register: tasks

- name: Wait for all found tasks to finish
  wait_for_task:
    server_url: "https://foreman.example.com"
    password: changeme
    username: admin
    task: "{{ item }}"
    timeout: 900
  loop: "{{ tasks.resources | map(attribute='id') | list }}"
'''

RETURN = '''
task:
  description: The finished task
  returned: success
  type: dict
'''


from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import ForemanAnsibleModule


class ForemanWaitForTask(ForemanAnsibleModule):
    pass


def main():
    module = ForemanWaitForTask(
        argument_spec=dict(
            task=dict(type="str", required=True),
            timeout=dict(type="int", required=False, default=60),
        )
    )
    module.task_timeout = module.foreman_params["timeout"]
    with module.api_connection():

        task = module.wait_for_task(module.show_resource(
            'foreman_tasks', module.foreman_params["task"]))
        module.exit_json(task=task, task_id=task['id'])


if __name__ == "__main__":
    main()
