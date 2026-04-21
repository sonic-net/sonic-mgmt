#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tasks_count_info
short_description: Information module for Tasks Count
description:
  - Get all Tasks Count.
  - Returns the number of tasks that meet the filter
    criteria.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  startTime:
    description:
      - StartTime query parameter. This is the epoch
        millisecond start time from which tasks need
        to be fetched.
    type: int
  endTime:
    description:
      - EndTime query parameter. This is the epoch millisecond
        end time upto which task records need to be
        fetched.
    type: int
  parentId:
    description:
      - ParentId query parameter. Fetch tasks that have
        this parent Id.
    type: str
  rootId:
    description:
      - RootId query parameter. Fetch tasks that have
        this root Id.
    type: str
  status:
    description:
      - Status query parameter. Fetch tasks that have
        this status. Available values PENDING, FAILURE,
        SUCCESS.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task GetTasksCount
    description: Complete reference of the GetTasksCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tasks-count
notes:
  - SDK Method used are
    task.Task.get_tasks_count,
  - Paths used are
    get /dna/intent/api/v1/tasks/count,
"""

EXAMPLES = r"""
---
- name: Get all Tasks Count
  cisco.dnac.tasks_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    startTime: 0
    endTime: 0
    parentId: string
    rootId: string
    status: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "count": 0
      },
      "version": "string"
    }
"""
