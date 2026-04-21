#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tasks_info
short_description: Information module for Tasks
description:
  - Get all Tasks.
  - Get Tasks by id.
  - Returns tasks based on filter criteria.
  - Returns the task with the given ID.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: float
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page;The minimum is 1, and
        the maximum is 500.
    type: float
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - Order query parameter. Whether ascending or
        descending order should be used to sort the
        response.
    type: str
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
  id:
    description:
      - Id path parameter. The `id` of the task to retrieve.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task GetTasks
    description: Complete reference of the GetTasks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tasks
  - name: Cisco DNA Center documentation for Task GetTasksByID
    description: Complete reference of the GetTasksByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-tasks-by-id
notes:
  - SDK Method used are
    task.Task.get_tasks,
    task.Task.get_tasks_by_id,
  - Paths used are
    get /dna/intent/api/v1/tasks,
    get
    /dna/intent/api/v1/tasks/{id},
"""

EXAMPLES = r"""
---
- name: Get all Tasks
  cisco.dnac.tasks_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    sortBy: string
    order: string
    startTime: 0
    endTime: 0
    parentId: string
    rootId: string
    status: string
  register: result
- name: Get Tasks by id
  cisco.dnac.tasks_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
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
        "endTime": 0,
        "id": "string",
        "updatedTime": 0,
        "parentId": "string",
        "resultLocation": "string",
        "rootId": "string",
        "startTime": 0,
        "status": "string"
      },
      "version": "string"
    }
"""
