#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_tasks_info
short_description: Information module for Assurance
  Tasks
description:
  - Get all Assurance Tasks.
  - returns all existing tasks in a paginated list.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  limit:
    description:
      - Limit query parameter. Maximum number of records
        to return.
    type: int
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point within all records returned by the API.
        It's one based offset. The starting value is
        1.
    type: int
  sortBy:
    description:
      - SortBy query parameter. A field within the response
        to sort by.
    type: str
  order:
    description:
      - Order query parameter. The sort order of the
        field ascending or descending.
    type: str
  status:
    description:
      - Status query parameter. Used to get a subset
        of tasks by their status.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task RetrieveAListOfAssuranceTasks
    description: Complete reference of the RetrieveAListOfAssuranceTasks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-a-list-of-assurance-tasks
notes:
  - SDK Method used are
    task.Task.retrieve_a_list_of_assurance_tasks,
  - Paths used are
    get /dna/data/api/v1/assuranceTasks,
"""

EXAMPLES = r"""
---
- name: Get all Assurance Tasks
  cisco.dnac.assurance_tasks_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
    sortBy: string
    order: string
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
      "response": [
        {
          "id": "string",
          "status": "string",
          "startTime": 0,
          "endTime": 0,
          "updateTime": 0,
          "progress": "string",
          "failureReason": "string",
          "errorCode": "string",
          "requestType": "string",
          "data": {},
          "resultUrl": "string"
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0,
        "sortBy": [
          {
            "name": "string",
            "order": "string"
          }
        ]
      },
      "version": "string"
    }
"""
