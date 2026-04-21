#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: task_operation_info
short_description: Information module for Task Operation
description:
  - Get Task Operation by id.
  - Returns root tasks associated with an Operationid.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  operationId:
    description:
      - OperationId path parameter.
    type: str
  offset:
    description:
      - Offset path parameter. Index, minimum value
        is 0.
    type: int
  limit:
    description:
      - >
        Limit path parameter. The maximum value of {limit}
        supported is 500. Base 1 indexing for {limit},
        minimum value is 1.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task GetTaskByOperationId
    description: Complete reference of the GetTaskByOperationId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-task-by-operation-id
notes:
  - SDK Method used are
    task.Task.get_task_by_operationid,
  - Paths used are
    get /dna/intent/api/v1/task/operation/{operationId}/{offset}/{limit},
"""

EXAMPLES = r"""
---
- name: Get Task Operation by id
  cisco.dnac.task_operation_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    operationId: string
    offset: 0
    limit: 0
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
          "additionalStatusURL": "string",
          "data": "string",
          "endTime": 0,
          "errorCode": "string",
          "errorKey": "string",
          "failureReason": "string",
          "id": "string",
          "instanceTenantId": "string",
          "isError": true,
          "lastUpdate": 0,
          "operationIdList": {},
          "parentId": "string",
          "progress": "string",
          "rootId": "string",
          "serviceType": "string",
          "startTime": 0,
          "username": "string",
          "version": 0
        }
      ],
      "version": "string"
    }
"""
