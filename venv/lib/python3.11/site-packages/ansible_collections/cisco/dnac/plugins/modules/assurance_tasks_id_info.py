#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_tasks_id_info
short_description: Information module for Assurance
  Tasks Id
description:
  - Get Assurance Tasks Id by id. - > returns a task
    given a specific task id For detailed information
    about the usage of the API, please refer to the
    Open API specification document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceTasks-1.0.0-resolved.yaml.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Unique task id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task RetrieveASpecificAssuranceTaskById
    description: Complete reference of the RetrieveASpecificAssuranceTaskById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-a-specific-assurance-task-by-id
notes:
  - SDK Method used are
    task.Task.retrieve_a_specific_assurance_task_by_id,
  - Paths used are
    get /dna/data/api/v1/assuranceTasks/{id},
"""

EXAMPLES = r"""
---
- name: Get Assurance Tasks Id by id
  cisco.dnac.assurance_tasks_id_info:
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
      },
      "version": "string"
    }
"""
