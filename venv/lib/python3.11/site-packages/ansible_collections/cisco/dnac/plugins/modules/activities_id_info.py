#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: activities_id_info
short_description: Information module for Activities
  Id
description:
  - Get Activities Id by id.
  - Returns the activity with the given ID.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. The id of the activity to
        retrieve.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task GetActivityByID
    description: Complete reference of the GetActivityByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-activity-by-id
notes:
  - SDK Method used are
    task.Task.get_activity_by_id,
  - Paths used are
    get /intent/api/v1/activities/{id},
"""

EXAMPLES = r"""
---
- name: Get Activities Id by id
  cisco.dnac.activities_id_info:
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
        "description": "string",
        "endTime": 0,
        "id": "string",
        "originatingWorkItemActivityId": "string",
        "recurring": true,
        "startTime": 0,
        "status": "string",
        "type": "string"
      },
      "version": "string"
    }
"""
