#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: activities_info
short_description: Information module for Activities
description:
  - Get all Activities.
  - Returns activitys based on filter criteria.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  description:
    description:
      - Description query parameter. The description
        of the activity.
    type: str
  status:
    description:
      - Status query parameter. The status of the activity.
    type: str
  type:
    description:
      - Type query parameter. The type of the activity.
    type: str
  recurring:
    description:
      - Recurring query parameter. If the activity is
        recurring.
    type: bool
  startTime:
    description:
      - StartTime query parameter. This is the epoch
        millisecond start time from which activities
        need to be fetched.
    type: str
  endTime:
    description:
      - EndTime query parameter. This is the epoch millisecond
        end time upto which activities need to be fetched.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page.
    type: int
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task GetActivities
    description: Complete reference of the GetActivities
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-activities
notes:
  - SDK Method used are
    task.Task.get_activities,
  - Paths used are
    get /dna/intent/api/v1/activities,
"""

EXAMPLES = r"""
---
- name: Get all Activities
  cisco.dnac.activities_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    description: string
    status: string
    type: string
    recurring: true
    startTime: string
    endTime: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
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
          "description": "string",
          "endTime": 0,
          "id": "string",
          "originatingWorkItemActivityId": "string",
          "recurring": true,
          "startTime": 0,
          "status": "string",
          "type": "string"
        }
      ],
      "version": "string"
    }
"""
