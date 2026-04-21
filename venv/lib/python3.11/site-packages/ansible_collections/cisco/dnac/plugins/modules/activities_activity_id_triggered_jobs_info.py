#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: activities_activity_id_triggered_jobs_info
short_description: Information module for Activities
  Activity Id Triggered Jobs
description:
  - Get all Activities Activity Id Triggered Jobs.
  - Returns the triggered jobs by the activity with
    the given activity id.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  activityId:
    description:
      - ActivityId path parameter. The id of the activity.
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
  - name: Cisco DNA Center documentation for Task GetTriggeredJobsByActivityId
    description: Complete reference of the GetTriggeredJobsByActivityId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-triggered-jobs-by-activity-id
notes:
  - SDK Method used are
    task.Task.get_triggered_jobs_by_activity_id,
  - Paths used are
    get /dna/intent/api/v1/activities/{activityId}/triggeredJobs,
"""

EXAMPLES = r"""
---
- name: Get all Activities Activity Id Triggered Jobs
  cisco.dnac.activities_activity_id_triggered_jobs_info:
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
    activityId: string
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
          "id": "string",
          "status": "string",
          "taskId": "string",
          "taskUrl": "string"
        }
      ],
      "version": "string"
    }
"""
