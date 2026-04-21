#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: activities_activity_id_triggered_jobs_count_info
short_description: Information module for Activities
  Activity Id Triggered Jobs Count
description:
  - Get all Activities Activity Id Triggered Jobs Count.
  - Retrieves the count of triggered jobs by activity
    id.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Task RetrievesTheCountOfTriggeredJobsByActivityId
    description: Complete reference of the RetrievesTheCountOfTriggeredJobsByActivityId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-count-of-triggered-jobs-by-activity-id
notes:
  - SDK Method used are
    task.Task.retrieves_the_count_of_triggered_jobs_by_activity_id,
  - Paths used are
    get /dna/intent/api/v1/activities/{activityId}/triggeredJobs/count,
"""

EXAMPLES = r"""
---
- name: Get all Activities Activity Id Triggered Jobs
    Count
  cisco.dnac.activities_activity_id_triggered_jobs_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
      "response": {
        "count": 0
      },
      "version": "string"
    }
"""
