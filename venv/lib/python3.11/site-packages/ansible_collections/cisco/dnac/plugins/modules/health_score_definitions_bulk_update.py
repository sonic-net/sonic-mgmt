#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: health_score_definitions_bulk_update
short_description: Resource module for Health Score
  Definitions Bulk Update
description:
  - Manage operation create of the resource Health Score
    Definitions Bulk Update.
  - Update health thresholds, include status of overall
    health status for each metric.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  payload:
    description: Health Score Definitions Bulk Update's
      payload.
    elements: dict
    suboptions:
      id:
        description: Id.
        type: str
      includeForOverallHealth:
        description: Include For Overall Health.
        type: bool
      synchronizeToIssueThreshold:
        description: Synchronize To Issue Threshold.
        type: bool
      thresholdValue:
        description: Threshold Value.
        type: float
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      UpdateHealthScoreDefinitions
    description: Complete reference of the UpdateHealthScoreDefinitions
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-health-score-definitions
notes:
  - SDK Method used are
    devices.Devices.update_health_score_definitions,
  - Paths used are
    post /dna/intent/api/v1/healthScoreDefinitions/bulkUpdate,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.health_score_definitions_bulk_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
    payload:
      - id: string
        includeForOverallHealth: true
        synchronizeToIssueThreshold: true
        thresholdValue: 0
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
          "name": "string",
          "displayName": "string",
          "deviceFamily": "string",
          "description": "string",
          "includeForOverallHealth": true,
          "definitionStatus": "string",
          "thresholdValue": 0,
          "synchronizeToIssueThreshold": true,
          "lastModified": "string"
        }
      ],
      "version": "string"
    }
"""
