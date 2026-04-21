#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reports_info
short_description: Information module for Reports
description:
  - Get all Reports.
  - Get Reports by id.
  - Get list of scheduled report configurations.
  - Get scheduled report configuration by reportId.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  viewGroupId:
    description:
      - ViewGroupId query parameter. ViewGroupId of
        viewgroup for report.
    type: str
  viewId:
    description:
      - ViewId query parameter. ViewId of view for report.
    type: str
  reportId:
    description:
      - ReportId path parameter. ReportId of report.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Reports
      GetAScheduledReport
    description: Complete reference of the GetAScheduledReport
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-a-scheduled-report
  - name: Cisco DNA Center documentation for Reports
      GetListOfScheduledReports
    description: Complete reference of the GetListOfScheduledReports
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-list-of-scheduled-reports
notes:
  - SDK Method used are
    reports.Reports.get_a_scheduled_report,
    reports.Reports.get_list_of_scheduled_reports,
  - Paths used are
    get /dna/intent/api/v1/data/reports,
    get /dna/intent/api/v1/data/reports/{reportId},
"""

EXAMPLES = r"""
---
- name: Get all Reports
  cisco.dnac.reports_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    viewGroupId: string
    viewId: string
  register: result
- name: Get Reports by id
  cisco.dnac.reports_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    reportId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "tags": [
        "string"
      ],
      "dataCategory": "string",
      "deliveries": [
        {}
      ],
      "executionCount": 0,
      "executions": [
        {
          "endTime": 0,
          "errors": [
            "string"
          ],
          "executionId": "string",
          "processStatus": "string",
          "requestStatus": "string",
          "startTime": 0,
          "warnings": [
            "string"
          ]
        }
      ],
      "name": "string",
      "reportId": "string",
      "reportWasExecuted": true,
      "schedule": {},
      "view": {
        "fieldGroups": [
          {
            "fieldGroupDisplayName": "string",
            "fieldGroupName": "string",
            "fields": [
              {
                "displayName": "string",
                "name": "string"
              }
            ]
          }
        ],
        "filters": [
          {
            "displayName": "string",
            "name": "string",
            "type": "string",
            "value": {}
          }
        ],
        "format": {
          "formatType": "string",
          "name": "string",
          "default": true
        },
        "name": "string",
        "viewId": "string",
        "description": "string",
        "viewInfo": "string"
      },
      "viewGroupId": "string",
      "viewGroupVersion": "string"
    }
"""
