#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: reports
short_description: Resource module for Reports
description:
  - Manage operations create and delete of the resource
    Reports. - > Create/Schedule a report configuration.
    Use "Get view details for a given view group & view"
    API to get the metadata required to configure a
    report.
  - Delete a scheduled report configuration. Deletes
    the report executions also.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  dataCategory:
    description: Category of viewgroup for the report.
    type: str
  deliveries:
    description: Array of available delivery channels.
    elements: dict
    type: list
  name:
    description: Report name.
    type: str
  reportId:
    description: ReportId path parameter. ReportId of
      report.
    type: str
  schedule:
    description: Reports's schedule.
    type: dict
  tags:
    description: Array of tags for report.
    elements: str
    type: list
  view:
    description: Reports's view.
    suboptions:
      fieldGroups:
        description: Reports's fieldGroups.
        elements: dict
        suboptions:
          fieldGroupDisplayName:
            description: Field group label/displayname
              for user.
            type: str
          fieldGroupName:
            description: Field group name.
            type: str
          fields:
            description: Reports's fields.
            elements: dict
            suboptions:
              displayName:
                description: Field label/displayname.
                type: str
              name:
                description: Field name.
                type: str
            type: list
        type: list
      filters:
        description: Reports's filters.
        elements: dict
        suboptions:
          displayName:
            description: Filter label/displayname.
            type: str
          name:
            description: Filter name.
            type: str
          type:
            description: Filter type.
            type: str
          value:
            description: Value of filter. Data type
              is based on the filter type. Use the filter
              definitions from the view to fetch the
              options for a filter.
            type: dict
        type: list
      format:
        description: Reports's format.
        suboptions:
          formatType:
            description: Format type of report.
            type: str
          name:
            description: Format name of report.
            type: str
        type: dict
      name:
        description: View name.
        type: str
      viewId:
        description: View Id.
        type: str
    type: dict
  viewGroupId:
    description: ViewGroupId of the viewgroup for the
      report.
    type: str
  viewGroupVersion:
    description: Version of viewgroup for the report.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Reports
      CreateOrScheduleAReport
    description: Complete reference of the CreateOrScheduleAReport
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-or-schedule-a-report
  - name: Cisco DNA Center documentation for Reports
      DeleteAScheduledReport
    description: Complete reference of the DeleteAScheduledReport
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-a-scheduled-report
notes:
  - SDK Method used are
    reports.Reports.create_or_schedule_a_report,
    reports.Reports.delete_a_scheduled_report,
  - Paths used are
    post /dna/intent/api/v1/data/reports,
    delete /dna/intent/api/v1/data/reports/{reportId},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.reports:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    dataCategory: string
    deliveries:
      - {}
    name: string
    schedule: {}
    tags:
      - string
    view:
      fieldGroups:
        - fieldGroupDisplayName: string
          fieldGroupName: string
          fields:
            - displayName: string
              name: string
      filters:
        - displayName: string
          name: string
          type: string
          value: {}
      format:
        formatType: string
        name: string
      name: string
      viewId: string
    viewGroupId: string
    viewGroupVersion: string
- name: Delete by id
  cisco.dnac.reports:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    reportId: string
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
          "name": "string"
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
