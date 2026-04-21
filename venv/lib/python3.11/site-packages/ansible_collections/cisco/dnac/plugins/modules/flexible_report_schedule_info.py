#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: flexible_report_schedule_info
short_description: Information module for Flexible Report
  Schedule
description:
  - Get Flexible Report Schedule by id.
  - Get flexible report schedule by report id.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  reportId:
    description:
      - ReportId path parameter. Id of the report.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Reports
      GetFlexibleReportScheduleByReportId
    description: Complete reference of the GetFlexibleReportScheduleByReportId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-flexible-report-schedule-by-report-id
notes:
  - SDK Method used are
    reports.Reports.get_flexible_report_schedule_by_report_id,
  - Paths used are
    get /dna/data/api/v1/flexible-report/schedule/{reportId},
"""

EXAMPLES = r"""
---
- name: Get Flexible Report Schedule by id
  cisco.dnac.flexible_report_schedule_info:
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
      "schedule": {}
    }
"""
