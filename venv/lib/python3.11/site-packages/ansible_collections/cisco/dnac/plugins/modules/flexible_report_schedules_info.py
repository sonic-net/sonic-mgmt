#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: flexible_report_schedules_info
short_description: Information module for Flexible Report
  Schedules
description:
  - Get all Flexible Report Schedules.
  - Get all flexible report schedules.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Reports
      GetAllFlexibleReportSchedules
    description: Complete reference of the GetAllFlexibleReportSchedules
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-all-flexible-report-schedules
notes:
  - SDK Method used are
    reports.Reports.get_all_flexible_report_schedules,
  - Paths used are
    get /dna/data/api/v1/flexible-report/schedules,
"""

EXAMPLES = r"""
---
- name: Get all Flexible Report Schedules
  cisco.dnac.flexible_report_schedules_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "reportId": "string",
        "schedule": {},
        "reportName": "string"
      }
    ]
"""
