#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_advisories_results_trend_count_info
short_description: Information module for Security Advisories
  Results Trend Count
description:
  - Get all Security Advisories Results Trend Count.
  - Get count of security advisories results trend over
    time.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  scanTime:
    description:
      - ScanTime query parameter. Return advisories
        trend with scanTime greater than this scanTime.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetCountOfSecurityAdvisoriesResultsTrendOverTime
    description: Complete reference of the GetCountOfSecurityAdvisoriesResultsTrendOverTime
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-count-of-security-advisories-results-trend-over-time
notes:
  - SDK Method used are
    compliance.Compliance.get_count_of_security_advisories_results_trend_over_time,
  - Paths used are
    get /dna/intent/api/v1/securityAdvisories/resultsTrend/count,
"""

EXAMPLES = r"""
---
- name: Get all Security Advisories Results Trend Count
  cisco.dnac.security_advisories_results_trend_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    scanTime: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "count": 0
      }
    }
"""
