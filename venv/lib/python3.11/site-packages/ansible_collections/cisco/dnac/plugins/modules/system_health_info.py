#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: system_health_info
short_description: Information module for System Health
description:
  - Get all System Health.
  - This API retrieves the latest system events.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  summary:
    description:
      - Summary query parameter. Fetch the latest high
        severity event.
    type: bool
  domain:
    description:
      - >
        Domain query parameter. Fetch system events
        with this domain. Possible values of domain
        are listed here /dna/platform/app/consumer-portal/developer-toolkit/events.
    type: str
  subdomain:
    description:
      - >
        Subdomain query parameter. Fetch system events
        with this subdomain. Possible values of subdomain
        are listed here /dna/platform/app/consumer-portal/developer-toolkit/events.
    type: str
  limit:
    description:
      - >
        Limit query parameter. Specifies the maximum
        number of system health events to return per
        page. Must be an integer between 1 and 50, inclusive.
    type: float
  offset:
    description:
      - >
        Offset query parameter. Specifies the starting
        point for the list of system health events to
        return. Must be an integer greater than or equal
        to 0.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Health
      and Performance SystemHealthAPI
    description: Complete reference of the SystemHealthAPI
      API.
    link: https://developer.cisco.com/docs/dna-center/#!system-health-api
notes:
  - SDK Method used are
    health_and_performance.HealthAndPerformance.system_health,
  - Paths used are
    get /dna/intent/api/v1/diagnostics/system/health,
"""

EXAMPLES = r"""
---
- name: Get all System Health
  cisco.dnac.system_health_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    summary: true
    domain: string
    subdomain: string
    limit: 0
    offset: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "healthEvents": [
        {
          "severity": "string",
          "hostname": "string",
          "instance": "string",
          "subDomain": "string",
          "domain": "string",
          "description": "string",
          "state": "string",
          "timestamp": "string",
          "status": "string"
        }
      ],
      "version": "string",
      "hostName": "string",
      "cimcaddress": [
        "string"
      ]
    }
"""
