#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: compliance_device_info
short_description: Information module for Compliance
  Device
description:
  - Get all Compliance Device.
  - Return compliance status of devices.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  complianceStatus:
    description:
      - >
        ComplianceStatus query parameter. Specify "Compliance
        status(es)" separated by commas. The Compliance
        status can be 'COMPLIANT', 'NON_COMPLIANT',
        'IN_PROGRESS', 'NOT_AVAILABLE', 'NOT_APPLICABLE',
        'ERROR'.
    type: str
  deviceUuid:
    description:
      - DeviceUuid query parameter. Comma separated
        'Device Ids'.
    type: str
  offset:
    description:
      - "Offset query parameter. Offset/starting row\tnumber."
    type: int
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to be retrieved defaults to 500 if not specified,
        with a maximum allowed limit of 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetComplianceStatus
    description: Complete reference of the GetComplianceStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-compliance-status
notes:
  - SDK Method used are
    compliance.Compliance.get_compliance_status,
  - Paths used are
    get /dna/intent/api/v1/compliance,
"""

EXAMPLES = r"""
---
- name: Get all Compliance Device
  cisco.dnac.compliance_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    complianceStatus: string
    deviceUuid: string
    offset: 0
    limit: 0
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
      "response": [
        {
          "deviceUuid": "string",
          "complianceStatus": "string",
          "message": "string",
          "scheduleTime": 0,
          "lastUpdateTime": 0
        }
      ]
    }
"""
