#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: compliance_device_status_count_info
short_description: Information module for Compliance
  Device Status Count
description:
  - Get all Compliance Device Status Count.
  - Return Compliance Status Count.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Compliance
      GetComplianceStatusCount
    description: Complete reference of the GetComplianceStatusCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-compliance-status-count
notes:
  - SDK Method used are
    compliance.Compliance.get_compliance_status_count,
  - Paths used are
    get /dna/intent/api/v1/compliance/count,
"""

EXAMPLES = r"""
---
- name: Get all Compliance Device Status Count
  cisco.dnac.compliance_device_status_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    complianceStatus: string
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
      "response": 0
    }
"""
