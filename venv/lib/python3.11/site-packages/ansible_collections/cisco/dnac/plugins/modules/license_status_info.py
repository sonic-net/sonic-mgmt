#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_status_info
short_description: Information module for License Status
description:
  - Get all License Status. - > Fetches registration
    status, authorization status and entitlements of
    the system with Cisco Smart Software Manage CSSM
    .
version_added: '6.17.0'
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
  - name: Cisco DNA Center documentation for Licenses
      SystemLicensingStatus
    description: Complete reference of the SystemLicensingStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!system-licensing-status
notes:
  - SDK Method used are
    licenses.Licenses.system_licensing_status,
  - Paths used are
    get /dna/system/api/v1/license/status,
"""

EXAMPLES = r"""
---
- name: Get all License Status
  cisco.dnac.license_status_info:
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
  type: dict
  sample: >
    {
      "response": {
        "registrationStatus": {
          "status": "string",
          "lastAttemptTimestamp": 0,
          "expiryTimestamp": 0,
          "nextAttemptTimestamp": 0,
          "lastAttemptStatus": "string",
          "lastAttemptFailReason": "string"
        },
        "authorizationStatus": {
          "status": "string",
          "lastAttemptTimestamp": 0,
          "evaluationRemainderTimestamp": 0,
          "expiryTimestamp": 0,
          "nextAttemptTimestamp": 0,
          "lastAttemptStatus": "string",
          "lastAttemptFailReason": "string"
        },
        "entitlements": {
          "tag": "string",
          "description": "string",
          "usageCount": 0,
          "status": "string"
        },
        "smartAccountId": "string",
        "virtualAccountId": "string",
        "exportControl": "string"
      },
      "version": "string"
    }
"""
