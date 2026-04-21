#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_last_operation_status_info
short_description: Information module for License Last
  Operation Status
description:
  - Get all License Last Operation Status.
  - Retrieves the status of the last system licensing
    operation.
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
      SystemLicensingLastOperationStatus
    description: Complete reference of the SystemLicensingLastOperationStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!system-licensing-last-operation-status
notes:
  - SDK Method used are
    licenses.Licenses.system_licensing_last_operation_status,
  - Paths used are
    get /dna/system/api/v1/license/lastOperationStatus,
"""

EXAMPLES = r"""
---
- name: Get all License Last Operation Status
  cisco.dnac.license_last_operation_status_info:
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
        "id": "string",
        "status": "string",
        "isError": true,
        "failureReason": "string",
        "errorCode": "string",
        "lastUpdate": 0
      },
      "version": "string"
    }
"""
