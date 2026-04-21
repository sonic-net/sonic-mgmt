#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device_history_info
short_description: Information module for Pnp Device
  History
description:
  - Get all Pnp Device History.
  - Returns history for a specific device. Serial number
    is a required parameter.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  serialNumber:
    description:
      - SerialNumber query parameter. Device Serial
        Number.
    type: str
  sort:
    description:
      - Sort query parameter. Comma seperated list of
        fields to sort on.
    elements: str
    type: list
  sortOrder:
    description:
      - SortOrder query parameter. Sort Order Ascending
        (asc) or Descending (des).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Device
      Onboarding (PnP) GetDeviceHistory
    description: Complete reference of the GetDeviceHistory
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-history
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.get_device_history,
  - Paths used are
    get /dna/intent/api/v1/onboarding/pnp-device/history,
"""

EXAMPLES = r"""
---
- name: Get all Pnp Device History
  cisco.dnac.pnp_device_history_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    serialNumber: string
    sort: []
    sortOrder: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "timestamp": 0,
          "details": "string",
          "historyTaskInfo": {
            "name": "string",
            "type": "string",
            "timeTaken": 0,
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "startTime": 0,
                "endTime": 0,
                "timeTaken": 0,
                "outputStr": "string"
              }
            ],
            "addnDetails": [
              {
                "key": "string",
                "value": "string"
              }
            ]
          },
          "errorFlag": true
        }
      ],
      "statusCode": 0
    }
"""
