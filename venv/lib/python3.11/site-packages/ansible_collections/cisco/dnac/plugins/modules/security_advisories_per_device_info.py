#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_advisories_per_device_info
short_description: Information module for Security Advisories
  Per Device
description:
  - Get all Security Advisories Per Device.
  - Retrieves list of advisories for a device.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceId:
    description:
      - DeviceId path parameter. Device instance UUID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Security
      Advisories GetAdvisoriesPerDevice
    description: Complete reference of the GetAdvisoriesPerDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-advisories-per-device
notes:
  - SDK Method used are
    security_advisories.SecurityAdvisories.get_advisories_per_device,
  - Paths used are
    get /dna/intent/api/v1/security-advisory/device/{deviceId}/advisory,
"""

EXAMPLES = r"""
---
- name: Get all Security Advisories Per Device
  cisco.dnac.security_advisories_per_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceId: string
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
        "advisoryId": "string",
        "deviceCount": 0,
        "hiddenDeviceCount": 0,
        "cves": [
          "string"
        ],
        "publicationUrl": "string",
        "sir": "string",
        "detectionType": "string",
        "defaultDetectionType": "string",
        "defaultConfigMatchPattern": "string",
        "fixedVersions": {}
      },
      "version": "string"
    }
"""
