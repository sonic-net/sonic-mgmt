#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_poe_info
short_description: Information module for Network Device
  Poe
description:
  - Get all Network Device Poe.
  - Returns POE details for device.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceUuid:
    description:
      - DeviceUuid path parameter. UUID of the device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      POEDetails
    description: Complete reference of the POEDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!p-oe-details
notes:
  - SDK Method used are
    devices.Devices.poe_details,
  - Paths used are
    get /dna/intent/api/v1/network-device/{deviceUuid}/poe,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Poe
  cisco.dnac.network_device_poe_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceUuid: string
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
        "powerAllocated": "string",
        "powerConsumed": "string",
        "powerRemaining": "string"
      },
      "version": "string"
    }
"""
