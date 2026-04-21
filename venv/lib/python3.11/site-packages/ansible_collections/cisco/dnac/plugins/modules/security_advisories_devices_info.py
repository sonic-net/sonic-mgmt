#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_advisories_devices_info
short_description: Information module for Security Advisories
  Devices
description:
  - Get all Security Advisories Devices.
  - Retrieves list of devices for an advisory.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  advisoryId:
    description:
      - AdvisoryId path parameter. Advisory ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Security
      Advisories GetDevicesPerAdvisory
    description: Complete reference of the GetDevicesPerAdvisory
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-devices-per-advisory
notes:
  - SDK Method used are
    security_advisories.SecurityAdvisories.get_devices_per_advisory,
  - Paths used are
    get /dna/intent/api/v1/security-advisory/advisory/{advisoryId}/device,
"""

EXAMPLES = r"""
---
- name: Get all Security Advisories Devices
  cisco.dnac.security_advisories_devices_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    advisoryId: string
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
        "string"
      ],
      "version": "string"
    }
"""
