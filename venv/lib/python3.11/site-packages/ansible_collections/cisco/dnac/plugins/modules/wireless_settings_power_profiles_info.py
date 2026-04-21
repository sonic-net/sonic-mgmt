#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_power_profiles_info
short_description: Information module for Wireless Settings
  Power Profiles
description:
  - Get all Wireless Settings Power Profiles.
  - This API allows the user to get Power Profiles that
    captured in wireless settings design.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  limit:
    description:
      - Limit query parameter.
    type: float
  offset:
    description:
      - Offset query parameter.
    type: float
  profileName:
    description:
      - ProfileName query parameter. Power Profile Name.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetPowerProfiles
    description: Complete reference of the GetPowerProfiles
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-power-profiles
notes:
  - SDK Method used are
    wireless.Wireless.get_power_profiles,
  - Paths used are
    get /dna/intent/api/v1/wirelessSettings/powerProfiles,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Settings Power Profiles
  cisco.dnac.wireless_settings_power_profiles_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
    profileName: string
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
          "id": "string",
          "profileName": "string",
          "description": "string",
          "rules": [
            {
              "sequence": 0,
              "interfaceType": "string",
              "interfaceId": "string",
              "parameterType": "string",
              "parameterValue": "string"
            }
          ]
        }
      ],
      "version": "string"
    }
"""
