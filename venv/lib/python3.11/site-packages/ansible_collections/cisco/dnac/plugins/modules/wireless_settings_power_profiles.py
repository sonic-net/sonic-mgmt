#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_power_profiles
short_description: Resource module for Wireless Settings
  Power Profiles
description:
  - Manage operation create of the resource Wireless
    Settings Power Profiles.
  - This API allows the user to create a custom Power
    Profile.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Description of the Power Profile. Max
      allowed characters is 128.
    type: str
  profileName:
    description: Name of the Power Profile. Max allowed
      characters is 128.
    type: str
  rules:
    description: Wireless Settings Power Profiles's
      rules.
    elements: dict
    suboptions:
      interfaceId:
        description: Interface Id for the rule.
        type: str
      interfaceType:
        description: Interface Type for the rule.
        type: str
      parameterType:
        description: Parameter Type for the rule.
        type: str
      parameterValue:
        description: Parameter Value for the rule.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreatePowerProfile
    description: Complete reference of the CreatePowerProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-power-profile
notes:
  - SDK Method used are
    wireless.Wireless.create_power_profile,
  - Paths used are
    post /dna/intent/api/v1/wirelessSettings/powerProfiles,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_settings_power_profiles:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    description: string
    profileName: string
    rules:
      - interfaceId: string
        interfaceType: string
        parameterType: string
        parameterValue: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
