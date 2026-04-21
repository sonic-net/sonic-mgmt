#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_rf_profile_info
short_description: Information module for Wireless Rf
  Profile
description:
  - Get all Wireless Rf Profile.
  - Retrieve all RF profiles.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  rf_profile_name:
    description:
      - Rf-profile-name query parameter. RF Profile
        Name.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      RetrieveRFProfiles
    description: Complete reference of the RetrieveRFProfiles
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-rf-profiles
notes:
  - SDK Method used are
    wireless.Wireless.retrieve_rf_profiles,
  - Paths used are
    get /dna/intent/api/v1/wireless/rf-profile,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Rf Profile
  cisco.dnac.wireless_rf_profile_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    rf_profile_name: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "name": "string",
      "defaultRfProfile": true,
      "enableRadioTypeA": true,
      "enableRadioTypeB": true,
      "channelWidth": "string",
      "enableCustom": true,
      "enableBrownField": true,
      "radioTypeAProperties": {
        "parentProfile": "string",
        "radioChannels": "string",
        "dataRates": "string",
        "mandatoryDataRates": "string",
        "powerThresholdV1": 0,
        "rxSopThreshold": "string",
        "minPowerLevel": 0,
        "maxPowerLevel": 0
      },
      "radioTypeBProperties": {
        "parentProfile": "string",
        "radioChannels": "string",
        "dataRates": "string",
        "mandatoryDataRates": "string",
        "powerThresholdV1": 0,
        "rxSopThreshold": "string",
        "minPowerLevel": 0,
        "maxPowerLevel": 0
      },
      "radioTypeCProperties": {
        "parentProfile": "string",
        "radioChannels": "string",
        "dataRates": "string",
        "mandatoryDataRates": "string",
        "rxSopThreshold": "string",
        "minPowerLevel": 0,
        "maxPowerLevel": 0,
        "powerThresholdV1": 0
      },
      "enableRadioTypeC": true
    }
"""
