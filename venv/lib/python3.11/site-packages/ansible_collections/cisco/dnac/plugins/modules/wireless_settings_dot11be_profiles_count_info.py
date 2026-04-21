#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_dot11be_profiles_count_info
short_description: Information module for Wireless Settings
  Dot11be Profiles Count
description:
  - Get all Wireless Settings Dot11be Profiles Count.
  - This API allows the user to get count of all 802.11be
    Profiles.
version_added: '6.15.0'
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
  - name: Cisco DNA Center documentation for Wireless
      Get80211beProfilesCount
    description: Complete reference of the Get80211beProfilesCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-80-21-1be-profiles-count
notes:
  - SDK Method used are
    wireless.Wireless.get80211be_profiles_count,
  - Paths used are
    get /dna/intent/api/v1/wirelessSettings/dot11beProfiles/count,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Settings Dot11be Profiles Count
  cisco.dnac.wireless_settings_dot11be_profiles_count_info:
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
        "count": 0
      },
      "version": "string"
    }
"""
