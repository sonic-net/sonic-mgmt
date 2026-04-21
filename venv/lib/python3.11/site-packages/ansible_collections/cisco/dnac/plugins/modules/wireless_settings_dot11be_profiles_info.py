#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_dot11be_profiles_info
short_description: Information module for Wireless Settings
  Dot11be Profiles
description:
  - Get all Wireless Settings Dot11be Profiles.
  - Get Wireless Settings Dot11be Profiles by id.
  - This API allows the user to get 802.11be Profile
    by ID.
  - This API allows the user to get 802.11be Profiles
    configured under Wireless Settings.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. Default is 500 if not
        specified. Maximum allowed limit is 500.
    type: float
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page, the first record is numbered
        1.
    type: float
  profileName:
    description:
      - ProfileName query parameter. Profile Name.
    type: str
  isOfDmaDownLink:
    description:
      - IsOfDmaDownLink query parameter. OFDMA Downlink.
    type: bool
  isOfDmaUpLink:
    description:
      - IsOfDmaUpLink query parameter. OFDMA Uplink.
    type: bool
  isMuMimoUpLink:
    description:
      - IsMuMimoUpLink query parameter. MU-MIMO Uplink.
    type: bool
  isMuMimoDownLink:
    description:
      - IsMuMimoDownLink query parameter. MU-MIMO Downlink.
    type: bool
  isOfDmaMultiRu:
    description:
      - IsOfDmaMultiRu query parameter. OFDMA Multi-RU.
    type: bool
  id:
    description:
      - Id path parameter. 802.11be Profile ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      Get80211beProfileByID
    description: Complete reference of the Get80211beProfileByID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-80-21-1be-profile-by-id
  - name: Cisco DNA Center documentation for Wireless
      Get80211beProfiles
    description: Complete reference of the Get80211beProfiles
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-80-21-1be-profiles
notes:
  - SDK Method used are
    wireless.Wireless.get80211be_profile_by_id,
    wireless.Wireless.get80211be_profiles,
  - Paths used are
    get /dna/intent/api/v1/wirelessSettings/dot11beProfiles,
    get /dna/intent/api/v1/wirelessSettings/dot11beProfiles/{id},
"""

EXAMPLES = r"""
---
- name: Get all Wireless Settings Dot11be Profiles
  cisco.dnac.wireless_settings_dot11be_profiles_info:
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
    isOfDmaDownLink: true
    isOfDmaUpLink: true
    isMuMimoUpLink: true
    isMuMimoDownLink: true
    isOfDmaMultiRu: true
  register: result
- name: Get Wireless Settings Dot11be Profiles by id
  cisco.dnac.wireless_settings_dot11be_profiles_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
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
        "profileName": "string",
        "ofdmaDownLink": true,
        "ofdmaUpLink": true,
        "muMimoDownLink": true,
        "muMimoUpLink": true,
        "ofdmaMultiRu": true,
        "default": true
      },
      "version": "string"
    }
"""
