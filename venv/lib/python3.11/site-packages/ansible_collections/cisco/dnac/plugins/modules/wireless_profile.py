#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_profile
short_description: Resource module for Wireless Profile
description:
  - Manage operations create, update and delete of the
    resource Wireless Profile.
  - Creates Wireless Network Profile on Cisco DNA Center
    and associates sites and SSIDs to it.
  - Delete the Wireless Profile whose name is provided.
    - > Updates the wireless Network Profile with updated
    details provided. All sites to be present in the
    network profile should be provided.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  profileDetails:
    description: Wireless Profile's profileDetails.
    suboptions:
      name:
        description: Profile Name.
        type: str
      sites:
        description: Array of site name hierarchies(eg
          "Global/aaa/zzz", "Global/aaa/zzz").
        elements: str
        type: list
      ssidDetails:
        description: Wireless Profile's ssidDetails.
        elements: dict
        suboptions:
          enableFabric:
            description: True if ssid is fabric else
              false.
            type: bool
          flexConnect:
            description: Wireless Profile's flexConnect.
            suboptions:
              enableFlexConnect:
                description: True if flex connect is
                  enabled else false.
                type: bool
              localToVlan:
                description: Local to VLAN ID. Required
                  if enableFlexConnect is true.
                type: int
            type: dict
          interfaceName:
            description: Interface Name.
            type: str
          name:
            description: Ssid Name.
            type: str
          policyProfileName:
            description: Policy Profile Name.
            type: str
          wlanProfileName:
            description: WLAN Profile Name.
            type: str
        type: list
    type: dict
  wirelessProfileName:
    description: WirelessProfileName path parameter.
      Wireless Profile Name.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateWirelessProfile
    description: Complete reference of the CreateWirelessProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-wireless-profile
  - name: Cisco DNA Center documentation for Wireless
      DeleteWirelessProfile
    description: Complete reference of the DeleteWirelessProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-wireless-profile
  - name: Cisco DNA Center documentation for Wireless
      UpdateWirelessProfile
    description: Complete reference of the UpdateWirelessProfile
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-wireless-profile
notes:
  - SDK Method used are
    wireless.Wireless.create_wireless_profile,
    wireless.Wireless.delete_wireless_profile,
    wireless.Wireless.update_wireless_profile,
  - Paths used are
    post /dna/intent/api/v1/wireless/profile,
    delete /dna/intent/api/v1/wireless-profile/{wirelessProfileName},
    put /dna/intent/api/v1/wireless/profile,
"""

EXAMPLES = r"""
---
- name: Delete by name
  cisco.dnac.wireless_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    wirelessProfileName: string
- name: Update all
  cisco.dnac.wireless_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    profileDetails:
      name: string
      sites:
        - string
      ssidDetails:
        - enableFabric: true
          flexConnect:
            enableFlexConnect: true
            localToVlan: 0
          interfaceName: string
          name: string
          policyProfileName: string
          wlanProfileName: string
- name: Create
  cisco.dnac.wireless_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    profileDetails:
      name: string
      sites:
        - string
      ssidDetails:
        - enableFabric: true
          flexConnect:
            enableFlexConnect: true
            localToVlan: 0
          interfaceName: string
          name: string
          policyProfileName: string
          wlanProfileName: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
