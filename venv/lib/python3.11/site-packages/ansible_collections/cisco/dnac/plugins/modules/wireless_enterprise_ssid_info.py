#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_enterprise_ssid_info
short_description: Information module for Wireless Enterprise
  Ssid
description:
  - Get all Wireless Enterprise Ssid.
  - Get Enterprise SSID.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  ssidName:
    description:
      - >
        SsidName query parameter. Enter the enterprise
        SSID name that needs to be retrieved. If not
        entered, all the enterprise SSIDs will be retrieved.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetEnterpriseSSID
    description: Complete reference of the GetEnterpriseSSID
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-enterprise-ssid
notes:
  - SDK Method used are
    wireless.Wireless.get_enterprise_ssid,
  - Paths used are
    get /dna/intent/api/v1/enterprise-ssid,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Enterprise Ssid
  cisco.dnac.wireless_enterprise_ssid_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    ssidName: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "instanceUuid": "string",
        "version": 0,
        "ssidDetails": [
          {
            "name": "string",
            "wlanType": "string",
            "enableFastLane": true,
            "securityLevel": "string",
            "authServer": "string",
            "passphrase": "string",
            "trafficType": "string",
            "enableMACFiltering": true,
            "isEnabled": true,
            "isFabric": true,
            "fastTransition": "string",
            "radioPolicy": "string",
            "enableBroadcastSSID": true,
            "nasOptions": [
              "string"
            ],
            "aaaOverride": true,
            "coverageHoleDetectionEnable": true,
            "protectedManagementFrame": "string",
            "multiPSKSettings": [
              {
                "priority": 0,
                "passphraseType": "string",
                "passphrase": "string"
              }
            ],
            "clientRateLimit": 0,
            "enableSessionTimeOut": true,
            "sessionTimeOut": 0,
            "enableClientExclusion": true,
            "clientExclusionTimeout": 0,
            "enableBasicServiceSetMaxIdle": true,
            "basicServiceSetClientIdleTimeout": 0,
            "enableDirectedMulticastService": true,
            "enableNeighborList": true,
            "mfpClientProtection": "string"
          }
        ],
        "groupUuid": "string",
        "inheritedGroupUuid": "string",
        "inheritedGroupName": "string"
      }
    ]
"""
