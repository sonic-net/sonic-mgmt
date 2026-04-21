#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_rogue_wireless_containment_status_info
short_description: Information module for Security Rogue
  Wireless-Containment Status
description:
  - Get Security Rogue Wireless-Containment Status by
    id. - > Intent API to check the wireless rogue access
    point containment status. The response includes
    all the details like containment status, contained
    by WLC, containment status of each BSSID etc. This
    API also includes the information of strongest detecting
    WLC for this rogue access point.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  macAddress:
    description:
      - MacAddress path parameter. MAC Address of the
        Wireless Rogue AP.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      WirelessRogueAPContainmentStatus
    description: Complete reference of the WirelessRogueAPContainmentStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!wireless-rogue-ap-containment-status
notes:
  - SDK Method used are
    devices.Devices.wireless_rogue_ap_containment_status,
  - Paths used are
    get /dna/intent/api/v1/security/rogue/wireless-containment/status/{macAddress},
"""

EXAMPLES = r"""
---
- name: Get Security Rogue Wireless-Containment Status
    by id
  cisco.dnac.security_rogue_wireless-containment_status_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    macAddress: string
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
          "macAddress": "string",
          "type": 0,
          "classification": "string",
          "containmentStatus": "string",
          "containedByWlcIp": [
            "string"
          ],
          "lastSeen": 0,
          "strongestDetectingWlcIp": "string",
          "lastTaskDetail": {
            "taskId": "string",
            "taskType": "string",
            "taskState": "string",
            "taskStartTime": 0,
            "initiatedOnWlcIp": "string",
            "initiatedOnBssid": [
              "string"
            ]
          },
          "bssidContainmentStatus": [
            {
              "bssid": "string",
              "ssid": "string",
              "radioType": "string",
              "containmentStatus": "string",
              "containedByWlcIp": "string",
              "isAdhoc": true
            }
          ]
        }
      ],
      "version": "string"
    }
"""
