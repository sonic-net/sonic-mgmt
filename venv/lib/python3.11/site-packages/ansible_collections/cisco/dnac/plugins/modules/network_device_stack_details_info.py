#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_stack_details_info
short_description: Information module for Network Device
  Stack Details
description:
  - Get all Network Device Stack Details.
  - Retrieves complete stack details for given device
    ID.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceId:
    description:
      - DeviceId path parameter. Device ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetStackDetailsForDevice
    description: Complete reference of the GetStackDetailsForDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-stack-details-for-device
notes:
  - SDK Method used are
    devices.Devices.get_stack_details_for_device,
  - Paths used are
    get /dna/intent/api/v1/network-device/{deviceId}/stack,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Stack Details
  cisco.dnac.network_device_stack_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceId: string
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
        "deviceId": "string",
        "stackPortInfo": [
          {
            "isSynchOk": "string",
            "linkActive": true,
            "linkOk": true,
            "name": "string",
            "neighborPort": "string",
            "nrLinkOkChanges": 0,
            "stackCableLengthInfo": "string",
            "stackPortOperStatusInfo": "string",
            "switchPort": "string"
          }
        ],
        "stackSwitchInfo": [
          {
            "entPhysicalIndex": "string",
            "hwPriority": 0,
            "macAddress": "string",
            "numNextReload": 0,
            "platformId": "string",
            "role": "string",
            "serialNumber": "string",
            "softwareImage": "string",
            "stackMemberNumber": 0,
            "state": "string",
            "switchPriority": 0
          }
        ],
        "svlSwitchInfo": [
          {
            "dadProtocol": "string",
            "dadRecoveryReloadEnabled": true,
            "domainNumber": 0,
            "inDadRecoveryMode": true,
            "swVirtualStatus": "string",
            "switchMembers": [
              {
                "bandwidth": "string",
                "svlMemberEndPoints": [
                  {
                    "svlMemberEndPointPorts": [
                      {
                        "svlProtocolStatus": "string",
                        "swLocalInterface": "string",
                        "swRemoteInterface": "string"
                      }
                    ],
                    "svlNumber": 0,
                    "svlStatus": "string"
                  }
                ],
                "svlMemberNumber": 0,
                "svlMemberPepSettings": [
                  {
                    "dadEnabled": true,
                    "dadInterfaceName": "string"
                  }
                ]
              }
            ]
          }
        ]
      },
      "version": "string"
    }
"""
