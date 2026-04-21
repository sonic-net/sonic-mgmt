#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: interface_network_device_range_info
short_description: Information module for Interface
  Network Device Range
description:
  - Get all Interface Network Device Range.
  - Returns the list of interfaces for the device for
    the specified range.
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
  startIndex:
    description:
      - StartIndex path parameter. Start index.
    type: int
  recordsToReturn:
    description:
      - RecordsToReturn path parameter. Number of records
        to return.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetDeviceInterfacesBySpecifiedRange
    description: Complete reference of the GetDeviceInterfacesBySpecifiedRange
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-interfaces-by-specified-range
notes:
  - SDK Method used are
    devices.Devices.get_device_interfaces_by_specified_range,
  - Paths used are
    get /dna/intent/api/v1/interface/network-device/{deviceId}/{startIndex}/{recordsToReturn},
"""

EXAMPLES = r"""
---
- name: Get all Interface Network Device Range
  cisco.dnac.interface_network_device_range_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceId: string
    startIndex: 0
    recordsToReturn: 0
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
          "addresses": [
            {
              "address": {
                "ipAddress": {
                  "address": "string"
                },
                "ipMask": {
                  "address": "string"
                },
                "isInverseMask": true
              },
              "type": "string"
            }
          ],
          "adminStatus": "string",
          "className": "string",
          "description": "string",
          "name": "string",
          "deviceId": "string",
          "duplex": "string",
          "id": "string",
          "ifIndex": "string",
          "instanceTenantId": "string",
          "instanceUuid": "string",
          "interfaceType": "string",
          "ipv4Address": "string",
          "ipv4Mask": "string",
          "isisSupport": "string",
          "lastOutgoingPacketTime": 0,
          "lastIncomingPacketTime": 0,
          "lastUpdated": "string",
          "macAddress": "string",
          "mappedPhysicalInterfaceId": "string",
          "mappedPhysicalInterfaceName": "string",
          "mediaType": "string",
          "mtu": "string",
          "nativeVlanId": "string",
          "ospfSupport": "string",
          "pid": "string",
          "portMode": "string",
          "portName": "string",
          "portType": "string",
          "serialNo": "string",
          "series": "string",
          "speed": "string",
          "status": "string",
          "vlanId": "string",
          "voiceVlan": "string"
        }
      ],
      "version": "string"
    }
"""
