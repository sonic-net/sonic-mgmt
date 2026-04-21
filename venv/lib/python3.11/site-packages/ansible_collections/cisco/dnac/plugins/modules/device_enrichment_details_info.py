#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_enrichment_details_info
short_description: Information module for Device Enrichment
  Details
description:
  - Get all Device Enrichment Details. - > Enriches
    a given network device context device id or device
    Mac Address or device management IP address with
    details about the device and neighbor topology.
version_added: '3.1.0'
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
  - name: Cisco DNA Center documentation for Devices
      GetDeviceEnrichmentDetails
    description: Complete reference of the GetDeviceEnrichmentDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-enrichment-details
notes:
  - SDK Method used are
    devices.Devices.get_device_enrichment_details,
  - Paths used are
    get /dna/intent/api/v1/device-enrichment-details,
"""

EXAMPLES = r"""
---
- name: Get all Device Enrichment Details
  cisco.dnac.device_enrichment_details_info:
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
  type: list
  elements: dict
  sample: >
    [
      {
        "deviceDetails": {
          "family": "string",
          "type": "string",
          "location": {},
          "errorCode": "string",
          "macAddress": "string",
          "role": "string",
          "apManagerInterfaceIp": "string",
          "associatedWlcIp": "string",
          "bootDateTime": "string",
          "collectionStatus": "string",
          "interfaceCount": "string",
          "lineCardCount": "string",
          "lineCardId": "string",
          "managementIpAddress": "string",
          "memorySize": "string",
          "platformId": "string",
          "reachabilityFailureReason": "string",
          "reachabilityStatus": "string",
          "snmpContact": "string",
          "snmpLocation": "string",
          "tunnelUdpPort": {},
          "waasDeviceMode": {},
          "series": "string",
          "inventoryStatusDetail": "string",
          "collectionInterval": "string",
          "serialNumber": "string",
          "softwareVersion": "string",
          "roleSource": "string",
          "hostname": "string",
          "upTime": "string",
          "lastUpdateTime": 0,
          "errorDescription": "string",
          "locationName": {},
          "tagCount": "string",
          "lastUpdated": "string",
          "instanceUuid": "string",
          "id": "string",
          "neighborTopology": [
            {
              "nodes": [
                {
                  "role": "string",
                  "name": "string",
                  "id": "string",
                  "description": "string",
                  "deviceType": "string",
                  "platformId": "string",
                  "family": "string",
                  "ip": "string",
                  "softwareVersion": "string",
                  "userId": {},
                  "nodeType": "string",
                  "radioFrequency": {},
                  "clients": {},
                  "count": {},
                  "healthScore": 0,
                  "level": 0,
                  "fabricGroup": {},
                  "connectedDevice": {}
                }
              ],
              "links": [
                {
                  "source": "string",
                  "linkStatus": "string",
                  "label": [
                    {}
                  ],
                  "target": "string",
                  "id": {},
                  "portUtilization": {}
                }
              ]
            }
          ]
        }
      }
    ]
"""
