#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: discovery_device_info
short_description: Information module for Discovery
  Device
description:
  - Get all Discovery Device. - > Returns the network
    devices discovered for the given Discovery ID. Discovery
    ID can be obtained using the "Get Discoveries by
    range" API.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Discovery ID.
    type: str
  taskId:
    description:
      - TaskId query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Discovery
      GetDiscoveredNetworkDevicesByDiscoveryId
    description: Complete reference of the GetDiscoveredNetworkDevicesByDiscoveryId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-discovered-network-devices-by-discovery-id
notes:
  - SDK Method used are
    discovery.Discovery.get_discovered_network_devices_by_discovery_id,
  - Paths used are
    get /dna/intent/api/v1/discovery/{id}/network-device,
"""

EXAMPLES = r"""
---
- name: Get all Discovery Device
  cisco.dnac.discovery_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    taskId: string
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
      "response": [
        {
          "anchorWlcForAp": "string",
          "authModelId": "string",
          "avgUpdateFrequency": 0,
          "bootDateTime": "string",
          "cliStatus": "string",
          "duplicateDeviceId": "string",
          "errorCode": "string",
          "errorDescription": "string",
          "family": "string",
          "hostname": "string",
          "httpStatus": "string",
          "id": "string",
          "imageName": "string",
          "ingressQueueConfig": "string",
          "interfaceCount": "string",
          "inventoryCollectionStatus": "string",
          "inventoryReachabilityStatus": "string",
          "lastUpdated": "string",
          "lineCardCount": "string",
          "lineCardId": "string",
          "location": "string",
          "locationName": "string",
          "macAddress": "string",
          "managementIpAddress": "string",
          "memorySize": "string",
          "netconfStatus": "string",
          "numUpdates": 0,
          "pingStatus": "string",
          "platformId": "string",
          "portRange": "string",
          "qosStatus": "string",
          "reachabilityFailureReason": "string",
          "reachabilityStatus": "string",
          "role": "string",
          "roleSource": "string",
          "serialNumber": "string",
          "snmpContact": "string",
          "snmpLocation": "string",
          "snmpStatus": "string",
          "softwareVersion": "string",
          "tag": "string",
          "tagCount": 0,
          "type": "string",
          "upTime": "string",
          "vendor": "string",
          "wlcApDeviceStatus": "string"
        }
      ],
      "version": "string"
    }
"""
