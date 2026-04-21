#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_ip_address_info
short_description: Information module for Network Device
  Ip Address
description:
  - Get Network Device Ip Address by id.
  - Returns the network device by specified IP address.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  ipAddress:
    description:
      - IpAddress path parameter. Device IP address.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetNetworkDeviceByIP
    description: Complete reference of the GetNetworkDeviceByIP
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-network-device-by-ip
notes:
  - SDK Method used are
    devices.Devices.get_network_device_by_ip,
  - Paths used are
    get /dna/intent/api/v1/network-device/ip-address/{ipAddress},
"""

EXAMPLES = r"""
---
- name: Get Network Device Ip Address by id
  cisco.dnac.network_device_ip_address_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    ipAddress: string
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
        "apManagerInterfaceIp": "string",
        "associatedWlcIp": "string",
        "bootDateTime": "string",
        "collectionInterval": "string",
        "collectionStatus": "string",
        "errorCode": "string",
        "errorDescription": "string",
        "family": "string",
        "hostname": "string",
        "id": "string",
        "instanceTenantId": "string",
        "instanceUuid": "string",
        "interfaceCount": "string",
        "inventoryStatusDetail": "string",
        "lastUpdateTime": 0,
        "lastUpdated": "string",
        "lineCardCount": "string",
        "lineCardId": "string",
        "location": "string",
        "locationName": "string",
        "macAddress": "string",
        "managementIpAddress": "string",
        "memorySize": "string",
        "platformId": "string",
        "reachabilityFailureReason": "string",
        "reachabilityStatus": "string",
        "role": "string",
        "roleSource": "string",
        "serialNumber": "string",
        "series": "string",
        "snmpContact": "string",
        "snmpLocation": "string",
        "softwareType": "string",
        "softwareVersion": "string",
        "tagCount": "string",
        "tunnelUdpPort": "string",
        "type": "string",
        "upTime": "string",
        "waasDeviceMode": "string",
        "dnsResolvedManagementAddress": "string",
        "apEthernetMacAddress": "string",
        "vendor": "string",
        "reasonsForPendingSyncRequests": "string",
        "pendingSyncRequestsCount": "string",
        "reasonsForDeviceResync": "string",
        "lastDeviceResyncStartTime": "string",
        "uptimeSeconds": 0,
        "managedAtleastOnce": true,
        "deviceSupportLevel": "string",
        "managementState": "string",
        "description": "string"
      },
      "version": "string"
    }
"""
