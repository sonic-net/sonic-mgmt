#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_lexicographically_sorted_info
short_description: Information module for Network Device
  Lexicographically Sorted
description:
  - Get all Network Device Lexicographically Sorted.
  - Returns the list of values of the first given required
    parameter.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  vrfName:
    description:
      - VrfName query parameter.
    type: str
  managementIpAddress:
    description:
      - ManagementIpAddress query parameter.
    type: str
  hostname:
    description:
      - Hostname query parameter.
    type: str
  macAddress:
    description:
      - MacAddress query parameter.
    type: str
  family:
    description:
      - Family query parameter.
    type: str
  collectionStatus:
    description:
      - CollectionStatus query parameter.
    type: str
  collectionInterval:
    description:
      - CollectionInterval query parameter.
    type: str
  softwareVersion:
    description:
      - SoftwareVersion query parameter.
    type: str
  softwareType:
    description:
      - SoftwareType query parameter.
    type: str
  reachabilityStatus:
    description:
      - ReachabilityStatus query parameter.
    type: str
  reachabilityFailureReason:
    description:
      - ReachabilityFailureReason query parameter.
    type: str
  errorCode:
    description:
      - ErrorCode query parameter.
    type: str
  platformId:
    description:
      - PlatformId query parameter.
    type: str
  series:
    description:
      - Series query parameter.
    type: str
  type:
    description:
      - Type query parameter.
    type: str
  serialNumber:
    description:
      - SerialNumber query parameter.
    type: str
  upTime:
    description:
      - UpTime query parameter.
    type: str
  role:
    description:
      - Role query parameter.
    type: str
  roleSource:
    description:
      - RoleSource query parameter.
    type: str
  associatedWlcIp:
    description:
      - AssociatedWlcIp query parameter.
    type: str
  offset:
    description:
      - Offset query parameter.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page. Min 1, Max 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetDeviceValuesThatMatchFullyOrPartiallyAnAttribute
    description: Complete reference of the GetDeviceValuesThatMatchFullyOrPartiallyAnAttribute
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-values-that-match-fully-or-partially-an-attribute
notes:
  - SDK Method used are
    devices.Devices.get_device_values_that_match_fully_or_partially_an_attribute,
  - Paths used are
    get /dna/intent/api/v1/network-device/autocomplete,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Lexicographically Sorted
  cisco.dnac.network_device_lexicographically_sorted_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    vrfName: string
    managementIpAddress: string
    hostname: string
    macAddress: string
    family: string
    collectionStatus: string
    collectionInterval: string
    softwareVersion: string
    softwareType: string
    reachabilityStatus: string
    reachabilityFailureReason: string
    errorCode: string
    platformId: string
    series: string
    type: string
    serialNumber: string
    upTime: string
    role: string
    roleSource: string
    associatedWlcIp: string
    offset: 0
    limit: 0
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
        "string"
      ],
      "version": "string"
    }
"""
