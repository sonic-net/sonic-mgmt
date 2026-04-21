#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_devices_interfaces_query
short_description: Resource module for Network Devices
  Interfaces Query
description:
  - Manage operation create of the resource Network
    Devices Interfaces Query. - > This API returns the
    Interface Stats for the given Device Id. Please
    refer to the Feature tab for the Request Body usage
    and the API filtering support.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceId:
    description: DeviceId path parameter. Network Device
      Id.
    type: str
  endTime:
    description: UTC epoch timestamp in milliseconds.
    type: int
  query:
    description: Network Devices Interfaces Query's
      query.
    suboptions:
      fields:
        description: Required field names, default ALL.
        elements: dict
        type: list
      filters:
        description: Network Devices Interfaces Query's
          filters.
        elements: dict
        suboptions:
          key:
            description: Name of the field that the
              filter should be applied to.
            type: str
          operator:
            description: Supported operators are eq,in,like.
            type: str
          value:
            description: Value of the field.
            type: str
        type: list
      page:
        description: Network Devices Interfaces Query's
          page.
        suboptions:
          limit:
            description: Number of records, Max is 1000.
            type: int
          offset:
            description: Record offset value, default
              0.
            type: float
          orderBy:
            description: Network Devices Interfaces
              Query's orderBy.
            elements: dict
            suboptions:
              name:
                description: Name of the field used
                  to sort.
                type: str
              order:
                description: Possible values asc, des.
                type: str
            type: list
        type: dict
    type: dict
  startTime:
    description: UTC epoch timestamp in milliseconds.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetDeviceInterfaceStatsInfoV2
    description: Complete reference of the GetDeviceInterfaceStatsInfoV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-device-interface-stats-info-v-2
notes:
  - SDK Method used are
    devices.Devices.get_device_interface_stats_info_v2,
  - Paths used are
    post /dna/intent/api/v2/networkDevices/{deviceId}/interfaces/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.network_devices_interfaces_query:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceId: string
    endTime: 0
    query:
      fields:
        - {}
      filters:
        - key: string
          operator: string
          value: string
      page:
        limit: 0
        offset: 0
        orderBy:
          - name: string
            order: string
    startTime: 0
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "totalCount": 0,
      "response": [
        {
          "id": "string",
          "values": {
            "adminStatus": "string",
            "deviceId": "string",
            "duplexConfig": "string",
            "duplexOper": "string",
            "interfaceId": "string",
            "interfaceType": "string",
            "instanceId": "string",
            "ipv4Address": "string",
            "ipv6AddressList": [
              "string"
            ],
            "isL3Interface": "string",
            "isWan": "string",
            "macAddr": "string",
            "mediaType": "string",
            "name": "string",
            "operStatus": "string",
            "peerStackMember": "string",
            "peerStackPort": "string",
            "portChannelId": "string",
            "portMode": "string",
            "portType": "string",
            "description": "string",
            "rxDiscards": "string",
            "rxError": "string",
            "rxRate": "string",
            "rxUtilization": "string",
            "speed": "string",
            "stackPortType": "string",
            "timestamp": "string",
            "txDiscards": "string",
            "txError": "string",
            "txRate": "string",
            "txUtilization": "string",
            "vlanId": "string"
          }
        }
      ],
      "page": {
        "limit": 0,
        "offset": 0,
        "count": 0
      }
    }
"""
