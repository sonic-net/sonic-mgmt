#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_interface_info
short_description: Information module for Device Interface
description:
  - Get all Device Interface.
  - Get Device Interface by id. - > Returns all available
    interfaces. This endpoint can return a maximum of
    500 interfaces. The API returns a paginated response
    based on 'limit' and 'offset' parameters, allowing
    up to 500 records per page. 'limit' specifies the
    number of records, and 'offset' sets the starting
    point using 1-based indexing. Use '/dna/intent/api/v1/interface/count'
    to get the total record count. For data sets over
    500 records, make multiple calls, adjusting 'limit'
    and 'offset' to retrieve all records incrementally.
  - Returns the interface for the given interface ID.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
      - Offset query parameter.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page. Min 1, Max 500.
    type: int
  lastInputTime:
    description:
      - LastInputTime query parameter. Last Input Time.
    type: str
  lastOutputTime:
    description:
      - LastOutputTime query parameter. Last Output
        Time.
    type: str
  id:
    description:
      - Id path parameter. Interface ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetAllInterfaces
    description: Complete reference of the GetAllInterfaces
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-all-interfaces
  - name: Cisco DNA Center documentation for Devices
      GetInterfaceById
    description: Complete reference of the GetInterfaceById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-interface-by-id
notes:
  - SDK Method used are
    devices.Devices.get_all_interfaces,
    devices.Devices.get_interface_by_id,
  - Paths used are
    get /dna/intent/api/v1/interface,
    get /dna/intent/api/v1/interface/{id},
"""

EXAMPLES = r"""
---
- name: Get all Device Interface
  cisco.dnac.device_interface_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    lastInputTime: string
    lastOutputTime: string
  register: result
- name: Get Device Interface by id
  cisco.dnac.device_interface_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
      "response": {
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
      },
      "version": "string"
    }
"""
