#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_devices_count_info
short_description: Information module for Sda Fabric
  Devices Count
description:
  - Get all Sda Fabric Devices Count.
  - Returns the count of fabric devices that match the
    provided query parameters.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - FabricId query parameter. ID of the fabric this
        device belongs to.
    type: str
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. Network device
        ID of the fabric device.
    type: str
  deviceRoles:
    description:
      - >
        DeviceRoles query parameter. Device roles of
        the fabric device. Allowed values are CONTROL_PLANE_NODE,
        EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE,
        EXTENDED_NODE.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetFabricDevicesCount
    description: Complete reference of the GetFabricDevicesCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-fabric-devices-count
notes:
  - SDK Method used are
    sda.Sda.get_fabric_devices_count,
  - Paths used are
    get /dna/intent/api/v1/sda/fabricDevices/count,
"""

EXAMPLES = r"""
---
- name: Get all Sda Fabric Devices Count
  cisco.dnac.sda_fabric_devices_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
    networkDeviceId: string
    deviceRoles: string
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
        "count": 0
      },
      "version": "string"
    }
"""
