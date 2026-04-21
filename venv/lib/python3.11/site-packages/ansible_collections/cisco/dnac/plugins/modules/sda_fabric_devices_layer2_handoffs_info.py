#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_devices_layer2_handoffs_info
short_description: Information module for Sda Fabricdevices
  Layer2handoffs
description:
  - Get all Sda Fabricdevices Layer2handoffs.
  - Returns a list of layer 2 handoffs of fabric devices
    that match the provided query parameters.
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
  offset:
    description:
      - Offset query parameter. Starting record for
        pagination.
    type: int
  limit:
    description:
      - >
        Limit query parameter. Maximum number of records
        to return. The maximum number of objects supported
        in a single request is 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetFabricDevicesLayer2Handoffs
    description: Complete reference of the GetFabricDevicesLayer2Handoffs
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-fabric-devices-layer-2-handoffs
notes:
  - SDK Method used are
    sda.Sda.get_fabric_devices_layer2_handoffs,
  - Paths used are
    get /dna/intent/api/v1/sda/fabricDevices/layer2Handoffs,
"""

EXAMPLES = r"""
---
- name: Get all Sda Fabricdevices Layer2handoffs
  cisco.dnac.sda_fabricDevices_layer2Handoffs_info:
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
        {
          "id": "string",
          "networkDeviceId": "string",
          "fabricId": "string",
          "interfaceName": "string",
          "internalVlanId": 0,
          "externalVlanId": 0
        }
      ],
      "version": "string"
    }
"""
