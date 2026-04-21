#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: iot_network_devices_network_device_id_mrp_rings_count_info
short_description: Information module for Iot Network
  Devices  Network Device Id Mrp Rings Count
description:
  - Get all Iot Network Devices  Network Device Id Mrp
    Rings Count. - > This API returns the count of MRP
    rings for the given fields - networkDeviceId Network
    device ID of the MRP ring member. The networkDeviceId
    is the instanceUuid attribute in the response of
    API - /dna/intent/api/v1/networkDevices .
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - NetworkDeviceId path parameter. Network device
        ID of the MRP ring member.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Industrial
      Configuration RetrievesTheCountOfMRPRings
    description: Complete reference of the RetrievesTheCountOfMRPRings
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-count-of-mrp-rings
notes:
  - SDK Method used are
    industrial_configuration.IndustrialConfiguration.retrieves_the_count_of_m_r_p_rings,
  - Paths used are
    get /dna/intent/api/v1/iot/networkDevices/{networkDeviceId}/mrpRings/count,
"""

EXAMPLES = r"""
---
- name: Get all Iot Network Devices  Network Device
    Id Mrp Rings Count
  cisco.dnac.iot_network_devices_network_device_id_mrp_rings_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
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
        "response": [
          {
            "count": 0
          }
        ],
        "version": 0
      }
    ]
"""
